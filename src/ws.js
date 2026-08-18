import { WebSocketServer } from "ws";
import { getDb } from "./db.js";
import { spins } from "./services/spins.js";
import { slots } from "./services/slots.js";
import { getOverlayAuthStatus } from "./services/authStatus.js";
import { env } from "./utils/env.js";

const MAX_CONNECTIONS_PER_IP = 12;
const MAX_CONNECTIONS_PER_BROADCASTER = 24;

export function isAllowedWebSocketOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return env.NODE_ENV !== "production";
  try {
    const actual = new URL(origin).origin;
    if (env.PUBLIC_BASE_URL && actual === new URL(env.PUBLIC_BASE_URL).origin) return true;
    if (env.NODE_ENV !== "production") {
      const host = String(req.headers.host || "").split(",")[0].trim();
      return actual === `http://${host}` || actual === `https://${host}`;
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Create the WebSocket server with per-streamer room support.
 *
 * Clients connect to /ws?key={overlay_key} and are grouped by broadcaster_id.
 * Broadcasts target a specific broadcaster's connected clients only.
 */
export function createWSS() {
  const wss = new WebSocketServer({ noServer: true });

  // Room map: broadcasterId -> Set<WebSocket>
  const rooms = new Map();
  const connectionsByIp = new Map();

  function addToRoom(broadcasterId, ws) {
    if (!rooms.has(broadcasterId)) rooms.set(broadcasterId, new Set());
    rooms.get(broadcasterId).add(ws);
  }

  function removeFromRoom(broadcasterId, ws) {
    const room = rooms.get(broadcasterId);
    if (room) {
      room.delete(ws);
      if (room.size === 0) rooms.delete(broadcasterId);
    }
  }

  wss.on("connection", (ws, req) => {
    const bid = ws._broadcasterId;
    console.log(`WS client connected: bid=${bid} ip=${req.socket.remoteAddress}`);

    ws.isAlive = true;
    const ip = req.socket.remoteAddress || "unknown";
    connectionsByIp.set(ip, (connectionsByIp.get(ip) || 0) + 1);
    ws.on("pong", () => { ws.isAlive = true; });

    // Send current state on connect
    try {
      const pending = spins.getPending(bid);
      const timeUntilNext = spins.getTimeUntilNextSpin(bid);
      const streamer = getDb().getStreamerById(bid);
      const auth = getOverlayAuthStatus(streamer);
      ws.send(JSON.stringify({
        action: "pending",
        count: pending,
        type: "delay",
        timeUntilNext: Math.ceil(timeUntilNext / 1000),
        pending,
        auth_ok: auth.auth_ok,
        auth_message: auth.auth_message,
      }));
    } catch {}

    ws.on("close", () => {
      removeFromRoom(bid, ws);
      const next = Math.max(0, (connectionsByIp.get(ip) || 1) - 1);
      if (next) connectionsByIp.set(ip, next); else connectionsByIp.delete(ip);
      console.log(`WS closed: bid=${bid}`);
    });

    ws.on("error", (e) => {
      console.error(`WS client error bid=${bid}:`, e);
    });
  });

  wss.on("error", (err) => console.error("WS server error:", err));

  // Heartbeat
  setInterval(() => {
    for (const ws of wss.clients) {
      if (ws.isAlive === false) { ws.terminate(); continue; }
      ws.isAlive = false;
      try { ws.ping(); } catch {}
    }
  }, 30_000);

  // Register the broadcast function with the spins + slots services.
  // Signature: (broadcasterId, msg) => numberOfClientsReached
  const broadcastToRoom = (broadcasterId, msg) => {
    const room = rooms.get(broadcasterId);
    if (!room) return 0;
    let sent = 0;
    const data = JSON.stringify(msg);
    for (const client of room) {
      if (client.readyState === 1) {
        try { client.send(data); sent++; } catch {}
      }
    }
    return sent;
  };
  spins.setBroadcaster(broadcastToRoom);
  slots.setBroadcaster(broadcastToRoom);

  /**
   * Broadcast to a specific broadcaster's connected clients.
   * Used by routes (e.g., config updates) outside of the spins service.
   */
  wss.broadcastTo = (broadcasterId, msg) => {
    const room = rooms.get(broadcasterId);
    if (!room) return 0;
    let sent = 0;
    const data = JSON.stringify(msg);
    for (const client of room) {
      if (client.readyState === 1) {
        try { client.send(data); sent++; } catch {}
      }
    }
    return sent;
  };

  // Store addToRoom for use in upgrade handler
  wss._addToRoom = addToRoom;
  wss._rooms = rooms;
  wss._connectionsByIp = connectionsByIp;

  return wss;
}

export function attachUpgrade(server, wss) {
  server.on("upgrade", (req, socket, head) => {
    // Parse URL: /ws?key={overlay_key}
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    if (url.pathname !== "/ws") {
      socket.destroy();
      return;
    }

    if (!isAllowedWebSocketOrigin(req)) {
      socket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
      socket.destroy();
      return;
    }

    const ip = req.socket.remoteAddress || "unknown";
    if ((wss._connectionsByIp?.get(ip) || 0) >= MAX_CONNECTIONS_PER_IP) {
      socket.write("HTTP/1.1 429 Too Many Requests\r\n\r\n");
      socket.destroy();
      return;
    }

    const overlayKey = url.searchParams.get("key");
    if (!overlayKey) {
      socket.write("HTTP/1.1 400 Bad Request\r\n\r\n");
      socket.destroy();
      return;
    }

    // Look up streamer by overlay key
    let streamer;
    try {
      streamer = getDb().getStreamerByOverlayKey(overlayKey);
    } catch {}

    if (!streamer) {
      socket.write("HTTP/1.1 404 Not Found\r\n\r\n");
      socket.destroy();
      return;
    }

    if ((wss._rooms?.get(streamer.broadcaster_id)?.size || 0) >= MAX_CONNECTIONS_PER_BROADCASTER) {
      socket.write("HTTP/1.1 429 Too Many Requests\r\n\r\n");
      socket.destroy();
      return;
    }

    wss.handleUpgrade(req, socket, head, (ws) => {
      ws._broadcasterId = streamer.broadcaster_id;
      ws._overlayKey = overlayKey;
      wss._addToRoom(streamer.broadcaster_id, ws);
      wss.emit("connection", ws, req);
    });
  });
}
