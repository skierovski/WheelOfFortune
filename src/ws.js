import { WebSocketServer } from "ws";
import { spins } from "./services/spins.js";

export function createWSS() {
  const wss = new WebSocketServer({ noServer: true });
  wss.on("connection", (ws, req) => {
    console.log("WS client connected:", req.socket.remoteAddress);
    ws.isAlive = true;
    ws.on("pong", () => { ws.isAlive = true; });
    try { ws.send(JSON.stringify({ action: "pending", count: spins.getPending() })); } catch {}
    ws.on("close", () => console.log("WS closed"));
    ws.on("error", (e) => console.error("WS client error:", e));
  });
  wss.on("error", (err) => console.error("WS server error:", err));

  // heartbeat
  setInterval(() => {
    for (const ws of wss.clients) {
      if (ws.isAlive === false) { ws.terminate(); continue; }
      ws.isAlive = false; try { ws.ping(); } catch {}
    }
  }, 30_000);

  spins.setBroadcaster(msg => {
    let sent = 0;
    for (const client of wss.clients) {
      if (client.readyState === 1) { try { client.send(JSON.stringify(msg)); sent++; } catch {} }
    }
    return sent;
  });

  return wss;
}

export function attachUpgrade(server, wss) {
  server.on("upgrade", (req, socket, head) => {
    if (req.url !== "/ws") { socket.destroy(); return; }
    wss.handleUpgrade(req, socket, head, (ws) => { wss.emit("connection", ws, req); });
  });
}
