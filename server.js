// server.js
import express from "express";
import bodyParser from "body-parser";
import { WebSocketServer } from "ws";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Diagnostics
console.log("cwd      :", process.cwd());
console.log("__dirname:", __dirname);

// Static dir
const PUB = path.join(__dirname, "public");
console.log("public   :", PUB, "exists:", fs.existsSync(PUB));
if (fs.existsSync(PUB)) {
  try { console.log("public files:", fs.readdirSync(PUB)); } catch {}
}

const app = express();
app.use(bodyParser.json());

// CSP: allow self (HTTP + WS on same origin) and localhost during dev
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self' data: blob:",
      "connect-src 'self' http://localhost:3000 ws://localhost:3000 wss:",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval' http://localhost:3000",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:",
      "font-src 'self' data:"
    ].join("; ")
  );
  next();
});

// Static
app.use(express.static(PUB));

// Index
app.get("/", (req, res) => {
  const file = path.join(PUB, "index.html");
  if (!fs.existsSync(file)) {
    console.error("❌ Missing:", file);
    return res.status(404).send("index.html not found in /public");
  }
  res.sendFile(file);
});

// Health
app.get("/health", (req, res) => res.send("OK"));

// Webhook (Kick)
let pendingGifts = 0;
app.post("/webhook", (req, res) => {
  const eventType = req.get("Kick-Event-Type");
  console.log("Event:", eventType);

  if (eventType === "channel.subscription.gifts") {
    const { gifter, giftees = [] } = req.body;
    const count = Array.isArray(giftees) ? giftees.length : 0;
    console.log(`🎁 ${gifter?.username || "Anon"} gifted ${count} subs`);
    pendingGifts += count;
    const spins = Math.floor(pendingGifts / 5);
    pendingGifts %= 5;
    if (spins > 0) broadcast({ action: "spin", times: spins });
  }
  res.status(200).send("ok");
});

// Test endpoint
app.get("/test/:n", (req, res) => {
  const n = parseInt(req.params.n, 10) || 0;
  broadcast({ action: "spin", times: n });
  res.send(`sent ${n}`);
});

const PORT_HTTP = 3000;
const httpServer = app.listen(PORT_HTTP, () => {
  console.log(`HTTP on http://localhost:${PORT_HTTP}`);
});
httpServer.on("error", (err) => {
  console.error("HTTP error:", err);
});

// === WebSocket on same HTTP server (upgrade on /ws) ===
const wss = new WebSocketServer({ noServer: true });

httpServer.on("upgrade", (req, socket, head) => {
  if (req.url === "/ws") {
    wss.handleUpgrade(req, socket, head, (ws) => {
      wss.emit("connection", ws, req);
    });
  } else {
    socket.destroy();
  }
});

wss.on("connection", () => {
  console.log("WS client connected");
});

const broadcast = (obj) => {
  const msg = JSON.stringify(obj);
  wss.clients.forEach((c) => c.readyState === 1 && c.send(msg));
};
