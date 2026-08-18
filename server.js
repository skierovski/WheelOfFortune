import "dotenv/config";
import http from "http";
import { app } from "./src/app.js";
import { createWSS, attachUpgrade } from "./src/ws.js";
import { assertSafeProductionEnv, env } from "./src/utils/env.js";
import { initDb } from "./src/db.js";
import { startWatchdogs } from "./src/services/watchdogs.js";
import { startSpinChecker } from "./src/services/spins.js";
import { startSlotsChecker } from "./src/services/slots.js";

assertSafeProductionEnv();

// Initialize database
const db = initDb(env.DB_PATH);
app.locals.db = db;
console.log(`[DB] Initialized at ${env.DB_PATH}`);

// Create HTTP server and WebSocket
const server = http.createServer(app);
const wss = createWSS();
attachUpgrade(server, wss);

// Store wss on app.locals so routes can broadcast
app.locals.wss = wss;

server.listen(env.PORT_HTTP, () => {
  console.log(`HTTP on http://localhost:${env.PORT_HTTP}`);
  console.log(`WS on   ws://localhost:${env.PORT_HTTP}/ws?key=<overlay_key>`);
  console.log("[ENV]", {
    KICK_CLIENT_ID: env.KICK_CLIENT_ID ? "(set)" : "(missing)",
    KICK_REDIRECT_URI: env.KICK_REDIRECT_URI || "<dynamic>",
    PUBLIC_BASE_URL: env.PUBLIC_BASE_URL || "<not set>",
    DB_PATH: env.DB_PATH,
    ADMIN_KEY: env.ADMIN_KEY ? "(set)" : "(missing)",
    REQUIRE_INVITE: env.REQUIRE_INVITE,
    DEV_BYPASS_AUTH: env.DEV_BYPASS_AUTH,
  });
  
  const streamers = db.getAllStreamers();
  console.log(`[DB] ${streamers.length} registered streamer(s)`);
});

// Start background services
startWatchdogs();
startSpinChecker();
startSlotsChecker();
