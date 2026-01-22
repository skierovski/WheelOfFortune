import 'dotenv/config';
import http from "http";
import { app } from "./src/app.js";
import { createWSS, attachUpgrade } from "./src/ws.js";
import { env } from "./src/utils/env.js";
import { startWatchdogs } from "./src/services/watchdogs.js";
import fs from "fs";
import path from "path";

const server = http.createServer(app);
const wss = createWSS();
attachUpgrade(server, wss);

server.listen(env.PORT_HTTP, () => {
  console.log(`HTTP on http://localhost:${env.PORT_HTTP}`);
  console.log(`WS on    ws://localhost:${env.PORT_HTTP}/ws`);
  const pub = path.join(process.cwd(), "public");
  console.log("Public:", pub, fs.existsSync(pub) ? "(ok)" : "(missing)");
  console.log("[ENV]", {
    KICK_CLIENT_ID: env.KICK_CLIENT_ID ? "(set)" : "(missing)",
    KICK_REDIRECT_URI: env.KICK_REDIRECT_URI || "<dynamic>",
    WEBHOOK_SECRET: env.mask(env.WEBHOOK_SECRET),
    TOK_PATH: env.TOK_PATH, CFG_PATH: env.CFG_PATH, GOALS_PATH: env.GOALS_PATH,
    ADMIN_KEY: env.ADMIN_KEY ? "(set)" : "(missing)",
    SESSION_SECRET: env.SESSION_SECRET ? "(set)" : "(missing)",
    TRIGGER_KEY: env.TRIGGER_KEY ? "(set)" : "(missing)",
    DEV_BYPASS_AUTH: env.DEV_BYPASS_AUTH, DEV_FAKE_BID: env.DEV_FAKE_BID, DEV_BYPASS_IPS: env.DEV_BYPASS_IPS
  });
});

// watchdogi (subskrypcje + tokeny)
startWatchdogs();
