import crypto from "crypto";
import fs from "fs";
import path from "path";

const TOK_PATH = process.env.TOK_PATH || `${process.cwd()}/tokens.json`;

function getPersistentSessionSecret() {
  if (process.env.SESSION_SECRET?.trim()) return process.env.SESSION_SECRET.trim();
  if (process.env.ADMIN_KEY?.trim()) return process.env.ADMIN_KEY.trim();
  const secretPath = process.env.SESSION_SECRET_FILE || path.join(path.dirname(TOK_PATH), ".session_secret");
  try {
    const s = fs.readFileSync(secretPath, "utf8").trim();
    if (s) return s;
  } catch {}
  const generated = crypto.randomBytes(32).toString("hex");
  try {
    fs.mkdirSync(path.dirname(secretPath), { recursive: true });
    fs.writeFileSync(secretPath, generated, { mode: 0o600 });
  } catch (e) {
    console.warn("[env] Could not persist SESSION_SECRET to", secretPath, e.message);
  }
  return generated;
}

export const env = {
  NODE_ENV: process.env.NODE_ENV || "development",
  PORT_HTTP: Number(process.env.PORT) || 3000,

  KICK_OAUTH_HOST: "https://id.kick.com",
  KICK_CLIENT_ID: process.env.KICK_CLIENT_ID || "",
  KICK_CLIENT_SECRET: process.env.KICK_CLIENT_SECRET || "",
  KICK_REDIRECT_URI: process.env.KICK_REDIRECT_URI || "",
  /** Optional: public base URL (e.g. https://wheel.example.com) so webhook callback is known on startup without a visit */
  PUBLIC_BASE_URL: (process.env.PUBLIC_BASE_URL || "").trim(),

  ADMIN_KEY: process.env.ADMIN_KEY || "",
  get SESSION_SECRET() {
    return (this._sessionSecret ??= getPersistentSessionSecret());
  },
  TRIGGER_KEY: process.env.TRIGGER_KEY || process.env.ADMIN_KEY || "",

  WEBHOOK_SECRET: process.env.KICK_WEBHOOK_SECRET || process.env.WEBHOOK_SECRET || "dev_webhook_secret",

  TOK_PATH,
  CFG_PATH: process.env.CFG_PATH || "/data/wheel.json",
  GOALS_PATH: process.env.GOALS_PATH || "/data/goals.json",
  PENDING_PATH: process.env.PENDING_PATH || "/data/pending.json",

  DEV_BYPASS_AUTH: process.env.DEV_BYPASS_AUTH === "1",
  DEV_FAKE_BID: Number(process.env.DEV_FAKE_BID || 999999),
  DEV_BYPASS_KEY: process.env.DEV_BYPASS_KEY || "",
  DEV_BYPASS_IPS: (process.env.DEV_BYPASS_IPS || "").split(",").map(s=>s.trim()).filter(Boolean),

  mask(v) {
    if (!v || typeof v !== "string") return v;
    if (v.length <= 8) return v;
    return v.slice(0,4)+"..."+v.slice(-4);
  }
};
