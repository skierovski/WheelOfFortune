export const env = {
  NODE_ENV: process.env.NODE_ENV || "development",
  PORT_HTTP: Number(process.env.PORT) || 3000,

  KICK_OAUTH_HOST: "https://id.kick.com",
  KICK_CLIENT_ID: process.env.KICK_CLIENT_ID || "",
  KICK_CLIENT_SECRET: process.env.KICK_CLIENT_SECRET || "",
  KICK_REDIRECT_URI: process.env.KICK_REDIRECT_URI || "",

  ADMIN_KEY: process.env.ADMIN_KEY || "",
  SESSION_SECRET: process.env.SESSION_SECRET || process.env.ADMIN_KEY || "dev_session_secret",
  TRIGGER_KEY: process.env.TRIGGER_KEY || process.env.ADMIN_KEY || "",

  WEBHOOK_SECRET: process.env.KICK_WEBHOOK_SECRET || process.env.WEBHOOK_SECRET || "dev_webhook_secret",

  TOK_PATH: process.env.TOK_PATH || `${process.cwd()}/tokens.json`,
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
