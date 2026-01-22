import { Router } from "express";
import path from "path";
import fs from "fs";
import { requireSession } from "../middleware/requireSession.js";
import { ensureAccessToken } from "../services/tokens.js";
import { getBroadcasterId, listSubscriptions } from "../services/kick.js";

const router = Router();

router.get("/", (req, res) => {
  const file = path.join(process.cwd(), "public", "index.html");
  if (!fs.existsSync(file)) return res.status(404).send("index.html not found");
  res.sendFile(file);
});

router.get("/home", requireSession, (req, res) => {
  const file = path.join(process.cwd(), "public", "home.html");
  if (!fs.existsSync(file)) return res.status(404).send("home.html not found");
  res.sendFile(file);
});

router.get("/status", async (_req, res) => {
  try {
    let hasTokens = false, scope = null, broadcasterId = null, subs = [];
    try {
      await ensureAccessToken();
      hasTokens = true;
      broadcasterId = await getBroadcasterId();
      subs = await listSubscriptions(broadcasterId);
    } catch {
      hasTokens = false;
    }
    res.json({ ok:true, hasTokens, scope, broadcaster_user_id: broadcasterId, subscriptions: subs });
  } catch (e) {
    res.status(500).json({ ok:false, error: String(e?.message||e) });
  }
});

router.get("/health", (_req, res) => res.send("OK"));

export default router;
