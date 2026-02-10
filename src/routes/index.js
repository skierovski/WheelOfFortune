import { Router } from "express";
import path from "path";
import fs from "fs";
import { requireSession, resolveOverlayKey } from "../middleware/requireSession.js";
import { getSessionBroadcasterId } from "../utils/cookies.js";
import { getDb } from "../db.js";

const router = Router();
const publicDir = path.join(process.cwd(), "public");
const viewsDir = path.join(process.cwd(), "views");

// Landing page (redirect to dashboard if already logged in)
router.get("/", (req, res) => {
  const bid = getSessionBroadcasterId(req);
  if (bid && getDb().getStreamerById(bid)) {
    return res.redirect("/dashboard");
  }

  const file = path.join(publicDir, "landing.html");
  if (!fs.existsSync(file)) {
    return res.send(`<h1>Wheel of Fortune</h1><p><a href="/auth/login">Login with Kick</a></p>`);
  }
  res.sendFile(file);
});

// Streamer dashboard (session-protected)
router.get("/dashboard", requireSession, (req, res) => {
  const file = path.join(viewsDir, "home.html");
  if (!fs.existsSync(file)) return res.status(404).send("home.html not found");
  res.sendFile(file);
});

// Overlay: wheel (by overlay_key)
router.get("/overlay/:key", resolveOverlayKey, (req, res) => {
  const file = path.join(publicDir, "index.html");
  if (!fs.existsSync(file)) return res.status(404).send("index.html not found");
  res.sendFile(file);
});

// Overlay: delay timer (by overlay_key)
router.get("/delay/:key", resolveOverlayKey, (req, res) => {
  const file = path.join(publicDir, "delay.html");
  if (!fs.existsSync(file)) return res.status(404).send("delay.html not found");
  res.sendFile(file);
});

// Status endpoint (session-protected)
router.get("/dashboard/status", requireSession, async (req, res) => {
  try {
    const bid = req.session.broadcaster_user_id;
    const streamer = req.session.streamer;
    const db = getDb();
    const subs = db.getActiveSubscriptions(bid);
    const spinState = db.getSpinState(bid);

    res.json({
      ok: true,
      broadcaster_user_id: bid,
      kick_username: streamer.kick_username,
      overlay_key: streamer.overlay_key,
      hasTokens: !!streamer.access_token,
      subscriptions: subs,
      pending_spins: spinState.pending_count,
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// Health check
router.get("/health", (_req, res) => res.send("OK"));

export default router;
