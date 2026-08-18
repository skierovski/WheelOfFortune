import { Router } from "express";
import path from "path";
import fs from "fs";
import { createRequire } from "module";
import { requireSession, resolveOverlayKey, requireModSession } from "../middleware/requireSession.js";
import { getSessionBroadcasterId } from "../utils/cookies.js";
import { getDb } from "../db.js";

const require = createRequire(import.meta.url);
const pkg = require("../../package.json");

const router = Router();
const publicDir = path.join(process.cwd(), "public");
const viewsDir = path.join(process.cwd(), "views");

// Landing page (redirect to dashboard if already logged in)
router.get("/", (req, res) => {
  const bid = getSessionBroadcasterId(req);
  if (bid) {
    if (getDb().getStreamerById(bid)) {
      return res.redirect("/dashboard");
    }
    if (getDb().getModeratorships(bid).length > 0) {
      return res.redirect("/mod");
    }
  }

  const file = path.join(publicDir, "landing.html");
  if (!fs.existsSync(file)) {
    return res.send(`<h1>Wheel of Fortune</h1><p><a href="/auth/login">Login with Kick</a></p>`);
  }
  res.sendFile(file);
});

// Streamer dashboard (session-protected)
router.get("/dashboard", requireSession, (req, res) => {
  const file = path.join(viewsDir, "dashboard.html");
  if (!fs.existsSync(file)) return res.status(404).send("dashboard.html not found");
  res.sendFile(file);
});

router.get("/advanced", requireSession, (req, res) => {
  const file = path.join(viewsDir, "home.html");
  if (!fs.existsSync(file)) return res.status(404).send("home.html not found");
  res.sendFile(file);
});

// Moderator panel (Kick login + moderatorship)
router.get("/mod", requireModSession, (req, res) => {
  const file = path.join(viewsDir, "mod.html");
  if (!fs.existsSync(file)) return res.status(404).send("mod.html not found");
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

// Overlay: sub counter (by overlay_key)
router.get("/subs/:key", resolveOverlayKey, (req, res) => {
  const file = path.join(publicDir, "subs.html");
  if (!fs.existsSync(file)) return res.status(404).send("subs.html not found");
  res.sendFile(file);
});

// Overlay: manual counter XXX/XXX (by overlay_key)
router.get("/counter/:key", resolveOverlayKey, (req, res) => {
  const file = path.join(publicDir, "counter.html");
  if (!fs.existsSync(file)) return res.status(404).send("counter.html not found");
  res.sendFile(file);
});

// Overlay: slots (by overlay_key)
router.get("/slots/:key", resolveOverlayKey, (req, res) => {
  const file = path.join(publicDir, "slots.html");
  if (!fs.existsSync(file)) return res.status(404).send("slots.html not found");
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
      version: pkg.version,
      broadcaster_user_id: bid,
      kick_username: streamer.kick_username,
      overlay_key: streamer.overlay_key,
      hasTokens: !!streamer.access_token,
      subscriptions: subs,
      pending_spins: spinState.pending_count,
      moderatorships: getDb().getModeratorships(bid).length,
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// Version endpoint (public)
router.get("/version", (_req, res) => res.json({ version: pkg.version }));

// Privacy policy page
router.get("/privacy", (_req, res) => {
  const file = path.join(publicDir, "privacy.html");
  if (!fs.existsSync(file)) return res.status(404).send("privacy.html not found");
  res.sendFile(file);
});

// Health check
router.get("/health", (_req, res) => res.send("OK"));

export default router;
