import { Router } from "express";
import { requireSession, resolveOverlayKey } from "../middleware/requireSession.js";
import { loadConfig, saveConfig, loadGoals, saveGoals } from "../services/configStore.js";
import { validateWheelItems, validateTheme } from "../utils/validate.js";

const router = Router();

// ── Overlay endpoints (by overlay_key) ──────────────────────────────

// GET config for an overlay (public, keyed by overlay_key)
router.get("/overlay/:key/config", resolveOverlayKey, (req, res) => {
  const bid = req.streamer.broadcaster_id;
  const cfg = loadConfig(bid);
  res.json({ ok: true, items: cfg?.items ?? null, theme: cfg?.theme ?? "wood" });
});

// ── Dashboard endpoints (session-protected) ─────────────────────────

// GET own config
router.get("/dashboard/config", requireSession, (req, res) => {
  const bid = req.session.broadcaster_user_id;
  const cfg = loadConfig(bid);
  res.json({ ok: true, items: cfg?.items ?? null, theme: cfg?.theme ?? "wood" });
});

// Save config and broadcast live update to overlays
router.post("/dashboard/config", requireSession, (req, res) => {
  const bid = req.session.broadcaster_user_id;

  const validation = validateWheelItems(req.body?.items);
  if (!validation.valid) {
    return res.status(400).json({ ok: false, error: validation.error });
  }

  const theme = validateTheme(req.body?.theme);
  const saved = saveConfig(bid, validation.items, theme);

  // Broadcast config update to this streamer's connected overlays
  try {
    const { app } = req;
    if (app?.locals?.wss?.broadcastTo) {
      app.locals.wss.broadcastTo(bid, { type: "config", items: saved.items, theme: saved.theme });
    }
  } catch (e) {
    console.warn("[/dashboard/config] ws broadcast failed:", e?.message || e);
  }

  return res.json({ ok: true, items: saved.items, theme: saved.theme });
});

// ── Goals ────────────────────────────────────────────────────────────

router.get("/dashboard/goals", requireSession, (req, res) => {
  const bid = req.session.broadcaster_user_id;
  try {
    res.json({ ok: true, goals: loadGoals(bid) });
  } catch {
    res.json({ ok: true, goals: [] });
  }
});

router.post("/dashboard/goals", requireSession, (req, res) => {
  const bid = req.session.broadcaster_user_id;
  try {
    const goals = Array.isArray(req.body?.goals) ? req.body.goals : [];
    const saved = saveGoals(bid, goals);
    res.json({ ok: true, goals: saved });
  } catch {
    res.status(500).json({ ok: false, error: "Save failed" });
  }
});

export default router;
