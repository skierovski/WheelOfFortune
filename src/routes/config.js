import { Router } from "express";
import { requireSession, resolveOverlayKey } from "../middleware/requireSession.js";
import { loadConfig, saveConfig, loadGoals, saveGoals } from "../services/configStore.js";
import { validateWheelItems, validateGiftsPerSpin, validateAccentColor } from "../utils/validate.js";

const router = Router();

// ── Overlay endpoints (by overlay_key) ──────────────────────────────

// GET config for an overlay (public, keyed by overlay_key)
router.get("/overlay/:key/config", resolveOverlayKey, (req, res) => {
  const bid = req.streamer.broadcaster_id;
  const cfg = loadConfig(bid);
  res.json({
    ok: true,
    items: cfg?.items ?? null,
    accent_color: cfg?.accent_color ?? "#7c3aed",
    gifts_per_spin: cfg?.gifts_per_spin ?? 5,
  });
});

// ── Dashboard endpoints (session-protected) ─────────────────────────

// GET own config
router.get("/dashboard/config", requireSession, (req, res) => {
  const bid = req.session.broadcaster_user_id;
  const cfg = loadConfig(bid);
  res.json({
    ok: true,
    items: cfg?.items ?? null,
    accent_color: cfg?.accent_color ?? "#7c3aed",
    gifts_per_spin: cfg?.gifts_per_spin ?? 5,
  });
});

// Save config and broadcast live update to overlays
router.post("/dashboard/config", requireSession, (req, res) => {
  const bid = req.session.broadcaster_user_id;

  const validation = validateWheelItems(req.body?.items);
  if (!validation.valid) {
    return res.status(400).json({ ok: false, error: validation.error });
  }

  const accent_color = validateAccentColor(req.body?.accent_color);
  const gifts_per_spin = validateGiftsPerSpin(req.body?.gifts_per_spin);
  const saved = saveConfig(bid, validation.items, { accent_color, gifts_per_spin });

  // Broadcast config update to this streamer's connected overlays
  try {
    const { app } = req;
    if (app?.locals?.wss?.broadcastTo) {
      app.locals.wss.broadcastTo(bid, {
        type: "config",
        items: saved.items,
        accent_color: saved.accent_color,
        gifts_per_spin: saved.gifts_per_spin,
      });
    }
  } catch (e) {
    console.warn("[/dashboard/config] ws broadcast failed:", e?.message || e);
  }

  return res.json({
    ok: true,
    items: saved.items,
    accent_color: saved.accent_color,
    gifts_per_spin: saved.gifts_per_spin,
  });
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
