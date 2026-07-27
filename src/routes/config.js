import { Router } from "express";
import { requireSession, resolveOverlayKey } from "../middleware/requireSession.js";
import { loadConfig, saveConfig, loadGoals, saveGoals } from "../services/configStore.js";
import { validateWheelItems, validateTiers, validateGiftsPerSpin, validateAccentColor, validateSecondaryColor, validateWheelOpacity } from "../utils/validate.js";
import { getOverlayAuthStatus } from "../services/authStatus.js";
import { fetchChannelInfo } from "../services/kick.js";

const router = Router();

// ── Overlay endpoints (by overlay_key) ──────────────────────────────

// GET config for an overlay (public, keyed by overlay_key)
router.get("/overlay/:key/config", resolveOverlayKey, (req, res) => {
  const bid = req.streamer.broadcaster_id;
  const cfg = loadConfig(bid);
  const auth = getOverlayAuthStatus(req.streamer);
  res.json({
    ok: true,
    items: cfg?.items ?? null,
    tiers: cfg?.tiers ?? null,
    accent_color: cfg?.accent_color ?? "#7c3aed",
    secondary_color: cfg?.secondary_color ?? "#121228",
    wheel_opacity: cfg?.wheel_opacity ?? 0.9,
    gifts_per_spin: cfg?.gifts_per_spin ?? 5,
    auth_ok: auth.auth_ok,
    auth_message: auth.auth_message,
  });
});

// GET live subscriber count from Kick API (public overlay endpoint)
router.get("/overlay/:key/subs", resolveOverlayKey, async (req, res) => {
  const bid = req.streamer.broadcaster_id;
  try {
    const info = await fetchChannelInfo(bid);
    res.json({ ok: true, active_subscribers_count: info.active_subscribers_count });
  } catch (e) {
    console.warn(`[/overlay/subs] bid=${bid} error:`, e?.message || e);
    res.status(502).json({ ok: false, error: "Failed to fetch subscriber count from Kick" });
  }
});

// ── Dashboard endpoints (session-protected) ─────────────────────────

// GET own config
router.get("/dashboard/config", requireSession, (req, res) => {
  const bid = req.session.broadcaster_user_id;
  const cfg = loadConfig(bid);
  res.json({
    ok: true,
    items: cfg?.items ?? null,
    tiers: cfg?.tiers ?? null,
    accent_color: cfg?.accent_color ?? "#7c3aed",
    secondary_color: cfg?.secondary_color ?? "#121228",
    wheel_opacity: cfg?.wheel_opacity ?? 0.9,
    gifts_per_spin: cfg?.gifts_per_spin ?? 5,
  });
});

// Save config and broadcast live update to overlays
router.post("/dashboard/config", requireSession, (req, res) => {
  const bid = req.session.broadcaster_user_id;
  const accent_color = validateAccentColor(req.body?.accent_color);
  const secondary_color = validateSecondaryColor(req.body?.secondary_color);
  const wheel_opacity = validateWheelOpacity(req.body?.wheel_opacity);

  // Tiers mode: save multiple prize tiers
  if (Array.isArray(req.body?.tiers)) {
    const tierResult = validateTiers(req.body.tiers);
    if (!tierResult.valid) {
      return res.status(400).json({ ok: false, error: tierResult.error });
    }
    // gifts_per_spin is derived from the lowest tier's min_gifts
    const gifts_per_spin = tierResult.tiers[0].min_gifts;
    const saved = saveConfig(bid, tierResult.tiers[0].items, {
      accent_color,
      secondary_color,
      wheel_opacity,
      gifts_per_spin,
      tiers: tierResult.tiers,
    });

    // Broadcast to overlays
    try {
      const { app } = req;
      if (app?.locals?.wss?.broadcastTo) {
        app.locals.wss.broadcastTo(bid, {
          type: "config",
          items: saved.items,
          tiers: saved.tiers,
          accent_color: saved.accent_color,
          secondary_color: saved.secondary_color,
          wheel_opacity: saved.wheel_opacity,
          gifts_per_spin: saved.gifts_per_spin,
        });
      }
    } catch (e) {
      console.warn("[/dashboard/config] ws broadcast failed:", e?.message || e);
    }

    return res.json({
      ok: true,
      items: saved.items,
      tiers: saved.tiers,
      accent_color: saved.accent_color,
      secondary_color: saved.secondary_color,
      wheel_opacity: saved.wheel_opacity,
      gifts_per_spin: saved.gifts_per_spin,
    });
  }

  // Legacy single-tier mode
  const validation = validateWheelItems(req.body?.items);
  if (!validation.valid) {
    return res.status(400).json({ ok: false, error: validation.error });
  }

  const gifts_per_spin = validateGiftsPerSpin(req.body?.gifts_per_spin);
  const saved = saveConfig(bid, validation.items, { accent_color, secondary_color, wheel_opacity, gifts_per_spin });

  try {
    const { app } = req;
    if (app?.locals?.wss?.broadcastTo) {
      app.locals.wss.broadcastTo(bid, {
        type: "config",
        items: saved.items,
        tiers: saved.tiers,
        accent_color: saved.accent_color,
        secondary_color: saved.secondary_color,
        wheel_opacity: saved.wheel_opacity,
        gifts_per_spin: saved.gifts_per_spin,
      });
    }
  } catch (e) {
    console.warn("[/dashboard/config] ws broadcast failed:", e?.message || e);
  }

  return res.json({
    ok: true,
    items: saved.items,
    tiers: saved.tiers,
    accent_color: saved.accent_color,
    secondary_color: saved.secondary_color,
    wheel_opacity: saved.wheel_opacity,
    gifts_per_spin: saved.gifts_per_spin,
  });
});

// GET sub counter config
router.get("/dashboard/sub-counter", requireSession, (req, res) => {
  const bid = req.session.broadcaster_user_id;
  const cfg = loadConfig(bid);
  res.json({
    ok: true,
    sub_goal: cfg?.sub_goal ?? 0,
    sub_counter_title: cfg?.sub_counter_title ?? "Subskrybenci",
    sub_counter_label: cfg?.sub_counter_label ?? "aktywne subskrypcje",
  });
});

// POST sub counter config
router.post("/dashboard/sub-counter", requireSession, (req, res) => {
  const bid = req.session.broadcaster_user_id;
  const sub_goal = Math.max(0, Math.min(1_000_000, Math.round(Number(req.body?.sub_goal) || 0)));
  const sub_counter_title = String(req.body?.sub_counter_title || "Subskrybenci").trim().slice(0, 60);
  const sub_counter_label = String(req.body?.sub_counter_label || "aktywne subskrypcje").trim().slice(0, 60);

  const prev = loadConfig(bid);
  // Preserve all existing config fields, just update sub counter fields
  const items = prev?.items ?? [];
  const saved = saveConfig(bid, items, {
    accent_color: prev?.accent_color,
    secondary_color: prev?.secondary_color,
    wheel_opacity: prev?.wheel_opacity,
    gifts_per_spin: prev?.gifts_per_spin,
    tiers: prev?.tiers,
    sub_goal,
    sub_counter_title,
    sub_counter_label,
  });

  // Broadcast to overlays so subs.html reacts live
  try {
    const { app } = req;
    if (app?.locals?.wss?.broadcastTo) {
      app.locals.wss.broadcastTo(bid, {
        type: "config",
        accent_color: saved.accent_color,
        secondary_color: saved.secondary_color,
        wheel_opacity: saved.wheel_opacity,
        sub_goal,
        sub_counter_title,
        sub_counter_label,
      });
    }
  } catch (e) {
    console.warn("[/dashboard/sub-counter] ws broadcast failed:", e?.message || e);
  }

  return res.json({ ok: true, sub_goal, sub_counter_title, sub_counter_label });
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
