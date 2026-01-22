// src/routes/config.js
import { Router } from "express";
import { env } from "../utils/env.js";
import { getSessionBroadcasterId } from "../utils/cookies.js";
import { loadConfig, saveConfig, loadGoals, saveGoals } from "../services/configStore.js";
import { wsBroadcast } from "../services/spins.js";

const router = Router();

// GET current config (items + theme)
router.get("/config", (_req, res) => {
  const cfg = loadConfig();
  res.json({ ok: true, items: cfg?.items ?? null, theme: cfg?.theme ?? "wood" });
});

// Save config and broadcast live update to overlays
router.post("/config", (req, res) => {
  const hasAdminKey = env.ADMIN_KEY && req.get("X-Admin-Key") === env.ADMIN_KEY;
  const hasSession = !!getSessionBroadcasterId(req);
  if (!hasAdminKey && !hasSession) {
    return res.status(401).json({ ok:false, error:"Unauthorized" });
  }

  const items = Array.isArray(req.body?.items) ? req.body.items : null;
  const theme = typeof req.body?.theme === "string" ? req.body.theme : undefined;
  if (!items) {
    return res.status(400).json({ ok:false, error: "Missing items[]" });
  }

  const saved = saveConfig(items, theme);

  // >>> natychmiastowy push do overlayów (WS)
  try {
    wsBroadcast({ type: "config", items: saved.items, theme: saved.theme });
  } catch (e) {
    // brak ws? nic się nie dzieje — overlay i tak dociągnie config przy starcie
    console.warn("[/config] ws broadcast failed:", e?.message || e);
  }

  return res.json({ ok: true, items: saved.items, theme: saved.theme });
});

/* ---------- Goals (opcjonalny moduł) ---------- */

router.get("/goals", (_req, res) => {
  try { res.json({ ok: true, goals: loadGoals() }); }
  catch { res.json({ ok: true, goals: [] }); }
});

router.post("/goals", (req, res) => {
  const hasAdminKey = env.ADMIN_KEY && req.get("X-Admin-Key") === env.ADMIN_KEY;
  const hasSession = !!getSessionBroadcasterId(req);
  if (!hasAdminKey && !hasSession) {
    return res.status(401).json({ ok:false, error:"Unauthorized" });
  }
  try {
    const goals = Array.isArray(req.body?.goals) ? req.body.goals : [];
    const saved = saveGoals(goals);
    res.json({ ok: true, goals: saved });
  } catch {
    res.status(500).json({ ok: false, error: "Save failed" });
  }
});

export default router;
