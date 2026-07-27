import { Router } from "express";
import { slots } from "../services/slots.js";
import { requireSession, resolveOverlayKey } from "../middleware/requireSession.js";
import { getDb } from "../db.js";
import { validateSlotsPrizes } from "../utils/validate.js";
import { announcePrize } from "../services/chatBot.js";

const router = Router();

// ── Overlay ─────────────────────────────────────────────────────────

router.get("/overlay/:key/slots/state", resolveOverlayKey, (req, res) => {
  const bid = req.streamer.broadcaster_id;
  const state = slots.getState(bid);
  const cfg = getDb().getConfig(bid);
  res.json({
    ok: true,
    ...state,
    accent_color: cfg?.accent_color ?? "#7c3aed",
    secondary_color: cfg?.secondary_color ?? "#121228",
    wheel_opacity: cfg?.wheel_opacity ?? 0.9,
    bet: slots.BET,
  });
});

router.post("/overlay/:key/slots/complete", resolveOverlayKey, (req, res) => {
  const bid = req.streamer.broadcaster_id;
  slots.markComplete(bid, { bonus: !!req.body?.bonus });
  res.json({ ok: true });
});

// ── Dashboard ───────────────────────────────────────────────────────

router.get("/dashboard/slots", requireSession, (req, res) => {
  const bid = req.session.broadcaster_user_id;
  res.json({ ok: true, ...slots.getState(bid), bet: slots.BET });
});

router.post("/dashboard/slots/prizes", requireSession, (req, res) => {
  const bid = req.session.broadcaster_user_id;
  const result = validateSlotsPrizes(req.body?.slots_prizes ?? req.body?.prizes);
  if (!result.valid) {
    return res.status(400).json({ ok: false, error: result.error });
  }
  getDb().saveSlotsPrizes(bid, result.prizes);
  const wss = req.app.locals.wss;
  if (wss?.broadcastTo) {
    wss.broadcastTo(bid, {
      type: "slots_config",
      prizes: result.prizes,
      bank: slots.getBank(bid),
      claimed: slots.getState(bid).claimed,
    });
  }
  res.json({ ok: true, prizes: result.prizes });
});

router.post("/dashboard/slots/reset-bank", requireSession, (req, res) => {
  const bid = req.session.broadcaster_user_id;
  const out = slots.resetBank(bid);
  res.json({ ok: true, ...out });
});

router.post("/dashboard/slots/reset-delay", requireSession, (req, res) => {
  const bid = req.session.broadcaster_user_id;
  slots.resetDelay(bid);
  res.json({ ok: true, pending: slots.getPending(bid) });
});

/** Test slots spin — skips delay */
router.get("/dashboard/test-slots/:n", requireSession, (req, res) => {
  const bid = req.session.broadcaster_user_id;
  const n = Math.max(1, Math.min(20, parseInt(req.params.n, 10) || 1));
  const delivered = slots.testSpin(bid, n);
  res.json({
    ok: true,
    message: `Sent ${n} slots spin(s) to ${delivered} connected client(s)`,
    pending: slots.getPending(bid),
    bank: slots.getBank(bid),
    delivered,
  });
});

router.post("/dashboard/simulate-sub", requireSession, (req, res) => {
  const bid = req.session.broadcaster_user_id;
  const delivered = slots.deliverOrQueue(bid, 1);
  res.json({
    ok: true,
    message: `Simulated subscription → 1 slots spin (${delivered} delivered)`,
    pending: slots.getPending(bid),
    bank: slots.getBank(bid),
    delivered,
  });
});

router.post("/overlay/:key/slots/announce", resolveOverlayKey, async (req, res) => {
  try {
    const bid = req.streamer.broadcaster_id;
    const label = String(req.body?.label || "").trim();
    if (!label) return res.status(400).json({ ok: false, error: "Missing label" });
    await announcePrize(bid, label);
    return res.json({ ok: true });
  } catch (e) {
    console.error("[slots/announce] error:", e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

export default router;
