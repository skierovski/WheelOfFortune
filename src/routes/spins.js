import { Router } from "express";
import { spins } from "../services/spins.js";
import { postChatMessage } from "../services/kick.js";
import { requireSession, resolveOverlayKey } from "../middleware/requireSession.js";
import { env } from "../utils/env.js";
import { getDb } from "../db.js";

const router = Router();

// ── Overlay endpoints (by overlay_key) ──────────────────────────────

// Pending spins count for an overlay
router.get("/overlay/:key/spins/pending", resolveOverlayKey, (req, res) => {
  const bid = req.streamer.broadcaster_id;
  const timeUntilNext = spins.getTimeUntilNextSpin(bid);
  res.json({
    ok: true,
    count: spins.getPending(bid),
    timeUntilNext: Math.ceil(timeUntilNext / 1000),
  });
});

// Spin complete callback from overlay
router.post("/overlay/:key/spins/complete", resolveOverlayKey, (req, res) => {
  const bid = req.streamer.broadcaster_id;
  spins.markSpinComplete(bid);
  res.json({ ok: true });
});

// ── Dashboard endpoints (session-protected) ─────────────────────────

// Test spin trigger from dashboard
router.get("/dashboard/test/:n", requireSession, (req, res) => {
  const bid = req.session.broadcaster_user_id;
  const n = Math.max(1, Math.min(20, parseInt(req.params.n, 10) || 1));
  const delivered = spins.deliverSpinOrQueue(bid, n);
  res.json({
    ok: true,
    message: `Sent ${n} spin(s) to ${delivered} connected client(s)`,
    pending: spins.getPending(bid),
  });
});

// Dashboard: get pending spins
router.get("/dashboard/spins/pending", requireSession, (req, res) => {
  const bid = req.session.broadcaster_user_id;
  const timeUntilNext = spins.getTimeUntilNextSpin(bid);
  res.json({
    ok: true,
    count: spins.getPending(bid),
    timeUntilNext: Math.ceil(timeUntilNext / 1000),
  });
});

// Reset delay timer
router.post("/dashboard/reset-delay", requireSession, (req, res) => {
  const bid = req.session.broadcaster_user_id;
  spins.resetDelay(bid);
  res.json({ ok: true, message: "Delay timer reset." });
});

// External trigger (requires TRIGGER_KEY + broadcaster_id)
router.get("/trigger/spin", (req, res) => {
  try {
    const key = String(req.query.key || "");
    const bid = Number(req.query.bid || 0);
    const n = Math.max(1, Math.min(10, Number(req.query.n || 1)));
    if (!env.TRIGGER_KEY || key !== env.TRIGGER_KEY) {
      return res.status(401).json({ ok: false, error: "Unauthorized" });
    }
    if (!bid) {
      return res.status(400).json({ ok: false, error: "Missing bid parameter" });
    }
    const streamer = getDb().getStreamerById(bid);
    if (!streamer) {
      return res.status(404).json({ ok: false, error: "Streamer not found" });
    }
    const delivered = spins.deliverSpinOrQueue(bid, n);
    return res.json({ ok: true, requested: n, delivered, pending: spins.getPending(bid) });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// Chat announce (called by frontend after spin completes)
router.post("/overlay/:key/chat/announce", resolveOverlayKey, async (req, res) => {
  try {
    const bid = req.streamer.broadcaster_id;
    const label = String(req.body?.label || "").trim();
    if (!label) return res.status(400).json({ ok: false, error: "Missing label" });
    await postChatMessage(bid, label);
    return res.json({ ok: true });
  } catch (e) {
    console.error("[chat/announce] error:", e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

export default router;
