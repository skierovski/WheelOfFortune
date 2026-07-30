import { Router } from "express";
import { spins } from "../services/spins.js";
import { slots } from "../services/slots.js";
import { postChatMessage } from "../services/kick.js";
import { announcePrize } from "../services/chatBot.js";
import { requireSession, resolveOverlayKey } from "../middleware/requireSession.js";
import { env } from "../utils/env.js";
import { getDb } from "../db.js";
import { getOverlayAuthStatus } from "../services/authStatus.js";
import { trackGiftEvent } from "../services/giftTracker.js";
import { loadConfig } from "../services/configStore.js";
import { bumpManualCounter } from "../services/manualCounter.js";

const router = Router();

// ── Overlay endpoints (by overlay_key) ──────────────────────────────

// Pending spins count for an overlay
router.get("/overlay/:key/spins/pending", resolveOverlayKey, (req, res) => {
  const bid = req.streamer.broadcaster_id;
  const timeUntilNext = spins.getTimeUntilNextSpin(bid);
  const auth = getOverlayAuthStatus(req.streamer);
  res.json({
    ok: true,
    count: spins.getPending(bid),
    timeUntilNext: Math.ceil(timeUntilNext / 1000),
    auth_ok: auth.auth_ok,
    auth_message: auth.auth_message,
  });
});

// Spin complete callback from overlay
router.post("/overlay/:key/spins/complete", resolveOverlayKey, (req, res) => {
  const bid = req.streamer.broadcaster_id;
  spins.markSpinComplete(bid);
  res.json({ ok: true });
});

// ── Dashboard endpoints (session-protected) ─────────────────────────

// Test spin trigger from dashboard (direct, no tier logic)
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

// Simulate gift event (tier-aware) from dashboard
router.post("/dashboard/simulate-gift", requireSession, (req, res) => {
  const bid = req.session.broadcaster_user_id;
  const giftCount = Math.max(1, Math.min(100, Number(req.body?.gift_count) || 1));

  // Track for hybrid sub counter
  const tracked = trackGiftEvent(bid, {
    messageId: `sim_${bid}_${Date.now()}`,
    giftCount,
    gifterUsername: "SimulateGift",
  });
  try {
    const cfg = loadConfig(bid);
    req.app?.locals?.wss?.broadcastTo?.(bid, {
      type: "subs",
      gift_delta: giftCount,
      active_tracked_gifts: tracked.active_tracked,
      sub_seed_offset: cfg?.sub_seed_offset ?? 0,
      sub_goal: cfg?.sub_goal ?? 0,
    });
  } catch {}

  // Slots: every gifted sub = 1 slots spin
  const slotsDelivered = slots.deliverOrQueue(bid, giftCount);
  bumpManualCounter(bid, giftCount, req.app?.locals?.wss);

  const config = getDb().getConfig(bid);
  const configTiers = config?.tiers;
  let delivered = 0;
  let spinCount = 0;
  let tierUsed = null;

  if (Array.isArray(configTiers) && configTiers.length > 0) {
    for (let i = configTiers.length - 1; i >= 0; i--) {
      if (giftCount >= configTiers[i].min_gifts) {
        tierUsed = configTiers[i].name;
        spinCount = 1;
        break;
      }
    }
    if (spinCount > 0) {
      delivered = spins.deliverSpinOrQueue(bid, 1, { tier: tierUsed });
    }
  } else {
    const giftsPerSpin = config?.gifts_per_spin || 5;
    spinCount = Math.floor(giftCount / giftsPerSpin);
    if (spinCount > 0) {
      delivered = spins.deliverSpinOrQueue(bid, spinCount);
    }
  }

  res.json({
    ok: true,
    gift_count: giftCount,
    spin_count: spinCount,
    tier: tierUsed,
    delivered,
    slots_delivered: slotsDelivered,
    slots_pending: slots.getPending(bid),
    slots_bank: slots.getBank(bid),
    pending: spins.getPending(bid),
    message: `${giftCount} gifts -> wheel: ${spinCount} spin(s)${tierUsed ? ` [${tierUsed}]` : ""} (${delivered} delivered); slots: ${giftCount} queued (${slotsDelivered} delivered)`,
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
// Uses bot config template if bot is enabled, falls back to raw label
router.post("/overlay/:key/chat/announce", resolveOverlayKey, async (req, res) => {
  try {
    const bid = req.streamer.broadcaster_id;
    const label = String(req.body?.label || "").trim();
    if (!label) return res.status(400).json({ ok: false, error: "Missing label" });
    await announcePrize(bid, label);
    return res.json({ ok: true });
  } catch (e) {
    console.error("[chat/announce] error:", e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

export default router;
