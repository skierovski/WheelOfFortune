import { Router } from "express";
import { requireModOfStreamer, requireModSession } from "../middleware/requireSession.js";
import { getDb } from "../db.js";
import { spins } from "../services/spins.js";
import { slots } from "../services/slots.js";
import { loadConfig } from "../services/configStore.js";
import { resolveGiftSpins } from "../services/giftSpins.js";
import { trackGiftEvent } from "../services/giftTracker.js";
import { bumpManualCounter } from "../services/manualCounter.js";

const router = Router();

function clampCounterValue(n) {
  return Math.max(0, Math.min(1_000_000, Math.round(Number(n) || 0)));
}

function broadcastCounter(req, bid, count, goal, accent_color, label) {
  try {
    req.app?.locals?.wss?.broadcastTo?.(bid, {
      type: "counter",
      count,
      goal,
      label,
      accent_color,
    });
  } catch {}
}

/** List channels this Kick user moderates */
router.get("/mod/channels", requireModSession, (req, res) => {
  res.json({
    ok: true,
    kick_user_id: req.mod.kick_user_id,
    channels: req.mod.moderatorships.map((m) => ({
      broadcaster_id: m.broadcaster_id,
      username: m.streamer_username,
      display_name: m.streamer_display_name || m.streamer_username,
    })),
  });
});

router.get("/mod/:bid/status", requireModOfStreamer, (req, res) => {
  const bid = req.mod.broadcaster_id;
  const spinState = getDb().getSpinState(bid);
  const cfg = loadConfig(bid);
  res.json({
    ok: true,
    broadcaster_id: bid,
    kick_username: req.modStreamer.kick_username,
    display_name: req.modStreamer.display_name || req.modStreamer.kick_username,
    accent_color: cfg?.accent_color ?? "#7c3aed",
    pending_spins: spinState.pending_count,
    time_until_next: Math.ceil(spins.getTimeUntilNextSpin(bid) / 1000),
    spin_in_progress: !!spinState.spin_in_progress,
    slots_pending: slots.getPending(bid),
    slots_bank: slots.getBank(bid),
    counter: {
      count: cfg?.manual_count ?? 0,
      goal: cfg?.manual_goal ?? 0,
      label: cfg?.manual_label ?? "",
    },
  });
});

router.post("/mod/:bid/reset-delay", requireModOfStreamer, (req, res) => {
  const bid = req.mod.broadcaster_id;
  spins.resetDelay(bid);
  res.json({
    ok: true,
    message: "Delay timer reset",
    pending: spins.getPending(bid),
    time_until_next: Math.ceil(spins.getTimeUntilNextSpin(bid) / 1000),
  });
});

router.post("/mod/:bid/test-spin", requireModOfStreamer, (req, res) => {
  const bid = req.mod.broadcaster_id;
  const n = Math.max(1, Math.min(20, Number(req.body?.n) || 1));
  const delivered = spins.testSpin(bid, n);
  res.json({
    ok: true,
    delivered,
    pending: spins.getPending(bid),
    message: `Sent ${n} spin(s) (${delivered} delivered)`,
  });
});

router.post("/mod/:bid/simulate-gift", requireModOfStreamer, (req, res) => {
  const bid = req.mod.broadcaster_id;
  const giftCount = Math.max(1, Math.min(100, Number(req.body?.gift_count) || 1));

  const tracked = trackGiftEvent(bid, {
    messageId: `mod_sim_${bid}_${Date.now()}`,
    giftCount,
    gifterUsername: "ModSimulate",
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

  const slotsDelivered = slots.deliverOrQueue(bid, giftCount);
  bumpManualCounter(bid, giftCount, req.app?.locals?.wss);

  const config = getDb().getConfig(bid);
  const { spinCount, tier } = resolveGiftSpins(config, giftCount);
  let delivered = 0;
  if (spinCount > 0) {
    delivered = spins.deliverSpinOrQueue(bid, spinCount, tier ? { tier } : {});
  }

  res.json({
    ok: true,
    gift_count: giftCount,
    spin_count: spinCount,
    tier,
    delivered,
    slots_delivered: slotsDelivered,
    pending: spins.getPending(bid),
    message: `${giftCount} gifts → ${spinCount} wheel spin(s)${tier ? ` [${tier}]` : ""}`,
  });
});

router.get("/mod/:bid/counter", requireModOfStreamer, (req, res) => {
  const bid = req.mod.broadcaster_id;
  const cfg = loadConfig(bid);
  res.json({
    ok: true,
    count: cfg?.manual_count ?? 0,
    goal: cfg?.manual_goal ?? 0,
    label: cfg?.manual_label ?? "",
    accent_color: cfg?.accent_color ?? "#7c3aed",
  });
});

router.post("/mod/:bid/counter", requireModOfStreamer, (req, res) => {
  const bid = req.mod.broadcaster_id;
  const prev = loadConfig(bid);
  let count = prev?.manual_count ?? 0;
  let goal = prev?.manual_goal ?? 0;
  let label = prev?.manual_label ?? "";
  const accent_color = prev?.accent_color ?? "#7c3aed";

  if (req.body?.delta != null && req.body.delta !== "") {
    count = clampCounterValue(count + Number(req.body.delta));
  }
  if (req.body?.count != null && req.body.count !== "") {
    count = clampCounterValue(req.body.count);
  }
  if (req.body?.goal != null && req.body.goal !== "") {
    goal = clampCounterValue(req.body.goal);
  }
  if (typeof req.body?.label === "string") {
    label = req.body.label.trim().slice(0, 60);
  }

  getDb().saveManualCounter(bid, { count, goal, label });
  broadcastCounter(req, bid, count, goal, accent_color, label);
  res.json({ ok: true, count, goal, label, accent_color });
});

export default router;
