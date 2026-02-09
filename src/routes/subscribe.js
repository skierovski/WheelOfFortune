import { Router } from "express";
import { requireSession } from "../middleware/requireSession.js";
import { listSubscriptions, subscribeToEvents } from "../services/kick.js";
import { getDb } from "../db.js";

const router = Router();

function getCallbackUrl(req) {
  const proto = (req.headers["x-forwarded-proto"] || req.protocol || "http").split(",")[0].trim();
  const host = (req.headers["x-forwarded-host"] || req.get("host")).split(",")[0].trim();
  return `${proto}://${host}/webhook`;
}

// GET /dashboard/subscribe - Check subscription status
router.get("/dashboard/subscribe", requireSession, async (req, res) => {
  try {
    const bid = req.session.broadcaster_user_id;
    const subs = await listSubscriptions(bid);
    const callback = getCallbackUrl(req);
    const hasGifts = subs.some((s) => s?.name === "channel.subscription.gifts");

    return res.json({
      ok: true,
      subscribed: hasGifts,
      callbackUrl: callback,
      allSubscriptions: subs,
    });
  } catch (e) {
    console.error("[GET /dashboard/subscribe] error:", e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// POST /dashboard/subscribe - Create subscription for this streamer
router.post("/dashboard/subscribe", requireSession, async (req, res) => {
  try {
    const bid = req.session.broadcaster_user_id;
    const callback = getCallbackUrl(req);

    const resp = await subscribeToEvents(bid, callback);

    // Store subscription in DB
    const db = getDb();
    const subId = resp?.data?.[0]?.id || resp?.id || null;
    if (subId) {
      db.deactivateSubscriptions(bid);
      db.addSubscription(bid, {
        subscription_id: String(subId),
        event_type: "channel.subscription.gifts",
        callback_url: callback,
      });
    }

    return res.json({ ok: true, data: resp });
  } catch (e) {
    console.error("[POST /dashboard/subscribe] error:", e);
    return res.status(400).json({ ok: false, error: String(e?.message || e) });
  }
});

// POST /dashboard/subscribe/check - Manually trigger subscription check
router.post("/dashboard/subscribe/check", requireSession, async (req, res) => {
  try {
    const bid = req.session.broadcaster_user_id;
    const callback = getCallbackUrl(req);
    const subs = await listSubscriptions(bid);
    const hasGifts = subs.some(
      (s) => s?.name === "channel.subscription.gifts" && s?.callback === callback
    );

    if (!hasGifts) {
      console.log(`[SUBSCRIBE] bid=${bid} missing subscription -> creating`);
      await subscribeToEvents(bid, callback);
    }

    return res.json({ ok: true, message: "Subscription check completed", subscribed: true });
  } catch (e) {
    console.error("[POST /dashboard/subscribe/check] error:", e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

export default router;
