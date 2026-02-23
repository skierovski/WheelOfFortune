import { Router } from "express";
import bodyParser from "body-parser";
import { verifyKickSignature } from "../webhookVerify.js";
import { spins } from "../services/spins.js";
import { getDb } from "../db.js";
import { handleChatMessage } from "../services/chatBot.js";

const router = Router();

router.get("/webhook", (req, res) => {
  console.log("[WEBHOOK][GET] ping", { ip: req.ip });
  res.status(200).send("webhook-get-ok");
});

router.head("/webhook", (req, res) => {
  res.status(200).end();
});

const SEEN_IDS = new Set();
const MAX_SEEN = 500;
function rememberId(id) {
  SEEN_IDS.add(id);
  if (SEEN_IDS.size > MAX_SEEN) {
    const it = SEEN_IDS.values().next();
    if (!it.done) SEEN_IDS.delete(it.value);
  }
}

// RAW body parser for webhook signature verification
router.post("/webhook", bodyParser.raw({ type: "*/*", limit: "2mb" }), (req, res) => {
  const startedAt = Date.now();
  try {
    const msgId = req.get("Kick-Event-Message-Id") || req.get("x-kick-message-id");
    const timestamp = req.get("Kick-Event-Message-Timestamp") || req.get("x-kick-timestamp");
    const signature = req.get("Kick-Event-Signature") || req.get("x-kick-signature");
    const eType = req.get("Kick-Event-Type") || req.get("x-kick-event-type");

    console.log("[WEBHOOK] Incoming:", { msgId, eType, ip: req.ip });

    if (!msgId || !timestamp || !signature) {
      return res.status(400).send("Missing signature headers");
    }

    if (SEEN_IDS.has(msgId)) {
      return res.status(200).send("ok-duplicate");
    }

    // Timestamp skew check (5 minutes)
    const sentAt = Date.parse(timestamp);
    if (!Number.isFinite(sentAt) || Math.abs(Date.now() - sentAt) > 5 * 60 * 1000) {
      return res.status(400).send("Stale or invalid timestamp");
    }

    // Verify signature
    const rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.from(req.body || "");
    const bodyUtf8 = rawBody.toString("utf8");
    if (!verifyKickSignature(msgId, timestamp, bodyUtf8, signature)) {
      return res.status(401).send("Invalid signature");
    }

    rememberId(msgId);

    let payload = {};
    try {
      payload = JSON.parse(bodyUtf8);
    } catch {
      return res.status(400).send("Invalid JSON");
    }

    const type = eType || payload?.type || payload?.event || payload?.name || "unknown";

    // Challenge response (webhook verification)
    if (type === "webhook_callback_verification" && payload?.challenge) {
      console.log("[WEBHOOK] Responding with challenge");
      return res.json({ challenge: payload.challenge });
    }

    // Process subscription gift events
    if (type === "channel.subscription.gifts" || payload?.name === "channel.subscription.gifts") {
      // Extract broadcaster_id from the event payload
      // Kick API sends: { broadcaster: { user_id: 123456789, ... }, gifter: {...}, giftees: [...] }
      const broadcasterId = Number(
        payload?.broadcaster?.user_id ||
        payload?.data?.broadcaster_user_id ||
        payload?.broadcaster_user_id ||
        0
      );

      if (!broadcasterId) {
        console.warn("[WEBHOOK] Gift event missing broadcaster_user_id. Payload keys:", Object.keys(payload), "broadcaster:", JSON.stringify(payload?.broadcaster));
        return res.status(200).send("ok-no-broadcaster");
      }

      // Verify this broadcaster exists in our DB
      const streamer = getDb().getStreamerById(broadcasterId);
      if (!streamer) {
        console.warn(`[WEBHOOK] Unknown broadcaster ${broadcasterId} - ignoring`);
        return res.status(200).send("ok-unknown-broadcaster");
      }

      // Count gifts
      let giftCount = 0;
      if (Array.isArray(payload?.giftees)) {
        giftCount = payload.giftees.length;
      } else if (payload?.data) {
        giftCount = Number(payload.data?.gift_count || payload.data?.count || 0);
      } else {
        giftCount = Number(payload?.gift_count || payload?.count || 0);
      }

      const gifter = payload?.gifter || payload?.data?.gifter || {};
      console.log(`[WEBHOOK] Gifts bid=${broadcasterId}: ${gifter?.username || "Anon"} x${giftCount}`);

      // Determine tier and spin count based on gift count
      const config = getDb().getConfig(broadcasterId);
      const tiers = config?.tiers;

      if (Array.isArray(tiers) && tiers.length > 0) {
        // Tiered mode: find the highest tier this gift event qualifies for
        // tiers are sorted by min_gifts ascending — pick the last one where giftCount >= min_gifts
        let matchedTier = null;
        for (let i = tiers.length - 1; i >= 0; i--) {
          if (giftCount >= tiers[i].min_gifts) {
            matchedTier = tiers[i];
            break;
          }
        }
        if (matchedTier) {
          console.log(`[WEBHOOK] bid=${broadcasterId} ${giftCount} gifts -> tier "${matchedTier.name}" (min=${matchedTier.min_gifts})`);
          spins.deliverSpinOrQueue(broadcasterId, 1, { tier: matchedTier.name });
        } else {
          console.log(`[WEBHOOK] bid=${broadcasterId} ${giftCount} gifts below minimum tier (${tiers[0].min_gifts}), no spin`);
        }
      } else {
        // Legacy single-tier mode
        const giftsPerSpin = config?.gifts_per_spin || 5;
        const spinCount = Math.floor(giftCount / giftsPerSpin);
        if (spinCount > 0) {
          console.log(`[WEBHOOK] bid=${broadcasterId} ${giftCount} gifts -> ${spinCount} spin(s)`);
          spins.deliverSpinOrQueue(broadcasterId, spinCount);
        }
      }
    } else if (type === "chat.message.sent") {
      const broadcasterId = Number(payload?.broadcaster?.user_id || 0);
      const content = payload?.content || "";
      const senderUsername = payload?.sender?.username || "unknown";

      // Respond 200 immediately, process command asynchronously
      res.status(200).send("ok");
      console.log(`[WEBHOOK] Chat bid=${broadcasterId} from=${senderUsername}: ${content.slice(0, 80)}`);

      if (broadcasterId && content.startsWith("!")) {
        setImmediate(() => handleChatMessage(broadcasterId, senderUsername, content));
      }
      return;
    } else {
      console.log(`[WEBHOOK] Unhandled event: ${type}`);
    }

    console.log(`[WEBHOOK] Done in ${Date.now() - startedAt}ms`);
    return res.status(200).send("ok");
  } catch (e) {
    console.error("[WEBHOOK] Handler error:", e);
    return res.status(400).send("Bad webhook");
  }
});

export default router;
