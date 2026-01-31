import { Router } from "express";
import bodyParser from "body-parser";
import { verifyKickSignature } from "../webhookVerify.js";
import { spins } from "../services/spins.js";

const router = Router();

router.get("/webhook", (req, res) => {
  console.log("[WEBHOOK][GET] ping", { ip: req.ip, ua: req.get("user-agent")||null, q: req.query });
  res.status(200).send("webhook-get-ok - Kick can reach this endpoint ✅");
});

router.head("/webhook", (req, res) => {
  console.log("[WEBHOOK][HEAD] ping", { ip: req.ip, ua: req.get("user-agent")||null });
  res.status(200).end();
});

// Webhook test/debug endpoint
router.get("/webhook/status", (req, res) => {
  const proto = (req.headers["x-forwarded-proto"] || req.protocol || "http").split(",")[0].trim();
  const host  = (req.headers["x-forwarded-host"]  || req.get("host")).split(",")[0].trim();
  const callback = `${proto}://${host}/webhook`;
  
  res.type("html").send(`
    <!DOCTYPE html>
    <html><head><meta charset="utf-8"><title>Webhook Status</title>
    <style>
      body { font-family: system-ui; margin: 40px; }
      .status { padding: 12px; border-radius: 8px; margin: 10px 0; }
      .ok { background: #dcfce7; border: 1px solid #16a34a; color: #15803d; }
      .warn { background: #fef3c7; border: 1px solid #f59e0b; color: #92400e; }
      code { background: #f6f8fa; padding: 2px 6px; border-radius: 4px; }
      pre { background: #f6f8fa; padding: 12px; border-radius: 8px; overflow-x: auto; }
    </style>
    </head><body>
      <h1>🪝 Webhook Status</h1>
      
      <div class="status ok">
        <strong>✅ Webhook endpoint is accessible</strong><br>
        Kick can reach: <code>${callback}</code>
      </div>
      
      <h2>Check Subscription:</h2>
      <p>Visit <a href="/subscribe"><code>/subscribe</code></a> to see current subscription status</p>
      
      <h2>Recent Activity:</h2>
      <p>Check server logs for:</p>
      <ul>
        <li><code>[WEBHOOK] ⇢ Incoming</code> - webhook received</li>
        <li><code>[WEBHOOK] ✅ OK type: channel.subscription.gifts</code> - event processed</li>
        <li><code>[SPIN] Broadcasting X spin(s)</code> - spins triggered</li>
      </ul>
      
      <h2>Test Webhook:</h2>
      <pre>curl -X POST ${callback} \\
  -H "Content-Type: application/json" \\
  -d '{"test": true}'</pre>
  
      <p><a href="/home">← Back to Home</a></p>
    </body></html>
  `);
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
    // Support both old (Kick-Event-*) and new (x-kick-*) header formats
    const msgId = req.get("Kick-Event-Message-Id") || req.get("x-kick-message-id");
    const timestamp = req.get("Kick-Event-Message-Timestamp") || req.get("x-kick-timestamp");
    const signature = req.get("Kick-Event-Signature") || req.get("x-kick-signature");
    const eType = req.get("Kick-Event-Type") || req.get("x-kick-event-type");

    console.log("[WEBHOOK] ⇢ Incoming");
    console.log("[WEBHOOK] Headers:", {
      "Kick-Event-Message-Id": msgId || null,
      "Kick-Event-Message-Timestamp": timestamp || null,
      "Kick-Event-Type": eType || null,
      "Kick-Event-Signature": signature ? `(len=${signature.length})` : null,
      "Content-Type": req.get("content-type") || null,
      "User-Agent": req.get("user-agent") || null,
      ip: req.ip,
    });

    if (!msgId || !timestamp || !signature) {
      console.warn("[WEBHOOK] Missing required signature headers");
      return res.status(400).send("Missing signature headers");
    }

    // Check if we've seen this message ID before (deduplication)
    if (SEEN_IDS.has(msgId)) {
      console.log("[WEBHOOK] Duplicate message id -> 200 ok-duplicate");
      return res.status(200).send("ok-duplicate");
    }

    // Verify timestamp skew (max 5 minutes)
    const sentAt = Date.parse(timestamp);
    const MAX_SKEW_MS = 5 * 60 * 1000;
    if (!Number.isFinite(sentAt)) {
      return res.status(400).send("Invalid timestamp");
    }
    const skew = Math.abs(Date.now() - sentAt);
    console.log("[WEBHOOK] Timestamp skew(ms):", skew);
    if (skew > MAX_SKEW_MS) {
      return res.status(400).send("Stale timestamp");
    }

    // Verify signature
    const rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.from(req.body || "");
    const bodyUtf8 = rawBody.toString("utf8");
    console.log("[WEBHOOK] Body bytes:", rawBody.length, " | Signed string length:", `${msgId}.${timestamp}.${bodyUtf8}`.length);

    const isValid = verifyKickSignature(msgId, timestamp, bodyUtf8, signature);
    console.log("[WEBHOOK] Signature verified:", isValid);
    if (!isValid) {
      return res.status(401).send("Invalid signature");
    }

    // Remember this message ID
    rememberId(msgId);

    // Parse the body
    let payload = {};
    try {
      payload = JSON.parse(bodyUtf8);
    } catch (e) {
      return res.status(400).send("Invalid JSON");
    }

    const type = eType || payload?.type || payload?.event || payload?.name || "unknown";
    console.log("[WEBHOOK] ✅ OK type:", type);

    // Challenge response (webhook verification)
    if (type === "webhook_callback_verification" && payload?.challenge) {
      console.log("[WEBHOOK] Responding with challenge");
      return res.json({ challenge: payload.challenge });
    }

    // Process subscription gift events
    if (type === "channel.subscription.gifts" || payload?.name === "channel.subscription.gifts") {
      // Support both old format (giftees array) and new format (gift_count/count)
      let giftCount = 0;
      if (Array.isArray(payload?.giftees)) {
        giftCount = payload.giftees.length;
      } else if (payload?.data) {
        giftCount = Number(payload.data?.gift_count || payload.data?.count || 0);
      } else {
        giftCount = Number(payload?.gift_count || payload?.count || 0);
      }

      const { gifter = {} } = payload || {};
      console.log("[WEBHOOK] 🎁 Gifts summary:", { gifter: gifter?.username || "Anon", count: giftCount });

      // Convert gifts to spins: 5 gifts = 1 spin
      const spinCount = Math.floor(giftCount / 5);
      if (spinCount > 0) {
        console.log(`[WEBHOOK] subscription gifts: ${giftCount} -> ${spinCount} spin(s)`);
        spins.deliverSpinOrQueue(spinCount);
      } else {
        console.log("[WEBHOOK] No spins (count < 5)");
      }
    } else {
      const short = JSON.stringify(payload).slice(0, 500);
      console.log("[WEBHOOK] Unhandled event:", type, "| payload:", short + (short.length === 500 ? "… (truncated)" : ""));
    }

    console.log(`[WEBHOOK] Done in ${Date.now() - startedAt}ms`);
    return res.status(200).send("ok");
  } catch (e) {
    console.error(`[WEBHOOK] Handler error:`, e);
    return res.status(400).send("Bad webhook");
  }
});

export default router;
