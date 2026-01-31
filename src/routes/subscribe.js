import { Router } from "express";
import { env } from "../utils/env.js";
import { getSessionBroadcasterId } from "../utils/cookies.js";
import { getBroadcasterId, subscribeToEvents } from "../services/kick.js";
import { watchdogState } from "../services/watchdogs.js";

const router = Router();

// GET /subscribe - Check current subscription status
router.get("/subscribe", async (req, res) => {
  try {
    const broadcasterId = await getBroadcasterId();
    const subs = await listSubscriptions(broadcasterId);
    
    const proto = (req.headers["x-forwarded-proto"] || req.protocol || "http").split(",")[0].trim();
    const host  = (req.headers["x-forwarded-host"]  || req.get("host")).split(",")[0].trim();
    const callback = `${proto}://${host}/webhook`;
    
    const hasGifts = subs.some(s => s?.name === "channel.subscription.gifts");
    const giftsSub = subs.find(s => s?.name === "channel.subscription.gifts");
    
    return res.json({ 
      ok: true, 
      subscribed: hasGifts,
      callbackUrl: callback,
      subscription: giftsSub || null,
      allSubscriptions: subs
    });
  } catch (e) {
    console.error("[GET /subscribe] error:", e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// POST /subscribe - Manually create subscription
router.post("/subscribe", async (req, res) => {
  try {
    const hasAdminKey = env.ADMIN_KEY && req.get("X-Admin-Key") === env.ADMIN_KEY;
    const hasSession = !!getSessionBroadcasterId(req);
    if (!hasAdminKey && !hasSession) return res.status(401).json({ ok:false, error:"Unauthorized" });

    const broadcasterId = await getBroadcasterId();
    const proto = (req.headers["x-forwarded-proto"] || req.protocol || "http").split(",")[0].trim();
    const host  = (req.headers["x-forwarded-host"]  || req.get("host")).split(",")[0].trim();
    const callback = `${proto}://${host}/webhook`;
    
    // Set callback URL for watchdog
    watchdogState.setLastCallbackUrl(callback);

    const resp = await subscribeToEvents(broadcasterId, callback);
    return res.json({ ok:true, data: resp });
  } catch (e) {
    console.error("[POST /subscribe] error:", e);
    return res.status(400).json({ ok:false, error:String(e?.message||e) });
  }
});

// POST /subscribe/check - Manually trigger subscription check (runs watchdog immediately)
router.post("/subscribe/check", async (req, res) => {
  try {
    const hasAdminKey = env.ADMIN_KEY && req.get("X-Admin-Key") === env.ADMIN_KEY;
    const hasSession = !!getSessionBroadcasterId(req);
    if (!hasAdminKey && !hasSession) return res.status(401).json({ ok:false, error:"Unauthorized" });

    console.log("[/subscribe/check] Manual watchdog trigger");
    await watchdogState.ensureSubscribed();
    
    return res.json({ ok: true, message: "Subscription check completed" });
  } catch (e) {
    console.error("[POST /subscribe/check] error:", e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

router.get("/setup", async (req, res) => {
  const hasTokens = true; // jeżeli brak tokena, /subscribe i tak zwróci błąd
  const proto = (req.headers["x-forwarded-proto"] || req.protocol || "http").split(",")[0].trim();
  const host  = (req.headers["x-forwarded-host"]  || req.get("host")).split(",")[0].trim();
  const base = `${proto}://${host}`;
  const cb = `${base}/webhook`;
  watchdogState.setLastCallbackUrl(cb);

  let subLine = '<span class="warn">spróbuj „Zasubskrybuj teraz” z /home</span>';

  res.type("html").send(`
    <!doctype html>
    <html><head><meta charset="utf-8"><title>Kick Wheel – Setup</title>
    <style>
      body { font-family: system-ui; margin: 40px; }
      .ok { color: #16a34a; }
      .warn { color: #b45309; }
      a.btn { display:inline-block; padding:10px 14px; border:1px solid #333; border-radius:8px; text-decoration:none; margin-top:6px; }
      code { background:#f6f8fa; padding:2px 6px; border-radius:6px; }
    </style>
    </head><body>
      <h1>Kick Wheel – konfiguracja</h1>
      <p>Status tokenów: ${hasTokens ? '<b class="ok">OK (?)</b>' : '<b class="warn">brak – zaloguj</b>'}</p>
      <p>Subskrypcja eventów: ${subLine}</p>
      <hr>
      <h2>OBS Browser Sources</h2>
      <ol>
        <li><b>Wheel overlay:</b> <code>${base}/index.html</code></li>
        <li><b>Delay timer overlay:</b> <code>${base}/delay.html</code></li>
        <li>Set background to transparent in OBS</li>
        <li>Webhook callback: <code>${cb}</code></li>
      </ol>
      <hr>
      <h2>Test Spins</h2>
      <p><a class="btn" href="/test">🎯 Open Test Panel</a> <span style="color:#22c55e;">(Recommended!)</span></p>
      <p>Or use direct URLs:</p>
      <ul>
        <li><a href="/test/1">Test 1 spin</a></li>
        <li><a href="/test/3">Test 3 spins</a></li>
        <li><a href="/test/5">Test 5 spins</a></li>
      </ul>
      <hr>
      <p><a class="btn" href="/home">🏠 Back to Home</a></p>
    </body></html>
  `);
});

export default router;
