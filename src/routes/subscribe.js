import { Router } from "express";
import { env } from "../utils/env.js";
import { getSessionBroadcasterId } from "../utils/cookies.js";
import { getBroadcasterId, subscribeToEvents } from "../services/kick.js";
import { watchdogState } from "../services/watchdogs.js";

const router = Router();

router.post("/subscribe", async (req, res) => {
  try {
    const hasAdminKey = env.ADMIN_KEY && req.get("X-Admin-Key") === env.ADMIN_KEY;
    const hasSession = !!getSessionBroadcasterId(req);
    if (!hasAdminKey && !hasSession) return res.status(401).json({ ok:false, error:"Unauthorized" });

    const broadcasterId = await getBroadcasterId();
    const proto = (req.headers["x-forwarded-proto"] || req.protocol || "http").split(",")[0].trim();
    const host  = (req.headers["x-forwarded-host"]  || req.get("host")).split(",")[0].trim();
    const callback = `${proto}://${host}/webhook`;

    const resp = await subscribeToEvents(broadcasterId, callback);
    return res.json({ ok:true, data: resp });
  } catch (e) {
    console.error("[/subscribe] error:", e);
    return res.status(400).json({ ok:false, error:String(e?.message||e) });
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
      <h2>OBS</h2>
      <ol>
        <li>W OBS dodaj <b>Browser Source</b>: <code>${base}/?overlay=1</code></li>
        <li>Tło jest przezroczyste.</li>
        <li>Webhook callback: <code>${cb}</code></li>
      </ol>
      <p>Panel: <a class="btn" href="/home">🏠 /home</a></p>
      <p>Test koła: <a class="btn" href="/test/1">▶️ /test/1</a></p>
    </body></html>
  `);
});

export default router;
