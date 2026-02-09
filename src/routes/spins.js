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

// Test page
router.get("/dashboard/test", requireSession, (req, res) => {
  res.type("html").send(`
    <!DOCTYPE html>
    <html><head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Wheel Test</title>
      <style>
        * { box-sizing: border-box; }
        body { font-family: system-ui, -apple-system, sans-serif; margin: 0; padding: 20px;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 16px;
          padding: 32px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); }
        h1 { margin: 0 0 24px 0; font-size: 32px; color: #1f2937; }
        .buttons { display: grid; grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
          gap: 12px; margin: 24px 0; }
        button { padding: 16px 24px; border: none; border-radius: 12px; font-size: 18px;
          font-weight: 600; cursor: pointer; transition: all 0.2s; background: #667eea;
          color: white; }
        button:hover { transform: translateY(-2px); }
        #result { margin: 24px 0; padding: 16px; border-radius: 12px; background: #f3f4f6;
          display: none; }
        .links { margin-top: 24px; padding-top: 24px; border-top: 2px solid #e5e7eb; }
        .links a { display: inline-block; margin-right: 16px; color: #667eea; text-decoration: none; }
      </style>
    </head><body>
      <div class="container">
        <h1>Wheel Test Panel</h1>
        <div class="buttons">
          <button onclick="testSpin(1)">1 Spin</button>
          <button onclick="testSpin(2)">2 Spins</button>
          <button onclick="testSpin(3)">3 Spins</button>
          <button onclick="testSpin(5)">5 Spins</button>
        </div>
        <div id="result"></div>
        <div class="links">
          <a href="/dashboard">Dashboard</a>
        </div>
      </div>
      <script>
        async function testSpin(n) {
          const el = document.getElementById('result');
          el.style.display = 'block';
          el.textContent = 'Sending...';
          try {
            const r = await fetch('/dashboard/test/' + n);
            const data = await r.json();
            el.textContent = data.message;
            el.style.background = '#d1fae5';
          } catch (e) {
            el.textContent = 'Error: ' + e.message;
            el.style.background = '#fee2e2';
          }
        }
      </script>
    </body></html>
  `);
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
