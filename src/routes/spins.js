import { Router } from "express";
import { spins } from "../services/spins.js";
import { postChatMessage } from "../services/kick.js";
import { env } from "../utils/env.js";

const router = Router();

// Test page with buttons
router.get("/test", (req, res) => {
  res.type("html").send(`
    <!DOCTYPE html>
    <html><head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>🎡 Wheel Test</title>
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
          color: white; box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4); }
        button:hover { transform: translateY(-2px); box-shadow: 0 6px 16px rgba(102, 126, 234, 0.5); }
        button:active { transform: translateY(0); }
        .custom { display: flex; gap: 12px; margin: 24px 0; }
        .custom input { flex: 1; padding: 12px 16px; border: 2px solid #e5e7eb; border-radius: 8px; 
          font-size: 16px; }
        .custom button { flex: 0 0 120px; }
        .result { margin: 24px 0; padding: 16px; border-radius: 12px; background: #f3f4f6; 
          color: #1f2937; font-size: 14px; white-space: pre-wrap; display: none; }
        .result.show { display: block; }
        .result.success { background: #d1fae5; color: #065f46; border: 2px solid #10b981; }
        .result.error { background: #fee2e2; color: #991b1b; border: 2px solid #ef4444; }
        .links { margin-top: 24px; padding-top: 24px; border-top: 2px solid #e5e7eb; }
        .links a { display: inline-block; margin-right: 16px; color: #667eea; text-decoration: none; 
          font-weight: 500; }
        .links a:hover { text-decoration: underline; }
        .info { background: #dbeafe; border: 2px solid #3b82f6; color: #1e40af; padding: 16px; 
          border-radius: 12px; margin-bottom: 24px; font-size: 14px; }
      </style>
    </head><body>
      <div class="container">
        <h1>🎡 Wheel Test Panel</h1>
        
        <div class="info">
          <strong>💡 Tip:</strong> Click a button to instantly trigger spins on your wheel overlay!<br>
          Make sure your wheel overlay is open in OBS or browser.
        </div>
        
        <h3>Quick Test:</h3>
        <div class="buttons">
          <button onclick="testSpin(1)">1 Spin</button>
          <button onclick="testSpin(2)">2 Spins</button>
          <button onclick="testSpin(3)">3 Spins</button>
          <button onclick="testSpin(5)">5 Spins</button>
        </div>
        
        <h3>Custom Amount:</h3>
        <div class="custom">
          <input type="number" id="customAmount" min="1" max="20" value="1" placeholder="Number of spins">
          <button onclick="testCustom()">Test</button>
        </div>
        
        <div id="result" class="result"></div>
        
        <div class="links">
          <a href="/index.html" target="_blank">🎡 Open Wheel</a>
          <a href="/delay.html" target="_blank">⏱️ Open Delay Timer</a>
          <a href="/home">🏠 Home</a>
        </div>
      </div>
      
      <script>
        const result = document.getElementById('result');
        
        async function testSpin(n) {
          result.className = 'result';
          result.textContent = '⏳ Sending...';
          result.classList.add('show');
          
          try {
            const response = await fetch('/test/' + n);
            const text = await response.text();
            result.className = 'result show success';
            result.textContent = '✅ ' + text;
          } catch (e) {
            result.className = 'result show error';
            result.textContent = '❌ Error: ' + e.message;
          }
        }
        
        function testCustom() {
          const n = parseInt(document.getElementById('customAmount').value) || 1;
          testSpin(Math.max(1, Math.min(20, n)));
        }
        
        // Enter key support
        document.getElementById('customAmount').addEventListener('keypress', (e) => {
          if (e.key === 'Enter') testCustom();
        });
      </script>
    </body></html>
  `);
});

// Simple test endpoint - just trigger spins
router.get("/test/:n", (req, res) => {
  const n = Math.max(1, Math.min(20, parseInt(req.params.n, 10) || 1));
  const delivered = spins.deliverSpinOrQueue(n);
  
  res.send(`Success! Sent ${n} spin(s) to ${delivered} connected client(s).

The wheel overlay will handle the 5-minute delays automatically.

Open these to see the results:
• Wheel: /index.html
• Delay Timer: /delay.html

Trigger more: /test/${n}`);
});

// Endpoint for delay.html to check pending spins
router.get("/spins/pending", (_req, res) => {
  const timeUntilNext = spins.getTimeUntilNextSpin();
  res.json({ 
    ok: true, 
    count: spins.getPending(),
    timeUntilNext: Math.ceil(timeUntilNext / 1000)
  });
});

router.get("/trigger/spin", (req, res) => {
  try {
    const key = String(req.query.key || "");
    const n = Math.max(1, Math.min(10, Number(req.query.n || 1)));
    if (!env.TRIGGER_KEY || key !== env.TRIGGER_KEY) {
      return res.status(401).json({ ok:false, error:"Unauthorized" });
    }
    const delivered = spins.deliverSpinOrQueue(n);
    return res.json({ ok:true, requested:n, delivered, pending:spins.getPending() });
  } catch (e) {
    return res.status(500).json({ ok:false, error:String(e?.message||e) });
  }
});

router.post("/chat/announce", async (req, res) => {
  try {
    const label = String(req.body?.label || "").trim();
    if (!label) {
      return res.status(400).json({ ok: false, error: "Missing label" });
    }
    
    // Send result to Kick chat
    await postChatMessage(`🎡 ${label}`);
    
    return res.json({ ok: true });
  } catch (e) {
    console.error("[chat/announce] error:", e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

export default router;
