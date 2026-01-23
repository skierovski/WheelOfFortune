import { Router } from "express";
import { spins } from "../services/spins.js";
import { postChatMessage } from "../services/kick.js";
import { env } from "../utils/env.js";

const router = Router();

router.get("/test/:n", (req, res) => {
  const n = parseInt(req.params.n, 10) || 0;
  const timeUntilNext = spins.getTimeUntilNextSpin();
  const pendingBefore = spins.getPending();
  
  spins.deliverSpinOrQueue(n);
  
  const pendingAfter = spins.getPending();
  const delaySeconds = Math.ceil(timeUntilNext / 1000);
  
  if (timeUntilNext > 0) {
    res.send(`✅ Dodano ${n} spin(ów) do kolejki\n` +
             `⏱️ Opóźnienie: ${delaySeconds}s (${Math.floor(delaySeconds/60)}:${String(delaySeconds%60).padStart(2,'0')})\n` +
             `📊 Oczekujące: ${pendingAfter} spin(ów)\n` +
             `\nTimer będzie widoczny na /delay.html`);
  } else {
    res.send(`✅ Wysłano ${n} spin(ów)\n` +
             `📊 Oczekujące: ${pendingAfter} spin(ów)\n` +
             `\nNastępny spin będzie miał 5-minutowe opóźnienie po zakończeniu.`);
  }
});

router.get("/spins/pending", (_req, res) => {
  const timeUntilNext = spins.getTimeUntilNextSpin();
  res.json({ 
    ok: true, 
    count: spins.getPending(),
    timeUntilNext: Math.ceil(timeUntilNext / 1000)
  });
});

// REMOVED: /spins/consume endpoint was causing race conditions when multiple 
// wheel instances tried to consume spins simultaneously. The server now handles
// all spin distribution via WebSocket broadcasts in deliverSpinOrQueue().

router.post("/spins/complete", (_req, res) => {
  spins.markSpinComplete();
  res.json({ ok: true });
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
