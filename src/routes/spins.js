import { Router } from "express";
import { spins } from "../services/spins.js";
import { env } from "../utils/env.js";

const router = Router();

router.get("/test/:n", (req, res) => {
  const n = parseInt(req.params.n, 10) || 0;
  spins.deliverSpinOrQueue(n);
  res.send(`sent ${n}`);
});

router.get("/spins/pending", (_req, res) => res.json({ ok:true, count: spins.getPending() }));
router.post("/spins/consume", (req, res) => {
  const want = Number(req.body?.count || 0);
  const taken = spins.consumePending(want);
  res.json({ ok:true, taken });
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

export default router;
