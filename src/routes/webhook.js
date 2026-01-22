import { Router } from "express";
import { verifyKickSignature } from "../webhookVerify.js";
import { spins } from "../services/spins.js";

const router = Router();

router.get("/webhook", (req, res) => {
  console.log("[WEBHOOK][GET] ping", { ip: req.ip, ua: req.get("user-agent")||null, q: req.query });
  res.status(200).send("webhook-get-ok");
});
router.head("/webhook", (req, res) => {
  console.log("[WEBHOOK][HEAD] ping", { ip: req.ip, ua: req.get("user-agent")||null });
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

// RAW body
router.post("/webhook", (req, res, next) => {
  // raw body potrzebny – przekieruj do raw parsera tylko dla tego endpointu
  next("route");
});
router.post("/webhook", (req, res) => res.status(415).send("Use raw parser"));
export default router;
