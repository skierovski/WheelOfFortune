import { Router } from "express";
import { env } from "../utils/env.js";
import { getDb } from "../db.js";

const router = Router();

// Admin auth middleware
function requireAdmin(req, res, next) {
  const key = req.get("X-Admin-Key") || req.query.admin_key;
  if (!env.ADMIN_KEY || key !== env.ADMIN_KEY) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }
  next();
}

// Generate invite codes
router.post("/admin/invites", requireAdmin, (req, res) => {
  const count = Math.max(1, Math.min(50, Number(req.body?.count || 1)));
  const codes = [];
  for (let i = 0; i < count; i++) {
    codes.push(getDb().createInviteCode(null));
  }
  res.json({ ok: true, codes });
});

// List unused invite codes
router.get("/admin/invites", requireAdmin, (req, res) => {
  const codes = getDb().getUnusedInviteCodes();
  res.json({ ok: true, codes });
});

// List all streamers
router.get("/admin/streamers", requireAdmin, (req, res) => {
  const streamers = getDb().getAllStreamers().map((s) => ({
    broadcaster_id: s.broadcaster_id,
    kick_username: s.kick_username,
    display_name: s.display_name,
    overlay_key: s.overlay_key,
    has_tokens: !!s.access_token,
    created_at: s.created_at,
  }));
  res.json({ ok: true, streamers });
});

export default router;
