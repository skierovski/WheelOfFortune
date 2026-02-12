import { Router } from "express";
import path from "path";
import fs from "fs";
import { env } from "../utils/env.js";
import { getDb } from "../db.js";
import { spins } from "../services/spins.js";
import { loadConfig, saveConfig, loadGoals, saveGoals } from "../services/configStore.js";

const router = Router();

// ── Admin auth ──────────────────────────────────────────────────────

function requireAdmin(req, res, next) {
  // In dev mode with DEV_BYPASS_AUTH, allow without key
  if (env.NODE_ENV !== "production" && env.DEV_BYPASS_AUTH) {
    return next();
  }
  const key = req.get("X-Admin-Key") || req.query.admin_key || req.body?.admin_key;
  if (!env.ADMIN_KEY || key !== env.ADMIN_KEY) {
    return res.status(401).json({ ok: false, error: "Unauthorized. Set ADMIN_KEY env var or enable DEV_BYPASS_AUTH=1" });
  }
  next();
}

// ── Admin Panel Page ────────────────────────────────────────────────

router.get("/admin", requireAdmin, (req, res) => {
  const file = path.join(process.cwd(), "views", "admin.html");
  if (!fs.existsSync(file)) return res.status(404).send("admin.html not found");
  res.sendFile(file);
});

// ── Overview / Dashboard ────────────────────────────────────────────

router.get("/admin/overview", requireAdmin, (req, res) => {
  const db = getDb();
  const streamers = db.getAllStreamers();
  const unusedInvites = db.getUnusedInviteCodes();

  const streamerDetails = streamers.map((s) => {
    const config = db.getConfig(s.broadcaster_id);
    const spinState = db.getSpinState(s.broadcaster_id);
    const goals = db.getGoals(s.broadcaster_id);
    const subs = db.getActiveSubscriptions(s.broadcaster_id);

    return {
      broadcaster_id: s.broadcaster_id,
      kick_username: s.kick_username,
      display_name: s.display_name,
      overlay_key: s.overlay_key,
      has_tokens: !!s.access_token,
      created_at: s.created_at,
      updated_at: s.updated_at,
      config: {
        items_count: config?.items?.length || 0,
        tiers_count: Array.isArray(config?.tiers) ? config.tiers.length : 0,
        tiers: Array.isArray(config?.tiers) ? config.tiers.map(t => ({ name: t.name, min_gifts: t.min_gifts, items_count: t.items?.length || 0 })) : null,
        accent_color: config?.accent_color || "#7c3aed",
        gifts_per_spin: config?.gifts_per_spin ?? 5,
      },
      spins: {
        pending: spinState.pending_count,
        last_spin_time: spinState.last_spin_time,
        in_progress: !!spinState.spin_in_progress,
      },
      goals_count: goals.length,
      subscriptions_count: subs.length,
    };
  });

  res.json({
    ok: true,
    env: {
      NODE_ENV: env.NODE_ENV,
      PORT_HTTP: env.PORT_HTTP,
      REQUIRE_INVITE: env.REQUIRE_INVITE,
      DEV_BYPASS_AUTH: env.DEV_BYPASS_AUTH,
      KICK_CLIENT_ID: env.KICK_CLIENT_ID ? "(set)" : "(missing)",
      PUBLIC_BASE_URL: env.PUBLIC_BASE_URL || "(not set)",
      DB_PATH: env.DB_PATH,
    },
    streamers: streamerDetails,
    unused_invites: unusedInvites.length,
  });
});

// ── Invite Codes ────────────────────────────────────────────────────

router.post("/admin/invites", requireAdmin, (req, res) => {
  const count = Math.max(1, Math.min(50, Number(req.body?.count || 1)));
  const codes = [];
  for (let i = 0; i < count; i++) {
    codes.push(getDb().createInviteCode(null));
  }
  res.json({ ok: true, codes });
});

router.get("/admin/invites", requireAdmin, (req, res) => {
  const codes = getDb().getUnusedInviteCodes();
  res.json({ ok: true, codes });
});

// ── Streamers ───────────────────────────────────────────────────────

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

// Create a dev/test streamer (without real Kick OAuth)
router.post("/admin/streamers", requireAdmin, (req, res) => {
  const bid = Number(req.body?.broadcaster_id);
  const username = String(req.body?.kick_username || `dev_${bid}`).trim();
  const displayName = String(req.body?.display_name || username).trim();

  if (!Number.isFinite(bid) || bid <= 0) {
    return res.status(400).json({ ok: false, error: "Invalid broadcaster_id (must be a positive number)" });
  }

  const streamer = getDb().upsertStreamer({
    broadcaster_id: bid,
    kick_username: username,
    display_name: displayName,
    access_token: null,
    refresh_token: null,
  });

  // Initialize default config if none exists
  const existing = getDb().getConfig(bid);
  if (!existing) {
    saveConfig(bid, [
      { label: "VIP 24h", weight: 15, bonus: false },
      { label: "Sing 30s", weight: 15, bonus: false },
      { label: "Reroll", weight: 10, bonus: true },
      { label: "Chat's choice", weight: 15, bonus: false },
      { label: "Giveaway x1", weight: 10, bonus: false },
      { label: "Map choice", weight: 15, bonus: false },
      { label: "Shot (18+)", weight: 10, bonus: false },
      { label: "Meme on IG", weight: 10, bonus: false },
    ]);
  }

  console.log(`[ADMIN] Created streamer bid=${bid} username=${username} overlay_key=${streamer.overlay_key}`);

  res.json({
    ok: true,
    streamer: {
      broadcaster_id: streamer.broadcaster_id,
      kick_username: streamer.kick_username,
      display_name: streamer.display_name,
      overlay_key: streamer.overlay_key,
    },
  });
});

// Rename a streamer (update display_name)
router.patch("/admin/streamers/:bid", requireAdmin, (req, res) => {
  const bid = Number(req.params.bid);
  const streamer = getDb().getStreamerById(bid);
  if (!streamer) {
    return res.status(404).json({ ok: false, error: "Streamer not found" });
  }

  const newName = String(req.body?.display_name || "").trim().slice(0, 100);
  if (!newName) {
    return res.status(400).json({ ok: false, error: "display_name is required (non-empty string, max 100 chars)" });
  }

  getDb().updateDisplayName(bid, newName);
  console.log(`[ADMIN] Renamed streamer bid=${bid} -> "${newName}"`);

  res.json({
    ok: true,
    broadcaster_id: bid,
    display_name: newName,
  });
});

// Delete a streamer
router.delete("/admin/streamers/:bid", requireAdmin, (req, res) => {
  const bid = Number(req.params.bid);
  const streamer = getDb().getStreamerById(bid);
  if (!streamer) {
    return res.status(404).json({ ok: false, error: "Streamer not found" });
  }

  try {
    const db = getDb();
    // Clean up all related data (invite_codes must be cleared before streamers due to FK)
    db.raw.prepare("UPDATE invite_codes SET created_by = NULL WHERE created_by = ?").run(bid);
    db.raw.prepare("UPDATE invite_codes SET used_by = NULL WHERE used_by = ?").run(bid);
    db.raw.prepare("DELETE FROM wheel_configs WHERE broadcaster_id = ?").run(bid);
    db.raw.prepare("DELETE FROM goals WHERE broadcaster_id = ?").run(bid);
    db.raw.prepare("DELETE FROM spin_state WHERE broadcaster_id = ?").run(bid);
    db.raw.prepare("DELETE FROM subscriptions WHERE broadcaster_id = ?").run(bid);
    db.raw.prepare("DELETE FROM streamers WHERE broadcaster_id = ?").run(bid);

    console.log(`[ADMIN] Deleted streamer bid=${bid}`);
    res.json({ ok: true, deleted: bid });
  } catch (err) {
    console.error(`[ADMIN] Error deleting streamer bid=${bid}:`, err);
    res.status(500).json({ ok: false, error: err.message || "Failed to delete streamer" });
  }
});

// ── Streamer Details ────────────────────────────────────────────────

router.get("/admin/streamers/:bid", requireAdmin, (req, res) => {
  const bid = Number(req.params.bid);
  const streamer = getDb().getStreamerById(bid);
  if (!streamer) {
    return res.status(404).json({ ok: false, error: "Streamer not found" });
  }

  const config = loadConfig(bid);
  const goals = loadGoals(bid);
  const spinState = getDb().getSpinState(bid);
  const subs = getDb().getActiveSubscriptions(bid);

  res.json({
    ok: true,
    streamer: {
      broadcaster_id: streamer.broadcaster_id,
      kick_username: streamer.kick_username,
      display_name: streamer.display_name,
      overlay_key: streamer.overlay_key,
      has_tokens: !!streamer.access_token,
      created_at: streamer.created_at,
    },
    config: config || { items: [], accent_color: "#7c3aed", gifts_per_spin: 5 },
    goals,
    spins: {
      pending: spinState.pending_count,
      last_spin_time: spinState.last_spin_time,
      in_progress: !!spinState.spin_in_progress,
      time_until_next: spins.getTimeUntilNextSpin(bid),
    },
    subscriptions: subs,
  });
});

// ── Spin Controls ───────────────────────────────────────────────────

// Trigger spins for a streamer
router.post("/admin/streamers/:bid/spin", requireAdmin, (req, res) => {
  const bid = Number(req.params.bid);
  const streamer = getDb().getStreamerById(bid);
  if (!streamer) {
    return res.status(404).json({ ok: false, error: "Streamer not found" });
  }

  const n = Math.max(1, Math.min(20, Number(req.body?.count || 1)));
  const delivered = spins.deliverSpinOrQueue(bid, n);

  res.json({
    ok: true,
    requested: n,
    delivered,
    pending: spins.getPending(bid),
    time_until_next: Math.ceil(spins.getTimeUntilNextSpin(bid) / 1000),
  });
});

// Reset spins (clear pending, reset delay)
router.post("/admin/streamers/:bid/spin/reset", requireAdmin, (req, res) => {
  const bid = Number(req.params.bid);
  const streamer = getDb().getStreamerById(bid);
  if (!streamer) {
    return res.status(404).json({ ok: false, error: "Streamer not found" });
  }

  getDb().saveSpinState(bid, { pending_count: 0, last_spin_time: 0, spin_in_progress: false });
  console.log(`[ADMIN] Reset spins for bid=${bid}`);

  res.json({ ok: true, message: `Spins reset for bid=${bid}` });
});

// Complete current spin (end the 5-min delay early)
router.post("/admin/streamers/:bid/spin/complete", requireAdmin, (req, res) => {
  const bid = Number(req.params.bid);
  const streamer = getDb().getStreamerById(bid);
  if (!streamer) {
    return res.status(404).json({ ok: false, error: "Streamer not found" });
  }

  // Set last_spin_time to far in the past to bypass delay
  getDb().saveSpinState(bid, {
    pending_count: spins.getPending(bid),
    last_spin_time: 0,
    spin_in_progress: false,
  });
  console.log(`[ADMIN] Force-completed spin for bid=${bid}`);

  res.json({ ok: true, message: `Spin delay cleared for bid=${bid}` });
});

// ── Simulate Webhook Event ──────────────────────────────────────────

router.post("/admin/streamers/:bid/simulate-gift", requireAdmin, (req, res) => {
  const bid = Number(req.params.bid);
  const streamer = getDb().getStreamerById(bid);
  if (!streamer) {
    return res.status(404).json({ ok: false, error: "Streamer not found" });
  }

  const giftCount = Math.max(1, Math.min(100, Number(req.body?.gift_count || 5)));
  const gifterName = String(req.body?.gifter_name || "TestGifter");

  // Convert gifts to spins (tier-aware)
  const config = getDb().getConfig(bid);
  const configTiers = config?.tiers;
  let delivered = 0;
  let spinCount = 0;
  let tierUsed = null;

  if (Array.isArray(configTiers) && configTiers.length > 0) {
    // Tiered mode: find highest matching tier
    for (let i = configTiers.length - 1; i >= 0; i--) {
      if (giftCount >= configTiers[i].min_gifts) {
        tierUsed = configTiers[i].name;
        spinCount = 1;
        break;
      }
    }
    if (spinCount > 0) {
      delivered = spins.deliverSpinOrQueue(bid, 1, { tier: tierUsed });
    }
  } else {
    const giftsPerSpin = config?.gifts_per_spin || 5;
    spinCount = Math.floor(giftCount / giftsPerSpin);
    if (spinCount > 0) {
      delivered = spins.deliverSpinOrQueue(bid, spinCount);
    }
  }

  console.log(`[ADMIN] Simulated gift: bid=${bid} gifter=${gifterName} gifts=${giftCount} -> spins=${spinCount}${tierUsed ? ` tier="${tierUsed}"` : ""}`);

  res.json({
    ok: true,
    gift_count: giftCount,
    spin_count: spinCount,
    tier: tierUsed,
    delivered,
    pending: spins.getPending(bid),
    message: spinCount > 0
      ? `${giftCount} gifts -> ${spinCount} spin(s)${tierUsed ? ` [${tierUsed}]` : ""}, ${delivered} delivered to overlay`
      : `${giftCount} gifts -> not enough for a spin (need ${giftsPerSpin})`,
  });
});

// ── Config Management ───────────────────────────────────────────────

router.post("/admin/streamers/:bid/config", requireAdmin, (req, res) => {
  const bid = Number(req.params.bid);
  if (!getDb().getStreamerById(bid)) {
    return res.status(404).json({ ok: false, error: "Streamer not found" });
  }

  const items = req.body?.items;
  const accent_color = req.body?.accent_color;
  const gifts_per_spin = req.body?.gifts_per_spin;
  if (!Array.isArray(items)) {
    return res.status(400).json({ ok: false, error: "items[] required" });
  }

  const saved = saveConfig(bid, items, { accent_color, gifts_per_spin });

  // Broadcast to overlay
  try {
    const wss = req.app?.locals?.wss;
    if (wss?.broadcastTo) {
      wss.broadcastTo(bid, { type: "config", items: saved.items, accent_color: saved.accent_color, gifts_per_spin: saved.gifts_per_spin });
    }
  } catch {}

  res.json({ ok: true, items: saved.items, accent_color: saved.accent_color, gifts_per_spin: saved.gifts_per_spin });
});

// ── Quick Setup (create dev streamer + login in one step) ───────────

router.post("/admin/quick-setup", requireAdmin, (req, res) => {
  const bid = Number(req.body?.broadcaster_id || env.DEV_FAKE_BID || 999999);
  const username = String(req.body?.kick_username || `dev_${bid}`).trim();

  // Create streamer
  const streamer = getDb().upsertStreamer({
    broadcaster_id: bid,
    kick_username: username,
    display_name: username,
    access_token: null,
    refresh_token: null,
  });

  // Initialize default config if needed
  if (!getDb().getConfig(bid)) {
    saveConfig(bid, [
      { label: "VIP 24h", weight: 15, bonus: false },
      { label: "Sing 30s", weight: 15, bonus: false },
      { label: "Reroll", weight: 10, bonus: true },
      { label: "Chat's choice", weight: 15, bonus: false },
      { label: "Giveaway x1", weight: 10, bonus: false },
      { label: "Map choice", weight: 15, bonus: false },
      { label: "Shot (18+)", weight: 10, bonus: false },
      { label: "Meme on IG", weight: 10, bonus: false },
    ]);
  }

  // Create an invite code (for testing the flow)
  const inviteCode = getDb().createInviteCode(bid);

  const base = `${(req.headers["x-forwarded-proto"] || req.protocol || "http").split(",")[0].trim()}://${(req.headers["x-forwarded-host"] || req.get("host")).split(",")[0].trim()}`;

  console.log(`[ADMIN] Quick setup: bid=${bid} overlay_key=${streamer.overlay_key} invite=${inviteCode}`);

  res.json({
    ok: true,
    streamer: {
      broadcaster_id: streamer.broadcaster_id,
      kick_username: streamer.kick_username,
      overlay_key: streamer.overlay_key,
    },
    invite_code: inviteCode,
    urls: {
      overlay: `${base}/overlay/${streamer.overlay_key}`,
      delay: `${base}/delay/${streamer.overlay_key}`,
      dashboard: `${base}/dashboard`,
      dev_login: `${base}/auth/dev-login?bid=${bid}`,
      ws: `ws://${req.get("host")}/ws?key=${streamer.overlay_key}`,
    },
  });
});

// ── Database Reset (dev only) ───────────────────────────────────────

router.post("/admin/reset-db", requireAdmin, (req, res) => {
  if (env.NODE_ENV === "production") {
    return res.status(403).json({ ok: false, error: "Forbidden in production" });
  }

  const db = getDb();
  db.raw.exec("DELETE FROM spin_state");
  db.raw.exec("DELETE FROM wheel_configs");
  db.raw.exec("DELETE FROM goals");
  db.raw.exec("DELETE FROM subscriptions");
  db.raw.exec("DELETE FROM invite_codes");
  db.raw.exec("DELETE FROM streamers");

  console.log("[ADMIN] Database reset");
  res.json({ ok: true, message: "All data cleared" });
});

export default router;
