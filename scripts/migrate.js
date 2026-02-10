/**
 * One-time migration script: imports existing JSON files into SQLite.
 *
 * Usage:
 *   node scripts/migrate.js [--broadcaster-id=12345]
 *
 * Reads from:
 *   - tokens.json (or TOK_PATH env)
 *   - /data/wheel.json (or CFG_PATH env)
 *   - /data/goals.json (or GOALS_PATH env)
 *   - /data/pending.json (or PENDING_PATH env)
 *
 * Writes to:
 *   - data/wheeloffortune.db (or DB_PATH env)
 */

import "dotenv/config";
import fs from "fs";
import { env } from "../src/utils/env.js";
import { initDb } from "../src/db.js";
import { encrypt } from "../src/utils/crypto.js";

function loadJsonSafe(filePath, fallback) {
  try {
    if (!fs.existsSync(filePath)) return fallback;
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return fallback;
  }
}

// Parse --broadcaster-id from CLI args
const bidArg = process.argv.find((a) => a.startsWith("--broadcaster-id="));
const broadcasterId = bidArg ? Number(bidArg.split("=")[1]) : null;

if (!broadcasterId || !Number.isFinite(broadcasterId)) {
  console.error("Usage: node scripts/migrate.js --broadcaster-id=YOUR_KICK_BROADCASTER_ID");
  console.error("  You can find your broadcaster ID at /status after logging in.");
  process.exit(1);
}

console.log("=== Wheel of Fortune: JSON -> SQLite Migration ===");
console.log(`Broadcaster ID: ${broadcasterId}`);
console.log(`DB Path: ${env.DB_PATH}`);
console.log();

// Initialize database
const db = initDb(env.DB_PATH);

// 1. Migrate tokens
console.log("--- Tokens ---");
const tokens = loadJsonSafe(env.TOK_PATH, null);
if (tokens?.access_token) {
  const streamer = db.upsertStreamer({
    broadcaster_id: broadcasterId,
    kick_username: null, // will be filled on next login
    display_name: null,
    access_token: encrypt(tokens.access_token, env.ENCRYPTION_KEY),
    refresh_token: encrypt(tokens.refresh_token, env.ENCRYPTION_KEY),
    token_expires_at: tokens.expires_at || null,
    token_scope: tokens.scope || null,
  });
  console.log(`  Imported tokens for broadcaster ${broadcasterId}`);
  console.log(`  Overlay key: ${streamer.overlay_key}`);
} else {
  // Create streamer without tokens (will need to re-login)
  const streamer = db.upsertStreamer({
    broadcaster_id: broadcasterId,
    kick_username: null,
    access_token: null,
    refresh_token: null,
  });
  console.log(`  No tokens found at ${env.TOK_PATH}`);
  console.log(`  Created streamer entry (will need re-login)`);
  console.log(`  Overlay key: ${streamer.overlay_key}`);
}

// 2. Migrate wheel config
console.log("--- Wheel Config ---");
const config = loadJsonSafe(env.CFG_PATH, null);
if (config?.items) {
  db.saveConfig(broadcasterId, { items: config.items });
  console.log(`  Imported ${config.items.length} items`);
} else {
  console.log(`  No config found at ${env.CFG_PATH}`);
}

// 3. Migrate goals
console.log("--- Goals ---");
const goals = loadJsonSafe(env.GOALS_PATH, []);
if (goals.length > 0) {
  db.saveGoals(broadcasterId, goals);
  console.log(`  Imported ${goals.length} goals`);
} else {
  console.log(`  No goals found at ${env.GOALS_PATH}`);
}

// 4. Migrate pending spins
console.log("--- Pending Spins ---");
const pending = loadJsonSafe(env.PENDING_PATH, 0);
if (pending > 0) {
  db.saveSpinState(broadcasterId, { pending_count: pending, last_spin_time: 0, spin_in_progress: false });
  console.log(`  Imported ${pending} pending spins`);
} else {
  console.log(`  No pending spins`);
}

// Done
const streamer = db.getStreamerById(broadcasterId);
console.log();
console.log("=== Migration Complete ===");
console.log(`Streamer: bid=${streamer.broadcaster_id} overlay_key=${streamer.overlay_key}`);
console.log();
console.log("Your overlay URLs will be:");
console.log(`  Wheel:  /overlay/${streamer.overlay_key}`);
console.log(`  Delay:  /delay/${streamer.overlay_key}`);
console.log();
console.log("Update your OBS browser sources with these new URLs.");
console.log("You can delete the old JSON files once verified.");

db.close();
