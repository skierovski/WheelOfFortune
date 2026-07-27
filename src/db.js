import Database from "better-sqlite3";
import crypto from "crypto";
import fs from "fs";
import path from "path";

// ── Schema ──────────────────────────────────────────────────────────

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS streamers (
  broadcaster_id   INTEGER PRIMARY KEY,
  kick_username    TEXT,
  display_name     TEXT,
  overlay_key      TEXT UNIQUE NOT NULL,
  access_token     TEXT,
  refresh_token    TEXT,
  token_expires_at INTEGER,
  token_scope      TEXT,
  created_at       INTEGER DEFAULT (unixepoch()),
  updated_at       INTEGER DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS wheel_configs (
  broadcaster_id   INTEGER PRIMARY KEY REFERENCES streamers(broadcaster_id),
  items_json       TEXT DEFAULT '[]',
  tiers_json       TEXT DEFAULT NULL,
  accent_color     TEXT DEFAULT '#7c3aed',
  secondary_color  TEXT DEFAULT '#121228',
  wheel_opacity    REAL DEFAULT 0.9,
  gifts_per_spin   INTEGER DEFAULT 5,
  updated_at       INTEGER DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS goals (
  broadcaster_id   INTEGER PRIMARY KEY REFERENCES streamers(broadcaster_id),
  goals_json       TEXT DEFAULT '[]',
  updated_at       INTEGER DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS spin_state (
  broadcaster_id   INTEGER PRIMARY KEY REFERENCES streamers(broadcaster_id),
  pending_count    INTEGER DEFAULT 0,
  last_spin_time   INTEGER DEFAULT 0,
  spin_in_progress INTEGER DEFAULT 0,
  updated_at       INTEGER DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS subscriptions (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  broadcaster_id   INTEGER REFERENCES streamers(broadcaster_id),
  subscription_id  TEXT,
  event_type       TEXT,
  callback_url     TEXT,
  status           TEXT DEFAULT 'active',
  created_at       INTEGER DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS invite_codes (
  code             TEXT PRIMARY KEY,
  created_by       INTEGER REFERENCES streamers(broadcaster_id),
  used_by          INTEGER REFERENCES streamers(broadcaster_id),
  created_at       INTEGER DEFAULT (unixepoch()),
  used_at          INTEGER
);

CREATE TABLE IF NOT EXISTS bot_config (
  broadcaster_id        INTEGER PRIMARY KEY REFERENCES streamers(broadcaster_id),
  bot_enabled           INTEGER DEFAULT 0,
  announce_prizes       INTEGER DEFAULT 1,
  prize_announce_template TEXT DEFAULT 'The wheel landed on: {prize}!',
  wheel_description     TEXT DEFAULT 'Wheel of Fortune! Gift subs to spin the wheel and win prizes!',
  language              TEXT DEFAULT 'en',
  updated_at            INTEGER DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS chat_commands (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  broadcaster_id   INTEGER REFERENCES streamers(broadcaster_id),
  command          TEXT NOT NULL,
  response         TEXT NOT NULL,
  enabled          INTEGER DEFAULT 1,
  cooldown_seconds INTEGER DEFAULT 5,
  last_used_at     INTEGER DEFAULT 0,
  created_at       INTEGER DEFAULT (unixepoch()),
  UNIQUE(broadcaster_id, command)
);
`;

// ── Helpers ─────────────────────────────────────────────────────────

function generateOverlayKey() {
  return crypto.randomBytes(18).toString("base64url"); // 24 chars, ~107 bits
}

function generateInviteCode() {
  return crypto.randomBytes(8).toString("hex").toUpperCase(); // 16 chars
}

// ── Database initialization ─────────────────────────────────────────

/**
 * Open (or create) a SQLite database and apply the schema.
 * @param {string} dbPath  File path, or ":memory:" for in-memory DB (tests)
 * @returns {object} db wrapper with query helpers
 */
export function openDatabase(dbPath = ":memory:") {
  if (dbPath !== ":memory:") {
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  }

  const sqlite = new Database(dbPath);
  sqlite.pragma("journal_mode = WAL");
  sqlite.pragma("foreign_keys = ON");
  sqlite.exec(SCHEMA_SQL);

  // ── Migrations (add columns to existing tables) ─────────────────
  const cols = sqlite.prepare("PRAGMA table_info(wheel_configs)").all().map(c => c.name);
  if (!cols.includes("accent_color")) {
    sqlite.exec("ALTER TABLE wheel_configs ADD COLUMN accent_color TEXT DEFAULT '#7c3aed'");
  }
  if (!cols.includes("gifts_per_spin")) {
    sqlite.exec("ALTER TABLE wheel_configs ADD COLUMN gifts_per_spin INTEGER DEFAULT 5");
  }
  if (!cols.includes("tiers_json")) {
    sqlite.exec("ALTER TABLE wheel_configs ADD COLUMN tiers_json TEXT DEFAULT NULL");
  }
  if (!cols.includes("secondary_color")) {
    sqlite.exec("ALTER TABLE wheel_configs ADD COLUMN secondary_color TEXT DEFAULT '#121228'");
  }
  if (!cols.includes("wheel_opacity")) {
    sqlite.exec("ALTER TABLE wheel_configs ADD COLUMN wheel_opacity REAL DEFAULT 0.9");
  }
  if (!cols.includes("sub_goal")) {
    sqlite.exec("ALTER TABLE wheel_configs ADD COLUMN sub_goal INTEGER DEFAULT 0");
  }
  if (!cols.includes("sub_counter_title")) {
    sqlite.exec("ALTER TABLE wheel_configs ADD COLUMN sub_counter_title TEXT DEFAULT 'Subskrybenci'");
  }
  if (!cols.includes("sub_counter_label")) {
    sqlite.exec("ALTER TABLE wheel_configs ADD COLUMN sub_counter_label TEXT DEFAULT 'aktywne subskrypcje'");
  }

  // bot_config migrations
  const botCols = sqlite.prepare("PRAGMA table_info(bot_config)").all().map(c => c.name);
  if (botCols.length > 0 && !botCols.includes("language")) {
    sqlite.exec("ALTER TABLE bot_config ADD COLUMN language TEXT DEFAULT 'en'");
  }

  // Migrate existing single-tier configs into tiers_json format
  const needsMigration = sqlite.prepare(
    "SELECT broadcaster_id, items_json, gifts_per_spin FROM wheel_configs WHERE tiers_json IS NULL AND items_json != '[]'"
  ).all();
  if (needsMigration.length > 0) {
    const migrateStmt = sqlite.prepare("UPDATE wheel_configs SET tiers_json = ? WHERE broadcaster_id = ?");
    for (const row of needsMigration) {
      const items = JSON.parse(row.items_json || "[]");
      if (items.length > 0) {
        const tiers = [{ name: "Default", min_gifts: row.gifts_per_spin || 5, items }];
        migrateStmt.run(JSON.stringify(tiers), row.broadcaster_id);
        console.log(`[migrate] Converted single config to tier for bid=${row.broadcaster_id}`);
      }
    }
  }

  // ── Prepared statements ─────────────────────────────────────────

  const stmts = {
    // Streamers
    upsertStreamer: sqlite.prepare(`
      INSERT INTO streamers (broadcaster_id, kick_username, display_name, overlay_key, access_token, refresh_token, token_expires_at, token_scope, updated_at)
      VALUES (@broadcaster_id, @kick_username, @display_name, @overlay_key, @access_token, @refresh_token, @token_expires_at, @token_scope, unixepoch())
      ON CONFLICT(broadcaster_id) DO UPDATE SET
        kick_username    = excluded.kick_username,
        display_name     = excluded.display_name,
        access_token     = excluded.access_token,
        refresh_token    = excluded.refresh_token,
        token_expires_at = excluded.token_expires_at,
        token_scope      = excluded.token_scope,
        updated_at       = unixepoch()
    `),
    getStreamerById: sqlite.prepare(`SELECT * FROM streamers WHERE broadcaster_id = ?`),
    getStreamerByKey: sqlite.prepare(`SELECT * FROM streamers WHERE overlay_key = ?`),
    getAllStreamers: sqlite.prepare(`SELECT * FROM streamers ORDER BY created_at`),
    updateTokens: sqlite.prepare(`
      UPDATE streamers SET access_token = @access_token, refresh_token = @refresh_token,
        token_expires_at = @token_expires_at, token_scope = @token_scope, updated_at = unixepoch()
      WHERE broadcaster_id = @broadcaster_id
    `),
    updateOverlayKey: sqlite.prepare(`
      UPDATE streamers SET overlay_key = @overlay_key, updated_at = unixepoch()
      WHERE broadcaster_id = @broadcaster_id
    `),
    updateDisplayName: sqlite.prepare(`
      UPDATE streamers SET display_name = @display_name, updated_at = unixepoch()
      WHERE broadcaster_id = @broadcaster_id
    `),

    // Wheel configs
    upsertConfig: sqlite.prepare(`
      INSERT INTO wheel_configs (broadcaster_id, items_json, tiers_json, accent_color, secondary_color, wheel_opacity, gifts_per_spin, sub_goal, sub_counter_title, sub_counter_label, updated_at)
      VALUES (@broadcaster_id, @items_json, @tiers_json, @accent_color, @secondary_color, @wheel_opacity, @gifts_per_spin, @sub_goal, @sub_counter_title, @sub_counter_label, unixepoch())
      ON CONFLICT(broadcaster_id) DO UPDATE SET
        items_json          = excluded.items_json,
        tiers_json          = excluded.tiers_json,
        accent_color        = excluded.accent_color,
        secondary_color     = excluded.secondary_color,
        wheel_opacity       = excluded.wheel_opacity,
        gifts_per_spin      = excluded.gifts_per_spin,
        sub_goal            = excluded.sub_goal,
        sub_counter_title   = excluded.sub_counter_title,
        sub_counter_label   = excluded.sub_counter_label,
        updated_at          = unixepoch()
    `),
    getConfig: sqlite.prepare(`SELECT * FROM wheel_configs WHERE broadcaster_id = ?`),

    // Goals
    upsertGoals: sqlite.prepare(`
      INSERT INTO goals (broadcaster_id, goals_json, updated_at)
      VALUES (@broadcaster_id, @goals_json, unixepoch())
      ON CONFLICT(broadcaster_id) DO UPDATE SET
        goals_json = excluded.goals_json,
        updated_at = unixepoch()
    `),
    getGoals: sqlite.prepare(`SELECT * FROM goals WHERE broadcaster_id = ?`),

    // Spin state
    upsertSpinState: sqlite.prepare(`
      INSERT INTO spin_state (broadcaster_id, pending_count, last_spin_time, spin_in_progress, updated_at)
      VALUES (@broadcaster_id, @pending_count, @last_spin_time, @spin_in_progress, unixepoch())
      ON CONFLICT(broadcaster_id) DO UPDATE SET
        pending_count    = excluded.pending_count,
        last_spin_time   = excluded.last_spin_time,
        spin_in_progress = excluded.spin_in_progress,
        updated_at       = unixepoch()
    `),
    getSpinState: sqlite.prepare(`SELECT * FROM spin_state WHERE broadcaster_id = ?`),
    getStreamersWithPendingSpins: sqlite.prepare(`
      SELECT s.*, ss.pending_count, ss.last_spin_time, ss.spin_in_progress
      FROM streamers s
      JOIN spin_state ss ON s.broadcaster_id = ss.broadcaster_id
      WHERE ss.pending_count > 0
    `),

    // Subscriptions
    insertSubscription: sqlite.prepare(`
      INSERT INTO subscriptions (broadcaster_id, subscription_id, event_type, callback_url, status)
      VALUES (@broadcaster_id, @subscription_id, @event_type, @callback_url, @status)
    `),
    getActiveSubscriptions: sqlite.prepare(`
      SELECT * FROM subscriptions WHERE broadcaster_id = ? AND status = 'active'
    `),
    deactivateSubscriptions: sqlite.prepare(`
      UPDATE subscriptions SET status = 'inactive' WHERE broadcaster_id = ? AND status = 'active'
    `),

    // Invite codes
    insertInviteCode: sqlite.prepare(`
      INSERT INTO invite_codes (code, created_by) VALUES (@code, @created_by)
    `),
    getInviteCode: sqlite.prepare(`SELECT * FROM invite_codes WHERE code = ?`),
    useInviteCode: sqlite.prepare(`
      UPDATE invite_codes SET used_by = @used_by, used_at = unixepoch()
      WHERE code = @code AND used_by IS NULL
    `),
    getUnusedInviteCodes: sqlite.prepare(`SELECT * FROM invite_codes WHERE used_by IS NULL ORDER BY created_at`),

    // Bot config
    upsertBotConfig: sqlite.prepare(`
      INSERT INTO bot_config (broadcaster_id, bot_enabled, announce_prizes, prize_announce_template, wheel_description, language, updated_at)
      VALUES (@broadcaster_id, @bot_enabled, @announce_prizes, @prize_announce_template, @wheel_description, @language, unixepoch())
      ON CONFLICT(broadcaster_id) DO UPDATE SET
        bot_enabled           = excluded.bot_enabled,
        announce_prizes       = excluded.announce_prizes,
        prize_announce_template = excluded.prize_announce_template,
        wheel_description     = excluded.wheel_description,
        language              = excluded.language,
        updated_at            = unixepoch()
    `),
    getBotConfig: sqlite.prepare(`SELECT * FROM bot_config WHERE broadcaster_id = ?`),

    // Chat commands
    insertCommand: sqlite.prepare(`
      INSERT INTO chat_commands (broadcaster_id, command, response, enabled, cooldown_seconds)
      VALUES (@broadcaster_id, @command, @response, @enabled, @cooldown_seconds)
    `),
    updateCommand: sqlite.prepare(`
      UPDATE chat_commands SET command = @command, response = @response, enabled = @enabled, cooldown_seconds = @cooldown_seconds
      WHERE id = @id AND broadcaster_id = @broadcaster_id
    `),
    deleteCommand: sqlite.prepare(`DELETE FROM chat_commands WHERE id = ? AND broadcaster_id = ?`),
    getCommands: sqlite.prepare(`SELECT * FROM chat_commands WHERE broadcaster_id = ? ORDER BY created_at`),
    getCommandById: sqlite.prepare(`SELECT * FROM chat_commands WHERE id = ? AND broadcaster_id = ?`),
    getEnabledCommands: sqlite.prepare(`SELECT * FROM chat_commands WHERE broadcaster_id = ? AND enabled = 1`),
    updateCommandCooldown: sqlite.prepare(`UPDATE chat_commands SET last_used_at = ? WHERE id = ?`),
  };

  // ── Public API ──────────────────────────────────────────────────

  const db = {
    /** Direct access to the underlying better-sqlite3 instance */
    raw: sqlite,

    close() {
      sqlite.close();
    },

    // ── Streamers ───────────────────────────────────────────────

    upsertStreamer({ broadcaster_id, kick_username, display_name, access_token, refresh_token, token_expires_at, token_scope }) {
      const existing = stmts.getStreamerById.get(broadcaster_id);
      const overlay_key = existing?.overlay_key || generateOverlayKey();
      stmts.upsertStreamer.run({
        broadcaster_id,
        kick_username: kick_username || existing?.kick_username || null,
        display_name: display_name || existing?.display_name || null,
        overlay_key,
        access_token: access_token ?? existing?.access_token ?? null,
        refresh_token: refresh_token ?? existing?.refresh_token ?? null,
        token_expires_at: token_expires_at ?? existing?.token_expires_at ?? null,
        token_scope: token_scope ?? existing?.token_scope ?? null,
      });
      return stmts.getStreamerById.get(broadcaster_id);
    },

    getStreamerById(broadcasterId) {
      return stmts.getStreamerById.get(broadcasterId) || null;
    },

    getStreamerByOverlayKey(overlayKey) {
      return stmts.getStreamerByKey.get(overlayKey) || null;
    },

    getAllStreamers() {
      return stmts.getAllStreamers.all();
    },

    updateDisplayName(broadcasterId, displayName) {
      return stmts.updateDisplayName.run({ broadcaster_id: broadcasterId, display_name: displayName });
    },

    updateTokens(broadcasterId, { access_token, refresh_token, token_expires_at, token_scope }) {
      return stmts.updateTokens.run({
        broadcaster_id: broadcasterId,
        access_token, refresh_token, token_expires_at,
        token_scope: token_scope ?? null,
      });
    },

    regenerateOverlayKey(broadcasterId) {
      const newKey = generateOverlayKey();
      stmts.updateOverlayKey.run({ broadcaster_id: broadcasterId, overlay_key: newKey });
      return newKey;
    },

    // ── Wheel Config ────────────────────────────────────────────

    getConfig(broadcasterId) {
      const row = stmts.getConfig.get(broadcasterId);
      if (!row) return null;
      const tiers = row.tiers_json ? JSON.parse(row.tiers_json) : null;
      return {
        items: JSON.parse(row.items_json),
        tiers: Array.isArray(tiers) ? tiers : null,
        accent_color: row.accent_color || "#7c3aed",
        secondary_color: row.secondary_color || "#121228",
        wheel_opacity: row.wheel_opacity ?? 0.9,
        gifts_per_spin: row.gifts_per_spin ?? 5,
        sub_goal: row.sub_goal ?? 0,
        sub_counter_title: row.sub_counter_title ?? "Subskrybenci",
        sub_counter_label: row.sub_counter_label ?? "aktywne subskrypcje",
      };
    },

    saveConfig(broadcasterId, { items, tiers, accent_color, secondary_color, wheel_opacity, gifts_per_spin, sub_goal, sub_counter_title, sub_counter_label }) {
      const prev = stmts.getConfig.get(broadcasterId);
      stmts.upsertConfig.run({
        broadcaster_id: broadcasterId,
        items_json: JSON.stringify(items),
        tiers_json: tiers ? JSON.stringify(tiers) : (prev?.tiers_json ?? null),
        accent_color: accent_color ?? prev?.accent_color ?? "#7c3aed",
        secondary_color: secondary_color ?? prev?.secondary_color ?? "#121228",
        wheel_opacity: wheel_opacity ?? prev?.wheel_opacity ?? 0.9,
        gifts_per_spin: gifts_per_spin ?? prev?.gifts_per_spin ?? 5,
        sub_goal: sub_goal ?? prev?.sub_goal ?? 0,
        sub_counter_title: sub_counter_title ?? prev?.sub_counter_title ?? "Subskrybenci",
        sub_counter_label: sub_counter_label ?? prev?.sub_counter_label ?? "aktywne subskrypcje",
      });
    },

    // ── Goals ───────────────────────────────────────────────────

    getGoals(broadcasterId) {
      const row = stmts.getGoals.get(broadcasterId);
      if (!row) return [];
      return JSON.parse(row.goals_json);
    },

    saveGoals(broadcasterId, goalsArray) {
      stmts.upsertGoals.run({
        broadcaster_id: broadcasterId,
        goals_json: JSON.stringify(goalsArray),
      });
    },

    // ── Spin State ──────────────────────────────────────────────

    getSpinState(broadcasterId) {
      return stmts.getSpinState.get(broadcasterId) || {
        broadcaster_id: broadcasterId,
        pending_count: 0,
        last_spin_time: 0,
        spin_in_progress: 0,
      };
    },

    saveSpinState(broadcasterId, { pending_count, last_spin_time, spin_in_progress }) {
      stmts.upsertSpinState.run({
        broadcaster_id: broadcasterId,
        pending_count: pending_count ?? 0,
        last_spin_time: last_spin_time ?? 0,
        spin_in_progress: spin_in_progress ? 1 : 0,
      });
    },

    getStreamersWithPendingSpins() {
      return stmts.getStreamersWithPendingSpins.all();
    },

    // ── Subscriptions ───────────────────────────────────────────

    addSubscription(broadcasterId, { subscription_id, event_type, callback_url }) {
      stmts.insertSubscription.run({
        broadcaster_id: broadcasterId,
        subscription_id,
        event_type,
        callback_url,
        status: "active",
      });
    },

    getActiveSubscriptions(broadcasterId) {
      return stmts.getActiveSubscriptions.all(broadcasterId);
    },

    deactivateSubscriptions(broadcasterId) {
      stmts.deactivateSubscriptions.run(broadcasterId);
    },

    // ── Invite Codes ────────────────────────────────────────────

    createInviteCode(createdBy = null) {
      const code = generateInviteCode();
      stmts.insertInviteCode.run({ code, created_by: createdBy });
      return code;
    },

    validateInviteCode(code) {
      const row = stmts.getInviteCode.get(code);
      if (!row) return { valid: false, reason: "not_found" };
      if (row.used_by != null) return { valid: false, reason: "already_used" };
      return { valid: true, code: row };
    },

    useInviteCode(code, usedByBroadcasterId) {
      const result = stmts.useInviteCode.run({ code, used_by: usedByBroadcasterId });
      return result.changes > 0;
    },

    getUnusedInviteCodes() {
      return stmts.getUnusedInviteCodes.all();
    },

    // ── Bot Config ──────────────────────────────────────────────

    getBotConfig(broadcasterId) {
      return stmts.getBotConfig.get(broadcasterId) || {
        broadcaster_id: broadcasterId,
        bot_enabled: 0,
        announce_prizes: 1,
        prize_announce_template: "The wheel landed on: {prize}!",
        wheel_description: "Wheel of Fortune! Gift subs to spin the wheel and win prizes!",
        language: "en",
      };
    },

    saveBotConfig(broadcasterId, { bot_enabled, announce_prizes, prize_announce_template, wheel_description, language }) {
      const prev = stmts.getBotConfig.get(broadcasterId);
      stmts.upsertBotConfig.run({
        broadcaster_id: broadcasterId,
        bot_enabled: bot_enabled ?? prev?.bot_enabled ?? 0,
        announce_prizes: announce_prizes ?? prev?.announce_prizes ?? 1,
        prize_announce_template: prize_announce_template ?? prev?.prize_announce_template ?? "The wheel landed on: {prize}!",
        wheel_description: wheel_description ?? prev?.wheel_description ?? "Wheel of Fortune! Gift subs to spin the wheel and win prizes!",
        language: language ?? prev?.language ?? "en",
      });
      return stmts.getBotConfig.get(broadcasterId);
    },

    // ── Chat Commands ───────────────────────────────────────────

    getCommands(broadcasterId) {
      return stmts.getCommands.all(broadcasterId);
    },

    getEnabledCommands(broadcasterId) {
      return stmts.getEnabledCommands.all(broadcasterId);
    },

    getCommandById(id, broadcasterId) {
      return stmts.getCommandById.get(id, broadcasterId) || null;
    },

    addCommand(broadcasterId, { command, response, enabled = 1, cooldown_seconds = 5 }) {
      const cmd = command.startsWith("!") ? command.toLowerCase() : `!${command.toLowerCase()}`;
      stmts.insertCommand.run({
        broadcaster_id: broadcasterId,
        command: cmd,
        response,
        enabled: enabled ? 1 : 0,
        cooldown_seconds: Math.max(0, Number(cooldown_seconds) || 5),
      });
      return stmts.getCommands.all(broadcasterId);
    },

    updateCommand(broadcasterId, id, { command, response, enabled, cooldown_seconds }) {
      const existing = stmts.getCommandById.get(id, broadcasterId);
      if (!existing) return null;
      const cmd = command
        ? (command.startsWith("!") ? command.toLowerCase() : `!${command.toLowerCase()}`)
        : existing.command;
      stmts.updateCommand.run({
        id,
        broadcaster_id: broadcasterId,
        command: cmd,
        response: response ?? existing.response,
        enabled: enabled != null ? (enabled ? 1 : 0) : existing.enabled,
        cooldown_seconds: cooldown_seconds != null ? Math.max(0, Number(cooldown_seconds) || 5) : existing.cooldown_seconds,
      });
      return stmts.getCommandById.get(id, broadcasterId);
    },

    deleteCommand(id, broadcasterId) {
      const result = stmts.deleteCommand.run(id, broadcasterId);
      return result.changes > 0;
    },

    updateCommandCooldown(id, timestamp) {
      stmts.updateCommandCooldown.run(timestamp, id);
    },
  };

  return db;
}

// ── Singleton for production use ──────────────────────────────────

let _instance = null;

/**
 * Get or create the singleton DB instance.
 * Call setDbPath() before first use, or it defaults to ./data/wheeloffortune.db
 */
export function getDb() {
  if (!_instance) {
    throw new Error("Database not initialized. Call initDb(path) first.");
  }
  return _instance;
}

/**
 * Initialize the singleton database.
 * @param {string} dbPath
 */
export function initDb(dbPath) {
  if (_instance) _instance.close();
  _instance = openDatabase(dbPath);
  return _instance;
}

/**
 * Replace the singleton with an externally-created DB (for testing).
 */
export function setDb(db) {
  _instance = db;
}

export { generateOverlayKey, generateInviteCode };
