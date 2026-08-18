import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { openDatabase } from "../../src/db.js";

describe("database schema and queries", () => {
  let db;

  beforeEach(() => {
    db = openDatabase(":memory:");
  });

  afterEach(() => {
    db.close();
  });

  // ── Schema ──────────────────────────────────────────────────────

  describe("schema", () => {
    it("creates all tables", () => {
      const tables = db.raw
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .all()
        .map((r) => r.name);

      expect(tables).toContain("streamers");
      expect(tables).toContain("wheel_configs");
      expect(tables).toContain("goals");
      expect(tables).toContain("spin_state");
      expect(tables).toContain("slots_state");
      expect(tables).toContain("subscriptions");
      expect(tables).toContain("streamer_moderators");
    });

    it("has WAL journal mode (in-memory reports 'memory' which is expected)", () => {
      const mode = db.raw.pragma("journal_mode", { simple: true });
      // In-memory DBs don't support WAL; they report "memory"
      // WAL is applied for file-based DBs in production
      expect(["wal", "memory"]).toContain(mode);
    });

    it("enforces unique overlay_key", () => {
      db.upsertStreamer({
        broadcaster_id: 1,
        kick_username: "user1",
        access_token: "t1",
        refresh_token: "r1",
      });
      const streamer1 = db.getStreamerById(1);

      // Try to manually insert another streamer with same overlay_key
      expect(() => {
        db.raw
          .prepare("INSERT INTO streamers (broadcaster_id, overlay_key) VALUES (?, ?)")
          .run(999, streamer1.overlay_key);
      }).toThrow();
    });
  });

  // ── Streamers ───────────────────────────────────────────────────

  describe("streamers", () => {
    it("creates a streamer with generated overlay_key", () => {
      const streamer = db.upsertStreamer({
        broadcaster_id: 100,
        kick_username: "testuser",
        display_name: "Test User",
        access_token: "at_123",
        refresh_token: "rt_456",
        token_expires_at: 1700000000,
        token_scope: "user:read",
      });

      expect(streamer.broadcaster_id).toBe(100);
      expect(streamer.kick_username).toBe("testuser");
      expect(streamer.display_name).toBe("Test User");
      expect(streamer.overlay_key).toBeTruthy();
      expect(streamer.overlay_key.length).toBe(24);
      expect(streamer.access_token).toBe("at_123");
    });

    it("preserves overlay_key on upsert (re-login)", () => {
      const first = db.upsertStreamer({
        broadcaster_id: 100,
        kick_username: "user",
        access_token: "old_token",
        refresh_token: "old_refresh",
      });

      const second = db.upsertStreamer({
        broadcaster_id: 100,
        kick_username: "user",
        access_token: "new_token",
        refresh_token: "new_refresh",
      });

      expect(second.overlay_key).toBe(first.overlay_key); // preserved!
      expect(second.access_token).toBe("new_token"); // updated
    });

    it("looks up streamer by overlay_key", () => {
      const created = db.upsertStreamer({
        broadcaster_id: 200,
        kick_username: "streamer",
        access_token: "tok",
        refresh_token: "ref",
      });

      const found = db.getStreamerByOverlayKey(created.overlay_key);
      expect(found).toBeTruthy();
      expect(found.broadcaster_id).toBe(200);
    });

    it("returns null for nonexistent streamer", () => {
      expect(db.getStreamerById(9999)).toBeNull();
      expect(db.getStreamerByOverlayKey("nonexistent")).toBeNull();
    });

    it("lists all streamers", () => {
      db.upsertStreamer({ broadcaster_id: 1, kick_username: "a", access_token: "t", refresh_token: "r" });
      db.upsertStreamer({ broadcaster_id: 2, kick_username: "b", access_token: "t", refresh_token: "r" });
      db.upsertStreamer({ broadcaster_id: 3, kick_username: "c", access_token: "t", refresh_token: "r" });

      const all = db.getAllStreamers();
      expect(all).toHaveLength(3);
    });

    it("updates tokens separately", () => {
      db.upsertStreamer({ broadcaster_id: 100, kick_username: "u", access_token: "old", refresh_token: "old_r" });
      db.updateTokens(100, {
        access_token: "new_at",
        refresh_token: "new_rt",
        token_expires_at: 9999999,
        token_scope: "channel:read",
      });

      const updated = db.getStreamerById(100);
      expect(updated.access_token).toBe("new_at");
      expect(updated.refresh_token).toBe("new_rt");
      expect(updated.token_expires_at).toBe(9999999);
    });

    it("regenerates overlay_key", () => {
      const created = db.upsertStreamer({ broadcaster_id: 100, kick_username: "u", access_token: "t", refresh_token: "r" });
      const oldKey = created.overlay_key;

      const newKey = db.regenerateOverlayKey(100);
      expect(newKey).not.toBe(oldKey);
      expect(newKey.length).toBe(24);

      const updated = db.getStreamerById(100);
      expect(updated.overlay_key).toBe(newKey);
    });
  });

  // ── Wheel Config ────────────────────────────────────────────────

  describe("wheel config", () => {
    beforeEach(() => {
      db.upsertStreamer({ broadcaster_id: 1, kick_username: "u", access_token: "t", refresh_token: "r" });
    });

    it("returns null for streamer with no config", () => {
      expect(db.getConfig(1)).toBeNull();
    });

    it("saves and loads config", () => {
      const items = [{ id: "itm_1", label: "Prize", weight: 50, bonus: false }];
      db.saveConfig(1, { items, accent_color: "#ff0000" });

      const loaded = db.getConfig(1);
      expect(loaded.accent_color).toBe("#ff0000");
      expect(loaded.items).toHaveLength(1);
      expect(loaded.items[0].label).toBe("Prize");
      expect(loaded.slots_token).toBe("🪙");
    });

    it("saves and loads slots_token", () => {
      db.saveConfig(1, { items: [{ label: "A" }] });
      db.saveSlotsToken(1, "🍕");
      expect(db.getConfig(1).slots_token).toBe("🍕");
    });

    it("persists sub-counter image in SQLite", () => {
      const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
      db.saveSubCounterImage(1, {
        data: png,
        mime: "image/png",
        url: "/overlay/abc/sub-counter-image?v=1",
      });
      const img = db.getSubCounterImage(1);
      expect(img).toBeTruthy();
      expect(Buffer.from(img.data).equals(png)).toBe(true);
      expect(img.mime).toBe("image/png");
      expect(db.getConfig(1).sub_counter_image_url).toContain("sub-counter-image");
    });

    it("upserts config on save (overwrite)", () => {
      db.saveConfig(1, { items: [{ label: "A" }], accent_color: "#111111" });
      db.saveConfig(1, { items: [{ label: "B" }, { label: "C" }], accent_color: "#222222" });

      const loaded = db.getConfig(1);
      expect(loaded.items).toHaveLength(2);
      expect(loaded.accent_color).toBe("#222222");
    });

    it("isolates config between streamers", () => {
      db.upsertStreamer({ broadcaster_id: 2, kick_username: "u2", access_token: "t", refresh_token: "r" });

      db.saveConfig(1, { items: [{ label: "StreamerA" }] });
      db.saveConfig(2, { items: [{ label: "StreamerB" }] });

      expect(db.getConfig(1).items[0].label).toBe("StreamerA");
      expect(db.getConfig(2).items[0].label).toBe("StreamerB");
    });

    it("saves and loads tiers_json", () => {
      const tiers = [
        { name: "Basic", min_gifts: 5, items: [{ label: "P1", weight: 100 }] },
        { name: "Premium", min_gifts: 25, items: [{ label: "P2", weight: 50 }, { label: "P3", weight: 50 }] },
      ];
      db.saveConfig(1, { items: tiers[0].items, tiers, accent_color: "#abcdef" });

      const loaded = db.getConfig(1);
      expect(loaded.tiers).toHaveLength(2);
      expect(loaded.tiers[0].name).toBe("Basic");
      expect(loaded.tiers[0].min_gifts).toBe(5);
      expect(loaded.tiers[1].name).toBe("Premium");
      expect(loaded.tiers[1].items).toHaveLength(2);
    });

    it("returns null tiers when not set", () => {
      db.saveConfig(1, { items: [{ label: "A" }] });
      const loaded = db.getConfig(1);
      expect(loaded.tiers).toBeNull();
    });

    it("preserves tiers on update without new tiers", () => {
      const tiers = [{ name: "T1", min_gifts: 5, items: [{ label: "X" }] }];
      db.saveConfig(1, { items: [{ label: "X" }], tiers, accent_color: "#111111" });
      db.saveConfig(1, { items: [{ label: "Y" }], accent_color: "#222222" }); // no tiers

      const loaded = db.getConfig(1);
      expect(loaded.tiers).toHaveLength(1);
      expect(loaded.tiers[0].name).toBe("T1");
      expect(loaded.accent_color).toBe("#222222");
    });
  });

  // ── Goals ───────────────────────────────────────────────────────

  describe("goals", () => {
    beforeEach(() => {
      db.upsertStreamer({ broadcaster_id: 1, kick_username: "u", access_token: "t", refresh_token: "r" });
    });

    it("returns empty array for streamer with no goals", () => {
      expect(db.getGoals(1)).toEqual([]);
    });

    it("saves and loads goals", () => {
      db.saveGoals(1, ["Goal 1", "Goal 2"]);
      expect(db.getGoals(1)).toEqual(["Goal 1", "Goal 2"]);
    });

    it("isolates goals between streamers", () => {
      db.upsertStreamer({ broadcaster_id: 2, kick_username: "u2", access_token: "t", refresh_token: "r" });

      db.saveGoals(1, ["A goals"]);
      db.saveGoals(2, ["B goals"]);

      expect(db.getGoals(1)).toEqual(["A goals"]);
      expect(db.getGoals(2)).toEqual(["B goals"]);
    });
  });

  // ── Spin State ──────────────────────────────────────────────────

  describe("spin state", () => {
    beforeEach(() => {
      db.upsertStreamer({ broadcaster_id: 1, kick_username: "u", access_token: "t", refresh_token: "r" });
    });

    it("returns default state for new streamer", () => {
      const state = db.getSpinState(1);
      expect(state.pending_count).toBe(0);
      expect(state.last_spin_time).toBe(0);
      expect(state.spin_in_progress).toBe(0);
    });

    it("saves and loads spin state", () => {
      db.saveSpinState(1, { pending_count: 5, last_spin_time: 1700000000, spin_in_progress: true });

      const state = db.getSpinState(1);
      expect(state.pending_count).toBe(5);
      expect(state.last_spin_time).toBe(1700000000);
      expect(state.spin_in_progress).toBe(1);
    });

    it("lists streamers with pending spins", () => {
      db.upsertStreamer({ broadcaster_id: 2, kick_username: "u2", access_token: "t", refresh_token: "r" });
      db.upsertStreamer({ broadcaster_id: 3, kick_username: "u3", access_token: "t", refresh_token: "r" });

      db.saveSpinState(1, { pending_count: 3, last_spin_time: 0, spin_in_progress: false });
      db.saveSpinState(2, { pending_count: 0, last_spin_time: 0, spin_in_progress: false });
      db.saveSpinState(3, { pending_count: 1, last_spin_time: 0, spin_in_progress: false });

      const pending = db.getStreamersWithPendingSpins();
      expect(pending).toHaveLength(2);
      expect(pending.map((r) => r.broadcaster_id).sort()).toEqual([1, 3]);
    });

    it("isolates spin state between streamers", () => {
      db.upsertStreamer({ broadcaster_id: 2, kick_username: "u2", access_token: "t", refresh_token: "r" });

      db.saveSpinState(1, { pending_count: 10, last_spin_time: 0, spin_in_progress: false });
      db.saveSpinState(2, { pending_count: 0, last_spin_time: 0, spin_in_progress: false });

      expect(db.getSpinState(1).pending_count).toBe(10);
      expect(db.getSpinState(2).pending_count).toBe(0);
    });
  });

  // ── Subscriptions ───────────────────────────────────────────────

  describe("subscriptions", () => {
    beforeEach(() => {
      db.upsertStreamer({ broadcaster_id: 1, kick_username: "u", access_token: "t", refresh_token: "r" });
    });

    it("adds and retrieves subscriptions", () => {
      db.addSubscription(1, {
        subscription_id: "sub_001",
        event_type: "channel.subscription.gifts",
        callback_url: "https://example.com/webhook",
      });

      const subs = db.getActiveSubscriptions(1);
      expect(subs).toHaveLength(1);
      expect(subs[0].subscription_id).toBe("sub_001");
      expect(subs[0].status).toBe("active");
    });

    it("deactivates subscriptions", () => {
      db.addSubscription(1, {
        subscription_id: "sub_001",
        event_type: "channel.subscription.gifts",
        callback_url: "https://example.com/webhook",
      });

      db.deactivateSubscriptions(1);
      expect(db.getActiveSubscriptions(1)).toHaveLength(0);
    });
  });

  // ── Moderators ──────────────────────────────────────────────────

  describe("moderators", () => {
    beforeEach(() => {
      db.upsertStreamer({ broadcaster_id: 10, kick_username: "streamer", access_token: "t", refresh_token: "r" });
      db.upsertStreamer({ broadcaster_id: 20, kick_username: "other", access_token: "t", refresh_token: "r" });
    });

    it("adds and lists moderators", () => {
      db.addModerator(10, { mod_kick_user_id: 99, mod_username: "modguy" });
      const list = db.listModerators(10);
      expect(list).toHaveLength(1);
      expect(list[0].mod_kick_user_id).toBe(99);
      expect(list[0].mod_username).toBe("modguy");
    });

    it("upserts on duplicate and resolves moderatorships", () => {
      db.addModerator(10, { mod_kick_user_id: 99, mod_username: "old" });
      db.addModerator(10, { mod_kick_user_id: 99, mod_username: "new" });
      expect(db.listModerators(10)).toHaveLength(1);
      expect(db.listModerators(10)[0].mod_username).toBe("new");

      db.addModerator(20, { mod_kick_user_id: 99, mod_username: "new" });
      const mods = db.getModeratorships(99);
      expect(mods).toHaveLength(2);
      expect(db.isModerator(10, 99)).toBe(true);
      expect(db.isModerator(10, 1)).toBe(false);
    });

    it("removes a moderator", () => {
      db.addModerator(10, { mod_kick_user_id: 99, mod_username: "modguy" });
      expect(db.removeModerator(10, 99)).toBe(true);
      expect(db.listModerators(10)).toHaveLength(0);
      expect(db.removeModerator(10, 99)).toBe(false);
    });
  });
});
