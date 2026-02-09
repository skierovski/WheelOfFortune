import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { openDatabase, setDb } from "../../src/db.js";
import { loadConfig, saveConfig, loadGoals, saveGoals } from "../../src/services/configStore.js";

describe("configStore (multi-tenant)", () => {
  let db;
  const BID = 100;

  beforeEach(() => {
    db = openDatabase(":memory:");
    setDb(db);
    // Create a test streamer
    db.upsertStreamer({
      broadcaster_id: BID,
      kick_username: "testuser",
      access_token: null,
      refresh_token: null,
    });
  });

  afterEach(() => {
    db.close();
  });

  // ── loadConfig ──────────────────────────────────────────────────

  describe("loadConfig", () => {
    it("returns null when no config exists", () => {
      expect(loadConfig(BID)).toBeNull();
    });

    it("loads config for a streamer", () => {
      db.saveConfig(BID, [{ id: "itm_1", label: "Prize", weight: 100, bonus: false }], "classic");
      const result = loadConfig(BID);
      expect(result.theme).toBe("classic");
      expect(result.items).toHaveLength(1);
      expect(result.items[0].label).toBe("Prize");
    });
  });

  // ── saveConfig ──────────────────────────────────────────────────

  describe("saveConfig", () => {
    it("saves normalized config and returns it", () => {
      const result = saveConfig(BID, [
        { label: "A", weight: 50 },
        { label: "B", weight: 50 },
      ], "classic");
      expect(result.theme).toBe("classic");
      expect(result.items).toHaveLength(2);
      expect(result.items[0].weight + result.items[1].weight).toBe(100);

      // Verify in DB
      const loaded = loadConfig(BID);
      expect(loaded.theme).toBe("classic");
    });

    it("normalizes weights when saving", () => {
      const result = saveConfig(BID, [
        { label: "A", weight: 10 },
        { label: "B", weight: 30 },
      ]);
      const sum = result.items.reduce((s, it) => s + it.weight, 0);
      expect(sum).toBe(100);
    });

    it("preserves previous theme when not provided", () => {
      saveConfig(BID, [{ label: "A", weight: 100 }], "classic");
      saveConfig(BID, [{ label: "A", weight: 100 }]); // no theme
      const loaded = loadConfig(BID);
      expect(loaded.theme).toBe("classic");
    });

    it("isolates config between streamers", () => {
      const BID2 = 200;
      db.upsertStreamer({ broadcaster_id: BID2, kick_username: "u2", access_token: null, refresh_token: null });

      saveConfig(BID, [{ label: "StreamerA" }], "wood");
      saveConfig(BID2, [{ label: "StreamerB" }], "classic");

      expect(loadConfig(BID).items[0].label).toBe("StreamerA");
      expect(loadConfig(BID2).items[0].label).toBe("StreamerB");
    });
  });

  // ── loadGoals ───────────────────────────────────────────────────

  describe("loadGoals", () => {
    it("returns empty array when no goals exist", () => {
      expect(loadGoals(BID)).toEqual([]);
    });

    it("loads goals after saving", () => {
      saveGoals(BID, ["Goal 1", "Goal 2"]);
      expect(loadGoals(BID)).toEqual(["Goal 1", "Goal 2"]);
    });
  });

  // ── saveGoals ───────────────────────────────────────────────────

  describe("saveGoals", () => {
    it("saves goals and returns them", () => {
      const result = saveGoals(BID, ["A", "B", "C"]);
      expect(result).toEqual(["A", "B", "C"]);
    });

    it("converts non-string items to strings", () => {
      const result = saveGoals(BID, [123, true, null]);
      expect(result).toEqual(["123", "true", "null"]);
    });

    it("returns empty array for non-array input", () => {
      expect(saveGoals(BID, "not an array")).toEqual([]);
      expect(saveGoals(BID, null)).toEqual([]);
    });
  });
});
