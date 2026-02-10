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
      db.saveConfig(BID, { items: [{ id: "itm_1", label: "Prize", weight: 100, bonus: false }], accent_color: "#ff0000" });
      const result = loadConfig(BID);
      expect(result.accent_color).toBe("#ff0000");
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
      ], { accent_color: "#ff0000" });
      expect(result.accent_color).toBe("#ff0000");
      expect(result.items).toHaveLength(2);
      expect(result.items[0].weight + result.items[1].weight).toBe(100);

      // Verify in DB
      const loaded = loadConfig(BID);
      expect(loaded.accent_color).toBe("#ff0000");
    });

    it("normalizes weights when saving", () => {
      const result = saveConfig(BID, [
        { label: "A", weight: 10 },
        { label: "B", weight: 30 },
      ]);
      const sum = result.items.reduce((s, it) => s + it.weight, 0);
      expect(sum).toBe(100);
    });

    it("preserves previous accent_color when not provided", () => {
      saveConfig(BID, [{ label: "A", weight: 100 }], { accent_color: "#ff0000" });
      saveConfig(BID, [{ label: "A", weight: 100 }]); // no accent_color
      const loaded = loadConfig(BID);
      expect(loaded.accent_color).toBe("#ff0000");
    });

    it("isolates config between streamers", () => {
      const BID2 = 200;
      db.upsertStreamer({ broadcaster_id: BID2, kick_username: "u2", access_token: null, refresh_token: null });

      saveConfig(BID, [{ label: "StreamerA" }], { accent_color: "#aaaaaa" });
      saveConfig(BID2, [{ label: "StreamerB" }], { accent_color: "#bbbbbb" });

      expect(loadConfig(BID).items[0].label).toBe("StreamerA");
      expect(loadConfig(BID2).items[0].label).toBe("StreamerB");
    });
  });

  // ── saveTiers ──────────────────────────────────────────────────

  describe("saveTiers", () => {
    it("saves tiers and returns them", () => {
      const result = saveConfig(BID, [], {
        accent_color: "#ff0000",
        tiers: [
          { name: "Basic", min_gifts: 5, items: [{ label: "A", weight: 50 }, { label: "B", weight: 50 }] },
          { name: "Premium", min_gifts: 25, items: [{ label: "C", weight: 100 }] },
        ],
      });
      expect(result.tiers).toHaveLength(2);
      expect(result.tiers[0].name).toBe("Basic");
      expect(result.tiers[0].min_gifts).toBe(5);
      expect(result.tiers[0].items).toHaveLength(2);
      expect(result.tiers[1].name).toBe("Premium");
      expect(result.tiers[1].min_gifts).toBe(25);
    });

    it("normalizes weights within each tier", () => {
      const result = saveConfig(BID, [], {
        tiers: [
          { name: "T1", min_gifts: 5, items: [{ label: "A", weight: 10 }, { label: "B", weight: 30 }] },
        ],
      });
      const sum = result.tiers[0].items.reduce((s, it) => s + it.weight, 0);
      expect(sum).toBe(100);
    });

    it("sorts tiers by min_gifts ascending", () => {
      const result = saveConfig(BID, [], {
        tiers: [
          { name: "High", min_gifts: 50, items: [{ label: "X", weight: 100 }] },
          { name: "Low", min_gifts: 5, items: [{ label: "Y", weight: 100 }] },
        ],
      });
      expect(result.tiers[0].min_gifts).toBe(5);
      expect(result.tiers[1].min_gifts).toBe(50);
    });

    it("sets items_json from first tier for backward compat", () => {
      const result = saveConfig(BID, [], {
        tiers: [
          { name: "T1", min_gifts: 5, items: [{ label: "First", weight: 100 }] },
          { name: "T2", min_gifts: 25, items: [{ label: "Second", weight: 100 }] },
        ],
      });
      // items (backward compat) should be from the first (lowest) tier
      expect(result.items[0].label).toBe("First");
    });

    it("loads tiers back from DB", () => {
      saveConfig(BID, [], {
        accent_color: "#aabbcc",
        tiers: [
          { name: "A", min_gifts: 3, items: [{ label: "P1", weight: 100 }] },
          { name: "B", min_gifts: 10, items: [{ label: "P2", weight: 50 }, { label: "P3", weight: 50 }] },
        ],
      });
      const loaded = loadConfig(BID);
      expect(loaded.tiers).toHaveLength(2);
      expect(loaded.tiers[0].name).toBe("A");
      expect(loaded.tiers[1].items).toHaveLength(2);
      expect(loaded.accent_color).toBe("#aabbcc");
    });

    it("returns null tiers when none are set", () => {
      saveConfig(BID, [{ label: "X", weight: 100 }]);
      const loaded = loadConfig(BID);
      expect(loaded.tiers).toBeNull();
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
