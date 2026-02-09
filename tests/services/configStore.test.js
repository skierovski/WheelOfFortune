import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "fs";
import path from "path";
import os from "os";

describe("configStore", () => {
  let tmpDir;
  let cfgPath;
  let goalsPath;

  beforeEach(() => {
    vi.resetModules();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "wof-test-"));
    cfgPath = path.join(tmpDir, "wheel.json");
    goalsPath = path.join(tmpDir, "goals.json");
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  async function getConfigStore() {
    // Mock env to use temp paths
    vi.doMock("../../src/utils/env.js", () => ({
      env: {
        CFG_PATH: cfgPath,
        GOALS_PATH: goalsPath,
      },
    }));
    return import("../../src/services/configStore.js");
  }

  // ── loadConfig ──────────────────────────────────────────────────

  describe("loadConfig", () => {
    it("returns null when config file does not exist", async () => {
      const { loadConfig } = await getConfigStore();
      expect(loadConfig()).toBeNull();
    });

    it("loads config from disk", async () => {
      const data = {
        items: [{ id: "itm_1", label: "Prize", weight: 100, bonus: false }],
        theme: "classic",
      };
      fs.writeFileSync(cfgPath, JSON.stringify(data));
      const { loadConfig } = await getConfigStore();
      const result = loadConfig();
      expect(result.theme).toBe("classic");
      expect(result.items).toHaveLength(1);
      expect(result.items[0].label).toBe("Prize");
    });

    it("returns null for corrupted JSON", async () => {
      fs.writeFileSync(cfgPath, "not valid json{{{");
      const { loadConfig } = await getConfigStore();
      expect(loadConfig()).toBeNull();
    });

    it("defaults theme to 'wood' if missing", async () => {
      fs.writeFileSync(cfgPath, JSON.stringify({ items: [] }));
      const { loadConfig } = await getConfigStore();
      const result = loadConfig();
      expect(result.theme).toBe("wood");
    });
  });

  // ── saveConfig ──────────────────────────────────────────────────

  describe("saveConfig", () => {
    it("saves config to disk and returns normalized items", async () => {
      const { saveConfig } = await getConfigStore();
      const result = saveConfig(
        [
          { label: "A", weight: 50 },
          { label: "B", weight: 50 },
        ],
        "classic"
      );
      expect(result.theme).toBe("classic");
      expect(result.items).toHaveLength(2);
      expect(result.items[0].weight + result.items[1].weight).toBe(100);

      // Verify file was written
      const onDisk = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
      expect(onDisk.theme).toBe("classic");
      expect(onDisk.items).toHaveLength(2);
    });

    it("normalizes weights when saving", async () => {
      const { saveConfig } = await getConfigStore();
      const result = saveConfig([
        { label: "A", weight: 10 },
        { label: "B", weight: 30 },
      ]);
      const sum = result.items.reduce((s, it) => s + it.weight, 0);
      expect(sum).toBe(100);
    });

    it("preserves previous theme when not provided", async () => {
      const { saveConfig, loadConfig } = await getConfigStore();
      saveConfig([{ label: "A", weight: 100 }], "classic");
      saveConfig([{ label: "A", weight: 100 }]); // no theme
      const loaded = loadConfig();
      expect(loaded.theme).toBe("classic");
    });

    it("creates directory if it does not exist", async () => {
      const deepPath = path.join(tmpDir, "sub", "dir", "wheel.json");
      vi.resetModules();
      vi.doMock("../../src/utils/env.js", () => ({
        env: { CFG_PATH: deepPath, GOALS_PATH: goalsPath },
      }));
      const { saveConfig } = await import("../../src/services/configStore.js");
      saveConfig([{ label: "A", weight: 100 }], "wood");
      expect(fs.existsSync(deepPath)).toBe(true);
    });
  });

  // ── loadGoals ───────────────────────────────────────────────────

  describe("loadGoals", () => {
    it("returns empty array when file does not exist", async () => {
      const { loadGoals } = await getConfigStore();
      expect(loadGoals()).toEqual([]);
    });

    it("loads goals from disk", async () => {
      fs.writeFileSync(goalsPath, JSON.stringify(["Goal 1", "Goal 2"]));
      const { loadGoals } = await getConfigStore();
      expect(loadGoals()).toEqual(["Goal 1", "Goal 2"]);
    });

    it("returns empty array for corrupted JSON", async () => {
      fs.writeFileSync(goalsPath, "broken{{{");
      const { loadGoals } = await getConfigStore();
      expect(loadGoals()).toEqual([]);
    });

    it("returns empty array if stored value is not an array", async () => {
      fs.writeFileSync(goalsPath, JSON.stringify({ not: "array" }));
      const { loadGoals } = await getConfigStore();
      expect(loadGoals()).toEqual([]);
    });
  });

  // ── saveGoals ───────────────────────────────────────────────────

  describe("saveGoals", () => {
    it("saves goals to disk", async () => {
      const { saveGoals } = await getConfigStore();
      const result = saveGoals(["A", "B", "C"]);
      expect(result).toEqual(["A", "B", "C"]);

      const onDisk = JSON.parse(fs.readFileSync(goalsPath, "utf8"));
      expect(onDisk).toEqual(["A", "B", "C"]);
    });

    it("converts non-string items to strings", async () => {
      const { saveGoals } = await getConfigStore();
      const result = saveGoals([123, true, null]);
      expect(result).toEqual(["123", "true", "null"]);
    });

    it("returns empty array for non-array input", async () => {
      const { saveGoals } = await getConfigStore();
      expect(saveGoals("not an array")).toEqual([]);
      expect(saveGoals(null)).toEqual([]);
    });
  });
});
