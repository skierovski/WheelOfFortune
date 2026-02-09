import { describe, it, expect } from "vitest";
import { normalizeItemsInt100 } from "../../src/utils/normalize.js";

describe("normalizeItemsInt100", () => {
  // ── Empty / invalid input ──────────────────────────────────────────

  it("returns empty array for empty input", () => {
    expect(normalizeItemsInt100([])).toEqual([]);
  });

  it("returns empty array for non-array input", () => {
    expect(normalizeItemsInt100(null)).toEqual([]);
    expect(normalizeItemsInt100(undefined)).toEqual([]);
    expect(normalizeItemsInt100("string")).toEqual([]);
    expect(normalizeItemsInt100(42)).toEqual([]);
  });

  // ── Weights always sum to 100 ─────────────────────────────────────

  it("output weights always sum to exactly 100", () => {
    const cases = [
      [{ label: "A", weight: 50 }, { label: "B", weight: 50 }],
      [{ label: "A", weight: 10 }, { label: "B", weight: 20 }, { label: "C", weight: 30 }],
      [{ label: "A", weight: 1 }, { label: "B", weight: 1 }, { label: "C", weight: 1 }],
      [{ label: "A", weight: 33 }, { label: "B", weight: 33 }, { label: "C", weight: 33 }],
      [{ label: "A", weight: 99 }, { label: "B", weight: 1 }],
      [{ label: "A", weight: 1000 }, { label: "B", weight: 1 }],
    ];
    for (const items of cases) {
      const result = normalizeItemsInt100(items);
      const sum = result.reduce((s, it) => s + it.weight, 0);
      expect(sum).toBe(100);
    }
  });

  // ── Single item ───────────────────────────────────────────────────

  it("single item gets weight 100", () => {
    const result = normalizeItemsInt100([{ label: "Only", weight: 42 }]);
    expect(result).toHaveLength(1);
    expect(result[0].weight).toBe(100);
    expect(result[0].label).toBe("Only");
  });

  // ── All-zero weights → equal distribution ─────────────────────────

  it("distributes equally when all weights are zero", () => {
    const result = normalizeItemsInt100([
      { label: "A", weight: 0 },
      { label: "B", weight: 0 },
      { label: "C", weight: 0 },
      { label: "D", weight: 0 },
    ]);
    expect(result).toHaveLength(4);
    const sum = result.reduce((s, it) => s + it.weight, 0);
    expect(sum).toBe(100);
    // Each should be 25
    result.forEach((it) => expect(it.weight).toBe(25));
  });

  it("distributes equally with remainder when all weights are zero (not evenly divisible)", () => {
    const result = normalizeItemsInt100([
      { label: "A", weight: 0 },
      { label: "B", weight: 0 },
      { label: "C", weight: 0 },
    ]);
    expect(result).toHaveLength(3);
    const sum = result.reduce((s, it) => s + it.weight, 0);
    expect(sum).toBe(100);
    // 100 / 3 = 33 remainder 1, so first item gets 34
    expect(result[0].weight).toBe(34);
    expect(result[1].weight).toBe(33);
    expect(result[2].weight).toBe(33);
  });

  // ── Negative weights treated as zero ──────────────────────────────

  it("treats negative weights as zero", () => {
    const result = normalizeItemsInt100([
      { label: "A", weight: -10 },
      { label: "B", weight: -5 },
    ]);
    // Both are effectively zero → equal distribution
    const sum = result.reduce((s, it) => s + it.weight, 0);
    expect(sum).toBe(100);
    expect(result[0].weight).toBe(50);
    expect(result[1].weight).toBe(50);
  });

  // ── Non-numeric weights treated as zero ───────────────────────────

  it("treats non-numeric weights as zero", () => {
    const result = normalizeItemsInt100([
      { label: "A", weight: "abc" },
      { label: "B", weight: null },
      { label: "C", weight: undefined },
    ]);
    const sum = result.reduce((s, it) => s + it.weight, 0);
    expect(sum).toBe(100);
  });

  // ── Every item gets at least weight 1 ─────────────────────────────

  it("ensures minimum weight of 1 for every item", () => {
    const items = [
      { label: "Big", weight: 9999 },
      { label: "Tiny1", weight: 1 },
      { label: "Tiny2", weight: 1 },
      { label: "Tiny3", weight: 1 },
    ];
    const result = normalizeItemsInt100(items);
    result.forEach((it) => {
      expect(it.weight).toBeGreaterThanOrEqual(1);
    });
    const sum = result.reduce((s, it) => s + it.weight, 0);
    expect(sum).toBe(100);
  });

  // ── Proportions roughly preserved ─────────────────────────────────

  it("preserves relative ordering of weights", () => {
    const result = normalizeItemsInt100([
      { label: "Small", weight: 10 },
      { label: "Medium", weight: 30 },
      { label: "Large", weight: 60 },
    ]);
    expect(result[0].weight).toBeLessThanOrEqual(result[1].weight);
    expect(result[1].weight).toBeLessThanOrEqual(result[2].weight);
  });

  // ── Output shape and fields ───────────────────────────────────────

  it("output items have id, label, bonus, weight fields", () => {
    const result = normalizeItemsInt100([
      { label: "Test", weight: 50, bonus: true },
      { label: "Other", weight: 50 },
    ]);
    for (const item of result) {
      expect(item).toHaveProperty("id");
      expect(item).toHaveProperty("label");
      expect(item).toHaveProperty("bonus");
      expect(item).toHaveProperty("weight");
      expect(typeof item.id).toBe("string");
      expect(typeof item.label).toBe("string");
      expect(typeof item.bonus).toBe("boolean");
      expect(typeof item.weight).toBe("number");
    }
  });

  it("preserves existing ids", () => {
    const result = normalizeItemsInt100([
      { id: "my_id_1", label: "A", weight: 50 },
      { id: "my_id_2", label: "B", weight: 50 },
    ]);
    expect(result[0].id).toBe("my_id_1");
    expect(result[1].id).toBe("my_id_2");
  });

  it("generates ids when missing", () => {
    const result = normalizeItemsInt100([
      { label: "A", weight: 50 },
      { label: "B", weight: 50 },
    ]);
    expect(result[0].id).toMatch(/^itm_/);
    expect(result[1].id).toMatch(/^itm_/);
    expect(result[0].id).not.toBe(result[1].id);
  });

  it("trims label whitespace", () => {
    const result = normalizeItemsInt100([
      { label: "  Hello World  ", weight: 100 },
    ]);
    expect(result[0].label).toBe("Hello World");
  });

  it("converts bonus to boolean", () => {
    const result = normalizeItemsInt100([
      { label: "A", weight: 50, bonus: 1 },
      { label: "B", weight: 50, bonus: 0 },
      { label: "C", weight: 50, bonus: "yes" },
      { label: "D", weight: 50 },
    ]);
    expect(result[0].bonus).toBe(true);
    expect(result[1].bonus).toBe(false);
    expect(result[2].bonus).toBe(true);
    expect(result[3].bonus).toBe(false);
  });

  // ── Many items stress test ────────────────────────────────────────

  it("handles many items and still sums to 100", () => {
    const items = Array.from({ length: 50 }, (_, i) => ({
      label: `Item ${i}`,
      weight: Math.floor(Math.random() * 100) + 1,
    }));
    const result = normalizeItemsInt100(items);
    expect(result).toHaveLength(50);
    const sum = result.reduce((s, it) => s + it.weight, 0);
    expect(sum).toBe(100);
    result.forEach((it) => expect(it.weight).toBeGreaterThanOrEqual(1));
  });

  it("handles 100 items (each gets at least 1)", () => {
    const items = Array.from({ length: 100 }, (_, i) => ({
      label: `Item ${i}`,
      weight: 1,
    }));
    const result = normalizeItemsInt100(items);
    expect(result).toHaveLength(100);
    const sum = result.reduce((s, it) => s + it.weight, 0);
    expect(sum).toBe(100);
    result.forEach((it) => expect(it.weight).toBe(1));
  });

  // ── Already-normalized input ──────────────────────────────────────

  it("preserves already-normalized weights that sum to 100", () => {
    const result = normalizeItemsInt100([
      { label: "A", weight: 25 },
      { label: "B", weight: 25 },
      { label: "C", weight: 25 },
      { label: "D", weight: 25 },
    ]);
    expect(result[0].weight).toBe(25);
    expect(result[1].weight).toBe(25);
    expect(result[2].weight).toBe(25);
    expect(result[3].weight).toBe(25);
  });
});
