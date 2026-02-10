import { describe, it, expect } from "vitest";
import { validateWheelItems, validateTiers, isValidOverlayKey, validateGiftsPerSpin, validateAccentColor } from "../../src/utils/validate.js";

describe("validateWheelItems", () => {
  it("accepts valid items", () => {
    const result = validateWheelItems([
      { label: "Prize 1", weight: 50, bonus: false },
      { label: "Prize 2", weight: 50, bonus: true },
    ]);
    expect(result.valid).toBe(true);
    expect(result.items).toHaveLength(2);
  });

  it("rejects non-array input", () => {
    expect(validateWheelItems(null).valid).toBe(false);
    expect(validateWheelItems("string").valid).toBe(false);
    expect(validateWheelItems(42).valid).toBe(false);
  });

  it("rejects empty array", () => {
    expect(validateWheelItems([]).valid).toBe(false);
  });

  it("rejects more than 100 items", () => {
    const items = Array.from({ length: 101 }, (_, i) => ({ label: `Item ${i}`, weight: 1 }));
    expect(validateWheelItems(items).valid).toBe(false);
  });

  it("strips HTML from labels", () => {
    const result = validateWheelItems([
      { label: '<script>alert("xss")</script>Prize', weight: 50 },
    ]);
    expect(result.valid).toBe(true);
    expect(result.items[0].label).toBe('alert("xss")Prize');
  });

  it("truncates labels to 100 chars", () => {
    const result = validateWheelItems([
      { label: "A".repeat(200), weight: 50 },
    ]);
    expect(result.valid).toBe(true);
    expect(result.items[0].label.length).toBe(100);
  });

  it("rejects items with empty labels after sanitization", () => {
    const result = validateWheelItems([{ label: "<b></b>", weight: 50 }]);
    expect(result.valid).toBe(false);
  });

  it("clamps negative weights to 0", () => {
    const result = validateWheelItems([{ label: "Test", weight: -10 }]);
    expect(result.valid).toBe(true);
    expect(result.items[0].weight).toBe(0);
  });

  it("converts bonus to boolean", () => {
    const result = validateWheelItems([
      { label: "A", weight: 50, bonus: 1 },
      { label: "B", weight: 50, bonus: undefined },
    ]);
    expect(result.items[0].bonus).toBe(true);
    expect(result.items[1].bonus).toBe(false);
  });
});

describe("validateAccentColor", () => {
  it("accepts valid hex colors", () => {
    expect(validateAccentColor("#ff0000")).toBe("#ff0000");
    expect(validateAccentColor("#7c3aed")).toBe("#7c3aed");
    expect(validateAccentColor("#AABBCC")).toBe("#AABBCC");
  });

  it("defaults for invalid input", () => {
    expect(validateAccentColor("red")).toBe("#7c3aed");
    expect(validateAccentColor("#fff")).toBe("#7c3aed");
    expect(validateAccentColor("")).toBe("#7c3aed");
    expect(validateAccentColor(null)).toBe("#7c3aed");
    expect(validateAccentColor(undefined)).toBe("#7c3aed");
  });
});

describe("validateGiftsPerSpin", () => {
  it("accepts valid numbers", () => {
    expect(validateGiftsPerSpin(1)).toBe(1);
    expect(validateGiftsPerSpin(5)).toBe(5);
    expect(validateGiftsPerSpin(100)).toBe(100);
  });

  it("clamps to range 1-100", () => {
    expect(validateGiftsPerSpin(0)).toBe(1);
    expect(validateGiftsPerSpin(-5)).toBe(1);
    expect(validateGiftsPerSpin(200)).toBe(100);
  });

  it("rounds floats", () => {
    expect(validateGiftsPerSpin(3.7)).toBe(4);
  });

  it("defaults to 5 for non-numeric input", () => {
    expect(validateGiftsPerSpin(null)).toBe(5);
    expect(validateGiftsPerSpin(undefined)).toBe(5);
    expect(validateGiftsPerSpin("abc")).toBe(5);
  });
});

describe("validateTiers", () => {
  const validItems = [
    { label: "Prize A", weight: 50, bonus: false },
    { label: "Prize B", weight: 50, bonus: false },
  ];

  it("accepts valid tiers", () => {
    const result = validateTiers([
      { name: "Basic", min_gifts: 5, items: validItems },
      { name: "Premium", min_gifts: 25, items: validItems },
    ]);
    expect(result.valid).toBe(true);
    expect(result.tiers).toHaveLength(2);
    expect(result.tiers[0].name).toBe("Basic");
    expect(result.tiers[1].name).toBe("Premium");
  });

  it("sorts tiers by min_gifts ascending", () => {
    const result = validateTiers([
      { name: "High", min_gifts: 50, items: validItems },
      { name: "Low", min_gifts: 5, items: validItems },
      { name: "Mid", min_gifts: 25, items: validItems },
    ]);
    expect(result.valid).toBe(true);
    expect(result.tiers[0].min_gifts).toBe(5);
    expect(result.tiers[1].min_gifts).toBe(25);
    expect(result.tiers[2].min_gifts).toBe(50);
  });

  it("rejects non-array input", () => {
    expect(validateTiers(null).valid).toBe(false);
    expect(validateTiers("string").valid).toBe(false);
    expect(validateTiers(42).valid).toBe(false);
  });

  it("rejects empty array", () => {
    expect(validateTiers([]).valid).toBe(false);
  });

  it("rejects more than 10 tiers", () => {
    const tiers = Array.from({ length: 11 }, (_, i) => ({
      name: `Tier ${i}`, min_gifts: i + 1, items: validItems,
    }));
    expect(validateTiers(tiers).valid).toBe(false);
  });

  it("rejects duplicate tier names (case insensitive)", () => {
    const result = validateTiers([
      { name: "Basic", min_gifts: 5, items: validItems },
      { name: "basic", min_gifts: 25, items: validItems },
    ]);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("Duplicate");
  });

  it("rejects tiers with invalid min_gifts", () => {
    expect(validateTiers([{ name: "X", min_gifts: 0, items: validItems }]).valid).toBe(false);
    expect(validateTiers([{ name: "X", min_gifts: -5, items: validItems }]).valid).toBe(false);
    expect(validateTiers([{ name: "X", min_gifts: 2000, items: validItems }]).valid).toBe(false);
    expect(validateTiers([{ name: "X", min_gifts: "abc", items: validItems }]).valid).toBe(false);
  });

  it("rejects tiers with invalid items", () => {
    const result = validateTiers([
      { name: "Bad", min_gifts: 5, items: [] },
    ]);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("items");
  });

  it("rejects tiers with empty name", () => {
    const result = validateTiers([
      { name: "<b></b>", min_gifts: 5, items: validItems },
    ]);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("name");
  });

  it("strips HTML from tier names", () => {
    const result = validateTiers([
      { name: '<script>xss</script>Basic', min_gifts: 5, items: validItems },
    ]);
    expect(result.valid).toBe(true);
    expect(result.tiers[0].name).toBe("xssBasic");
  });

  it("truncates tier names to 50 chars", () => {
    const result = validateTiers([
      { name: "A".repeat(100), min_gifts: 5, items: validItems },
    ]);
    expect(result.valid).toBe(true);
    expect(result.tiers[0].name.length).toBe(50);
  });

  it("defaults tier name when missing", () => {
    const result = validateTiers([
      { min_gifts: 5, items: validItems },
    ]);
    expect(result.valid).toBe(true);
    expect(result.tiers[0].name).toBe("Tier 1");
  });

  it("validates items within each tier", () => {
    const result = validateTiers([
      { name: "Good", min_gifts: 5, items: validItems },
      { name: "Bad", min_gifts: 25, items: [{ label: "", weight: 50 }] },
    ]);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("Bad");
  });
});

describe("isValidOverlayKey", () => {
  it("accepts valid 24-char base64url keys", () => {
    expect(isValidOverlayKey("abcdefghijklmnopqrstuvwx")).toBe(true);
    expect(isValidOverlayKey("ABCDEFghij1234567890_-ab")).toBe(true);
  });

  it("rejects too-short keys", () => {
    expect(isValidOverlayKey("short")).toBe(false);
  });

  it("rejects too-long keys", () => {
    expect(isValidOverlayKey("a".repeat(31))).toBe(false);
  });

  it("rejects keys with special characters", () => {
    expect(isValidOverlayKey("abc def ghi jkl mno pqr st")).toBe(false);
    expect(isValidOverlayKey("abc!@#$%^&*()12345678901")).toBe(false);
  });

  it("rejects non-string input", () => {
    expect(isValidOverlayKey(null)).toBe(false);
    expect(isValidOverlayKey(12345)).toBe(false);
  });
});
