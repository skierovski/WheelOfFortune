import { describe, it, expect } from "vitest";
import { validateWheelItems, validateTheme, isValidOverlayKey } from "../../src/utils/validate.js";

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

describe("validateTheme", () => {
  it("accepts 'wood'", () => {
    expect(validateTheme("wood")).toBe("wood");
  });

  it("accepts 'classic'", () => {
    expect(validateTheme("classic")).toBe("classic");
  });

  it("defaults to 'wood' for invalid theme", () => {
    expect(validateTheme("hacker")).toBe("wood");
    expect(validateTheme("")).toBe("wood");
    expect(validateTheme(null)).toBe("wood");
    expect(validateTheme(undefined)).toBe("wood");
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
