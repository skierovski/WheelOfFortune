import { describe, expect, it } from "vitest";
import { safeReturnPath } from "../../src/utils/redirects.js";

describe("safeReturnPath", () => {
  it("accepts an internal path with query and hash", () => {
    expect(safeReturnPath("/wheel?step=items#preview")).toBe("/wheel?step=items#preview");
  });

  it.each([
    "https://evil.example",
    "//evil.example/path",
    "/%2f%2fevil.example",
    "/\\evil.example",
    "javascript:alert(1)",
    "dashboard",
  ])("rejects unsafe return target %s", (value) => {
    expect(safeReturnPath(value)).toBe("/dashboard");
  });
});
