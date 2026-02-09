import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

describe("env", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    // Reset module registry so env.js re-reads process.env
    vi.resetModules();
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it("reads PORT from process.env", async () => {
    process.env.PORT = "4000";
    const { env } = await import("../../src/utils/env.js");
    expect(env.PORT_HTTP).toBe(4000);
  });

  it("defaults PORT to 3000", async () => {
    delete process.env.PORT;
    const { env } = await import("../../src/utils/env.js");
    expect(env.PORT_HTTP).toBe(3000);
  });

  it("reads KICK_CLIENT_ID from process.env", async () => {
    process.env.KICK_CLIENT_ID = "my_client_id";
    const { env } = await import("../../src/utils/env.js");
    expect(env.KICK_CLIENT_ID).toBe("my_client_id");
  });

  it("defaults KICK_CLIENT_ID to empty string", async () => {
    delete process.env.KICK_CLIENT_ID;
    const { env } = await import("../../src/utils/env.js");
    expect(env.KICK_CLIENT_ID).toBe("");
  });

  it("reads PUBLIC_BASE_URL and trims it", async () => {
    process.env.PUBLIC_BASE_URL = "  https://example.com  ";
    const { env } = await import("../../src/utils/env.js");
    expect(env.PUBLIC_BASE_URL).toBe("https://example.com");
  });

  it("reads DEV_BYPASS_AUTH as boolean", async () => {
    process.env.DEV_BYPASS_AUTH = "1";
    const { env } = await import("../../src/utils/env.js");
    expect(env.DEV_BYPASS_AUTH).toBe(true);
  });

  it("DEV_BYPASS_AUTH is false when not '1'", async () => {
    process.env.DEV_BYPASS_AUTH = "0";
    const { env } = await import("../../src/utils/env.js");
    expect(env.DEV_BYPASS_AUTH).toBe(false);
  });

  it("parses DEV_BYPASS_IPS as array", async () => {
    process.env.DEV_BYPASS_IPS = "1.2.3.4, 5.6.7.8, 9.10.11.12";
    const { env } = await import("../../src/utils/env.js");
    expect(env.DEV_BYPASS_IPS).toEqual(["1.2.3.4", "5.6.7.8", "9.10.11.12"]);
  });

  it("DEV_BYPASS_IPS is empty array when not set", async () => {
    delete process.env.DEV_BYPASS_IPS;
    const { env } = await import("../../src/utils/env.js");
    expect(env.DEV_BYPASS_IPS).toEqual([]);
  });

  it("WEBHOOK_SECRET prefers KICK_WEBHOOK_SECRET", async () => {
    process.env.KICK_WEBHOOK_SECRET = "kick_secret";
    process.env.WEBHOOK_SECRET = "other_secret";
    const { env } = await import("../../src/utils/env.js");
    expect(env.WEBHOOK_SECRET).toBe("kick_secret");
  });

  it("WEBHOOK_SECRET falls back to WEBHOOK_SECRET env", async () => {
    delete process.env.KICK_WEBHOOK_SECRET;
    process.env.WEBHOOK_SECRET = "fallback_secret";
    const { env } = await import("../../src/utils/env.js");
    expect(env.WEBHOOK_SECRET).toBe("fallback_secret");
  });

  it("TRIGGER_KEY falls back to ADMIN_KEY", async () => {
    delete process.env.TRIGGER_KEY;
    process.env.ADMIN_KEY = "admin123";
    const { env } = await import("../../src/utils/env.js");
    expect(env.TRIGGER_KEY).toBe("admin123");
  });

  describe("mask()", () => {
    it("masks middle of long strings", async () => {
      const { env } = await import("../../src/utils/env.js");
      expect(env.mask("abcdefghijkl")).toBe("abcd...ijkl");
    });

    it("does not mask short strings (8 chars or less)", async () => {
      const { env } = await import("../../src/utils/env.js");
      expect(env.mask("abcdefgh")).toBe("abcdefgh");
    });

    it("returns non-string values as-is", async () => {
      const { env } = await import("../../src/utils/env.js");
      expect(env.mask(null)).toBeNull();
      expect(env.mask(undefined)).toBeUndefined();
      expect(env.mask("")).toBe("");
    });
  });
});
