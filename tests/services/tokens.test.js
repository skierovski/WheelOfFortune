import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "fs";
import path from "path";
import os from "os";

describe("tokenStore", () => {
  let tmpDir;
  let tokPath;

  beforeEach(() => {
    vi.resetModules();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "wof-tok-test-"));
    tokPath = path.join(tmpDir, "tokens.json");
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  async function getTokenStore() {
    vi.doMock("../../src/utils/env.js", () => ({
      env: {
        TOK_PATH: tokPath,
        KICK_CLIENT_ID: "test_client_id",
        KICK_CLIENT_SECRET: "test_client_secret",
        KICK_OAUTH_HOST: "https://id.kick.com",
        mask: (v) => {
          if (!v || typeof v !== "string" || v.length <= 8) return v;
          return v.slice(0, 4) + "..." + v.slice(-4);
        },
      },
    }));
    const mod = await import("../../src/services/tokens.js");
    return mod.tokenStore;
  }

  // ── loadTokens ──────────────────────────────────────────────────

  describe("loadTokens", () => {
    it("returns null when file does not exist", async () => {
      const store = await getTokenStore();
      expect(store.loadTokens()).toBeNull();
    });

    it("loads tokens from disk", async () => {
      const data = {
        access_token: "at_123",
        refresh_token: "rt_456",
        expires_at: Date.now() + 3600_000,
      };
      fs.writeFileSync(tokPath, JSON.stringify(data));
      const store = await getTokenStore();
      const loaded = store.loadTokens();
      expect(loaded.access_token).toBe("at_123");
      expect(loaded.refresh_token).toBe("rt_456");
    });

    it("returns null for corrupted file", async () => {
      fs.writeFileSync(tokPath, "not json!!!{");
      const store = await getTokenStore();
      expect(store.loadTokens()).toBeNull();
    });
  });

  // ── saveTokens ──────────────────────────────────────────────────

  describe("saveTokens", () => {
    it("saves tokens to disk", async () => {
      const store = await getTokenStore();
      const tokens = {
        access_token: "at_abc",
        refresh_token: "rt_def",
        expires_at: 1700000000000,
        scope: "user:read",
      };
      store.saveTokens(tokens);

      const onDisk = JSON.parse(fs.readFileSync(tokPath, "utf8"));
      expect(onDisk.access_token).toBe("at_abc");
      expect(onDisk.refresh_token).toBe("rt_def");
      expect(onDisk.expires_at).toBe(1700000000000);
    });

    it("overwrites existing tokens", async () => {
      const store = await getTokenStore();
      store.saveTokens({ access_token: "first", refresh_token: "r1" });
      store.saveTokens({ access_token: "second", refresh_token: "r2" });

      const onDisk = JSON.parse(fs.readFileSync(tokPath, "utf8"));
      expect(onDisk.access_token).toBe("second");
    });
  });

  // ── withExpiresAt ──────────────────────────────────────────────

  describe("withExpiresAt", () => {
    it("computes expires_at from expires_in with 15-minute skew", async () => {
      const store = await getTokenStore();
      const now = Date.now();
      const tokens = { access_token: "at", expires_in: 3600 }; // 1 hour
      const result = store.withExpiresAt(tokens);

      const skewMs = 60_000 * 15;
      const expected = now + 3600 * 1000 - skewMs;
      // Allow 1 second tolerance for test execution time
      expect(Math.abs(result.expires_at - expected)).toBeLessThan(1000);
    });

    it("returns null for null input", async () => {
      const store = await getTokenStore();
      expect(store.withExpiresAt(null)).toBeNull();
    });

    it("does not set expires_at if expires_in is not a number", async () => {
      const store = await getTokenStore();
      const tokens = { access_token: "at" };
      const result = store.withExpiresAt(tokens);
      expect(result.expires_at).toBeUndefined();
    });
  });
});

describe("ensureAccessToken", () => {
  let tmpDir;
  let tokPath;

  beforeEach(() => {
    vi.resetModules();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "wof-eat-test-"));
    tokPath = path.join(tmpDir, "tokens.json");
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  async function setup(tokensOnDisk, fetchResponse) {
    vi.doMock("../../src/utils/env.js", () => ({
      env: {
        TOK_PATH: tokPath,
        KICK_CLIENT_ID: "test_client_id",
        KICK_CLIENT_SECRET: "test_client_secret",
        KICK_OAUTH_HOST: "https://id.kick.com",
        mask: (v) => {
          if (!v || typeof v !== "string" || v.length <= 8) return v;
          return v.slice(0, 4) + "..." + v.slice(-4);
        },
      },
    }));

    if (tokensOnDisk) {
      fs.writeFileSync(tokPath, JSON.stringify(tokensOnDisk));
    }

    if (fetchResponse) {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue({
          ok: true,
          text: () => Promise.resolve(JSON.stringify(fetchResponse)),
        })
      );
    }

    const mod = await import("../../src/services/tokens.js");
    return mod.ensureAccessToken;
  }

  it("returns existing access_token when not expired", async () => {
    const ensureAccessToken = await setup({
      access_token: "valid_token_123456",
      refresh_token: "rt",
      expires_at: Date.now() + 3600_000, // 1 hour from now
    });

    const token = await ensureAccessToken();
    expect(token).toBe("valid_token_123456");
  });

  it("throws when no tokens exist", async () => {
    const ensureAccessToken = await setup(null);
    await expect(ensureAccessToken()).rejects.toThrow("No tokens stored");
  });

  it("refreshes when token is expiring soon", async () => {
    const ensureAccessToken = await setup(
      {
        access_token: "old_token_abcdefgh",
        refresh_token: "my_refresh_token",
        expires_at: Date.now() + 60_000, // 1 minute from now (< 15 min threshold)
      },
      {
        access_token: "new_token_xyz12345",
        refresh_token: "new_refresh",
        expires_in: 3600,
      }
    );

    const token = await ensureAccessToken();
    expect(token).toBe("new_token_xyz12345");
    expect(fetch).toHaveBeenCalledOnce();
  });

  it("refreshes when token is already expired", async () => {
    const ensureAccessToken = await setup(
      {
        access_token: "expired_token_abc",
        refresh_token: "my_refresh_token",
        expires_at: Date.now() - 60_000, // expired 1 minute ago
      },
      {
        access_token: "fresh_token_12345",
        refresh_token: "new_refresh",
        expires_in: 3600,
      }
    );

    const token = await ensureAccessToken();
    expect(token).toBe("fresh_token_12345");
  });

  it("throws when refresh is needed but no refresh_token", async () => {
    const ensureAccessToken = await setup({
      access_token: "old_token_abcdefgh",
      expires_at: Date.now() - 60_000,
      // no refresh_token
    });

    await expect(ensureAccessToken()).rejects.toThrow("No refresh_token");
  });

  it("saves refreshed tokens to disk", async () => {
    const ensureAccessToken = await setup(
      {
        access_token: "old_token_abcdefgh",
        refresh_token: "my_refresh_token",
        expires_at: Date.now() - 1000,
      },
      {
        access_token: "saved_new_token_ab",
        refresh_token: "saved_new_refresh",
        expires_in: 7200,
      }
    );

    await ensureAccessToken();
    const saved = JSON.parse(fs.readFileSync(tokPath, "utf8"));
    expect(saved.access_token).toBe("saved_new_token_ab");
    expect(saved.refresh_token).toBe("saved_new_refresh");
  });
});
