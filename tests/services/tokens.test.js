import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { openDatabase, setDb } from "../../src/db.js";
import { encrypt } from "../../src/utils/crypto.js";

const ENCRYPTION_KEY = "test_encryption_key_for_tokens";
const BID = 100;

// Mock env
vi.mock("../../src/utils/env.js", () => ({
  env: {
    ENCRYPTION_KEY: "test_encryption_key_for_tokens",
    KICK_CLIENT_ID: "test_client_id",
    KICK_CLIENT_SECRET: "test_client_secret",
    KICK_OAUTH_HOST: "https://id.kick.com",
    mask: (v) => {
      if (!v || typeof v !== "string" || v.length <= 8) return v;
      return v.slice(0, 4) + "..." + v.slice(-4);
    },
  },
}));

describe("tokenStore (multi-tenant)", () => {
  let db;

  beforeEach(() => {
    db = openDatabase(":memory:");
    setDb(db);
  });

  afterEach(() => {
    db.close();
  });

  function createStreamerWithTokens(bid, accessToken, refreshToken, expiresAt) {
    db.upsertStreamer({
      broadcaster_id: bid,
      kick_username: "user",
      access_token: accessToken ? encrypt(accessToken, ENCRYPTION_KEY) : null,
      refresh_token: refreshToken ? encrypt(refreshToken, ENCRYPTION_KEY) : null,
      token_expires_at: expiresAt ?? null,
      token_scope: "user:read",
    });
  }

  describe("loadTokens", () => {
    it("returns null when streamer has no tokens", async () => {
      db.upsertStreamer({ broadcaster_id: BID, kick_username: "u", access_token: null, refresh_token: null });
      const { loadTokens } = await import("../../src/services/tokens.js");
      expect(loadTokens(BID)).toBeNull();
    });

    it("loads and decrypts tokens", async () => {
      createStreamerWithTokens(BID, "at_123456789", "rt_abcdefghi", Date.now() + 3600_000);
      const { loadTokens } = await import("../../src/services/tokens.js");
      const loaded = loadTokens(BID);
      expect(loaded.access_token).toBe("at_123456789");
      expect(loaded.refresh_token).toBe("rt_abcdefghi");
    });

    it("returns null for nonexistent streamer", async () => {
      const { loadTokens } = await import("../../src/services/tokens.js");
      expect(loadTokens(9999)).toBeNull();
    });
  });

  describe("saveTokens", () => {
    it("saves encrypted tokens to DB", async () => {
      db.upsertStreamer({ broadcaster_id: BID, kick_username: "u", access_token: null, refresh_token: null });
      const { saveTokens, loadTokens } = await import("../../src/services/tokens.js");
      saveTokens(BID, {
        access_token: "new_at_12345",
        refresh_token: "new_rt_67890",
        expires_in: 3600,
        scope: "user:read",
      });

      const loaded = loadTokens(BID);
      expect(loaded.access_token).toBe("new_at_12345");
      expect(loaded.refresh_token).toBe("new_rt_67890");
    });

    it("tokens are stored encrypted in DB (not plaintext)", async () => {
      db.upsertStreamer({ broadcaster_id: BID, kick_username: "u", access_token: null, refresh_token: null });
      const { saveTokens } = await import("../../src/services/tokens.js");
      saveTokens(BID, {
        access_token: "plaintext_token_abc",
        refresh_token: "plaintext_refresh_xyz",
      });

      // Read raw from DB
      const raw = db.getStreamerById(BID);
      expect(raw.access_token).not.toBe("plaintext_token_abc");
      expect(raw.refresh_token).not.toBe("plaintext_refresh_xyz");
      // But they should be non-null (encrypted)
      expect(raw.access_token).toBeTruthy();
      expect(raw.refresh_token).toBeTruthy();
    });
  });

  describe("withExpiresAt", () => {
    it("computes expires_at from expires_in with 15-minute skew", async () => {
      const { tokenStore } = await import("../../src/services/tokens.js");
      const now = Date.now();
      const tokens = { access_token: "at", expires_in: 3600 };
      const result = tokenStore.withExpiresAt(tokens);

      const skewMs = 60_000 * 15;
      const expected = now + 3600 * 1000 - skewMs;
      expect(Math.abs(result.expires_at - expected)).toBeLessThan(1000);
    });

    it("returns null for null input", async () => {
      const { tokenStore } = await import("../../src/services/tokens.js");
      expect(tokenStore.withExpiresAt(null)).toBeNull();
    });
  });
});

describe("ensureAccessToken (multi-tenant)", () => {
  let db;

  beforeEach(() => {
    db = openDatabase(":memory:");
    setDb(db);
  });

  afterEach(() => {
    db.close();
    vi.restoreAllMocks();
  });

  function createStreamerWithTokens(bid, accessToken, refreshToken, expiresAt) {
    db.upsertStreamer({
      broadcaster_id: bid,
      kick_username: "user",
      access_token: accessToken ? encrypt(accessToken, ENCRYPTION_KEY) : null,
      refresh_token: refreshToken ? encrypt(refreshToken, ENCRYPTION_KEY) : null,
      token_expires_at: expiresAt ?? null,
    });
  }

  it("returns existing access_token when not expired", async () => {
    createStreamerWithTokens(BID, "valid_token_123456", "rt", Date.now() + 3600_000);
    const { ensureAccessToken } = await import("../../src/services/tokens.js");
    const token = await ensureAccessToken(BID);
    expect(token).toBe("valid_token_123456");
  });

  it("throws when no tokens exist for broadcaster", async () => {
    db.upsertStreamer({ broadcaster_id: BID, kick_username: "u", access_token: null, refresh_token: null });
    const { ensureAccessToken } = await import("../../src/services/tokens.js");
    await expect(ensureAccessToken(BID)).rejects.toThrow("No tokens stored");
  });

  it("refreshes when token is expiring soon", async () => {
    createStreamerWithTokens(BID, "old_token_abcdefgh", "my_refresh_token", Date.now() + 60_000);

    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      text: () => Promise.resolve(JSON.stringify({
        access_token: "new_token_xyz12345",
        refresh_token: "new_refresh_token",
        expires_in: 3600,
      })),
    }));

    const { ensureAccessToken } = await import("../../src/services/tokens.js");
    const token = await ensureAccessToken(BID);
    expect(token).toBe("new_token_xyz12345");
    expect(fetch).toHaveBeenCalledOnce();
  });

  it("throws when refresh is needed but no refresh_token", async () => {
    createStreamerWithTokens(BID, "old_token_abcdefgh", null, Date.now() - 60_000);
    // Manually fix: the streamer was created with null refresh, but the encrypt would also be null
    // Let's create properly
    db.raw.prepare("UPDATE streamers SET token_expires_at = ? WHERE broadcaster_id = ?").run(Date.now() - 60_000, BID);

    const { ensureAccessToken } = await import("../../src/services/tokens.js");
    await expect(ensureAccessToken(BID)).rejects.toThrow("No refresh_token");
  });
});
