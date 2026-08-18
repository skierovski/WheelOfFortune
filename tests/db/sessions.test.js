import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { openDatabase } from "../../src/db.js";

describe("server-side sessions", () => {
  let db;
  beforeEach(() => { db = openDatabase(":memory:"); });
  afterEach(() => db.close());

  function addStreamer(id) {
    db.upsertStreamer({ broadcaster_id: id, kick_username: `user${id}`, display_name: `User ${id}` });
  }

  it("stores, resolves and revokes an opaque session hash", () => {
    addStreamer(100);
    db.createSession({ token_hash: "hash-one", broadcaster_id: 100, csrf_secret: "csrf", created_at: 1000, last_seen_at: 1000, expires_at: 2000, user_agent: null, ip_hash: null });
    expect(db.getSession("hash-one", 1500)?.broadcaster_id).toBe(100);
    expect(db.revokeSession("hash-one", 1600)).toBe(true);
    expect(db.getSession("hash-one", 1700)).toBeNull();
  });

  it("isolates session listing and supports logout-all", () => {
    addStreamer(100); addStreamer(200);
    for (const [hash, bid] of [["a",100],["b",100],["c",200]]) {
      db.createSession({ token_hash: hash, broadcaster_id: bid, csrf_secret: "csrf", created_at: 1000, last_seen_at: 1000, expires_at: 3000, user_agent: null, ip_hash: null });
    }
    expect(db.listSessions(100, 1500)).toHaveLength(2);
    expect(db.revokeAllSessions(100, 1600)).toBe(2);
    expect(db.listSessions(100, 1700)).toHaveLength(0);
    expect(db.listSessions(200, 1700)).toHaveLength(1);
  });

  it("does not return expired sessions", () => {
    addStreamer(100);
    db.createSession({ token_hash: "expired", broadcaster_id: 100, csrf_secret: "csrf", created_at: 1000, last_seen_at: 1000, expires_at: 1100, user_agent: null, ip_hash: null });
    expect(db.getSession("expired", 1101)).toBeNull();
  });
});
