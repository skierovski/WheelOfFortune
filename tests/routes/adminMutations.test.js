import { afterEach, beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import { app } from "../../src/app.js";
import { openDatabase, setDb } from "../../src/db.js";
import { env } from "../../src/utils/env.js";

describe("admin data mutations", () => {
  let db;
  let previousBypass;

  beforeEach(() => {
    previousBypass = env.DEV_BYPASS_AUTH;
    env.DEV_BYPASS_AUTH = true;
    db = openDatabase(":memory:");
    setDb(db);
  });

  afterEach(() => {
    env.DEV_BYPASS_AUTH = previousBypass;
    db.close();
  });

  it("deletes the streamer and all related operational data", async () => {
    db.upsertStreamer({ broadcaster_id: 810, kick_username: "delete_me" });
    db.saveConfig(810, { items: [{ id: "a", label: "A", weight: 100 }] });
    db.saveSpinState(810, { pending_count: 2, last_spin_time: 0, spin_in_progress: false });
    db.saveSlotsState(810, { bank: 1, claimed: [], pending_count: 1, last_spin_time: 0, spin_in_progress: false });
    db.createSession({ token_hash: "admin-delete-session", broadcaster_id: 810, csrf_secret: "csrf", created_at: 1, last_seen_at: 1, expires_at: Date.now() + 10_000, user_agent: null, ip_hash: null });

    const response = await request(app).delete("/admin/streamers/810");

    expect(response.status).toBe(200);
    expect(db.getStreamerById(810)).toBeNull();
    expect(db.raw.prepare("SELECT COUNT(*) AS count FROM sessions WHERE broadcaster_id = 810").get().count).toBe(0);
    expect(db.raw.prepare("SELECT COUNT(*) AS count FROM slots_state WHERE broadcaster_id = 810").get().count).toBe(0);
  });
});
