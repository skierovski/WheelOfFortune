import { afterEach, beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import { app } from "../../src/app.js";
import { openDatabase, setDb } from "../../src/db.js";
import { createSession } from "../../src/services/sessions.js";

describe("moderator panel access", () => {
  let db, cookie;
  beforeEach(() => {
    db = openDatabase(":memory:");
    setDb(db);
    db.upsertStreamer({ broadcaster_id: 700, kick_username: "channel_one" });
    db.upsertStreamer({ broadcaster_id: 701, kick_username: "channel_two" });
    db.addModerator(700, { mod_kick_user_id: 800, mod_username: "moderator" });
    createSession({}, { setHeader: (_name, value) => { cookie = value.split(";")[0]; } }, 800);
  });
  afterEach(() => db.close());
  it("exposes a public login landing but not channel APIs", async () => {
    expect((await request(app).get("/moderator?channel=700")).status).toBe(200);
    expect((await request(app).get("/mod/channels")).status).toBe(401);
    expect((await request(app).get("/mod/700/status")).status).toBe(401);
  });
  it("lists only granted channels and rejects another channel", async () => {
    const result = await request(app).get("/mod/channels").set("Cookie", cookie);
    expect(result.body.channels.map((item) => item.broadcaster_id)).toEqual([700]);
    expect((await request(app).get("/mod/701/status").set("Cookie", cookie)).status).toBe(403);
    expect((await request(app).post("/mod/701/counter").set("Cookie", cookie).send({ delta: 1 })).status).toBe(403);
  });
  it("revokes access immediately without logging out", async () => {
    db.removeModerator(700, 800);
    expect((await request(app).get("/mod/700/status").set("Cookie", cookie)).status).toBe(403);
    expect((await request(app).get("/mod/channels").set("Cookie", cookie)).status).toBe(403);
    const page = await request(app).get("/mod?channel=700").set("Cookie", cookie);
    expect(page.headers.location).toBe("/moderator?denied=1&channel=700");
  });
  it("tests the wheel without queuing production spins", async () => {
    const before = db.getSpinState(700);
    const result = await request(app).post("/mod/700/test-spin").set("Cookie", cookie).send({ n: 1 });
    expect(result.status).toBe(200);
    expect(db.getSpinState(700)).toEqual(before);
  });
  it("increments the counter without overwriting its goal or label", async () => {
    db.saveManualCounter(700, { count: 5, goal: 50, label: "Test" });
    const result = await request(app).post("/mod/700/counter").set("Cookie", cookie).send({ delta: 1 });
    expect(result.status).toBe(200);
    expect(result.body).toMatchObject({ count: 6, goal: 50, label: "Test" });
  });
});
