import { afterEach, beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import { app } from "../../src/app.js";
import { openDatabase, setDb } from "../../src/db.js";
import { clearOverlayTicketsForTests, issueOverlayTicket } from "../../src/services/overlayTickets.js";

describe("overlay mutation authorization", () => {
  let db;
  let streamer;

  beforeEach(() => {
    clearOverlayTicketsForTests();
    db = openDatabase(":memory:");
    setDb(db);
    streamer = db.upsertStreamer({ broadcaster_id: 700, kick_username: "overlay_test" });
  });

  afterEach(() => db.close());

  it("rejects completion with only the public overlay key", async () => {
    const response = await request(app).post(`/overlay/${streamer.overlay_key}/spins/complete`);
    expect(response.status).toBe(401);
  });

  it("accepts a matching wheel ticket once", async () => {
    const ticket = issueOverlayTicket({ broadcasterId: 700, kind: "wheel" });
    const first = await request(app)
      .post(`/overlay/${streamer.overlay_key}/spins/complete`)
      .set("X-Overlay-Ticket", ticket);
    const replay = await request(app)
      .post(`/overlay/${streamer.overlay_key}/spins/complete`)
      .set("X-Overlay-Ticket", ticket);
    expect(first.status).toBe(200);
    expect(replay.status).toBe(401);
  });

  it("does not accept a slots ticket on a wheel endpoint", async () => {
    const ticket = issueOverlayTicket({ broadcasterId: 700, kind: "slots" });
    const response = await request(app)
      .post(`/overlay/${streamer.overlay_key}/spins/complete`)
      .set("X-Overlay-Ticket", ticket);
    expect(response.status).toBe(401);
  });
});
