import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { openDatabase } from "../../src/db.js";

describe("persistent webhook replay protection", () => {
  let db;
  beforeEach(() => { db = openDatabase(":memory:"); });
  afterEach(() => db.close());

  it("atomically accepts a message only once", () => {
    const receipt = { messageId: "msg-1", eventType: "channel.subscription.new", payloadHash: "abc", now: 1000 };
    expect(db.claimWebhookReceipt(receipt)).toBe(true);
    expect(db.claimWebhookReceipt(receipt)).toBe(false);
  });

  it("allows an id again only after its receipt expires", () => {
    expect(db.claimWebhookReceipt({ messageId: "msg-2", payloadHash: "abc", now: 1000, ttlMs: 100 })).toBe(true);
    expect(db.claimWebhookReceipt({ messageId: "msg-2", payloadHash: "abc", now: 1101, ttlMs: 100 })).toBe(true);
  });
});
