import { beforeEach, describe, expect, it } from "vitest";
import { clearOverlayTicketsForTests, consumeOverlayTicket, issueOverlayTicket } from "../../src/services/overlayTickets.js";

describe("overlay execution tickets", () => {
  beforeEach(clearOverlayTicketsForTests);

  it("binds a ticket to broadcaster and overlay kind", () => {
    const token = issueOverlayTicket({ broadcasterId: 10, kind: "wheel", announceLabel: "Prize" }, 1_000);
    expect(consumeOverlayTicket(token, { broadcasterId: 11, kind: "wheel", action: "complete" }, 1_001)).toBeNull();
    expect(consumeOverlayTicket(token, { broadcasterId: 10, kind: "slots", action: "complete" }, 1_001)).toBeNull();
    expect(consumeOverlayTicket(token, { broadcasterId: 10, kind: "wheel", action: "complete" }, 1_001)).not.toBeNull();
  });

  it("allows announce and complete once each without trusting client data", () => {
    const token = issueOverlayTicket({ broadcasterId: 10, kind: "wheel", announceLabel: "Server prize", metadata: { bonus: true } }, 1_000);
    const announce = consumeOverlayTicket(token, { broadcasterId: 10, kind: "wheel", action: "announce" }, 1_001);
    expect(announce).toMatchObject({ announceLabel: "Server prize", metadata: { bonus: true } });
    expect(consumeOverlayTicket(token, { broadcasterId: 10, kind: "wheel", action: "announce" }, 1_002)).toBeNull();
    expect(consumeOverlayTicket(token, { broadcasterId: 10, kind: "wheel", action: "complete" }, 1_003)).not.toBeNull();
    expect(consumeOverlayTicket(token, { broadcasterId: 10, kind: "wheel", action: "complete" }, 1_004)).toBeNull();
  });

  it("rejects expired tickets", () => {
    const token = issueOverlayTicket({ broadcasterId: 10, kind: "slots" }, 1_000, 100);
    expect(consumeOverlayTicket(token, { broadcasterId: 10, kind: "slots", action: "complete" }, 1_101)).toBeNull();
  });
});
