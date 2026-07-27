import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { openDatabase, setDb } from "../../src/db.js";

describe("slots paytable", () => {
  it("pays 0 for fewer than 3 matches", async () => {
    const { evaluatePayline } = await import("../../src/services/slots.js");
    const grid = [
      ["a", "cherry", "b"],
      ["a", "lemon", "b"],
      ["a", "orange", "b"],
      ["a", "plum", "b"],
      ["a", "melon", "b"],
    ];
    const r = evaluatePayline(grid);
    expect(r.win).toBe(0);
  });

  it("pays for 3 cherries on middle line", async () => {
    const { evaluatePayline, PAYTABLE, BET } = await import("../../src/services/slots.js");
    const grid = [
      ["a", "cherry", "b"],
      ["a", "cherry", "b"],
      ["a", "cherry", "b"],
      ["a", "lemon", "b"],
      ["a", "lemon", "b"],
    ];
    const r = evaluatePayline(grid);
    expect(r.matchCount).toBe(3);
    expect(r.symbol).toBe("cherry");
    expect(r.win).toBe(Math.round(BET * PAYTABLE.cherry[3] * 100) / 100);
  });

  it("rollGrid returns 5x3", async () => {
    const { rollGrid } = await import("../../src/services/slots.js");
    const g = rollGrid();
    expect(g).toHaveLength(5);
    g.forEach((col) => expect(col).toHaveLength(3));
  });
});

describe("slots service queue", () => {
  let db;
  const BID = 200;

  beforeEach(() => {
    db = openDatabase(":memory:");
    setDb(db);
    db.upsertStreamer({
      broadcaster_id: BID,
      kick_username: "slotuser",
      access_token: null,
      refresh_token: null,
    });
  });

  afterEach(() => {
    db.close();
  });

  it("queues and delivers slots with result payload", async () => {
    const { slots } = await import("../../src/services/slots.js");
    const broadcasts = [];
    slots.setBroadcaster((bid, msg) => {
      broadcasts.push({ bid, msg });
      return 1;
    });

    db.saveSlotsPrizes(BID, [{ min_bank: 0.01, label: "Tiny" }]);

    const delivered = slots.testSpin(BID, 2);
    expect(delivered).toBe(1);
    const slotsMsgs = broadcasts.filter((b) => b.msg.action === "slots");
    expect(slotsMsgs).toHaveLength(1);
    expect(slotsMsgs[0].msg.result.grid).toHaveLength(5);
    expect(slots.getPending(BID)).toBe(1);

    slots.markComplete(BID);
  });

  it("updates bank after a winning spin", async () => {
    const { slots, evaluatePayline } = await import("../../src/services/slots.js");
    // Craft a guaranteed win grid via evaluatePayline sanity
    const grid = [
      ["x", "dollar", "y"],
      ["x", "dollar", "y"],
      ["x", "dollar", "y"],
      ["x", "dollar", "y"],
      ["x", "dollar", "y"],
    ];
    expect(evaluatePayline(grid).win).toBeGreaterThan(0);

    db.saveSlotsPrizes(BID, [{ min_bank: 0.01, label: "Any" }]);
    const broadcasts = [];
    slots.setBroadcaster((_bid, msg) => {
      broadcasts.push(msg);
      return 1;
    });

    // Keep spinning until we get a non-zero win (weighted RNG)
    let won = false;
    for (let i = 0; i < 100 && !won; i++) {
      slots.testSpin(BID, 1);
      slots.markComplete(BID);
      const last = broadcasts.filter((m) => m.action === "slots").pop();
      if (last?.result?.win > 0) {
        won = true;
        expect(last.result.bank).toBeGreaterThan(0);
        if (last.result.bank >= 0.01) {
          expect(last.result.prizes_hit.some((p) => p.label === "Any")).toBe(true);
        }
      }
    }
    expect(won).toBe(true);
  });
});
