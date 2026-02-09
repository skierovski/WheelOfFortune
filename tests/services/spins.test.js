import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { openDatabase, setDb } from "../../src/db.js";

describe("spins service (multi-tenant)", () => {
  let db;
  const BID = 100;

  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: false });
    db = openDatabase(":memory:");
    setDb(db);
    // Create a test streamer
    db.upsertStreamer({
      broadcaster_id: BID,
      kick_username: "testuser",
      access_token: null,
      refresh_token: null,
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    db.close();
  });

  async function getSpins() {
    // Import fresh each time to avoid module state leaking
    const mod = await import("../../src/services/spins.js");
    return mod.spins;
  }

  // ── getPending ──────────────────────────────────────────────────

  describe("getPending", () => {
    it("returns 0 for a new streamer", async () => {
      const spins = await getSpins();
      expect(spins.getPending(BID)).toBe(0);
    });

    it("returns persisted pending count", async () => {
      db.saveSpinState(BID, { pending_count: 5, last_spin_time: 0, spin_in_progress: false });
      const spins = await getSpins();
      expect(spins.getPending(BID)).toBe(5);
    });
  });

  // ── deliverSpinOrQueue ──────────────────────────────────────────

  describe("deliverSpinOrQueue", () => {
    it("queues spins and delivers one immediately when no delay", async () => {
      const spins = await getSpins();
      const broadcasts = [];
      spins.setBroadcaster((bid, msg) => {
        broadcasts.push({ bid, msg });
        return 1;
      });

      const delivered = spins.deliverSpinOrQueue(BID, 3);
      expect(delivered).toBe(1);

      const spinMsgs = broadcasts.filter((b) => b.msg.action === "spin");
      expect(spinMsgs).toHaveLength(1);
      expect(spinMsgs[0].bid).toBe(BID);
      expect(spinMsgs[0].msg.times).toBe(1);

      expect(spins.getPending(BID)).toBe(2);
    });

    it("returns 0 when called with 0 or negative", async () => {
      const spins = await getSpins();
      expect(spins.deliverSpinOrQueue(BID, 0)).toBe(0);
      expect(spins.deliverSpinOrQueue(BID, -1)).toBe(0);
      expect(spins.getPending(BID)).toBe(0);
    });

    it("queues but does not deliver when spin is in progress", async () => {
      const spins = await getSpins();
      const broadcasts = [];
      spins.setBroadcaster((bid, msg) => {
        broadcasts.push({ bid, msg });
        return 1;
      });

      // Use a separate BID to avoid in-progress state from prior tests
      const BID_IP = 300;
      db.upsertStreamer({ broadcaster_id: BID_IP, kick_username: "ip_test", access_token: null, refresh_token: null });

      spins.deliverSpinOrQueue(BID_IP, 1); // delivers
      spins.deliverSpinOrQueue(BID_IP, 2); // queued only (spin in progress)

      const spinMsgs = broadcasts.filter((b) => b.msg.action === "spin" && b.bid === BID_IP);
      expect(spinMsgs).toHaveLength(1);
      expect(spins.getPending(BID_IP)).toBe(2);
    });

    it("requeues if no clients connected", async () => {
      const spins = await getSpins();
      spins.setBroadcaster(() => 0); // 0 clients

      const delivered = spins.deliverSpinOrQueue(BID, 3);
      expect(delivered).toBe(0);
      expect(spins.getPending(BID)).toBe(3);
    });

    it("respects 5-minute delay after spin completion", async () => {
      const spins = await getSpins();
      const broadcasts = [];
      spins.setBroadcaster((bid, msg) => {
        broadcasts.push({ bid, msg });
        return 1;
      });

      spins.deliverSpinOrQueue(BID, 2);
      spins.markSpinComplete(BID);

      // Try immediately - should be blocked
      const result = spins.deliverSpinOrQueue(BID, 1);
      expect(result).toBe(0);

      // Advance 5 minutes
      vi.advanceTimersByTime(5 * 60 * 1000);
      expect(spins.getTimeUntilNextSpin(BID)).toBe(0);
    });

    it("isolates spins between streamers", async () => {
      const BID2 = 200;
      db.upsertStreamer({ broadcaster_id: BID2, kick_username: "u2", access_token: null, refresh_token: null });

      const spins = await getSpins();
      spins.setBroadcaster(() => 0); // no clients, so all requeued

      spins.deliverSpinOrQueue(BID, 5);
      spins.deliverSpinOrQueue(BID2, 3);

      expect(spins.getPending(BID)).toBe(5);
      expect(spins.getPending(BID2)).toBe(3);
    });
  });

  // ── markSpinComplete ────────────────────────────────────────────

  describe("markSpinComplete", () => {
    it("starts the 5-minute delay timer", async () => {
      const spins = await getSpins();
      spins.setBroadcaster(() => 1);

      spins.deliverSpinOrQueue(BID, 1);
      spins.markSpinComplete(BID);

      expect(spins.getTimeUntilNextSpin(BID)).toBeGreaterThan(0);
      expect(spins.getTimeUntilNextSpin(BID)).toBeLessThanOrEqual(5 * 60 * 1000);
    });

    it("broadcasts delay info when pending spins exist", async () => {
      const spins = await getSpins();
      const broadcasts = [];
      spins.setBroadcaster((bid, msg) => {
        broadcasts.push({ bid, msg });
        return 1;
      });

      spins.deliverSpinOrQueue(BID, 3);
      spins.markSpinComplete(BID);

      const delayMsgs = broadcasts.filter((b) => b.msg.type === "delay" && b.bid === BID);
      expect(delayMsgs.length).toBeGreaterThan(0);
      const last = delayMsgs[delayMsgs.length - 1];
      expect(last.msg.pending).toBe(2);
    });
  });

  // ── getTimeUntilNextSpin ────────────────────────────────────────

  describe("getTimeUntilNextSpin", () => {
    it("returns 0 when no spin has ever been done", async () => {
      const spins = await getSpins();
      expect(spins.getTimeUntilNextSpin(BID)).toBe(0);
    });

    it("counts down after spin completion", async () => {
      const spins = await getSpins();
      spins.setBroadcaster(() => 1);

      spins.deliverSpinOrQueue(BID, 1);
      spins.markSpinComplete(BID);

      const remaining = spins.getTimeUntilNextSpin(BID);
      expect(remaining).toBeGreaterThan(0);

      vi.advanceTimersByTime(2 * 60 * 1000);
      expect(spins.getTimeUntilNextSpin(BID)).toBeLessThan(remaining);

      vi.advanceTimersByTime(3 * 60 * 1000 + 1);
      expect(spins.getTimeUntilNextSpin(BID)).toBe(0);
    });
  });

  // ── Persistence ─────────────────────────────────────────────────

  describe("persistence", () => {
    it("saves pending count to DB when spins are queued", async () => {
      const spins = await getSpins();
      spins.setBroadcaster(() => 0);

      spins.deliverSpinOrQueue(BID, 5);
      expect(spins.getPending(BID)).toBe(5);

      // Verify in DB
      const state = db.getSpinState(BID);
      expect(state.pending_count).toBe(5);
    });
  });
});
