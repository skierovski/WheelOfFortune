import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "fs";
import path from "path";
import os from "os";

describe("spins service", () => {
  let tmpDir;
  let pendingPath;

  beforeEach(() => {
    vi.resetModules();
    vi.useFakeTimers({ shouldAdvanceTime: false });
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "wof-spins-test-"));
    pendingPath = path.join(tmpDir, "pending.json");
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  async function getSpins(initialPending = 0) {
    if (initialPending > 0) {
      fs.writeFileSync(pendingPath, JSON.stringify(initialPending));
    }

    vi.doMock("../../src/utils/env.js", () => ({
      env: {
        PENDING_PATH: pendingPath,
      },
    }));

    const mod = await import("../../src/services/spins.js");
    return mod.spins;
  }

  // ── getPending ──────────────────────────────────────────────────

  describe("getPending", () => {
    it("returns 0 when no pending file exists", async () => {
      const spins = await getSpins();
      expect(spins.getPending()).toBe(0);
    });

    it("loads pending count from disk on startup", async () => {
      const spins = await getSpins(5);
      expect(spins.getPending()).toBe(5);
    });
  });

  // ── deliverSpinOrQueue ──────────────────────────────────────────

  describe("deliverSpinOrQueue", () => {
    it("queues spins and delivers one immediately when no delay", async () => {
      const spins = await getSpins();
      const broadcasts = [];
      spins.setBroadcaster((msg) => {
        broadcasts.push(msg);
        return 1; // 1 client received
      });

      const delivered = spins.deliverSpinOrQueue(3);
      expect(delivered).toBe(1); // delivered to 1 client

      // Should have broadcast a spin action
      const spinMsg = broadcasts.find((m) => m.action === "spin");
      expect(spinMsg).toBeTruthy();
      expect(spinMsg.times).toBe(1); // delivers 1 at a time

      // 3 queued - 1 delivered = 2 remaining
      expect(spins.getPending()).toBe(2);
    });

    it("returns 0 when called with 0 or negative", async () => {
      const spins = await getSpins();
      expect(spins.deliverSpinOrQueue(0)).toBe(0);
      expect(spins.deliverSpinOrQueue(-1)).toBe(0);
      expect(spins.getPending()).toBe(0);
    });

    it("queues but does not deliver when spin is in progress", async () => {
      const spins = await getSpins();
      const broadcasts = [];
      spins.setBroadcaster((msg) => {
        broadcasts.push(msg);
        return 1;
      });

      // First delivery works
      spins.deliverSpinOrQueue(1);
      expect(broadcasts.filter((m) => m.action === "spin")).toHaveLength(1);

      // Second delivery queues only (spin still in progress)
      const result = spins.deliverSpinOrQueue(2);
      expect(result).toBe(0);
      expect(spins.getPending()).toBe(2); // 2 in queue

      // Should have broadcast a delay message, not a spin
      const lastBroadcast = broadcasts[broadcasts.length - 1];
      expect(lastBroadcast.type).toBe("delay");
    });

    it("requeues if no clients connected", async () => {
      const spins = await getSpins();
      spins.setBroadcaster(() => 0); // 0 clients

      const delivered = spins.deliverSpinOrQueue(3);
      expect(delivered).toBe(0);
      // All 3 should still be pending (requeued the one it tried to deliver)
      expect(spins.getPending()).toBe(3);
    });

    it("respects 5-minute delay after spin completion", async () => {
      const spins = await getSpins();
      const broadcasts = [];
      spins.setBroadcaster((msg) => {
        broadcasts.push(msg);
        return 1;
      });

      // Deliver first spin
      spins.deliverSpinOrQueue(2);
      expect(broadcasts.filter((m) => m.action === "spin")).toHaveLength(1);

      // Complete it (starts 5-min timer)
      spins.markSpinComplete();

      // Try to deliver next one immediately - should be blocked by delay
      const result = spins.deliverSpinOrQueue(1);
      expect(result).toBe(0);

      // Advance time by 5 minutes
      vi.advanceTimersByTime(5 * 60 * 1000);

      // Now getTimeUntilNextSpin should be 0
      expect(spins.getTimeUntilNextSpin()).toBe(0);
    });
  });

  // ── markSpinComplete ────────────────────────────────────────────

  describe("markSpinComplete", () => {
    it("starts the 5-minute delay timer", async () => {
      const spins = await getSpins();
      spins.setBroadcaster(() => 1);

      spins.deliverSpinOrQueue(1);
      spins.markSpinComplete();

      // Should have a non-zero delay
      expect(spins.getTimeUntilNextSpin()).toBeGreaterThan(0);
      expect(spins.getTimeUntilNextSpin()).toBeLessThanOrEqual(5 * 60 * 1000);
    });

    it("broadcasts delay info when pending spins exist", async () => {
      const spins = await getSpins();
      const broadcasts = [];
      spins.setBroadcaster((msg) => {
        broadcasts.push(msg);
        return 1;
      });

      spins.deliverSpinOrQueue(3); // queues 3, delivers 1
      spins.markSpinComplete(); // starts timer, 2 pending

      const delayMsg = broadcasts.filter((m) => m.type === "delay");
      expect(delayMsg.length).toBeGreaterThan(0);
      const last = delayMsg[delayMsg.length - 1];
      expect(last.pending).toBe(2);
      expect(last.timeUntilNext).toBeGreaterThan(0);
    });
  });

  // ── getTimeUntilNextSpin ────────────────────────────────────────

  describe("getTimeUntilNextSpin", () => {
    it("returns 0 when no spin has ever been done", async () => {
      const spins = await getSpins();
      expect(spins.getTimeUntilNextSpin()).toBe(0);
    });

    it("counts down after spin completion", async () => {
      const spins = await getSpins();
      spins.setBroadcaster(() => 1);

      spins.deliverSpinOrQueue(1);
      spins.markSpinComplete();

      const remaining = spins.getTimeUntilNextSpin();
      expect(remaining).toBeGreaterThan(0);
      expect(remaining).toBeLessThanOrEqual(5 * 60 * 1000);

      // Advance 2 minutes
      vi.advanceTimersByTime(2 * 60 * 1000);
      const after2min = spins.getTimeUntilNextSpin();
      expect(after2min).toBeLessThan(remaining);
      expect(after2min).toBeGreaterThan(0);

      // Advance remaining time
      vi.advanceTimersByTime(3 * 60 * 1000 + 1);
      expect(spins.getTimeUntilNextSpin()).toBe(0);
    });
  });

  // ── Persistence ─────────────────────────────────────────────────

  describe("persistence", () => {
    it("saves pending count to disk when spins are queued", async () => {
      const spins = await getSpins();
      spins.setBroadcaster(() => 0); // no clients so all requeued

      spins.deliverSpinOrQueue(5);
      expect(spins.getPending()).toBe(5);

      // Check file on disk
      const onDisk = JSON.parse(fs.readFileSync(pendingPath, "utf8"));
      expect(onDisk).toBe(5);
    });

    it("updates disk after spin delivery consumes a spin", async () => {
      const spins = await getSpins(10);
      spins.setBroadcaster(() => 1);

      spins.deliverSpinOrQueue(0); // don't add more, just trigger delivery check
      // Actually, deliverSpinOrQueue(0) returns 0, so let's trigger a delivery
      // The pending was loaded as 10, let's add 1 more and deliver
      spins.deliverSpinOrQueue(1); // adds 1 (total 11), delivers 1 (total 10)
      
      const onDisk = JSON.parse(fs.readFileSync(pendingPath, "utf8"));
      expect(onDisk).toBe(10);
    });
  });

  // ── Periodic checker ────────────────────────────────────────────

  describe("periodic checker (setInterval)", () => {
    it("auto-delivers pending spin after delay expires", async () => {
      const spins = await getSpins();
      const broadcasts = [];
      spins.setBroadcaster((msg) => {
        broadcasts.push(msg);
        return 1;
      });

      // Queue and deliver first spin
      spins.deliverSpinOrQueue(2); // queues 2, delivers 1, pending=1
      expect(broadcasts.filter((m) => m.action === "spin")).toHaveLength(1);

      // Complete spin (starts 5-min timer)
      spins.markSpinComplete();

      // Advance past 5 minutes to let the setInterval fire
      vi.advanceTimersByTime(5 * 60 * 1000 + 1000);

      // The periodic checker should have delivered the next spin
      const spinBroadcasts = broadcasts.filter((m) => m.action === "spin");
      expect(spinBroadcasts.length).toBe(2);
      expect(spins.getPending()).toBe(0);
    });
  });
});
