import { describe, it, expect, vi } from "vitest";
import { createSubscriberCountReader, subscriberPayload } from "../../src/services/subscriberCount.js";

describe("authoritative subscriber totals", () => {
  it("does not add gifted subscribers a second time", async () => {
    const read = createSubscriberCountReader(async () => ({ active_subscribers_count: 295, active_gifted_subscribers_count: 200 }));
    const result = subscriberPayload(await read(1));
    expect(result.active_subscribers_count).toBe(295);
    expect(result.estimated_subscribers_count).toBe(295);
    expect(result.sub_seed_offset).toBe(0);
  });
  it("preserves the last count on API failure and accepts decreases on recovery", async () => {
    let time = 0;
    const fetch = vi.fn().mockResolvedValueOnce({ active_subscribers_count: 295 }).mockRejectedValueOnce(new Error("offline")).mockResolvedValueOnce({ active_subscribers_count: 280 });
    const read = createSubscriberCountReader(fetch, () => time);
    await read(1);
    time = 11000;
    expect(await read(1)).toMatchObject({ active_subscribers_count: 295, stale: true });
    time = 22000;
    expect(await read(1)).toMatchObject({ active_subscribers_count: 280, stale: false });
  });
  it("does not invent zero without a successful response", async () => {
    const read = createSubscriberCountReader(async () => ({}));
    expect(await read(1)).toMatchObject({ active_subscribers_count: null, stale: true });
  });
  it("isolates channels and coalesces simultaneous requests", async () => {
    const fetch = vi.fn(async bid => ({ active_subscribers_count: bid * 10 }));
    const read = createSubscriberCountReader(fetch);
    const results = await Promise.all([read(1), read(1), read(2)]);
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(results.map(r => r.active_subscribers_count)).toEqual([10, 10, 20]);
  });
});
