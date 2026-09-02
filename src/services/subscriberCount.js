import { fetchChannelInfo } from "./kick.js";

// Cache only authoritative Kick totals. Gift events are refresh signals, not increments.
export function createSubscriberCountReader(fetchInfo = fetchChannelInfo, now = Date.now) {
  const cache = new Map();
  const inFlight = new Map();
  return async function read(bid) {
    const previous = cache.get(bid);
    if (previous && now() - previous.updated_at < 10000) return { ...previous, stale: false };
    if (inFlight.has(bid)) return inFlight.get(bid);
    const request = (async () => {
      try {
        const info = await fetchInfo(bid);
        const total = info.active_subscribers_count;
        if (!Number.isSafeInteger(total) || total < 0) throw new Error("Invalid active subscriber count");
        const result = { active_subscribers_count: total, active_gifted_subscribers_count: info.active_gifted_subscribers_count ?? null, updated_at: now() };
        cache.set(bid, result);
        return { ...result, stale: false };
      } catch {
        return { ...(previous || { active_subscribers_count: null, active_gifted_subscribers_count: null, updated_at: null }), stale: true };
      } finally {
        inFlight.delete(bid);
      }
    })();
    inFlight.set(bid, request);
    return request;
  };
}

export const readSubscriberCount = createSubscriberCountReader();

export function subscriberPayload(snapshot) {
  return { ...snapshot, source: "kick", api_count: snapshot.active_subscribers_count,
    // Legacy clients still read this name; it is now the exact total, never a sum.
    estimated_subscribers_count: snapshot.active_subscribers_count, sub_seed_offset: 0 };
}
