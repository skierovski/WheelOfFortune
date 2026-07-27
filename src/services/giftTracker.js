import { getDb } from "../db.js";

const DEFAULT_GIFT_TTL_SEC = 30 * 24 * 60 * 60; // 30 days

/**
 * Parse expires_at from Kick gift payload (iso string or unix sec/ms).
 * Falls back to now + 30 days.
 */
export function resolveGiftExpiresAt(payload, nowSec = Math.floor(Date.now() / 1000)) {
  const candidates = [
    payload?.expires_at,
    payload?.data?.expires_at,
    Array.isArray(payload?.giftees) ? payload.giftees[0]?.expires_at : null,
  ];
  for (const raw of candidates) {
    if (raw == null || raw === "") continue;
    if (typeof raw === "number" && Number.isFinite(raw)) {
      // Heuristic: ms vs sec
      return raw > 1e12 ? Math.floor(raw / 1000) : Math.floor(raw);
    }
    const parsed = Date.parse(String(raw));
    if (Number.isFinite(parsed)) return Math.floor(parsed / 1000);
  }
  return nowSec + DEFAULT_GIFT_TTL_SEC;
}

/**
 * Persist a gifted-sub event for hybrid subscriber counting.
 * Dedupes by Kick event message id when provided.
 * @returns {{ inserted: boolean, gift_count: number, active_tracked: number }}
 */
export function trackGiftEvent(broadcasterId, { messageId, giftCount, gifterUsername, expiresAt }) {
  const count = Math.max(0, Math.round(Number(giftCount) || 0));
  if (!broadcasterId || count <= 0) {
    return { inserted: false, gift_count: 0, active_tracked: getActiveTrackedGiftCount(broadcasterId) };
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const exp = Number.isFinite(expiresAt) && expiresAt > 0 ? Math.floor(expiresAt) : nowSec + DEFAULT_GIFT_TTL_SEC;
  const eventId = messageId ? String(messageId).slice(0, 128) : `auto_${broadcasterId}_${nowSec}_${Math.random().toString(36).slice(2, 10)}`;

  const inserted = getDb().addTrackedGift({
    broadcaster_id: broadcasterId,
    event_message_id: eventId,
    gift_count: count,
    gifter_username: gifterUsername ? String(gifterUsername).slice(0, 64) : null,
    expires_at: exp,
  });

  // Opportunistic cleanup
  getDb().purgeExpiredTrackedGifts(broadcasterId);

  const active = getActiveTrackedGiftCount(broadcasterId);
  if (inserted) {
    console.log(`[gift-tracker] bid=${broadcasterId} +${count} gifts (active_tracked=${active}, expires=${exp})`);
  }
  return { inserted, gift_count: count, active_tracked: active };
}

export function getActiveTrackedGiftCount(broadcasterId) {
  if (!broadcasterId) return 0;
  getDb().purgeExpiredTrackedGifts(broadcasterId);
  return getDb().countActiveTrackedGifts(broadcasterId);
}

/**
 * Hybrid display count: Kick API + seed offset + still-active tracked gifts.
 */
export function computeEstimatedSubCount(apiCount, seedOffset, activeTracked) {
  const api = Math.max(0, Math.round(Number(apiCount) || 0));
  const seed = Math.round(Number(seedOffset) || 0);
  const tracked = Math.max(0, Math.round(Number(activeTracked) || 0));
  return Math.max(0, api + seed + tracked);
}

/**
 * Compute seed offset so estimated == realTotal given current api + tracked.
 */
export function computeSeedOffset(realTotal, apiCount, activeTracked) {
  const real = Math.max(0, Math.round(Number(realTotal) || 0));
  const api = Math.max(0, Math.round(Number(apiCount) || 0));
  const tracked = Math.max(0, Math.round(Number(activeTracked) || 0));
  return real - api - tracked;
}

export function getGiftTrackerStats(broadcasterId) {
  getDb().purgeExpiredTrackedGifts(broadcasterId);
  return {
    active_tracked: getDb().countActiveTrackedGifts(broadcasterId),
    total_tracked_ever: getDb().countAllTrackedGifts(broadcasterId),
    recent: getDb().listRecentTrackedGifts(broadcasterId, 10),
  };
}
