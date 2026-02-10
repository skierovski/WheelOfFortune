import { getDb } from "../db.js";
import { normalizeItemsInt100 } from "../utils/normalize.js";

/**
 * Load wheel config for a streamer.
 * @param {number} broadcasterId
 * @returns {{ items: Array, accent_color: string, gifts_per_spin: number } | null}
 */
export function loadConfig(broadcasterId) {
  return getDb().getConfig(broadcasterId);
}

/**
 * Save wheel config for a streamer (normalizes weights).
 * @param {number} broadcasterId
 * @param {Array} items
 * @param {{ accent_color?: string, gifts_per_spin?: number }} [opts]
 * @returns {{ items: Array, accent_color: string, gifts_per_spin: number }}
 */
export function saveConfig(broadcasterId, items, opts = {}) {
  const normalized = normalizeItemsInt100(items);
  const prev = getDb().getConfig(broadcasterId);

  const finalAccent = typeof opts.accent_color === "string" ? opts.accent_color : (prev?.accent_color || "#7c3aed");
  const finalGifts = Number.isFinite(opts.gifts_per_spin) ? opts.gifts_per_spin : (prev?.gifts_per_spin ?? 5);

  getDb().saveConfig(broadcasterId, {
    items: normalized,
    accent_color: finalAccent,
    gifts_per_spin: finalGifts,
  });
  console.log(`[config] saved ${normalized.length} items for broadcaster ${broadcasterId} accent=${finalAccent} gifts_per_spin=${finalGifts}`);
  return { items: normalized, accent_color: finalAccent, gifts_per_spin: finalGifts };
}

/**
 * Load goals for a streamer.
 * @param {number} broadcasterId
 * @returns {string[]}
 */
export function loadGoals(broadcasterId) {
  return getDb().getGoals(broadcasterId);
}

/**
 * Save goals for a streamer.
 * @param {number} broadcasterId
 * @param {Array} arr
 * @returns {string[]}
 */
export function saveGoals(broadcasterId, arr) {
  const list = Array.isArray(arr) ? arr.map(String) : [];
  getDb().saveGoals(broadcasterId, list);
  console.log(`[goals] saved ${list.length} goals for broadcaster ${broadcasterId}`);
  return list;
}
