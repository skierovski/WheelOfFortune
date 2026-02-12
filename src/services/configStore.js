import { getDb } from "../db.js";
import { normalizeItemsInt100 } from "../utils/normalize.js";

/**
 * Load wheel config for a streamer.
 * @param {number} broadcasterId
 * @returns {{ items: Array, tiers: Array|null, accent_color: string, gifts_per_spin: number } | null}
 */
export function loadConfig(broadcasterId) {
  return getDb().getConfig(broadcasterId);
}

/**
 * Save wheel config for a streamer (normalizes weights).
 * @param {number} broadcasterId
 * @param {Array} items  — legacy single item list (used as fallback / Tier 1 items)
 * @param {{ accent_color?: string, secondary_color?: string, wheel_opacity?: number, gifts_per_spin?: number, tiers?: Array }} [opts]
 * @returns {{ items: Array, tiers: Array|null, accent_color: string, secondary_color: string, wheel_opacity: number, gifts_per_spin: number }}
 */
export function saveConfig(broadcasterId, items, opts = {}) {
  const prev = getDb().getConfig(broadcasterId);

  const finalAccent = typeof opts.accent_color === "string" ? opts.accent_color : (prev?.accent_color || "#7c3aed");
  const finalSecondary = typeof opts.secondary_color === "string" ? opts.secondary_color : (prev?.secondary_color || "#121228");
  const finalOpacity = Number.isFinite(opts.wheel_opacity) ? opts.wheel_opacity : (prev?.wheel_opacity ?? 0.9);
  const finalGifts = Number.isFinite(opts.gifts_per_spin) ? opts.gifts_per_spin : (prev?.gifts_per_spin ?? 5);

  // Normalize tiers if provided
  let finalTiers = null;
  if (Array.isArray(opts.tiers) && opts.tiers.length > 0) {
    finalTiers = opts.tiers.map(t => ({
      name: String(t.name || "Default").slice(0, 50),
      min_gifts: Math.max(1, Math.min(1000, Math.round(Number(t.min_gifts) || 5))),
      items: normalizeItemsInt100(Array.isArray(t.items) ? t.items : []),
    }));
    // Sort by min_gifts ascending
    finalTiers.sort((a, b) => a.min_gifts - b.min_gifts);
  }

  // items_json stores the first tier's items for backward compat (overlay fallback)
  const normalized = finalTiers ? finalTiers[0].items : normalizeItemsInt100(items);

  getDb().saveConfig(broadcasterId, {
    items: normalized,
    tiers: finalTiers,
    accent_color: finalAccent,
    secondary_color: finalSecondary,
    wheel_opacity: finalOpacity,
    gifts_per_spin: finalGifts,
  });
  const tierCount = finalTiers ? finalTiers.length : 0;
  console.log(`[config] saved ${normalized.length} items, ${tierCount} tiers for broadcaster ${broadcasterId} accent=${finalAccent} secondary=${finalSecondary} opacity=${finalOpacity} gifts_per_spin=${finalGifts}`);
  return { items: normalized, tiers: finalTiers, accent_color: finalAccent, secondary_color: finalSecondary, wheel_opacity: finalOpacity, gifts_per_spin: finalGifts };
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
