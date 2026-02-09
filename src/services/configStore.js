import { getDb } from "../db.js";
import { normalizeItemsInt100 } from "../utils/normalize.js";

/**
 * Load wheel config for a streamer.
 * @param {number} broadcasterId
 * @returns {{ items: Array, theme: string } | null}
 */
export function loadConfig(broadcasterId) {
  return getDb().getConfig(broadcasterId);
}

/**
 * Save wheel config for a streamer (normalizes weights).
 * @param {number} broadcasterId
 * @param {Array} items
 * @param {string} [theme]
 * @returns {{ items: Array, theme: string }}
 */
export function saveConfig(broadcasterId, items, theme) {
  const normalized = normalizeItemsInt100(items);
  const prev = getDb().getConfig(broadcasterId);
  const finalTheme = typeof theme === "string" ? theme : (prev?.theme || "wood");

  getDb().saveConfig(broadcasterId, normalized, finalTheme);
  console.log(`[config] saved ${normalized.length} items for broadcaster ${broadcasterId} theme=${finalTheme}`);
  return { items: normalized, theme: finalTheme };
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
