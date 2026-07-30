import { getDb } from "../db.js";
import { loadConfig } from "./configStore.js";

/**
 * Increment the second number (goal) on sub/gift events and broadcast.
 * Manual +1 on the dashboard still edits the first number (count).
 * @param {number} broadcasterId
 * @param {number} delta  — e.g. gift count or 1 for a paid sub
 * @param {{ broadcastTo?: Function } | null} [wss]
 * @returns {{ count: number, goal: number, accent_color: string } | null}
 */
export function bumpManualCounter(broadcasterId, delta, wss = null) {
  const amount = Math.round(Number(delta) || 0);
  if (!amount) return null;

  const prev = loadConfig(broadcasterId);
  const count = prev?.manual_count ?? 0;
  const goal = Math.max(0, Math.min(1_000_000, (prev?.manual_goal ?? 0) + amount));
  const accent_color = prev?.accent_color ?? "#7c3aed";

  getDb().saveManualCounter(broadcasterId, { count, goal });

  try {
    wss?.broadcastTo?.(broadcasterId, {
      type: "counter",
      count,
      goal,
      accent_color,
    });
  } catch (e) {
    console.warn(`[counter] broadcast failed bid=${broadcasterId}:`, e?.message || e);
  }

  console.log(`[counter] bid=${broadcasterId} goal ${amount > 0 ? "+" : ""}${amount} → ${count}/${goal}`);
  return { count, goal, accent_color };
}
