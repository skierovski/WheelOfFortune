import { getDb } from "../db.js";
import { loadConfig } from "./configStore.js";

/**
 * Increment (or decrement) the manual counter for a streamer and broadcast.
 * @param {number} broadcasterId
 * @param {number} delta  — e.g. gift count or 1 for a paid sub
 * @param {{ broadcastTo?: Function } | null} [wss]
 * @returns {{ count: number, goal: number, accent_color: string } | null}
 */
export function bumpManualCounter(broadcasterId, delta, wss = null) {
  const amount = Math.round(Number(delta) || 0);
  if (!amount) return null;

  const prev = loadConfig(broadcasterId);
  const count = Math.max(0, Math.min(1_000_000, (prev?.manual_count ?? 0) + amount));
  const goal = prev?.manual_goal ?? 0;
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

  console.log(`[counter] bid=${broadcasterId} ${amount > 0 ? "+" : ""}${amount} → ${count}/${goal}`);
  return { count, goal, accent_color };
}
