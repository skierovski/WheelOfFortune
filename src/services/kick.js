import { ensureAccessToken, tokenStore } from "./tokens.js";
import { env } from "../utils/env.js";

let CACHED_BROADCASTER_ID = null;

export async function getBroadcasterId() {
  if (CACHED_BROADCASTER_ID) return CACHED_BROADCASTER_ID;
  const token = await ensureAccessToken();
  const r = await fetch("https://api.kick.com/public/v1/users", {
    headers: { Authorization: `Bearer ${token}` }
  });
  if (!r.ok) throw new Error(`users (self) failed: ${r.status} ${await r.text().catch(()=> "")}`);
  const data = await r.json();
  const id = data?.data?.[0]?.user_id;
  if (!Number.isFinite(Number(id))) throw new Error("Cannot determine broadcaster_user_id");
  CACHED_BROADCASTER_ID = Number(id);
  return CACHED_BROADCASTER_ID;
}

export async function subscribeToEvents(broadcasterId, callbackUrl) {
  const token = await ensureAccessToken();
  const response = await fetch("https://api.kick.com/public/v1/events/subscriptions", {
    method: "POST",
    headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      broadcaster_user_id: Number(broadcasterId),
      events: [ { name: "channel.subscription.gifts", version: 1 } ],
      method: "webhook",
      callback: callbackUrl
    })
  });
  const text = await response.text();
  console.log("[SUBSCRIBE] status:", response.status, text);
  if (!response.ok) throw new Error(`Failed to subscribe: ${response.status} ${text}`);
  return JSON.parse(text);
}

export async function listSubscriptions(broadcasterId) {
  const token = await ensureAccessToken();
  const r = await fetch(`https://api.kick.com/public/v1/events/subscriptions?broadcaster_user_id=${broadcasterId}`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  if (!r.ok) return [];
  const j = await r.json().catch(()=> ({}));
  return Array.isArray(j?.data) ? j.data : [];
}

export async function postChatMessage(content) {
  if (!content?.trim()) return;
  try {
    const token = await ensureAccessToken();
    const broadcasterId = await getBroadcasterId();
    const r = await fetch("https://api.kick.com/public/v1/chat", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ broadcaster_user_id: broadcasterId, content: content.slice(0,500), type: "user" })
    });
    if (!r.ok) console.warn(`chat send failed: ${r.status} ${await r.text().catch(()=> "")}`);
  } catch (e) { console.warn("[chat] error:", e.message); }
}

export const tokensRaw = tokenStore;
export { env };
