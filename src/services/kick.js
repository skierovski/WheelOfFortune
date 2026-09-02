import { ensureAccessToken } from "./tokens.js";

/**
 * Fetch the broadcaster info (username, display name) from Kick API.
 * @param {string} accessToken
 * @returns {Promise<{ user_id: number, username: string, display_name: string }>}
 */
export async function fetchUserInfo(accessToken) {
  const r = await fetch("https://api.kick.com/public/v1/users", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!r.ok) throw new Error(`users (self) failed: ${r.status} ${await r.text().catch(() => "")}`);
  const data = await r.json();
  const user = data?.data?.[0];
  if (!user?.user_id) throw new Error("Cannot determine user from Kick API response");
  // Kick API returns: { user_id, name, email, profile_picture }
  // "name" is the display name; no separate "username" field in /users endpoint
  const name = user.name || user.username || user.display_name || null;
  return {
    user_id: Number(user.user_id),
    username: name,
    display_name: name,
  };
}

/**
 * Look up a Kick user by channel slug/username or numeric user id.
 * Official /users only accepts `id=` (slug/name are ignored and return self).
 * Username resolution uses /channels?slug= → broadcaster_user_id.
 *
 * @param {number} broadcasterId
 * @param {string|number} nameOrId
 * @returns {Promise<{ user_id: number, username: string, display_name: string }>}
 */
export async function lookupKickUser(broadcasterId, nameOrId) {
  const raw = String(nameOrId || "").trim().replace(/^@/, "");
  if (!raw) throw new Error("Missing username");

  const token = await ensureAccessToken(broadcasterId);

  // Numeric Kick user ID → /users?id=
  if (/^\d+$/.test(raw)) {
    const asId = Number(raw);
    const r = await fetch(`https://api.kick.com/public/v1/users?id=${asId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!r.ok) throw new Error(`Kick user lookup failed: ${r.status}`);
    const data = await r.json();
    const user = Array.isArray(data?.data) ? data.data[0] : data?.data;
    if (!user?.user_id) throw new Error("Kick user not found for that ID");
    const name = user.name || user.username || raw;
    return { user_id: Number(user.user_id), username: name, display_name: name };
  }

  // Username / channel slug → /channels?slug=
  const slug = raw.toLowerCase().slice(0, 25);
  const r = await fetch(`https://api.kick.com/public/v1/channels?slug=${encodeURIComponent(slug)}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!r.ok) {
    throw new Error(`Kick channel lookup failed: ${r.status}. Try the numeric Kick user ID instead.`);
  }
  const data = await r.json();
  const ch = Array.isArray(data?.data) ? data.data[0] : data?.data;
  const userId = Number(ch?.broadcaster_user_id);
  if (!Number.isFinite(userId) || !userId) {
    throw new Error(`No Kick channel found for "${raw}". Use their numeric Kick user ID.`);
  }
  const username = ch.slug || raw;
  return {
    user_id: userId,
    username,
    display_name: username,
  };
}

/**
 * Subscribe to events for a specific broadcaster.
 * @param {number} broadcasterId
 * @param {string} callbackUrl
 * @param {{ name: string, version: number }[]} [events]
 */
export async function subscribeToEvents(broadcasterId, callbackUrl, events) {
  const token = await ensureAccessToken(broadcasterId);
  const eventList = events || [
    { name: "channel.subscription.gifts", version: 1 },
    { name: "channel.subscription.new", version: 1 },
    { name: "channel.subscription.renewal", version: 1 },
    { name: "chat.message.sent", version: 1 },
  ];
  const response = await fetch("https://api.kick.com/public/v1/events/subscriptions", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      broadcaster_user_id: Number(broadcasterId),
      events: eventList,
      method: "webhook",
      callback: callbackUrl,
    }),
  });
  const text = await response.text();
  console.log(`[SUBSCRIBE] bid=${broadcasterId} events=${eventList.map(e => e.name).join(",")} status:`, response.status, text);
  if (!response.ok) throw new Error(`Failed to subscribe: ${response.status} ${text}`);
  return JSON.parse(text);
}

/**
 * List active subscriptions for a broadcaster.
 * @param {number} broadcasterId
 */
export async function listSubscriptions(broadcasterId) {
  const token = await ensureAccessToken(broadcasterId);
  const r = await fetch(
    `https://api.kick.com/public/v1/events/subscriptions?broadcaster_user_id=${broadcasterId}`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  if (!r.ok) return [];
  const j = await r.json().catch(() => ({}));
  return Array.isArray(j?.data) ? j.data : [];
}

/**
 * Fetch channel info (including active_subscribers_count) from Kick API.
 * @param {number} broadcasterId
 * @returns {Promise<{ active_subscribers_count: number, canceled_subscribers_count: number, slug: string, stream_title: string }>}
 */
export async function fetchChannelInfo(broadcasterId) {
  const token = await ensureAccessToken(broadcasterId);
  const r = await fetch(
    `https://api.kick.com/public/v1/channels?broadcaster_user_id=${broadcasterId}`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  if (!r.ok) throw new Error(`channels failed: ${r.status} ${await r.text().catch(() => "")}`);
  const j = await r.json();
  const ch = Array.isArray(j?.data) ? j.data[0] : j?.data;
  if (!ch) throw new Error("No channel data returned");
  if (!Number.isSafeInteger(ch.active_subscribers_count) || ch.active_subscribers_count < 0) {
    throw new Error("Kick returned no valid active subscriber total");
  }
  return {
    active_subscribers_count: ch.active_subscribers_count,
    active_gifted_subscribers_count: Number.isSafeInteger(ch.active_gifted_subscribers_count) && ch.active_gifted_subscribers_count >= 0 ? ch.active_gifted_subscribers_count : null,
    canceled_subscribers_count: Number(ch.canceled_subscribers_count ?? 0),
    slug: ch.slug ?? null,
    stream_title: ch.stream_title ?? null,
  };
}

/**
 * Post a chat message as a broadcaster (user) or as a bot.
 * @param {number} broadcasterId
 * @param {string} content
 * @param {{ type?: "user"|"bot" }} [opts]
 */
export async function postChatMessage(broadcasterId, content, { type = "bot" } = {}) {
  if (!content?.trim()) return;
  try {
    const token = await ensureAccessToken(broadcasterId);
    const body = { content: content.slice(0, 500), type };
    if (type === "user") body.broadcaster_user_id = broadcasterId;
    const r = await fetch("https://api.kick.com/public/v1/chat", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!r.ok) console.warn(`chat send failed bid=${broadcasterId}: ${r.status}`);
  } catch (e) {
    console.warn(`[chat] error bid=${broadcasterId}:`, e.message);
  }
}
