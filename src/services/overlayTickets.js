import crypto from "crypto";

const DEFAULT_TTL_MS = 2 * 60 * 1000;
const tickets = new Map();

function digest(token) {
  return crypto.createHash("sha256").update(String(token || "")).digest("hex");
}

function prune(now = Date.now()) {
  for (const [key, ticket] of tickets) {
    if (ticket.expiresAt <= now || (ticket.completed && ticket.announced)) tickets.delete(key);
  }
}

export function issueOverlayTicket({ broadcasterId, kind, announceLabel = "", metadata = {} }, now = Date.now(), ttlMs = DEFAULT_TTL_MS) {
  prune(now);
  const token = crypto.randomBytes(32).toString("base64url");
  tickets.set(digest(token), {
    broadcasterId: Number(broadcasterId),
    kind: String(kind),
    announceLabel: String(announceLabel || "").slice(0, 500),
    metadata,
    expiresAt: now + ttlMs,
    announced: false,
    completed: false,
  });
  return token;
}

export function consumeOverlayTicket(token, { broadcasterId, kind, action }, now = Date.now()) {
  prune(now);
  const key = digest(token);
  const ticket = tickets.get(key);
  if (!ticket || ticket.expiresAt <= now) return null;
  if (ticket.broadcasterId !== Number(broadcasterId) || ticket.kind !== String(kind)) return null;
  if (action === "announce") {
    if (ticket.announced || !ticket.announceLabel) return null;
    ticket.announced = true;
  } else if (action === "complete") {
    if (ticket.completed) return null;
    ticket.completed = true;
  } else {
    return null;
  }
  if (ticket.completed && (ticket.announced || !ticket.announceLabel)) tickets.delete(key);
  return { announceLabel: ticket.announceLabel, metadata: ticket.metadata };
}

export function clearOverlayTicketsForTests() {
  tickets.clear();
}
