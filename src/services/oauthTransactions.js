import crypto from "crypto";
import { getDb } from "../db.js";

const DEFAULT_TTL_MS = 10 * 60 * 1000;

function hash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

export function storeOAuthTransaction({ state, codeVerifier, redirectUri, returnPath, inviteCode = null }, now = Date.now(), ttlMs = DEFAULT_TTL_MS, db = getDb()) {
  if (!state || !codeVerifier || !redirectUri) throw new Error("Incomplete OAuth transaction");
  const browserBinding = crypto.randomBytes(32).toString("base64url");
  db.storeOAuthTransaction({
    state_hash: hash(state),
    code_verifier: codeVerifier,
    redirect_uri: redirectUri,
    return_path: returnPath || "/dashboard",
    invite_code: inviteCode,
    binding_hash: hash(browserBinding),
    created_at: now,
    expires_at: now + ttlMs,
  });
  return { browserBinding, expiresAt: now + ttlMs };
}

export function consumeOAuthTransaction(state, browserBinding, now = Date.now(), db = getDb()) {
  if (!state) return null;
  const tx = db.consumeOAuthTransaction(hash(state), now);
  if (!tx) return null;
  const expected = Buffer.from(tx.binding_hash, "hex");
  const actual = Buffer.from(hash(browserBinding), "hex");
  if (actual.length !== expected.length || !crypto.timingSafeEqual(expected, actual)) {
    return null;
  }
  return {
    codeVerifier: tx.code_verifier,
    redirectUri: tx.redirect_uri,
    returnPath: tx.return_path,
    inviteCode: tx.invite_code,
    expiresAt: tx.expires_at,
  };
}
