/**
 * Minimal auth state derived from stored Kick OAuth tokens.
 * If tokens are missing, overlays should show a re-login warning.
 */
export function getOverlayAuthStatus(streamer) {
  const auth_ok = Boolean(streamer?.access_token && streamer?.refresh_token);
  return {
    auth_ok,
    auth_message: auth_ok ? "" : "Re-login re auth",
  };
}
