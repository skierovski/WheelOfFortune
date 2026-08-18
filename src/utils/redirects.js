const CONTROL_OR_SEPARATOR = /[\\\u0000-\u001f\u007f]/;

/**
 * Accept only an application-internal path. Protocol-relative URLs, encoded
 * separators and control characters are rejected before URL parsing.
 */
export function safeReturnPath(value, fallback = "/dashboard") {
  if (typeof value !== "string") return fallback;
  const raw = value.trim();
  if (!raw.startsWith("/") || raw.startsWith("//") || CONTROL_OR_SEPARATOR.test(raw)) {
    return fallback;
  }

  let decoded;
  try {
    decoded = decodeURIComponent(raw);
  } catch {
    return fallback;
  }
  if (!decoded.startsWith("/") || decoded.startsWith("//") || CONTROL_OR_SEPARATOR.test(decoded)) {
    return fallback;
  }

  try {
    const parsed = new URL(decoded, "https://app.invalid");
    if (parsed.origin !== "https://app.invalid") return fallback;
    return `${parsed.pathname}${parsed.search}${parsed.hash}`;
  } catch {
    return fallback;
  }
}
