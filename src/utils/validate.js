const ALLOWED_THEMES = ["wood", "classic"];
const MAX_LABEL_LENGTH = 100;
const MAX_ITEMS = 100;

/**
 * Strip HTML tags from a string.
 */
function stripHtml(str) {
  return String(str || "").replace(/<[^>]*>/g, "");
}

/**
 * Validate and sanitize wheel items from user input.
 * @param {Array} items  Raw items from request body
 * @returns {{ valid: boolean, items?: Array, error?: string }}
 */
export function validateWheelItems(items) {
  if (!Array.isArray(items)) {
    return { valid: false, error: "items must be an array" };
  }
  if (items.length === 0) {
    return { valid: false, error: "items cannot be empty" };
  }
  if (items.length > MAX_ITEMS) {
    return { valid: false, error: `Maximum ${MAX_ITEMS} items allowed` };
  }

  const sanitized = items.map((item) => ({
    id: item.id ? String(item.id).slice(0, 50) : undefined,
    label: stripHtml(item.label).slice(0, MAX_LABEL_LENGTH).trim(),
    weight: Math.max(0, Number(item.weight) || 0),
    bonus: Boolean(item.bonus),
  }));

  // Check all labels are non-empty
  for (const item of sanitized) {
    if (!item.label) {
      return { valid: false, error: "All items must have a non-empty label" };
    }
  }

  return { valid: true, items: sanitized };
}

/**
 * Validate theme name.
 * @param {string} theme
 * @returns {string} Validated theme or default "wood"
 */
export function validateTheme(theme) {
  if (typeof theme !== "string") return "wood";
  return ALLOWED_THEMES.includes(theme) ? theme : "wood";
}

/**
 * Validate overlay key format.
 * @param {string} key
 * @returns {boolean}
 */
export function isValidOverlayKey(key) {
  return typeof key === "string" && /^[A-Za-z0-9_-]{20,30}$/.test(key);
}
