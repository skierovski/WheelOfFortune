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
 * Validate and clamp gifts_per_spin value.
 * @param {*} value
 * @returns {number} Clamped value between 1 and 100, default 5
 */
export function validateGiftsPerSpin(value) {
  if (value == null || value === "") return 5;
  const n = Number(value);
  if (!Number.isFinite(n)) return 5;
  return Math.max(1, Math.min(100, Math.round(n)));
}

/**
 * Validate accent color (hex format).
 * @param {string} color
 * @returns {string} Valid hex color or default
 */
export function validateAccentColor(color) {
  if (typeof color !== "string") return "#7c3aed";
  const trimmed = color.trim();
  return /^#[0-9a-fA-F]{6}$/.test(trimmed) ? trimmed : "#7c3aed";
}

/**
 * Validate secondary color (hex format).
 * @param {string} color
 * @returns {string} Valid hex color or default
 */
export function validateSecondaryColor(color) {
  if (typeof color !== "string") return "#121228";
  const trimmed = color.trim();
  return /^#[0-9a-fA-F]{6}$/.test(trimmed) ? trimmed : "#121228";
}

/**
 * Validate wheel opacity (0.1 to 1.0).
 * @param {*} value
 * @returns {number} Clamped value between 0.1 and 1.0, default 0.9
 */
export function validateWheelOpacity(value) {
  if (value == null || value === "") return 0.9;
  const n = Number(value);
  if (!Number.isFinite(n)) return 0.9;
  return Math.round(Math.max(0.1, Math.min(1.0, n)) * 100) / 100;
}

/**
 * Validate prize tiers array from user input.
 * @param {Array} tiers  Raw tiers array
 * @returns {{ valid: boolean, tiers?: Array, error?: string }}
 */
export function validateTiers(tiers) {
  if (!Array.isArray(tiers)) {
    return { valid: false, error: "tiers must be an array" };
  }
  if (tiers.length === 0) {
    return { valid: false, error: "At least one tier is required" };
  }
  if (tiers.length > 10) {
    return { valid: false, error: "Maximum 10 tiers allowed" };
  }

  const validated = [];
  const names = new Set();

  for (let i = 0; i < tiers.length; i++) {
    const t = tiers[i];
    const name = stripHtml(String(t?.name || `Tier ${i + 1}`)).slice(0, 50).trim();
    if (!name) {
      return { valid: false, error: `Tier ${i + 1}: name cannot be empty` };
    }
    if (names.has(name.toLowerCase())) {
      return { valid: false, error: `Duplicate tier name: "${name}"` };
    }
    names.add(name.toLowerCase());

    const minGifts = Math.round(Number(t?.min_gifts));
    if (!Number.isFinite(minGifts) || minGifts < 1 || minGifts > 1000) {
      return { valid: false, error: `Tier "${name}": min_gifts must be between 1 and 1000` };
    }

    const itemsResult = validateWheelItems(t?.items);
    if (!itemsResult.valid) {
      return { valid: false, error: `Tier "${name}": ${itemsResult.error}` };
    }

    validated.push({ name, min_gifts: minGifts, items: itemsResult.items });
  }

  // Sort by min_gifts ascending
  validated.sort((a, b) => a.min_gifts - b.min_gifts);

  return { valid: true, tiers: validated };
}

/**
 * Validate overlay key format.
 * @param {string} key
 * @returns {boolean}
 */
export function isValidOverlayKey(key) {
  return typeof key === "string" && /^[A-Za-z0-9_-]{20,30}$/.test(key);
}
