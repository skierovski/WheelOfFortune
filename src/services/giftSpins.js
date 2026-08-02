/**
 * Convert a gift event into wheel spin count + optional tier name.
 *
 * Tier mode (A): highest tier where giftCount >= min_gifts,
 * then spinCount = floor(giftCount / that tier's min_gifts).
 * Legacy mode: floor(giftCount / gifts_per_spin).
 *
 * @param {{ tiers?: Array|{name:string,min_gifts:number}[], gifts_per_spin?: number } | null} config
 * @param {number} giftCount
 * @returns {{ spinCount: number, tier: string|null }}
 */
export function resolveGiftSpins(config, giftCount) {
  const gifts = Math.max(0, Math.round(Number(giftCount) || 0));
  if (gifts <= 0) return { spinCount: 0, tier: null };

  const tiers = Array.isArray(config?.tiers) ? config.tiers : null;
  if (tiers && tiers.length > 0) {
    let matched = null;
    for (let i = tiers.length - 1; i >= 0; i--) {
      const min = Math.max(1, Math.round(Number(tiers[i]?.min_gifts) || 1));
      if (gifts >= min) {
        matched = { name: String(tiers[i]?.name || "Default"), min_gifts: min };
        break;
      }
    }
    if (!matched) return { spinCount: 0, tier: null };
    return {
      spinCount: Math.floor(gifts / matched.min_gifts),
      tier: matched.name,
    };
  }

  const giftsPerSpin = Math.max(1, Math.round(Number(config?.gifts_per_spin) || 5));
  return {
    spinCount: Math.floor(gifts / giftsPerSpin),
    tier: null,
  };
}
