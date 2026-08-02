import { describe, it, expect } from "vitest";
import { resolveGiftSpins } from "../../src/services/giftSpins.js";

describe("resolveGiftSpins", () => {
  it("returns 0 for empty/invalid gift counts", () => {
    expect(resolveGiftSpins({ gifts_per_spin: 5 }, 0)).toEqual({ spinCount: 0, tier: null });
    expect(resolveGiftSpins({ gifts_per_spin: 5 }, -3)).toEqual({ spinCount: 0, tier: null });
  });

  it("legacy mode: floor(gifts / gifts_per_spin)", () => {
    expect(resolveGiftSpins({ gifts_per_spin: 5 }, 30)).toEqual({ spinCount: 6, tier: null });
    expect(resolveGiftSpins({ gifts_per_spin: 5 }, 20)).toEqual({ spinCount: 4, tier: null });
    expect(resolveGiftSpins({ gifts_per_spin: 5 }, 4)).toEqual({ spinCount: 0, tier: null });
    expect(resolveGiftSpins(null, 10)).toEqual({ spinCount: 2, tier: null }); // default 5
  });

  it("tier mode: highest match, divide by that min_gifts", () => {
    const config = {
      tiers: [
        { name: "Basic", min_gifts: 5 },
        { name: "Premium", min_gifts: 10 },
        { name: "Legendary", min_gifts: 25 },
      ],
    };
    expect(resolveGiftSpins(config, 30)).toEqual({ spinCount: 1, tier: "Legendary" }); // floor(30/25)
    expect(resolveGiftSpins(config, 50)).toEqual({ spinCount: 2, tier: "Legendary" });
    expect(resolveGiftSpins(config, 20)).toEqual({ spinCount: 2, tier: "Premium" });
    expect(resolveGiftSpins(config, 9)).toEqual({ spinCount: 1, tier: "Basic" });
    expect(resolveGiftSpins(config, 4)).toEqual({ spinCount: 0, tier: null });
  });

  it("single tier at 5 gifts → many spins for large gift packs", () => {
    const config = { tiers: [{ name: "Default", min_gifts: 5 }] };
    expect(resolveGiftSpins(config, 30)).toEqual({ spinCount: 6, tier: "Default" });
    expect(resolveGiftSpins(config, 20)).toEqual({ spinCount: 4, tier: "Default" });
    expect(resolveGiftSpins(config, 5)).toEqual({ spinCount: 1, tier: "Default" });
  });
});
