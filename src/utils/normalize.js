function genId() {
  return `itm_${Math.random().toString(36).slice(2, 10)}${Date.now().toString(36)}`;
}

const CHANCE_UNITS = 1000;

/** Normalize chances to exactly 100.0%, preserving entries explicitly set to 0%. */
export function normalizeItemsInt100(list) {
  const items = Array.isArray(list) ? list : [];
  if (!items.length) return [];

  const raw = items.map((item) => Math.max(0, Number(item?.weight) || 0));
  const total = raw.reduce((sum, weight) => sum + weight, 0);
  const source = total > 0 ? raw : raw.map(() => 1);
  const sourceTotal = source.reduce((sum, weight) => sum + weight, 0);
  const scaled = source.map((weight, index) => {
    const exact = weight / sourceTotal * CHANCE_UNITS;
    return { index, units: Math.floor(exact), remainder: exact - Math.floor(exact) };
  });

  let remaining = CHANCE_UNITS - scaled.reduce((sum, item) => sum + item.units, 0);
  const order = [...scaled].sort((a, b) => b.remainder - a.remainder || a.index - b.index);
  for (let index = 0; remaining > 0; index = (index + 1) % order.length) {
    order[index].units += 1;
    remaining -= 1;
  }
  scaled.sort((a, b) => a.index - b.index);

  return items.map((item, index) => ({
    id: item.id || genId(),
    label: String(item.label || "").trim(),
    bonus: Boolean(item.bonus),
    weight: scaled[index].units / 10,
  }));
}
