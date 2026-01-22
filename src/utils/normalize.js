function genId(){ return 'itm_' + Math.random().toString(36).slice(2,10) + Date.now().toString(36); }

export function normalizeItemsInt100(list) {
  const items = Array.isArray(list) ? list : [];
  const n = items.length;
  if (!n) return [];

  const raw = items.map(it => ({ ...it, weight: Math.max(0, Number(it.weight)||0) }));
  const sumRaw = raw.reduce((s, it) => s + it.weight, 0);

  if (sumRaw <= 0) {
    const base = Math.floor(100 / n), rest = 100 - base * n;
    return items.map((it, i) => ({
      id: it.id || genId(),
      label: String(it.label||"").trim(),
      bonus: Boolean(it.bonus),
      weight: base + (i < rest ? 1 : 0)
    }));
  }

  const scaled = raw.map((it, idx) => {
    const v = (it.weight / sumRaw) * 100;
    return { idx, v, floor: Math.floor(v), frac: v - Math.floor(v) };
  });
  let total = scaled.reduce((s, x) => s + x.floor, 0);
  let remain = 100 - total;

  scaled.sort((a, b) => b.frac - a.frac);
  for (let i = 0; i < scaled.length && remain > 0; i++, remain--) scaled[i].floor += 1;

  let debt = 0;
  for (const x of scaled) { if (x.floor < 1) { debt += (1 - x.floor); x.floor = 1; } }
  if (debt > 0) {
    scaled.sort((a, b) => (a.frac - b.frac) || (a.floor - b.floor));
    for (let i = 0; i < scaled.length && debt > 0; i++) {
      if (scaled[i].floor > 1) { scaled[i].floor -= 1; debt--; i = -1; }
    }
  }

  scaled.sort((a, b) => a.idx - b.idx);
  return items.map((it, i) => ({
    id: it.id || genId(),
    label: String(it.label || "").trim(),
    bonus: Boolean(it.bonus),
    weight: Math.max(1, scaled[i].floor)
  }));
}
