import fs from "fs";
import path from "path";
import { env } from "../utils/env.js";
import { normalizeItemsInt100 } from "../utils/normalize.js";

function ensureDirFor(filePath) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}
function loadJsonSafe(file, fallback) {
  try { if (!fs.existsSync(file)) return fallback; return JSON.parse(fs.readFileSync(file,"utf8")); }
  catch { return fallback; }
}

export function loadConfig() {
  const obj = loadJsonSafe(env.CFG_PATH, null);
  if (!obj) return null;
  const items = Array.isArray(obj.items) ? obj.items : null;
  const theme = typeof obj.theme === "string" ? obj.theme : "wood";
  return { items, theme };
}
export function saveConfig(items, themeMaybe) {
  ensureDirFor(env.CFG_PATH);
  const normalized = normalizeItemsInt100(items);
  const prev = loadJsonSafe(env.CFG_PATH, {});
  const theme = typeof themeMaybe === "string" ? themeMaybe : (prev?.theme || "wood");
  fs.writeFileSync(env.CFG_PATH, JSON.stringify({ items: normalized, theme }, null, 2));
  console.log(`[config] saved ${normalized.length} items (int% to 100) theme=${theme} -> ${env.CFG_PATH}`);
  return { items: normalized, theme };
}

export function loadGoals() {
  const arr = loadJsonSafe(env.GOALS_PATH, []);
  return Array.isArray(arr) ? arr : [];
}
export function saveGoals(arr) {
  ensureDirFor(env.GOALS_PATH);
  const list = Array.isArray(arr) ? arr.map(String) : [];
  fs.writeFileSync(env.GOALS_PATH, JSON.stringify(list, null, 2));
  console.log(`[goals] saved ${list.length} goals -> ${env.GOALS_PATH}`);
  return list;
}
