import { getDb } from "../db.js";
import { postChatMessage } from "./kick.js";

// Per-command cooldown tracking: Map<"bid:command", lastUsedTimestamp>
const cooldowns = new Map();

const BUILTIN_COMMANDS = new Set(["!prizes", "!wheel"]);
const GLOBAL_COOLDOWN_MS = 2000;
const lastGlobalUse = new Map();

function isOnCooldown(key, cooldownMs) {
  const last = cooldowns.get(key) || 0;
  return Date.now() - last < cooldownMs;
}

function setCooldown(key) {
  cooldowns.set(key, Date.now());
}

function isGlobalCooldown(bid) {
  const last = lastGlobalUse.get(bid) || 0;
  return Date.now() - last < GLOBAL_COOLDOWN_MS;
}

function setGlobalCooldown(bid) {
  lastGlobalUse.set(bid, Date.now());
}

function formatPrizeList(config) {
  const tiers = config?.tiers;
  if (Array.isArray(tiers) && tiers.length > 0) {
    const parts = [];
    for (const tier of tiers) {
      const labels = (tier.items || []).map((i) => i.label).filter(Boolean);
      if (labels.length > 0) {
        parts.push(`[${tier.name}] ${labels.join(", ")}`);
      }
    }
    const full = parts.join(" | ");
    if (full.length <= 500) return full;
    return full.slice(0, 497) + "...";
  }
  const items = config?.items;
  if (Array.isArray(items) && items.length > 0) {
    const labels = items.map((i) => i.label).filter(Boolean);
    const full = `Prizes: ${labels.join(", ")}`;
    if (full.length <= 500) return full;
    return full.slice(0, 497) + "...";
  }
  return "No prizes configured yet.";
}

/**
 * Handle an incoming chat message and respond if it matches a command.
 * Designed to be called fire-and-forget (no await needed by caller).
 */
export async function handleChatMessage(broadcasterId, senderUsername, content) {
  try {
    const db = getDb();
    const botConfig = db.getBotConfig(broadcasterId);

    if (!botConfig.bot_enabled) return;

    const raw = content.trim();
    if (!raw.startsWith("!")) return;

    const command = raw.split(/\s+/)[0].toLowerCase();

    if (isGlobalCooldown(broadcasterId)) return;

    // Built-in: !prizes
    if (command === "!prizes") {
      const cdKey = `${broadcasterId}:!prizes`;
      if (isOnCooldown(cdKey, 10_000)) return;
      setCooldown(cdKey);
      setGlobalCooldown(broadcasterId);

      const config = db.getConfig(broadcasterId);
      const msg = formatPrizeList(config);
      await postChatMessage(broadcasterId, msg);
      return;
    }

    // Built-in: !wheel
    if (command === "!wheel") {
      const cdKey = `${broadcasterId}:!wheel`;
      if (isOnCooldown(cdKey, 10_000)) return;
      setCooldown(cdKey);
      setGlobalCooldown(broadcasterId);

      const desc = botConfig.wheel_description || "Wheel of Fortune!";
      await postChatMessage(broadcasterId, desc.slice(0, 500));
      return;
    }

    // Custom commands
    const commands = db.getEnabledCommands(broadcasterId);
    const match = commands.find((c) => c.command === command);
    if (!match) return;

    const cdKey = `${broadcasterId}:${match.command}`;
    const cdMs = (match.cooldown_seconds || 5) * 1000;
    if (isOnCooldown(cdKey, cdMs)) return;
    setCooldown(cdKey);
    setGlobalCooldown(broadcasterId);

    await postChatMessage(broadcasterId, match.response.slice(0, 500));
  } catch (e) {
    console.warn(`[chatBot] error bid=${broadcasterId}:`, e?.message || e);
  }
}

/**
 * Send a prize announcement to chat if enabled.
 */
export async function announcePrize(broadcasterId, prizeLabel) {
  try {
    const db = getDb();
    const botConfig = db.getBotConfig(broadcasterId);

    if (!botConfig.bot_enabled || !botConfig.announce_prizes) return;

    const template = botConfig.prize_announce_template || "The wheel landed on: {prize}!";
    const msg = template.replace(/\{prize\}/g, prizeLabel).slice(0, 500);
    await postChatMessage(broadcasterId, msg);
  } catch (e) {
    console.warn(`[chatBot] announce error bid=${broadcasterId}:`, e?.message || e);
  }
}
