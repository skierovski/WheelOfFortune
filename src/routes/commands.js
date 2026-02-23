import { Router } from "express";
import { requireSession } from "../middleware/requireSession.js";
import { getDb } from "../db.js";

const router = Router();

// ── Bot Config ──────────────────────────────────────────────────────

router.get("/dashboard/bot-config", requireSession, (req, res) => {
  const bid = req.session.broadcaster_user_id;
  const config = getDb().getBotConfig(bid);
  res.json({ ok: true, ...config });
});

router.post("/dashboard/bot-config", requireSession, (req, res) => {
  const bid = req.session.broadcaster_user_id;
  const { bot_enabled, announce_prizes, prize_announce_template, wheel_description } = req.body || {};

  if (prize_announce_template != null && typeof prize_announce_template === "string") {
    if (prize_announce_template.length > 500) {
      return res.status(400).json({ ok: false, error: "Prize template too long (max 500)" });
    }
  }
  if (wheel_description != null && typeof wheel_description === "string") {
    if (wheel_description.length > 500) {
      return res.status(400).json({ ok: false, error: "Wheel description too long (max 500)" });
    }
  }

  const saved = getDb().saveBotConfig(bid, {
    bot_enabled: bot_enabled != null ? (bot_enabled ? 1 : 0) : undefined,
    announce_prizes: announce_prizes != null ? (announce_prizes ? 1 : 0) : undefined,
    prize_announce_template,
    wheel_description,
  });
  res.json({ ok: true, ...saved });
});

// ── Custom Commands ─────────────────────────────────────────────────

router.get("/dashboard/commands", requireSession, (req, res) => {
  const bid = req.session.broadcaster_user_id;
  const commands = getDb().getCommands(bid);
  res.json({ ok: true, commands });
});

router.post("/dashboard/commands", requireSession, (req, res) => {
  const bid = req.session.broadcaster_user_id;
  const { command, response, enabled, cooldown_seconds } = req.body || {};

  if (!command || !response) {
    return res.status(400).json({ ok: false, error: "command and response are required" });
  }
  const cmdName = command.startsWith("!") ? command.toLowerCase() : `!${command.toLowerCase()}`;
  if (cmdName === "!prizes" || cmdName === "!wheel") {
    return res.status(400).json({ ok: false, error: `"${cmdName}" is a built-in command and cannot be overridden` });
  }
  if (cmdName.length > 32) {
    return res.status(400).json({ ok: false, error: "Command name too long (max 32)" });
  }
  if (response.length > 500) {
    return res.status(400).json({ ok: false, error: "Response too long (max 500)" });
  }

  try {
    const commands = getDb().addCommand(bid, { command: cmdName, response, enabled, cooldown_seconds });
    res.json({ ok: true, commands });
  } catch (e) {
    if (e?.message?.includes("UNIQUE constraint")) {
      return res.status(409).json({ ok: false, error: `Command "${cmdName}" already exists` });
    }
    throw e;
  }
});

router.put("/dashboard/commands/:id", requireSession, (req, res) => {
  const bid = req.session.broadcaster_user_id;
  const id = Number(req.params.id);
  const { command, response, enabled, cooldown_seconds } = req.body || {};

  if (command) {
    const cmdName = command.startsWith("!") ? command.toLowerCase() : `!${command.toLowerCase()}`;
    if (cmdName === "!prizes" || cmdName === "!wheel") {
      return res.status(400).json({ ok: false, error: `"${cmdName}" is a built-in command` });
    }
    if (cmdName.length > 32) {
      return res.status(400).json({ ok: false, error: "Command name too long (max 32)" });
    }
  }
  if (response && response.length > 500) {
    return res.status(400).json({ ok: false, error: "Response too long (max 500)" });
  }

  const updated = getDb().updateCommand(bid, id, { command, response, enabled, cooldown_seconds });
  if (!updated) return res.status(404).json({ ok: false, error: "Command not found" });
  res.json({ ok: true, command: updated });
});

router.delete("/dashboard/commands/:id", requireSession, (req, res) => {
  const bid = req.session.broadcaster_user_id;
  const id = Number(req.params.id);
  const deleted = getDb().deleteCommand(id, bid);
  if (!deleted) return res.status(404).json({ ok: false, error: "Command not found" });
  res.json({ ok: true });
});

export default router;
