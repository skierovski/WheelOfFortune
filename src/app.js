import express from "express";
import bodyParser from "body-parser";
import path from "path";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { accessLog } from "./middleware/logging.js";
import indexRoutes from "./routes/index.js";
import authRoutes from "./routes/auth.js";
import configRoutes from "./routes/config.js";
import subscribeRoutes from "./routes/subscribe.js";
import webhookRoutes from "./routes/webhook.js";
import spinsRoutes from "./routes/spins.js";
import adminRoutes from "./routes/admin.js";

export const app = express();
app.set("trust proxy", 1);

// ── Security headers via helmet ─────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'", "https:", "wss:", "http:", "ws:"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
      fontSrc: ["'self'", "data:"],
    },
  },
  // Allow OBS to embed overlay pages in iframes
  frameguard: false,
}));

// ── Request logging ─────────────────────────────────────────────────
app.use(accessLog);

// ── Rate limiting ───────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { ok: false, error: "Too many requests, try again later" },
  standardHeaders: true,
  legacyHeaders: false,
});

const webhookLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: "Too many requests",
  standardHeaders: true,
  legacyHeaders: false,
});

const dashboardLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { ok: false, error: "Too many requests" },
  standardHeaders: true,
  legacyHeaders: false,
});

const overlayLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  message: { ok: false, error: "Too many requests" },
  standardHeaders: true,
  legacyHeaders: false,
});

// ── Static files ────────────────────────────────────────────────────
// Disable automatic index.html serving so our "/" route handles the landing page
app.use(express.static(path.join(process.cwd(), "public"), { index: false }));

// ── Routes ──────────────────────────────────────────────────────────

// Webhook: MUST come before bodyParser.json() (needs raw body for signature)
app.use("/webhook", webhookLimiter);
app.use(webhookRoutes);

// JSON body parser for everything else
app.use(bodyParser.json());

// Auth routes (rate limited)
app.use("/auth", authLimiter);
app.use(authRoutes);

// Overlay routes (rate limited)
app.use("/overlay", overlayLimiter);

// Dashboard routes (rate limited)
app.use("/dashboard", dashboardLimiter);

// All routes
app.use(indexRoutes);
app.use(configRoutes);
app.use(subscribeRoutes);
app.use(spinsRoutes);
app.use(adminRoutes);
