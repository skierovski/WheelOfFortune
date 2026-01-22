import express from "express";
import bodyParser from "body-parser";
import path from "path";
import { fileURLToPath } from "url";
import { accessLog } from "./middleware/logging.js";
import { csp } from "./middleware/csp.js";
import indexRoutes from "./routes/index.js";
import authRoutes from "./routes/auth.js";
import configRoutes from "./routes/config.js";
import subscribeRoutes from "./routes/subscribe.js";
import webhookRoutes from "./routes/webhook.js";
import spinsRoutes from "./routes/spins.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const app = express();
app.set("trust proxy", 1);

// middleware
app.use(accessLog);
app.use(csp);
app.use(bodyParser.json());

// statyki
app.use(express.static(path.join(process.cwd(), "public")));

// routes
app.use(indexRoutes);
app.use(authRoutes);
app.use(configRoutes);
app.use(subscribeRoutes);
app.use(webhookRoutes);
app.use(spinsRoutes);
