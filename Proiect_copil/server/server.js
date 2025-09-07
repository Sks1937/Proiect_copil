// server/server.js
import "dotenv/config";
import express from "express";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import argon2 from "argon2";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";
import db from "./db.js";

// __dirname pentru ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// inițializează aplicația
const app = express();

// securitate & parsere
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(cookieParser());

// servește frontend-ul din folderul /public (același origin cu API-ul)
app.use(express.static(path.join(__dirname, "public")));

const limiter = rateLimit({ windowMs: 60_000, max: 60 });
const authLimiter = rateLimit({ windowMs: 60_000, max: 10 });
app.use(limiter);

// chei
const JWT_SECRET = Buffer.from(process.env.JWT_SECRET, "hex");
const ENC_KEY   = Buffer.from(process.env.EMAIL_ENC_KEY, "hex");  // 32B
const HMAC_KEY  = Buffer.from(process.env.EMAIL_HMAC_KEY, "hex");

// utilitare
function emailIndex(email) {
  return crypto.createHmac("sha256", HMAC_KEY)
    .update(email.trim().toLowerCase())
    .digest("hex");
}
function encryptEmail(email) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", ENC_KEY, iv);
  const enc = Buffer.concat([cipher.update(email, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    email_enc: enc.toString("base64"),
    email_iv: iv.toString("base64"),
    email_tag: tag.toString("base64"),
  };
}
function signAuthJWT(userId) {
  return jwt.sign({ uid: userId }, JWT_SECRET, { algorithm: "HS256", expiresIn: "30m" });
}
function setAuthCookie(res, token) {
  res.cookie("sid", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV !== "development", // true în producție (HTTPS)
    sameSite: "strict",
    path: "/",
    maxAge: 30 * 60 * 1000,
  });
}

// DB statements
const getByEmailHmac = db.prepare("SELECT * FROM users WHERE email_hmac = ?");
const insertUser = db.prepare(`
  INSERT INTO users (id, email_hmac, email_enc, email_iv, email_tag, password_hash, created_at)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`);

// middleware auth
function authRequired(req, res, next) {
  const token = req.cookies?.sid;
  if (!token) return res.status(401).json({ error: "Unauthenticated" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = { id: payload.uid };
    next();
  } catch {
    return res.status(401).json({ error: "Invalid session" });
  }
}

// rute API
app.post("/api/signup", authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (typeof email !== "string" || typeof password !== "string")
    return res.status(400).json({ error: "Invalid payload" });
  if (password.length < 12)
    return res.status(400).json({ error: "Parola trebuie să aibă minim 12 caractere" });

  const idx = emailIndex(email);
  const existing = getByEmailHmac.get(idx);
  if (existing) return res.status(409).json({ error: "Email deja folosit" });

  const password_hash = await argon2.hash(password, {
    type: argon2.argon2id, memoryCost: 19456, timeCost: 3, parallelism: 1
  });
  const enc = encryptEmail(email);
  const id = crypto.randomUUID();
  insertUser.run(id, idx, enc.email_enc, enc.email_iv, enc.email_tag, password_hash, new Date().toISOString());

  setAuthCookie(res, signAuthJWT(id));   // auto-login după signup
  return res.status(201).json({ ok: true });
});

app.post("/api/login", authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (typeof email !== "string" || typeof password !== "string")
    return res.status(400).json({ error: "Invalid payload" });

  const user = getByEmailHmac.get(emailIndex(email));
  if (!user) return res.status(401).json({ error: "Credențiale invalide" });

  const ok = await argon2.verify(user.password_hash, password);
  if (!ok) return res.status(401).json({ error: "Credențiale invalide" });

  setAuthCookie(res, signAuthJWT(user.id));
  return res.json({ ok: true });
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("sid", { path: "/" });
  return res.json({ ok: true });
});

app.get("/api/me", authRequired, (req, res) => {
  return res.json({ id: req.user.id });
});

app.get("/api/ping", (req, res) => res.json({ ok: true }));

// start
app.listen(process.env.PORT, () =>
  console.log(`Auth API on http://localhost:${process.env.PORT}`)
);
