/**
 * Gothic Reader — Express backend
 *
 * Storage: SQLite via better-sqlite3 (single file, zero deps)
 * Secrets: .env file (see .env.example)
 *
 * Endpoints:
 *   POST /api/claude          — proxy Claude call, deduct 1 credit
 *   GET  /api/credits?uid=…   — return credit balance
 *   POST /api/checkout        — create Stripe Checkout session
 *   POST /api/stripe-webhook  — Stripe webhook → top-up credits
 *   GET  /*                   — serve index.html
 */

import express from 'express';
import Database from 'better-sqlite3';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import 'dotenv/config';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

// ── Database ──────────────────────────────────────────────────────────────────

const db = new Database(process.env.DB_PATH || 'credits.db');
db.exec(`CREATE TABLE IF NOT EXISTS credits (uid TEXT PRIMARY KEY, balance INTEGER NOT NULL DEFAULT 0)`);

const getCredits = db.prepare(`SELECT balance FROM credits WHERE uid = ?`);
const upsertCredits = db.prepare(`
  INSERT INTO credits (uid, balance) VALUES (?, ?)
  ON CONFLICT(uid) DO UPDATE SET balance = excluded.balance
`);

function fetchBalance(uid) {
  return getCredits.get(uid)?.balance ?? 0;
}
function saveBalance(uid, n) {
  upsertCredits.run(uid, n);
}

// ── Packages ──────────────────────────────────────────────────────────────────

const PACKAGES = {
  pages_100:  { credits: 100,  price_id: process.env.STRIPE_PRICE_100  || 'price_100_REPLACE_ME'  },
  pages_500:  { credits: 500,  price_id: process.env.STRIPE_PRICE_500  || 'price_500_REPLACE_ME'  },
  pages_1000: { credits: 1000, price_id: process.env.STRIPE_PRICE_1000 || 'price_1000_REPLACE_ME' },
};

// ── Middleware ────────────────────────────────────────────────────────────────

app.use((req, res, next) => {
  res.set({
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-User-Id',
  });
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// Stripe webhook needs raw body for signature verification — register before json()
app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), handleWebhook);

app.use(express.json({ limit: '20mb' }));

// ── Routes ────────────────────────────────────────────────────────────────────

app.post('/api/claude',    handleClaude);
app.get('/api/credits',    handleCredits);
app.post('/api/checkout',  handleCheckout);

// Serve the frontend for all other routes
app.use(express.static(__dirname));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// ── Handlers ──────────────────────────────────────────────────────────────────

async function handleClaude(req, res) {
  const uid = req.headers['x-user-id'];
  if (!uid) return res.status(401).json({ error: 'Missing X-User-Id' });

  const credits = fetchBalance(uid);
  if (credits <= 0) return res.status(402).json({ error: 'no_credits' });

  saveBalance(uid, credits - 1);

  try {
    const upstream = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(req.body),
    });

    const data = await upstream.json();
    if (!upstream.ok) {
      saveBalance(uid, credits); // refund
      return res.status(upstream.status).json(data);
    }

    res.json({ ...data, credits_remaining: credits - 1 });
  } catch (err) {
    saveBalance(uid, credits); // refund
    res.status(502).json({ error: err.message });
  }
}

async function handleCredits(req, res) {
  const { uid } = req.query;
  if (!uid) return res.status(400).json({ error: 'Missing uid' });
  res.json({ credits: fetchBalance(uid) });
}

async function handleCheckout(req, res) {
  const { uid, package_id, success_url, cancel_url } = req.body;
  const pkg = PACKAGES[package_id];
  if (!pkg) return res.status(400).json({ error: 'Unknown package' });
  if (!uid)  return res.status(400).json({ error: 'Missing uid' });

  try {
    const r = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Bearer ${process.env.STRIPE_SECRET_KEY}`,
      },
      body: new URLSearchParams({
        'payment_method_types[]':  'card',
        'line_items[0][price]':    pkg.price_id,
        'line_items[0][quantity]': '1',
        'mode': 'payment',
        'success_url': success_url || 'https://fraktur.app/?payment=ok',
        'cancel_url':  cancel_url  || 'https://fraktur.app/?payment=cancel',
        'metadata[uid]':          uid,
        'metadata[package_id]':   package_id,
        'automatic_tax[enabled]': 'true',
      }),
    });

    const session = await r.json();
    if (!r.ok) return res.status(r.status).json(session);
    res.json({ url: session.url });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
}

async function handleWebhook(req, res) {
  const sig    = req.headers['stripe-signature'];
  const body   = req.body; // raw Buffer

  if (!verifyStripeSignature(body, sig, process.env.STRIPE_WEBHOOK_SECRET)) {
    return res.status(400).send('Bad signature');
  }

  const event = JSON.parse(body.toString());
  if (event.type === 'checkout.session.completed') {
    const { uid, package_id } = event.data.object.metadata || {};
    const pkg = PACKAGES[package_id];
    if (uid && pkg) {
      const current = fetchBalance(uid);
      saveBalance(uid, current + pkg.credits);
      console.log(`[credits] ${uid}: +${pkg.credits} → ${current + pkg.credits}`);
    }
  }

  res.send('OK');
}

// ── Stripe HMAC-SHA256 verification ──────────────────────────────────────────

function verifyStripeSignature(body, header, secret) {
  if (!header || !secret) return false;
  const parts = Object.fromEntries(header.split(',').map(p => p.split('=')));
  const { t: ts, v1 } = parts;
  if (!ts || !v1) return false;

  const payload = `${ts}.${body}`;
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(v1));
}

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => console.log(`gothic-reader listening on :${PORT}`));
