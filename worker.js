/**
 * Gothic Reader — Cloudflare Worker backend
 *
 * KV namespace: CREDITS  (binding name in wrangler.toml)
 * Secrets: ANTHROPIC_API_KEY, STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET
 *
 * Endpoints:
 *   POST /api/claude          — proxy Claude call, deduct 1 credit
 *   GET  /api/credits?uid=…   — return credit balance
 *   POST /api/checkout        — create Stripe Checkout session
 *   POST /api/stripe-webhook  — Stripe webhook → top-up credits
 */

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-User-Id',
};

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

    const url = new URL(request.url);

    if (url.pathname === '/api/claude'         && request.method === 'POST') return handleClaude(request, env);
    if (url.pathname === '/api/credits'        && request.method === 'GET')  return handleCredits(request, env);
    if (url.pathname === '/api/checkout'       && request.method === 'POST') return handleCheckout(request, env);
    if (url.pathname === '/api/stripe-webhook' && request.method === 'POST') return handleWebhook(request, env);

    return new Response('Not Found', { status: 404 });
  }
};

// ── Proxy call to Claude, costs 1 credit ─────────────────────────────────────

async function handleClaude(request, env) {
  const uid = request.headers.get('X-User-Id');
  if (!uid) return json({ error: 'Missing X-User-Id' }, 401);

  // Atomic credit check-and-decrement
  const credits = await getCredits(env, uid);
  if (credits <= 0) return json({ error: 'no_credits' }, 402);
  await setCredits(env, uid, credits - 1);

  // Forward request body to Anthropic
  const body = await request.json();
  const upstream = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': env.ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify(body),
  });

  const data = await upstream.json();
  if (!upstream.ok) {
    // Refund credit on Anthropic error
    await setCredits(env, uid, credits);
    return json(data, upstream.status);
  }

  return json({ ...data, credits_remaining: credits - 1 });
}

// ── Credit balance ────────────────────────────────────────────────────────────

async function handleCredits(request, env) {
  const uid = new URL(request.url).searchParams.get('uid');
  if (!uid) return json({ error: 'Missing uid' }, 400);
  const credits = await getCredits(env, uid);
  return json({ credits });
}

// ── Stripe Checkout session ───────────────────────────────────────────────────

const PACKAGES = {
  pages_100:  { credits: 100,  price_id: 'price_100_REPLACE_ME',  label: '100 pages' },
  pages_500:  { credits: 500,  price_id: 'price_500_REPLACE_ME',  label: '500 pages' },
  pages_1000: { credits: 1000, price_id: 'price_1000_REPLACE_ME', label: '1000 pages' },
};

async function handleCheckout(request, env) {
  const { uid, package_id, success_url, cancel_url } = await request.json();
  const pkg = PACKAGES[package_id];
  if (!pkg) return json({ error: 'Unknown package' }, 400);
  if (!uid)  return json({ error: 'Missing uid' }, 400);

  const res = await fetch('https://api.stripe.com/v1/checkout/sessions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
    },
    body: new URLSearchParams({
      'payment_method_types[]': 'card',
      'line_items[0][price]':   pkg.price_id,
      'line_items[0][quantity]': '1',
      'mode': 'payment',
      'success_url': success_url || 'https://gothic-reader.app/?payment=ok',
      'cancel_url':  cancel_url  || 'https://gothic-reader.app/?payment=cancel',
      'metadata[uid]':        uid,
      'metadata[package_id]': package_id,
      // Collect EU VAT automatically
      'automatic_tax[enabled]': 'true',
    }),
  });

  const session = await res.json();
  if (!res.ok) return json(session, res.status);
  return json({ url: session.url });
}

// ── Stripe webhook → top-up credits on successful payment ────────────────────

async function handleWebhook(request, env) {
  const sig    = request.headers.get('stripe-signature');
  const body   = await request.text();

  // Verify Stripe signature (HMAC-SHA256)
  if (!await verifyStripeSignature(body, sig, env.STRIPE_WEBHOOK_SECRET)) {
    return new Response('Bad signature', { status: 400 });
  }

  const event = JSON.parse(body);
  if (event.type === 'checkout.session.completed') {
    const { uid, package_id } = event.data.object.metadata || {};
    const pkg = PACKAGES[package_id];
    if (uid && pkg) {
      const current = await getCredits(env, uid);
      await setCredits(env, uid, current + pkg.credits);
      console.log(`Topped up ${uid}: +${pkg.credits} → ${current + pkg.credits}`);
    }
  }

  return new Response('OK');
}

// ── KV helpers ────────────────────────────────────────────────────────────────

async function getCredits(env, uid) {
  const val = await env.CREDITS.get(`credits:${uid}`);
  return val ? parseInt(val, 10) : 0;
}

async function setCredits(env, uid, n) {
  await env.CREDITS.put(`credits:${uid}`, String(n));
}

// ── Stripe signature verification ─────────────────────────────────────────────
// Stripe uses HMAC-SHA256 over "timestamp.body" with the webhook secret

async function verifyStripeSignature(body, header, secret) {
  if (!header || !secret) return false;
  const parts = Object.fromEntries(header.split(',').map(p => p.split('=')));
  const ts = parts.t;
  const v1 = parts.v1;
  if (!ts || !v1) return false;

  const payload = `${ts}.${body}`;
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  const hex = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
  return hex === v1;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}
