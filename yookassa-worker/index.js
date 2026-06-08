// Cloudflare Worker — YooKassa proxy
// Proxies requests to api.yookassa.ru (blocked from EU servers)

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS });
    }

    const url = new URL(request.url);

    if (url.pathname === '/api/yookassa' && request.method === 'POST') {
      return handleYooKassa(request, env);
    }

    return new Response('Not Found', { status: 404 });
  }
};

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

async function handleYooKassa(request, env) {
  const body = await request.json();
  const idempotenceKey = body._idempotence_key || crypto.randomUUID();
  delete body._idempotence_key;

  const auth = btoa(`${env.YOOKASSA_SHOP_ID}:${env.YOOKASSA_SECRET_KEY}`);

  const r = await fetch('https://api.yookassa.ru/v2/payments', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Idempotence-Key': idempotenceKey,
      'Authorization': `Basic ${auth}`,
    },
    body: JSON.stringify(body),
  });

  const data = await r.json();
  return new Response(JSON.stringify(data), {
    status: r.status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}
