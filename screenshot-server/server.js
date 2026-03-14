/**
 * Gothic Reader — Screenshot Server
 *
 * Запуск:
 *   npm install
 *   npx playwright install chromium
 *   npm start
 *
 * После запуска сервер слушает на http://localhost:3001
 * Фронтенд автоматически определяет его наличие и использует скриншоты
 * вместо прямой загрузки изображений (обходит Anubis bot-protection).
 */

const express = require('express');
const { chromium } = require('playwright');

const PORT = process.env.PORT || 3001;
const ALLOWED_ORIGINS = [
  'https://rbevzenko.github.io',
  'http://localhost',
  'http://127.0.0.1',
  null, // file:// and same-origin requests
];

const app = express();

// CORS — разрешаем запросы от GitHub Pages и localhost
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (!origin || ALLOWED_ORIGINS.some(o => o && origin.startsWith(o)) || origin.startsWith('http://localhost') || origin.startsWith('http://127.0.0.1')) {
    res.header('Access-Control-Allow-Origin', origin || '*');
  }
  res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// GET /ping — проверка доступности сервера
app.get('/ping', (req, res) => {
  res.json({ ok: true });
});

// GET /screenshot?url=<url>&width=1280&height=900
// Возвращает JPEG-скриншот страницы после полной загрузки (включая решение Anubis-challenge)
app.get('/screenshot', async (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) {
    return res.status(400).json({ error: 'Missing url parameter' });
  }

  // Ограничиваем только dlc.mpg.de во избежание SSRF
  try {
    const parsed = new URL(targetUrl);
    if (!parsed.hostname.endsWith('dlc.mpg.de')) {
      return res.status(403).json({ error: 'Only dlc.mpg.de URLs are allowed' });
    }
  } catch {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  const width  = Math.min(parseInt(req.query.width  || '1280', 10), 1920);
  const height = Math.min(parseInt(req.query.height || '900',  10), 1200);

  let browser;
  try {
    browser = await chromium.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
    });

    const context = await browser.newContext({
      viewport: { width, height },
      // Реальный User-Agent чтобы Anubis не заблокировал как явного бота
      userAgent:
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' +
        'AppleWebKit/537.36 (KHTML, like Gecko) ' +
        'Chrome/124.0.0.0 Safari/537.36',
      locale: 'ru-RU',
    });

    const page = await context.newPage();

    // Переходим на страницу; ждём завершения сетевых запросов
    await page.goto(targetUrl, { waitUntil: 'networkidle', timeout: 45000 });

    // Если Anubis показал challenge — ждём пока он не решится
    // (Playwright выполняет JS, поэтому PoW решается автоматически)
    const isChallenge = await page.$('#status').catch(() => null);
    if (isChallenge) {
      console.log('[screenshot] Anubis challenge detected, waiting...');
      await page.waitForFunction(
        () => {
          const el = document.querySelector('#status');
          return !el || el.textContent.toLowerCase().includes('done') || el.textContent === '';
        },
        { timeout: 30000 }
      ).catch(() => {});
      // Дополнительная пауза после решения challenge
      await page.waitForLoadState('networkidle', { timeout: 15000 }).catch(() => {});
    }

    const screenshot = await page.screenshot({ type: 'jpeg', quality: 88 });
    await browser.close();
    browser = null;

    res.set('Content-Type', 'image/jpeg');
    res.set('Cache-Control', 'public, max-age=300'); // кешируем 5 минут
    res.send(screenshot);
    console.log(`[screenshot] OK ${targetUrl}`);

  } catch (err) {
    console.error('[screenshot] Error:', err.message);
    if (browser) await browser.close().catch(() => {});
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Gothic Reader Screenshot Server → http://localhost:${PORT}`);
  console.log('Нажмите Ctrl+C для остановки\n');
});
