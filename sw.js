/* Minimal SW to enable installability.
   Never cache /api/* responses (auth + sensitive). */

const SW_VERSION = '20260215-f7';
const CACHE_NAME = `dmf-static-${SW_VERSION}`;

const PRECACHE = [
  '/',
  '/index.html',
  '/style.css',
  '/bootstrap.js',
  '/script.js',
  '/assistant.js',
  '/assistant.css',
  '/dashboard.fragment.html',
  '/payments.fragment.html',
  '/audit.fragment.html',
  '/admin.fragment.html',
  '/assistente.fragment.html',
  '/cobli.fragment.html',
  '/verify.html',
  '/verify.js',
  '/verify.css',
  '/offline.html',
  '/favicon.ico',
  '/assets/logo-dmf.png',
  '/manifest.webmanifest'
];

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    await cache.addAll(PRECACHE.map((u) => `${u}?v=${encodeURIComponent(SW_VERSION)}`));
  })());
});

self.addEventListener('message', (event) => {
  if (event?.data?.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.map((k) => (k.startsWith('dmf-static-') && k !== CACHE_NAME) ? caches.delete(k) : null));
    self.clients.claim();
  })());
});

function isApiRequest(url) {
  return url.pathname.startsWith('/api/');
}

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;

  // Never cache API
  if (isApiRequest(url)) return;

  // Navigation: network-first, fallback to cached index.
  if (event.request.mode === 'navigate') {
    event.respondWith((async () => {
      try {
        return await fetch(event.request);
      } catch (_) {
        const cache = await caches.open(CACHE_NAME);
        const offline = await cache.match(`/offline.html?v=${encodeURIComponent(SW_VERSION)}`);
        const cachedIndex = await cache.match(`/index.html?v=${encodeURIComponent(SW_VERSION)}`);
        return offline || cachedIndex || new Response('Offline', { status: 503, headers: { 'Content-Type': 'text/plain' } });
      }
    })());
    return;
  }

  // Static: cache-first, then network.
  event.respondWith((async () => {
    const cache = await caches.open(CACHE_NAME);
    const cached = await cache.match(event.request);
    if (cached) return cached;
    try {
      const resp = await fetch(event.request);
      // Only cache ok GETs.
      if (event.request.method === 'GET' && resp && resp.ok) {
        cache.put(event.request, resp.clone()).catch(() => {});
      }
      return resp;
    } catch (_) {
      return cached || new Response('Offline', { status: 503, headers: { 'Content-Type': 'text/plain' } });
    }
  })());
});
