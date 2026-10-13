// Only public, same-origin shell assets. No auth/API cache and no queued writes.
const SHELL = 'cf-shell-v2';
const ASSETS = ['/', '/styles.css', '/app.js', '/auth-client.js', '/status-cache.js', '/operational-alerts.js', '/parent-alerts.js', '/activity.js', '/schedule-editor.js', '/schedule-editor.css', '/time-requests.js', '/manifest.webmanifest', '/icon.svg'];
self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(SHELL).then((cache) => cache.addAll(ASSETS)));
});
self.addEventListener('activate', (event) => {
  event.waitUntil(caches.keys().then(async (names) => {
    await Promise.all(names.filter((name) => name.startsWith('cf-shell-') && name !== SHELL).map((name) => caches.delete(name)));
    await self.clients.claim();
  }));
});
self.addEventListener('fetch', (event) => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== 'GET' || url.origin !== self.location.origin || url.search || !ASSETS.includes(url.pathname)) return;
  event.respondWith(fetch(request).catch(async () => (await caches.open(SHELL)).match(url.pathname)));
});
