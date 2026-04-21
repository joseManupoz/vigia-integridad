
const CACHE = 'vigia-v4-cache';
const OFFLINE_PAGES = [
  '/',
  '/publico',
  '/manifest.json',
  '/icon-192.svg',
];

// Install: cache essential files
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(OFFLINE_PAGES)).catch(()=>{})
  );
  self.skipWaiting();
});

// Activate: clean old caches
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// Fetch: network first, cache fallback
self.addEventListener('fetch', e => {
  // Skip non-GET and API calls (they need fresh data)
  if(e.request.method !== 'GET') return;
  const url = new URL(e.request.url);
  if(url.pathname.startsWith('/api/')) return;

  e.respondWith(
    fetch(e.request)
      .then(resp => {
        // Cache successful HTML/CSS/JS responses
        if(resp && resp.status === 200){
          const clone = resp.clone();
          caches.open(CACHE).then(c => c.put(e.request, clone));
        }
        return resp;
      })
      .catch(() => {
        // Offline: serve from cache
        return caches.match(e.request).then(cached => {
          if(cached) return cached;
          // For navigation requests, serve the main page
          if(e.request.mode === 'navigate'){
            return caches.match('/');
          }
        });
      })
  );
});

// Background sync: notify when back online
self.addEventListener('message', e => {
  if(e.data === 'SKIP_WAITING') self.skipWaiting();
});
