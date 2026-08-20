"use strict";

const CACHE_NAME = "vplan-shell-v6";
const APP_SHELL = [
    "/static/vplan.css",
    "/static/vplan-theme.js",
    "/static/vplan-pwa.js",
    "/static/vplan.js",
    "/static/vplan-translate.css",
    "/static/vplan-translate.js",
    "/static/i18n/languages.json",
    "/static/i18n/de.json",
    "/static/i18n/en.json",
    "/static/vplan-icon.svg",
    "/static/vplan-icon-192.png",
    "/static/vplan-icon-512.png",
    "/static/vplan-icon-maskable-512.png",
];
const CACHEABLE_PATHS = new Set(APP_SHELL);

self.addEventListener("install", (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => cache.addAll(APP_SHELL))
            .then(() => self.skipWaiting()),
    );
});

self.addEventListener("activate", (event) => {
    event.waitUntil(
        caches.keys()
            .then((keys) => Promise.all(
                keys.filter((key) => key.startsWith("vplan-shell-") && key !== CACHE_NAME)
                    .map((key) => caches.delete(key)),
            ))
            .then(() => self.clients.claim()),
    );
});

self.addEventListener("fetch", (event) => {
    if (event.request.method !== "GET") return;

    const requestUrl = new URL(event.request.url);
    if (requestUrl.origin !== self.location.origin) return;

    // Planseiten bleiben immer netzwerkaktuell. Nur unveränderliche App-Ressourcen
    // werden lokal zwischengespeichert.
    if (event.request.mode === "navigate") {
        event.respondWith(fetch(event.request));
        return;
    }

    if (!CACHEABLE_PATHS.has(requestUrl.pathname)) return;
    event.respondWith(
        fetch(event.request)
            .then(async (networkResponse) => {
                if (networkResponse.ok) {
                    const responseCopy = networkResponse.clone();
                    try {
                        const cache = await caches.open(CACHE_NAME);
                        await cache.put(event.request, responseCopy);
                    } catch (error) {
                        // A cache write failure must never hide a valid network response.
                    }
                }
                return networkResponse;
            })
            .catch(async () => (await caches.match(event.request)) || Response.error()),
    );
});
