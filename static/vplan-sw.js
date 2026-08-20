"use strict";

const CACHE_NAME = "vplan-shell-v3";
const APP_SHELL = [
    "/static/vplan.css",
    "/static/vplan.js",
    "/static/manifest.webmanifest",
    "/static/vplan-icon.svg",
    "/static/vplan-icon-192.png",
    "/static/vplan-icon-512.png",
    "/static/vplan-icon-maskable-512.png",
];

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

    if (!requestUrl.pathname.startsWith("/static/")) return;
    event.respondWith(
        fetch(event.request)
            .then((networkResponse) => {
                if (networkResponse.ok) {
                    const responseCopy = networkResponse.clone();
                    caches.open(CACHE_NAME).then((cache) => cache.put(event.request, responseCopy));
                }
                return networkResponse;
            })
            .catch(async () => (await caches.match(event.request)) || Response.error()),
    );
});
