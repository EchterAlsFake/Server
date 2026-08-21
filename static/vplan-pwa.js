(() => {
    "use strict";

    const enabled = document.querySelector('meta[name="vplan-pwa-enabled"]')?.content === "true";
    let deferredPrompt = null;
    let installed = false;

    const dispatchStateChange = () => {
        window.dispatchEvent(new CustomEvent("vplan-pwa-state-change"));
    };

    window.vplanPwa = Object.freeze({
        get enabled() {
            return enabled;
        },
        get installPrompt() {
            return deferredPrompt;
        },
        get installed() {
            return installed;
        },
        takeInstallPrompt() {
            const prompt = deferredPrompt;
            deferredPrompt = null;
            return prompt;
        },
        isStandalone() {
            return window.matchMedia("(display-mode: standalone)").matches
                || window.navigator.standalone === true;
        },
    });

    window.addEventListener("beforeinstallprompt", (event) => {
        if (!enabled) return;
        event.preventDefault();
        deferredPrompt = event;
        dispatchStateChange();
    });

    window.addEventListener("appinstalled", () => {
        deferredPrompt = null;
        installed = true;
        dispatchStateChange();
    });

    const registerServiceWorker = () => {
        if (!enabled || !("serviceWorker" in navigator)) return;
        navigator.serviceWorker.register("/sw.js", { scope: "/vplan" }).catch(() => {
            // Installation is optional; the current online page remains usable.
        });
    };

    if (document.readyState === "complete") {
        registerServiceWorker();
    } else {
        window.addEventListener("load", registerServiceWorker, { once: true });
    }
})();
