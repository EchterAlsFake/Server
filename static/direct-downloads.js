/* Probe the exact IPv6-only file before handing the transfer to the browser. */
(() => {
  document.addEventListener('click', async event => {
    const link = event.target.closest('a[data-vps-url]');
    if (!link || event.defaultPrevented || event.button || event.metaKey ||
        event.ctrlKey || event.shiftKey || event.altKey) return;
    const direct = link.href;
    const fallback = new URL(link.dataset.vpsUrl, location.href).href;
    if (direct === fallback) return;
    event.preventDefault();
    if (link.dataset.checking) return;
    link.dataset.checking = 'true';
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);
    let destination = fallback;
    try {
      const response = await fetch(direct, {
        method: 'HEAD', mode: 'cors', credentials: 'omit', cache: 'no-store',
        redirect: 'error', referrerPolicy: 'no-referrer', signal: controller.signal,
      });
      if (response.ok) destination = direct;
    } catch (_) { /* IPv4-only, unavailable IPv6, or unavailable direct file. */ }
    finally {
      clearTimeout(timeout);
      delete link.dataset.checking;
    }
    const retry = document.querySelector('[data-download-retry]');
    if (retry) { retry.href = fallback; retry.hidden = false; }
    location.assign(destination);
  });
})();
