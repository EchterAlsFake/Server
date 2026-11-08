(() => {
  if (!document.querySelector('[data-patreon-pending]')) return;
  const deadline = Date.now() + 15 * 60 * 1000;
  async function poll() {
    if (Date.now() >= deadline) { location.reload(); return; }
    if (!document.hidden) {
      try {
        const response = await fetch('/activate/status', {cache: 'no-store'});
        if (response.ok && (await response.json()).status !== 'pending') {
          location.reload(); return;
        }
      } catch { /* Keep the manual refresh link available after network errors. */ }
    }
    setTimeout(poll, 5000);
  }
  setTimeout(poll, 5000);
})();
