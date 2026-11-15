/* Optional device suggestion and compact actions. No storage or tracking. */
(() => {
  'use strict';
  const opening = document.getElementById('guide-opening-actions');
  const bar = document.querySelector('.guide-bottom-actions');
  if (!opening || !bar) return;

  const ua = navigator.userAgent;
  const platform = /Android/i.test(ua) ? 'android' :
    /iPhone|iPad|iPod/i.test(ua) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1) ? 'ios' : null;
  if (platform) {
    const label = platform === 'ios' ? 'iPhone' : 'Android';
    const download = document.getElementById('guide-free-download');
    download.href = `/download/${platform}`;
    download.textContent = `Download for ${label}`;
    const stickyDownload = bar.querySelector('[data-guide-free]');
    stickyDownload.href = `/download/${platform}`;
    stickyDownload.textContent = `${label} · Free`;
    document.querySelector(`[data-platform="${platform}"]`)?.classList.add('guide-suggested');
  }

  if (!('IntersectionObserver' in window)) return;
  let openingPassed = false;
  const visibleActions = new Set();
  const update = () => {
    bar.hidden = !openingPassed || visibleActions.size > 0;
  };
  const openingObserver = new IntersectionObserver(([entry]) => {
    openingPassed = !entry.isIntersecting && entry.boundingClientRect.bottom < 0;
    update();
  });
  openingObserver.observe(opening);
  const actionObserver = new IntersectionObserver(entries => {
    for (const entry of entries) {
      if (entry.isIntersecting) visibleActions.add(entry.target);
      else visibleActions.delete(entry.target);
    }
    update();
  }, {rootMargin: '0px 0px 80px 0px'});
  document.querySelectorAll('.guide-platform-grid .btn, .guide-comparison .btn, .site-footer').forEach(el => actionObserver.observe(el));
})();
