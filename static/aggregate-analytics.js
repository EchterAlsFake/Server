/* Fixed aggregate counters only; no cookies, storage, IDs or journey state. */
(() => {
  'use strict';
  const {page, localePrefix} = document.currentScript?.dataset || {};
  if (!page || navigator.doNotTrack === '1' || window.doNotTrack === '1' || navigator.globalPrivacyControl === true) return;
  const send = action => fetch('/_metrics/event', {
    method: 'POST', credentials: 'omit', referrerPolicy: 'no-referrer',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({page, action}), keepalive: true,
  });
  const count = action => { send(action).catch(() => {}); };
  count('pageview');
  // Broad viewport category, not OS, browser version or a device fingerprint.
  count(`pageview_${innerWidth < 768 ? 'mobile' : innerWidth < 1024 ? 'tablet' : 'desktop'}`);
  function actionFor(element) {
    if (element.id === 'checkout-continue') return 'checkout_continue';
    if (element.dataset.metric === 'download_click') return 'download_click';
    if (!element.matches('a[href]')) return null;
    const target = new URL(element.href, location.origin);
    if (target.origin !== location.origin) return null;
    const path = localePrefix && target.pathname.startsWith(`${localePrefix}/`)
      ? target.pathname.slice(localePrefix.length) : target.pathname;
    if (path === '/download') return 'open_download';
    if (target.pathname === location.pathname && target.hash === '#mobile-downloads') return 'open_download';
    if (path === '/porn_fetch') return 'open_premium';
    if (path === '/help') return 'open_help';
    if (/^\/download\/(windows|macos|linux|android|ios|cli)$/.test(path)) return `choose_${path.split('/')[2]}`;
    if (target.hash.startsWith('#guide-')) return 'installation_guide';
    return null;
  }
  function placement(element) {
    if (element.closest('.site-header')) return 'header';
    if (element.closest('.site-footer')) return 'footer';
    if (element.closest('.guide-platforms, .page-heading')) return 'guide_top';
    if (element.closest('.guide-steps')) return 'guide_steps';
    if (element.closest('[data-metric-section="comparison"]')) return 'comparison';
    return 'content';
  }
  function kindFor(action) {
    if (action === 'open_premium') return 'premium';
    if (action === 'open_download' || action === 'download_click' || action?.startsWith('choose_')) return 'download';
    return null;
  }
  const seen = new Set();
  const observer = 'IntersectionObserver' in window ? new IntersectionObserver(entries => {
    for (const entry of entries) {
      if (!entry.isIntersecting || entry.intersectionRatio < 0.5) continue;
      const action = actionFor(entry.target), kind = kindFor(action);
      const key = `${kind}_${placement(entry.target)}`;
      if (kind && !seen.has(key)) { seen.add(key); count(`visible_${key}`); }
      observer.unobserve(entry.target);
    }
  }, {threshold: 0.5}) : null;
  document.querySelectorAll('a[href], button').forEach(element => {
    if (kindFor(actionFor(element))) observer?.observe(element);
  });
  document.addEventListener('click', event => {
    if (!event.isTrusted) return;
    const element = event.target.closest('a, button');
    if (!element) return;
    const action = actionFor(element);
    if (action) count(action);
    const kind = kindFor(action);
    if (kind) count(`click_${kind}_${placement(element)}`);
  }, {capture: true});
  const survey = document.getElementById('premium-feedback');
  if (survey && page === 'premium') {
    survey.hidden = false;
    let submitted = false, pending = false;
    survey.addEventListener('click', async event => {
      const button = event.target.closest('button[data-feedback]');
      if (!event.isTrusted || !button || submitted || pending) return;
      pending = true;
      const status = document.getElementById('premium-feedback-status');
      try {
        const response = await send(`feedback_${button.dataset.feedback}`);
        if (!response.ok) throw new Error('unavailable');
        submitted = true;
        status.textContent = 'Thank you. Your answer was counted anonymously.';
        status.tabIndex = -1;
        status.focus();
        survey.querySelectorAll('button').forEach(item => { item.disabled = true; });
      } catch {
        status.textContent = 'Feedback is temporarily unavailable. Please try again.';
      } finally { pending = false; }
    });
  }
})();
