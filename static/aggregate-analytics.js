/* Aggregate counts only. No cookies, storage, visitor IDs, or journey state. */
(() => {
  'use strict';
  const page = document.currentScript?.dataset.page;
  if (!page || navigator.doNotTrack === '1' || window.doNotTrack === '1' || navigator.globalPrivacyControl === true) return;
  const send = action => {
    fetch('/_metrics/event', {
      method: 'POST', credentials: 'omit', referrerPolicy: 'no-referrer',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({page, action}), keepalive: true,
    }).catch(() => {});
  };
  send('pageview');
  document.addEventListener('click', event => {
    if (!event.isTrusted) return;
    const element = event.target.closest('a, button');
    if (!element) return;
    let action = element.dataset.metric;
    if (!action && element.matches('a[href]')) {
      const target = new URL(element.href, location.origin);
      if (target.origin !== location.origin) return;
      const path = target.pathname;
      if (path === '/download') action = 'open_download';
      else if (path === '/porn_fetch') action = 'open_premium';
      else if (path === '/help') action = 'open_help';
      else if (/^\/download\/(windows|macos|linux|android|ios|cli)$/.test(path)) action = `choose_${path.split('/')[2]}`;
      else if (target.hash.startsWith('#guide-')) action = 'installation_guide';
    }
    if (action) send(action);
  }, {capture: true});
})();
