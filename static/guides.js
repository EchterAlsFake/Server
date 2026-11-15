/* Device selector, platform suggestion, and compact sticky actions. No storage or tracking. */
(() => {
  'use strict';
  const guide = document.querySelector('.video-guide');
  const opening = document.getElementById('guide-opening-actions');
  const bar = document.querySelector('.guide-bottom-actions');

  const ua = navigator.userAgent;
  const isAndroid = /Android/i.test(ua);
  const isIOS = /iPhone|iPad|iPod/i.test(ua) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
  const isDesktop = !isAndroid && !isIOS && /Win|Mac|Linux/i.test(navigator.platform || ua);
  const detectedPlatform = isAndroid ? 'android' : (isIOS ? 'ios' : (isDesktop ? 'desktop' : 'all'));

  // Adapt hero free download and sticky bar for mobile users
  if (isAndroid || isIOS) {
    const mobileKey = isIOS ? 'ios' : 'android';
    const mobileLabel = isIOS ? 'iPhone' : 'Android';
    const download = document.getElementById('guide-free-download');
    if (download) {
      download.href = `/download/${mobileKey}`;
      download.textContent = `Download for ${mobileLabel}`;
    }
    if (bar) {
      const stickyDownload = bar.querySelector('[data-guide-free]');
      if (stickyDownload) {
        stickyDownload.href = `/download/${mobileKey}`;
        stickyDownload.textContent = `${mobileLabel} · Free`;
      }
    }
    document.querySelector(`[data-platform="${mobileKey}"]`)?.classList.add('guide-suggested');
  }

  // Device selector management
  if (guide) {
    const tabs = document.querySelectorAll('.guide-device-tab');
    if (tabs.length) {
      guide.classList.add('js-platform-filter');

      const selectPlatform = (platform, shouldScroll) => {
        const valid = ['android', 'ios', 'desktop', 'cli', 'all'];
        const target = valid.includes(platform) ? platform : 'all';
        guide.setAttribute('data-active-platform', target);

        tabs.forEach(tab => {
          const isActive = tab.dataset.platform === target;
          tab.classList.toggle('is-active', isActive);
          if (isActive) tab.setAttribute('aria-current', 'true');
          else tab.removeAttribute('aria-current');
        });

        if (shouldScroll) {
          const targetEl = target === 'all'
            ? document.getElementById('all-platforms') || guide
            : document.querySelector(`[data-guide-platform="${target}"]`);
          if (targetEl) {
            targetEl.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth', block: 'start' });
          }
        }
      };

      const platformForHash = () => {
        const id = location.hash.slice(1);
        const aliases = {ios: 'ios', desktop: 'desktop', all: 'all', 'all-platforms': 'all'};
        if (aliases[id]) return aliases[id];
        return document.getElementById(id)?.closest('[data-guide-platform]')?.dataset.guidePlatform;
      };
      selectPlatform(platformForHash() || detectedPlatform, false);

      // Handle click events on tabs
      tabs.forEach((tab, index) => {
        tab.addEventListener('click', event => {
          event.preventDefault();
          selectPlatform(tab.dataset.platform, true);
        });

        // Keyboard navigation (ArrowLeft, ArrowRight)
        tab.addEventListener('keydown', event => {
          let nextIndex = index;
          if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
            nextIndex = (index + 1) % tabs.length;
          } else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
            nextIndex = (index - 1 + tabs.length) % tabs.length;
          } else if (event.key === 'Home') {
            nextIndex = 0;
          } else if (event.key === 'End') {
            nextIndex = tabs.length - 1;
          } else {
            return;
          }
          event.preventDefault();
          tabs[nextIndex].focus();
          selectPlatform(tabs[nextIndex].dataset.platform, false);
        });
      });

      // Handle jump links across the page (TOC, card jumps, etc.)
      document.addEventListener('click', event => {
        const link = event.target.closest('a[href^="#"]');
        if (!link || link.classList.contains('guide-device-tab')) return;
        const targetId = link.getAttribute('href').slice(1);
        const target = document.getElementById(targetId);
        const matched = targetId === 'all-platforms' ? 'all'
          : target?.closest('[data-guide-platform]')?.dataset.guidePlatform;
        if (matched) selectPlatform(matched, false);
      });

      window.addEventListener('hashchange', () => {
        const platform = platformForHash();
        if (platform) {
          selectPlatform(platform, false);
          document.getElementById(location.hash.slice(1))?.scrollIntoView();
        }
      });
    }
  }

  // Sticky bottom action bar visibility
  if (!bar || !opening || !('IntersectionObserver' in window)) return;
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
