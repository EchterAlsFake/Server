/* Local interactions only: no third-party requests or browser storage tracking. */
(() => {
  const root = document.documentElement;
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  const content = document.querySelector('#site-content');
  const overlay = document.querySelector('#age-overlay');
  const ageForm = document.querySelector('#age-form');
  let videoReady = false;
  let videoVisible = false;
  let userPaused = false;
  let automaticPause = false;
  const video = document.querySelector('#product-video');

  function loadVideo() {
    if (!video || videoReady || root.classList.contains('age-pending')) return;
    video.querySelectorAll('source[data-src]').forEach(source => {
      source.src = source.dataset.src;
    });
    video.load();
    videoReady = true;
  }
  function syncVideo() {
    if (!video || root.classList.contains('age-pending')) return;
    if (videoVisible) loadVideo();
    if (videoVisible && !document.hidden && !reducedMotion.matches && !userPaused) {
      video.play().catch(() => { /* Native Play control remains available. */ });
    } else if ((!videoVisible || document.hidden || reducedMotion.matches) && !video.paused) {
      automaticPause = true;
      video.pause();
    }
  }
  if (video) {
    new IntersectionObserver(entries => {
      videoVisible = entries[0].isIntersecting;
      syncVideo();
    }, {threshold: 0.15}).observe(video);
    video.addEventListener('pause', () => {
      if (automaticPause) automaticPause = false;
      else userPaused = true;
    });
    video.addEventListener('play', () => { userPaused = false; });
    // Load on interaction too, including when reduced motion disables autoplay.
    video.addEventListener('pointerdown', loadVideo);
    video.addEventListener('focus', loadVideo);
    document.addEventListener('visibilitychange', syncVideo);
    reducedMotion.addEventListener('change', syncVideo);
  }

  if (overlay && ageForm) {
    const dialog = overlay.querySelector('[role="dialog"]');
    const error = document.querySelector('#age-error');
    dialog.focus({preventScroll: true});
    overlay.addEventListener('keydown', event => {
      if (event.key === 'Escape') event.preventDefault();
      if (event.key !== 'Tab') return;
      const elements = [...dialog.querySelectorAll('a[href], button:not(:disabled), input:not([type="hidden"])')];
      const first = elements[0], last = elements[elements.length - 1];
      if (event.shiftKey && (document.activeElement === first || document.activeElement === dialog)) {
        event.preventDefault(); last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault(); first.focus();
      }
    });
    ageForm.addEventListener('submit', async event => {
      event.preventDefault();
      if (!ageForm.reportValidity()) return;
      const submit = ageForm.querySelector('button');
      submit.disabled = true;
      error.hidden = true;
      try {
        const response = await fetch(ageForm.action, {
          method: 'POST', body: new FormData(ageForm),
          credentials: 'same-origin', headers: {'Accept': 'application/json'}
        });
        if (!response.ok) throw new Error('Confirmation could not be saved. Please reload and try again.');
        const result = await response.json();
        if (!result.confirmed) throw new Error(result.error || 'Please confirm your age to continue.');
        root.classList.remove('age-pending');
        content.removeAttribute('inert');
        content.removeAttribute('aria-hidden');
        overlay.remove();
        document.querySelector('#main-content').focus({preventScroll: true});
        // Honor anchors that were opened while the dialog held the page still.
        if (location.hash) document.getElementById(location.hash.slice(1))?.scrollIntoView();
        syncVideo();
      } catch (failure) {
        error.textContent = failure.message;
        error.hidden = false;
        submit.disabled = false;
      }
    });
  }

  const menu = document.querySelector('.site-menu');
  const desktop = window.matchMedia('(min-width: 1250px)');
  function syncMenu() {
    if (!menu) return;
    menu.open = desktop.matches;
    menu.querySelector('summary').tabIndex = desktop.matches ? -1 : 0;
  }
  syncMenu();
  desktop.addEventListener('change', syncMenu);
  menu?.addEventListener('keydown', event => {
    if (event.key === 'Escape' && !desktop.matches) {
      menu.open = false; menu.querySelector('summary').focus();
    }
  });
  menu?.querySelectorAll('a').forEach(link => link.addEventListener('click', () => {
    if (!desktop.matches) menu.open = false;
  }));
})();
