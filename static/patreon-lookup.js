(() => {
  const submitting = document.querySelector('#patreon-submit-progress');
  const result = document.querySelector('#patreon-license-result');
  if (result) history.scrollRestoration = 'manual';
  document.querySelectorAll('[data-patreon-form]').forEach(form => {
    form.addEventListener('submit', event => {
      if (form.dataset.submitting) { event.preventDefault(); return; }
      form.dataset.submitting = 'true';
      form.setAttribute('aria-busy', 'true');
      form.querySelector('button[type="submit"]').disabled = true;
      submitting.hidden = false;
      document.querySelector('#patreon-submit-title').focus();
      submitting.scrollIntoView({block: 'start'});
    });
  });
  window.addEventListener('pageshow', () => {
    submitting.hidden = true;
    document.querySelectorAll('[data-patreon-form]').forEach(form => {
      delete form.dataset.submitting;
      form.removeAttribute('aria-busy');
      form.querySelector('button[type="submit"]').disabled = false;
    });
    if (result) window.PurchaseProgress.reveal(result, {animate: false});
  });
  document.querySelectorAll('[data-patreon-activity]').forEach(panel => {
    if (panel.dataset.pending !== 'true') return;
    const action = panel.dataset.patreonActivity;
    const refresh = panel.querySelector('[data-progress-refresh]');
    const connection = panel.querySelector('[data-progress-connection]');
    const checked = panel.querySelector('[data-progress-checked]');
    const announcement = document.getElementById(`${panel.id}-announcement`);
    const started = Date.now();
    let delay = 1000;
    let title = panel.querySelector('[data-progress-title]').textContent;
    let timer, busy = false, stopped = false;
    refresh.hidden = false;
    async function poll() {
      if (busy || document.hidden || stopped) return;
      clearTimeout(timer);
      busy = true; refresh.disabled = true;
      try {
        const response = await fetch(websitePath(`/activate/status?progress=1&action=${action}`), {cache: 'no-store', signal: AbortSignal.timeout(20000)});
        if (!response.ok) throw new Error(websiteText("Status unavailable"));
        const data = await response.json();
        connection.textContent = '';
        checked.textContent = websiteText("Connected · Checked at %(value1)s. Updates continue automatically.", { value1: new Date().toLocaleTimeString(document.documentElement.lang) });
        if (data.status === 'expired') {
          window.PurchaseProgress.render(panel, {title: websiteText("Browser status access expired"), message: websiteText("Status access lasts 15 minutes. Submit your purchase details again to check progress, or contact support if you are still waiting. Your license stays valid."), activity: 'attention', steps: []});
          refresh.textContent = websiteText("Enter purchase details again");
          refresh.dataset.expired = 'true';
          stopped = true;
        } else if (action === 'lookup' && data.status === 'ready') {
          stopped = true;
          history.scrollRestoration = 'manual';
          location.reload();
          return;
        } else {
          if (!data.progress) throw new Error(websiteText("Missing progress"));
          window.PurchaseProgress.render(panel, data.progress);
          delay = data.progress.poll_after_ms || 1000;
          stopped = data.status !== 'pending';
        }
        const nextTitle = panel.querySelector('[data-progress-title]').textContent;
        if (title !== nextTitle) { announcement.textContent = nextTitle; title = nextTitle; }
        if (stopped) checked.textContent = websiteText("Last checked at %(value1)s.", { value1: new Date().toLocaleTimeString(document.documentElement.lang) });
        else if (Date.now() - started > 10 * 60 * 1000) connection.textContent = websiteText("This is taking longer than usual. Your request is saved and checks continue. You can contact support if you need help.");
      } catch {
        connection.textContent = websiteText("Connection interrupted. Your saved request may still be processing. Retrying automatically; you do not need to submit it again.");
        checked.textContent = websiteText("Last connection attempt: %(value1)s.", { value1: new Date().toLocaleTimeString(document.documentElement.lang) });
      } finally {
        busy = false; refresh.disabled = false;
        if (!stopped && !document.hidden) timer = setTimeout(poll, delay);
      }
    }
    refresh.addEventListener('click', () => {
      if (refresh.dataset.expired) { location.reload(); return; }
      stopped = false; poll();
    });
    document.addEventListener('visibilitychange', () => { clearTimeout(timer); if (!document.hidden && !stopped) poll(); });
    poll();
  });
})();
