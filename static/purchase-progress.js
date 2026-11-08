/* Shared, server-driven purchase activity. Time never advances backend steps. */
(() => {
  function render(root, progress) {
    if (!root || !progress) return;
    root.dataset.activity = progress.activity || 'active';
    root.setAttribute('aria-busy', String(['active', 'waiting'].includes(root.dataset.activity)));
    root.querySelector('[data-progress-title]').textContent = progress.title;
    root.querySelector('[data-progress-message]').textContent = progress.message;
    const label = root.querySelector('[data-progress-label]');
    if (label) label.textContent = {complete: 'Complete', attention: 'Needs attention', waiting: 'Request saved · Automatic updates on', active: 'Working · Automatic updates on'}[root.dataset.activity];
    root.querySelector('[data-progress-steps]').replaceChildren(...progress.steps.map(step => {
      const li = document.createElement('li');
      li.className = `timeline-${step.state}`;
      if (step.state === 'current') li.setAttribute('aria-current', 'step');
      const marker = document.createElement('span');
      marker.className = 'timeline-marker'; marker.setAttribute('aria-hidden', 'true');
      marker.textContent = step.state === 'done' ? '✓' : '';
      const text = document.createElement('span'); text.textContent = step.label;
      li.append(marker, text);
      return li;
    }));
  }
  function reveal(element) {
    element.hidden = false;
    const heading = element.querySelector('[data-result-heading]');
    heading?.focus({preventScroll: true});
    element.scrollIntoView({behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth', block: 'start'});
  }
  document.querySelectorAll('[data-copy-license]').forEach(button => button.addEventListener('click', async () => {
    const key = document.getElementById(button.dataset.copyLicense);
    const status = button.parentElement.querySelector('[data-copy-status]');
    try {
      await navigator.clipboard.writeText(key.value || key.textContent);
      status.textContent = 'License key copied.';
    } catch {
      key.focus();
      if (key.select) key.select();
      else {
        const range = document.createRange(); range.selectNodeContents(key);
        const selection = getSelection(); selection.removeAllRanges(); selection.addRange(range);
      }
      status.textContent = 'Key selected. Copy it manually.';
    }
  }));
  window.PurchaseProgress = {render, reveal};
})();
