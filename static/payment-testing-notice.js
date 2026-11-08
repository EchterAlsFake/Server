(() => {
  const overlay = document.querySelector('#payment-testing-overlay');
  if (!overlay) return;
  const dialog = overlay.querySelector('[role="dialog"]');
  const form = overlay.querySelector('form');
  const checkbox = form.querySelector('[type="checkbox"]');
  const button = form.querySelector('button');
  const update = () => { button.disabled = !checkbox.checked; };
  checkbox.addEventListener('change', update);
  window.addEventListener('pageshow', update);
  update();
  dialog.focus({preventScroll: true});
  overlay.addEventListener('keydown', event => {
    if (event.key === 'Escape') event.preventDefault();
    if (event.key !== 'Tab') return;
    const controls = [...dialog.querySelectorAll('input:not([type="hidden"]), button:not(:disabled)')];
    const first = controls[0], last = controls[controls.length - 1];
    if (event.shiftKey && (document.activeElement === first || document.activeElement === dialog)) {
      event.preventDefault(); last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault(); first.focus();
    }
  });
})();
