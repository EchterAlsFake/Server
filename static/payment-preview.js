/* Deliberate test warnings. The server checks acknowledgment again before redirecting. */
(() => {
  const dialog = document.querySelector('#payment-test-dialog');
  if (!dialog || typeof dialog.showModal !== 'function') return;
  const form = dialog.querySelector('form');
  const ack = dialog.querySelector('#payment-test-ack');
  const submit = dialog.querySelector('#payment-test-continue');
  let trigger = null;
  function openPreview(href, method, source) {
    const url = new URL(href, location.href);
    if (!['patreon', 'card', 'banxa'].includes(method) || url.origin !== location.origin
        || url.pathname !== `/payment-preview/${method}`) return;
    trigger = source;
    ack.checked = false;
    submit.disabled = true;
    form.action = url.href;
    form.target = method === 'card' ? '_self' : '_blank';
    dialog.querySelector('#payment-test-provider').textContent = method === 'patreon' ? 'Patreon' : 'Onramp Pay / Banxa';
    dialog.querySelector("#patreon-preview-details").hidden = method !== "patreon";
    dialog.showModal();
  }
  document.querySelectorAll('a[data-payment-preview]').forEach(link => {
    link.addEventListener('click', event => {
      if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
      event.preventDefault();
      openPreview(link.href, link.dataset.paymentPreview, link);
    });
  });
  document.addEventListener('payment-preview', event => {
    openPreview(event.detail.url, event.detail.method, event.detail.trigger);
  });
  ack.addEventListener('change', () => { submit.disabled = !ack.checked; });
  dialog.querySelector('#payment-test-cancel').addEventListener('click', () => dialog.close());
  dialog.addEventListener('close', () => { trigger?.focus(); });
  form.addEventListener('submit', () => { if (form.reportValidity()) dialog.close(); });
})();
