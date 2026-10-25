/* Provider observations explain progress. Only the server's verified finished
   state exposes a license. Pause polling in hidden tabs and keep failures retryable. */
(() => {
  const root = document.querySelector('#payment-tracker');
  if (!root) return;
  const sessionId = root.dataset.sessionId;
  const refresh = document.querySelector('#refresh-progress');
  const note = document.querySelector('#provider-status-note');
  const heading = document.querySelector('#payment-progress-title');
  const message = document.querySelector('#payment-progress-message');
  const steps = document.querySelector('#payment-progress-steps');
  let timer = null;
  let busy = false;
  let stop = false;
  let announced = '';
  let firstFinished = true;
  let delay = 5000;
  function renderProgress(progress) {
    if (!progress) return;
    heading.textContent = progress.title;
    message.textContent = progress.message;
    steps.replaceChildren(...progress.steps.map(step => {
      const li = document.createElement('li');
      li.className = `timeline-${step.state}`;
      if (step.state === 'current') li.setAttribute('aria-current', 'step');
      const marker = document.createElement('span');
      marker.className = 'timeline-marker'; marker.setAttribute('aria-hidden', 'true');
      marker.textContent = step.state === 'done' ? '✓' : '';
      const label = document.createElement('span'); label.textContent = step.label;
      li.append(marker, label);
      return li;
    }));
    note.textContent = progress.refresh_unavailable ? 'Live provider updates are temporarily unavailable. Last known progress is shown. Do not pay again; I’ll keep checking.' : '';
    const timestamp = progress.updated_at ? new Date(progress.updated_at) : null;
    document.querySelector('#progress-updated').textContent = timestamp && !Number.isNaN(timestamp.getTime()) ? `Last checked: ${timestamp.toLocaleTimeString()}. Live updates continue automatically.` : 'Waiting for the provider’s first update. Checking automatically.';
    if (announced !== progress.title) {
      document.querySelector('#payment-status-announcement').textContent = progress.title;
      announced = progress.title;
    }
    if (!['provider', 'payment'].includes(progress.stage)) document.querySelector('#payment-launch').hidden = true;
    root.dataset.stage = progress.stage;
    delay = progress.poll_after_ms || 5000;
  }
  function renderLicense(data) {
    document.querySelector('#success-container').hidden = false;
    document.querySelector('#invoice-display').textContent = data.invoice_num || 'N/A';
    document.querySelector('#payment-launch').hidden = true;
    const isCard = root.dataset.card === 'true';
    const key = document.querySelector(isCard ? '#card-license-key' : '#crypto-license-key');
    if (isCard) key.textContent = data.license_key || '';
    else key.value = data.license_key || '';
    const delivery = data.delivery_status === 'sent' ? 'Your license was emailed.'
      : data.delivery_status === 'expired' ? 'The email retry period has ended. Download your license here, or contact support.'
      : data.delivery_status ? 'Your license is ready here. Email delivery is pending; failed deliveries are retried for up to seven days.'
      : 'No email delivery requested. Please save your license and invoice.';
    document.querySelector(isCard ? '#card-delivery-status' : '#crypto-delivery-status').textContent = delivery + (data.beta ? ' This historical beta license will be deleted at product release.' : '');
    if (firstFinished) { document.querySelector('#payment-success-heading').focus(); firstFinished = false; }
    if (!data.delivery_status || ['sent', 'expired'].includes(data.delivery_status)) stop = true;
    else delay = 15000;
  }
  async function check() {
    if (busy || document.hidden) return;
    clearTimeout(timer);
    busy = true; refresh.disabled = true;
    try {
      const response = await fetch(`/check-payment-status?session_id=${encodeURIComponent(sessionId)}`, {cache: 'no-store'});
      const data = await response.json();
      if (!response.ok) {
        if ([400, 404].includes(response.status)) { heading.textContent = 'Payment session not found'; message.textContent = 'Use your saved checkout URL or contact support with your session ID.'; stop = true; }
        else throw new Error(data.error || 'Payment status is temporarily unavailable.');
      } else {
        renderProgress(data.progress);
        if (data.status === 'finished') renderLicense(data);
      }
    } catch (e) {
      note.textContent = 'I couldn’t refresh payment progress. Your payment may still be processing. Do not pay again; I’ll retry automatically.';
    } finally {
      busy = false; refresh.disabled = false;
      if (!stop && !document.hidden) timer = setTimeout(check, delay);
    }
  }
  refresh.addEventListener('click', () => { stop = false; check(); });
  document.addEventListener('visibilitychange', () => { clearTimeout(timer); if (!document.hidden && !stop) check(); });
  document.querySelector('#tracking-js-help').hidden = true;
  check();
})();
