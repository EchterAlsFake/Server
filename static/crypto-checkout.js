(() => {
  const root = document.querySelector('#crypto-checkout');
  const form = document.querySelector('#crypto-payment-form');
  const email = document.querySelector('#delivery-email');
  const pay = document.querySelector('#pay-btn');
  const error = document.querySelector('#checkout-error');
  const dialog = document.querySelector('#no-email-dialog');
  let sessionId = null;
  let busy = false;
  const showError = (element, message) => { element.textContent = message; element.focus(); };
  async function post(url, body) {
    const response = await fetch(url, {method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').content}, body: JSON.stringify(body)});
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || 'Could not continue. Please try again.');
    return data;
  }
  async function createPayment(noEmailAcknowledged) {
    if (busy || root.dataset.confirmed !== 'true') return;
    busy = true; pay.disabled = true; error.textContent = ''; pay.textContent = 'Creating transaction…';
    try {
      const data = await post('/create-crypto-payment', {country: root.dataset.country, age_confirmed: true, terms_accepted: true, withdrawal_accepted: true, test_acknowledged: true, delivery_email: email.value.trim(), no_email_acknowledged: noEmailAcknowledged});
      sessionId = data.session_id;
      email.value = '';
      if (data.invoice_url.startsWith('local-sim:')) {
        document.querySelector('#checkout-form-container').hidden = true;
        document.querySelector('#tx-screen-container').hidden = false;
        document.querySelector('#sim-session-id').textContent = sessionId;
        document.querySelector('#simulation-heading').focus();
      } else location.assign(data.status_url);
    } catch (e) { showError(error, e.message); }
    finally { busy = false; pay.disabled = false; pay.textContent = 'Continue to NOWPayments →'; }
  }
  form.addEventListener('submit', event => {
    event.preventDefault();
    if (!form.reportValidity()) return;
    if (!email.value.trim()) dialog.showModal();
    else createPayment(false);
  });
  document.querySelector('#add-email').addEventListener('click', () => { dialog.close(); email.focus(); });
  document.querySelector('#continue-without-email').addEventListener('click', () => { dialog.close(); createPayment(true); });
  document.querySelector('#simulate-success-btn').addEventListener('click', async event => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      await post('/simulate-payment-success', {session_id: sessionId});
      location.assign(`/buy_success?session_id=${encodeURIComponent(sessionId)}`);
    } catch (e) { showError(document.querySelector('#simulation-error'), e.message); button.disabled = false; }
  });
  document.querySelector('#checkout-js-help').hidden = true;
  pay.disabled = root.dataset.confirmed !== 'true';
})();
