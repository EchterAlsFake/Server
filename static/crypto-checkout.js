(() => {
  const root = document.querySelector('#crypto-checkout');
  const form = document.querySelector('#crypto-payment-form');
  const email = document.querySelector('#delivery-email');
  const pay = document.querySelector('#pay-btn');
  const error = document.querySelector('#checkout-error');
  let sessionId = null;
  let statusUrl = null;
  let busy = false;
  const showError = (element, message) => { element.textContent = message; element.focus(); };
  async function post(url, body) {
    const response = await fetch(url, {method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').content}, body: JSON.stringify(body)});
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || 'Could not continue. Please try again.');
    return data;
  }
  async function createPayment() {
    if (busy || root.dataset.confirmed !== 'true') return;
    busy = true; pay.disabled = true; error.textContent = ''; pay.textContent = 'Creating transaction…';
    try {
      const country = document.querySelector('#crypto-country').value;
      const withdrawal = document.querySelector('#crypto-withdrawal').checked;
      if (root.dataset.needsConfirmation === 'true' || root.dataset.country !== country) {
        await post('/checkout/crypto-confirm', {country, withdrawal_accepted: withdrawal, offer_digest: root.dataset.offerDigest});
        root.dataset.needsConfirmation = 'false';
        root.dataset.country = country;
      }
      const data = await post('/create-crypto-payment', {country, age_confirmed: true, terms_accepted: true, withdrawal_accepted: withdrawal, test_acknowledged: true, delivery_email: email.value.trim()});
      sessionId = data.session_id;
      statusUrl = data.status_url;
      email.value = '';
      if (data.invoice_url.startsWith('local-sim:')) {
        document.querySelector('#checkout-form-container').hidden = true;
        document.querySelector('#tx-screen-container').hidden = false;
        document.querySelector('#sim-session-id').textContent = sessionId;
        document.querySelector('#simulation-heading').focus();
      } else location.assign(data.status_url);
    } catch (e) { showError(error, e.message); }
    finally { busy = false; pay.disabled = false; pay.textContent = `${pay.dataset.label} →`; }
  }
  form.addEventListener('submit', event => {
    event.preventDefault();
    if (!form.reportValidity()) return;
    createPayment();
  });
  document.querySelector('#simulate-success-btn').addEventListener('click', async event => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      await post('/simulate-payment-success', {session_id: sessionId});
      location.assign(statusUrl || `/buy_success?session_id=${encodeURIComponent(sessionId)}`);
    } catch (e) { showError(document.querySelector('#simulation-error'), e.message); button.disabled = false; }
  });
  document.querySelector('#checkout-js-help').hidden = true;
  pay.disabled = root.dataset.confirmed !== 'true';
})();
