/* Consent timing is also checked by the server; no payment starts on a timer. */
(() => {
    const form = document.getElementById('onramp-form');
    const dialog = document.getElementById('kyc-dialog');
    const next = document.getElementById('kyc-continue');
    const accepted = document.getElementById('card-kyc');
    const countdown = document.getElementById('kyc-countdown');
    const error = document.getElementById('kyc-error');
    let token = null;
    let deadline = Infinity;
    let interval = null;
    let generation = 0;
    let busy = false;
    const checked = id => document.getElementById(id)?.checked ?? (form.dataset.confirmed === 'true');
    async function post(path, body) {
        const response = await fetch(path, {
            method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').content},
            body: JSON.stringify(body)
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(data.error || 'Checkout is unavailable. Close this dialog and try again.');
        return data;
    }
    function update() {
        const remaining = Math.max(0, Math.ceil((deadline - performance.now()) / 1000));
        countdown.textContent = !token ? (error.textContent ? 'Close and reopen this disclosure to retry.' : 'Preparing the reading timer…') : remaining > 0 ? `Please read before continuing: ${remaining} seconds.` : 'You may continue after confirming you have read the disclosure.';
        next.disabled = busy || !token || remaining > 0 || !accepted.checked;
        if (remaining === 0) clearInterval(interval);
    }
    form.addEventListener('submit', async event => {
        event.preventDefault();
        if (!form.reportValidity()) return;
        const current = ++generation;
        token = null; deadline = Infinity; accepted.checked = false; error.textContent = ''; busy = false;
        dialog.showModal();
        update();
        try {
            const data = await post('/onramp-acknowledgment', {});
            if (current !== generation || !dialog.open) return;
            token = data.acknowledgment_token;
            deadline = performance.now() + data.wait_seconds * 1000;
            interval = setInterval(update, 200);
            update();
        } catch (e) { if (current === generation) { error.textContent = e.message; error.focus(); update(); } }
    });
    accepted.addEventListener('change', update);
    document.getElementById('kyc-cancel').addEventListener('click', () => dialog.close());
    dialog.addEventListener('cancel', event => { if (busy) event.preventDefault(); });
    dialog.addEventListener('close', () => { clearInterval(interval); ++generation; token = null; });
    next.addEventListener('click', async () => {
        if (next.disabled || !form.reportValidity()) return;
        busy = true; update(); error.textContent = '';
        document.getElementById('kyc-cancel').disabled = true;
        try {
            const data = await post('/create-onramp-payment', {
                acknowledgment_token: token, delivery_email: document.getElementById('delivery-email').value,
                country: form.dataset.country,
                age_confirmed: checked('card-age'), terms_accepted: checked('card-terms'),
                withdrawal_accepted: checked('card-withdrawal'), annual_terms_acknowledged: checked('card-annual'), kyc_acknowledged: accepted.checked
            });
            window.location.assign(data.status_url);
        } catch (e) {
            error.textContent = e.message; error.focus();
            // Reopening the dialog creates fresh consent; an ambiguous request
            // must never automatically create another provider payment.
            token = null;
        } finally { busy = false; document.getElementById('kyc-cancel').disabled = false; update(); }
    });
    document.getElementById('card-review').disabled = form.dataset.confirmed !== 'true';
    document.getElementById('card-js-help').hidden = true;
})();
