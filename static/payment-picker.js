(() => {
  const form = document.querySelector('#payment-choice-form');
  if (!form) return;
  const button = form.querySelector('#checkout-continue');
  const error = form.querySelector('#choice-error');
  const names = {crypto: 'Continue to crypto checkout', patreon: 'Preview Patreon checkout', card: 'Preview card checkout'};
  function update() {
    const method = form.querySelector('input[name="payment_method"]:checked')?.value;
    button.textContent = names[method] || 'Continue with selected method →';
  }
  form.addEventListener('change', update);
  window.addEventListener('pageshow', update);
  form.addEventListener('submit', async event => {
    if (!form.reportValidity()) return;
    event.preventDefault();
    button.disabled = true; error.textContent = '';
    try {
      const response = await fetch(form.action, {method: 'POST', body: JSON.stringify(Object.fromEntries(new FormData(form))), headers: {'Content-Type': 'application/json', 'X-CSRFToken': form.elements.csrf_token.value}});
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not continue. Please try again.');
      if (data.method === 'crypto') location.assign(data.next);
      else document.dispatchEvent(new CustomEvent('payment-preview', {detail: {url: data.next, method: data.method, trigger: button}}));
    } catch (e) { error.textContent = e.message; error.focus(); }
    finally { button.disabled = false; }
  });
  const preferred = new URLSearchParams(location.search).get("method");
  if (["crypto", "patreon", "card"].includes(preferred)) form.querySelector(`#method-${preferred}`).checked = true;
  update();
})();
