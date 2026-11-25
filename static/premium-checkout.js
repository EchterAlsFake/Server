(() => {
  const form = document.querySelector('#premium-form');
  if (!form) return;
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (!form.reportValidity()) return;
    const button = form.querySelector('button[type="submit"]');
    const error = document.querySelector('#premium-error');
    button.disabled = true;
    error.textContent = '';
    try {
      const response = await fetch(form.action, {method: 'POST', body: new FormData(form), headers: {'Accept': 'application/json'}});
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || websiteText("Checkout is unavailable. Please try again."));
      location.assign(data.next);
    } catch (_) {
      error.textContent = _.message || websiteText("Unable to connect. Retry to resume the same order.");
      error.focus();
      button.disabled = false;
    }
  });
})();
