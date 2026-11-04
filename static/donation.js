(() => {
  const age = document.querySelector('#chk-age-donation');
  const country = document.querySelector('#chk-country-donation');
  const options = document.querySelector('#donation-options');
  const wrapper = document.querySelector('#iframe-wrapper');
  const load = document.querySelector('#load-donation-widget');
  const unload = document.querySelector('#unload-donation-widget');
  const status = document.querySelector('#widget-status');
  if (!age || !country || !options || !wrapper || !load || !unload || !status) return;

  const eligible = () => age.checked && country.checked;
  function removeWidget() {
    wrapper.replaceChildren();
    wrapper.hidden = true;
    unload.hidden = true;
    load.hidden = false;
  }
  function update() {
    const allowed = eligible();
    options.inert = !allowed;
    options.style.opacity = allowed ? '1' : '0.5';
    options.style.pointerEvents = allowed ? 'auto' : 'none';
    load.disabled = !allowed;
    if (!allowed) removeWidget();
    status.textContent = !allowed
      ? 'Please confirm age and country above. / Bitte bestätigen Sie oben Alter und Land.'
      : wrapper.childElementCount
        ? 'Widget enabled. / Widget aktiviert.'
        : 'Widget blocked. Loading is optional. / Widget gesperrt. Das Laden ist freiwillig.';
  }
  load.addEventListener('click', () => {
    if (!eligible() || wrapper.childElementCount) return;
    const frame = document.createElement('iframe');
    frame.title = 'NOWPayments cryptocurrency donation';
    frame.referrerPolicy = 'no-referrer';
    frame.width = '346';
    frame.height = '623';
    frame.style.cssText = 'width:100%;max-width:346px;border:0;border-radius:12px;background:transparent;';
    frame.src = wrapper.dataset.widgetUrl;
    wrapper.append(frame);
    wrapper.hidden = false;
    load.hidden = true;
    unload.hidden = false;
    update();
  });
  unload.addEventListener('click', () => {
    removeWidget();
    update();
    load.focus();
  });
  age.addEventListener('change', update);
  country.addEventListener('change', update);
  document.querySelectorAll('.donation-btn').forEach(link => {
    link.addEventListener('click', event => {
      if (!eligible()) event.preventDefault();
    });
  });
  // Restoring a page must not silently restart a previously loaded provider frame.
  window.addEventListener('pagehide', removeWidget);
  window.addEventListener('pageshow', () => { removeWidget(); update(); });
  update();
})();
