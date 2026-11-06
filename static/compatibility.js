(() => {
  const picker = document.querySelector('.website-picker');
  if (!picker) return;
  const select = picker.querySelector('select');
  const cards = [...document.querySelectorAll('.website-result')];
  function show() {
    const requested = new URL(location.href).searchParams.get('website');
    if ([...select.options].some(option => option.value === requested)) select.value = requested;
    cards.forEach(card => { card.hidden = card.id !== `support-${select.value}`; });
  }
  picker.hidden = false;
  select.addEventListener('change', () => {
    const url = new URL(location.href);
    url.searchParams.set('website', select.value);
    history.replaceState({}, '', url);
    show();
  });
  window.addEventListener('popstate', show);
  show();
})();
