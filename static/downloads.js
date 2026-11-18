(() => {
  const picker = document.querySelector('.download-picker');
  if (!picker) return;
  const downloadPath = picker.dataset.downloadPath;
  const links = [...picker.querySelectorAll('[data-platform]')];
  const panels = [...picker.querySelectorAll('.platform-panel')];
  let detectedPlatform = null;
  let detectedArch = null;
  let userSelectedPackage = false;
  const ua = navigator.userAgent;
  const platform = navigator.userAgentData?.platform || navigator.platform || '';
  if (/Android/i.test(ua)) detectedPlatform = 'android';
  else if (/iPhone|iPad|iPod/i.test(ua) || (/Mac/i.test(platform) && navigator.maxTouchPoints > 1)) detectedPlatform = 'ios';
  else if (/Win/i.test(platform)) detectedPlatform = 'windows';
  else if (/Mac/i.test(platform)) detectedPlatform = 'macos';
  else if (/Linux/i.test(platform)) detectedPlatform = 'linux';

  function updatePackage(panel) {
    const select = panel.querySelector('.primary-package');
    if (!select) return;
    const option = select.selectedOptions[0];
    const cta = panel.querySelector('.primary-cta');
    cta.hidden = !option.value;
    if (!option.value) { cta.removeAttribute('href'); return; }
    cta.dataset.vpsUrl = option.value;
    cta.href = (picker.dataset.directOrigin || '') + option.value;
    panel.querySelector('.primary-version').textContent = option.dataset.versionLabel;
    panel.querySelector('.primary-requirements').textContent = option.dataset.requirements;
    panel.querySelector('.primary-installation').textContent = option.dataset.installationNote;
  }
  function selectPlatform(key) {
    panels.forEach(panel => { panel.hidden = panel.id !== key; });
    links.forEach(link => {
      if (link.dataset.platform === key) link.setAttribute('aria-current', 'page');
      else link.removeAttribute('aria-current');
    });
    picker.querySelector('.installation-link').href = `#guide-${key}`;
    picker.querySelectorAll('.download-channels a').forEach(link => {
      const url = new URL(link.href);
      link.href = `${downloadPath}/${key}${url.search}`;
    });
    const panel = panels.find(item => item.id === key);
    const select = panel?.querySelector('.primary-package');
    if (select && detectedArch && key === detectedPlatform && !userSelectedPackage) {
      const options = [...select.options].filter(option => option.dataset.arch === detectedArch || option.dataset.arch === 'universal');
      options.sort((a, b) =>
        Number(a.dataset.channel !== 'stable') - Number(b.dataset.channel !== 'stable') ||
        Number(a.dataset.kind !== 'installer') - Number(b.dataset.kind !== 'installer'));
      const choice = options[0];
      if (choice) {
        select.value = choice.value;
        panel.querySelector('.package-choice').hidden = true;
        panel.querySelector('.change-device').hidden = false;
      }
    }
    if (panel) updatePackage(panel);
  }
  picker.querySelectorAll('.primary-package').forEach(select => select.addEventListener('change', () => {
    userSelectedPackage = true;
    updatePackage(select.closest('.platform-panel'));
  }));
  picker.querySelectorAll('.change-device').forEach(button => button.addEventListener('click', () => {
    const choice = button.closest('.platform-panel').querySelector('.package-choice');
    choice.hidden = false;
    choice.querySelector('select').focus();
    button.hidden = true;
  }));
  picker.addEventListener('click', event => {
    const link = event.target.closest('a[href^="#guide-"], a[href="#verify-download"]');
    if (!link) return;
    const target = document.getElementById(link.hash.slice(1));
    if (target) target.open = true;
  });
  const initial = picker.dataset.initialPlatform || detectedPlatform || 'windows';
  selectPlatform(initial);
  // Only high-entropy client hints identify the OS CPU reliably. A 32-bit
  // browser on a 64-bit OS, or an Intel UA on Apple Silicon, is ambiguous.
  navigator.userAgentData?.getHighEntropyValues?.(['architecture', 'bitness'])
    .then(hints => {
      if (hints.bitness === '64') {
        if (hints.architecture === 'x86') detectedArch = 'x64';
        if (hints.architecture === 'arm') detectedArch = 'arm64';
      }
      const current = panels.find(panel => !panel.hidden);
      if (current && !userSelectedPackage) selectPlatform(current.id);
    }).catch(() => { /* Keep the explicit device choice. */ });
})();
