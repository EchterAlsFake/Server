/* Open in-page FAQ links without leaving checkout; native summaries do the rest. */
document.querySelectorAll('[data-checkout-faq]').forEach(link => {
  const question = document.getElementById(link.dataset.checkoutFaq);
  if (!question) return;
  link.addEventListener('click', event => {
    event.preventDefault();
    question.open = true;
    question.querySelector('summary').focus();
  });
});
