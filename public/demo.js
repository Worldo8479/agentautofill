document.querySelector('#demo-form').addEventListener('submit', event => {
  event.preventDefault();
  document.querySelector('#demo-form').classList.add('hidden');
  document.querySelector('#demo-result').classList.remove('hidden');
});
