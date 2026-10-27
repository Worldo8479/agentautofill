const id = location.pathname.split('/').pop();
const form = document.querySelector('#redeem');
document.querySelector('#demo-target').addEventListener('click', () => { document.querySelector('#target').value = `${location.origin}/demo`; });
form.addEventListener('submit', async event => {
  event.preventDefault();
  const button = document.querySelector('#redeem-button');
  const input = document.querySelector('#pin');
  const error = document.querySelector('#error');
  const pin = input.value;
  button.disabled = true; button.textContent = 'Filling in the private browser…'; error.textContent = '';
  input.value = '';
  try {
    const response = await fetch(`/api/agent/${id}/execute`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pin, target: document.querySelector('#target').value }) });
    const result = await response.json();
    if (!response.ok) { if ([410,422].includes(response.status)) { button.classList.add('hidden'); input.disabled = true; } throw new Error(result.error); }
    form.classList.add('hidden');
    const status = document.querySelector('#result');
    status.classList.remove('hidden');
    status.textContent = `${result.fieldsFilled} fields filled successfully. The owner can now review and submit in their private browser. This pass has been consumed.`;
  } catch (err) { error.textContent = err.message || 'Unable to connect. Check with the vault owner before retrying.'; }
  finally { button.disabled = false; button.textContent = 'Use this pass →'; }
});
