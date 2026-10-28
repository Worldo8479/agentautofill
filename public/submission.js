const id = location.pathname.split('/').pop();
const form = document.querySelector('#encrypted-form');
const input = document.querySelector('#encrypted-payload');
const button = document.querySelector('#submit-package');
const error = document.querySelector('#error');
form.addEventListener('submit', async event => {
  event.preventDefault();
  const payload = input.value.trim();
  button.disabled = true; button.textContent = 'Submitting encrypted package…'; error.textContent = '';
  try {
    const response = await fetch(`/api/forms/${id}/submit`, { method: 'POST', credentials: 'omit', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ payload }) });
    const result = await response.json();
    if (!response.ok) {
      if ([410, 422].includes(response.status)) { input.value = ''; form.classList.add('hidden'); }
      throw new Error(result.error || 'Submission failed.');
    }
    input.value = ''; form.classList.add('hidden');
    const status = document.querySelector('#submission-result');
    status.classList.remove('hidden');
    status.textContent = `Submission accepted. ${result.fieldsReceived} fields received. Receipt: ${result.receiptId}. The package has been consumed. No decrypted values were returned.`;
  } catch (err) {
    // Keep failures visible even when a consumed package hides the form.
    const status = document.querySelector('#submission-result');
    status.classList.remove('hidden');
    status.textContent = err.message || 'Unable to confirm submission. Ask the owner to check Activity before retrying.';
  } finally { button.disabled = false; button.textContent = 'Submit encrypted package →'; }
});
