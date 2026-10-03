// SPDX-License-Identifier: MIT OR Apache-2.0
(() => {
  const form = document.querySelector('form[action="/recover"]');
  const status = document.getElementById('recovery-verification');
  if (!form || !status) return;
  const button = form.querySelector('button[type="submit"]');
  let busy = false;
  const encode = bytes => btoa(String.fromCharCode(...bytes))
    .replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
  const digest = async bytes => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  const enough = (hash, bits) => {
    for (const byte of hash) {
      if (bits <= 0) return true;
      const needed = Math.min(bits, 8);
      if ((byte >>> (8 - needed)) !== 0) return false;
      bits -= needed;
    }
    return bits <= 0;
  };
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (busy || !form.reportValidity()) return;
    busy = true;
    button.disabled = true;
    status.textContent = 'Checking your browser. Please wait…';
    try {
      if (!crypto.subtle) throw new Error('unavailable');
      const identifier = form.elements.namedItem('identifier');
      const original = identifier.value;
      const target = form.elements.namedItem('return_to').value;
      const context = encode(await digest(new TextEncoder().encode(JSON.stringify([target, original]))));
      const response = await fetch(status.dataset.challengeUrl, {
        method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({endpoint: 'recover', context}),
        signal: AbortSignal.timeout(10000),
      });
      if (!response.ok) throw new Error(response.status === 429 ? 'limited' : 'unavailable');
      const challenge = await response.json();
      if (challenge.algorithm !== 'sha256-leading-zero-bits' ||
          !Number.isInteger(challenge.difficulty_bits) || challenge.difficulty_bits < 1 ||
          challenge.difficulty_bits > 24 || typeof challenge.challenge_id !== 'string' ||
          challenge.challenge_id.length > 256 || !/^[A-Za-z0-9_-]{43}$/.test(challenge.challenge)) {
        throw new Error('unavailable');
      }
      const bytes = Uint8Array.from(atob(challenge.challenge.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0));
      const input = new Uint8Array(bytes.length + 8);
      input.set(bytes);
      const counter = new DataView(input.buffer, bytes.length, 8);
      const deadline = performance.now() + 60000; // Browser responsiveness budget, never an authorization clock.
      for (let attempt = 0; attempt < 0xffffffff; attempt++) {
        counter.setUint32(0, attempt, true);
        if (enough(await digest(input), challenge.difficulty_bits)) {
          if (identifier.value !== original || form.elements.namedItem('return_to').value !== target) throw new Error('changed');
          for (const [name, value] of Object.entries({pow_challenge_id: challenge.challenge_id, pow_nonce: encode(input.slice(bytes.length)), pow_context: context})) {
            let field = form.elements.namedItem(name);
            if (!field) { field = document.createElement('input'); field.type = 'hidden'; field.name = name; form.append(field); }
            field.value = value;
          }
          status.textContent = 'Verification complete. Sending your request…';
          HTMLFormElement.prototype.submit.call(form);
          return;
        }
        if (performance.now() >= deadline) throw new Error('timeout');
      }
      throw new Error('timeout');
    } catch (error) {
      status.textContent = error.message === 'limited' ? 'Too many attempts. Please wait before trying again.' :
        error.message === 'changed' ? 'Your details changed. Select Send recovery instructions to try again.' :
        'Verification could not finish. Select Send recovery instructions to try again.';
      busy = false;
      button.disabled = false;
    }
  });
})();
