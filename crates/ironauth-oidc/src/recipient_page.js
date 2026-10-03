// SPDX-License-Identifier: MIT OR Apache-2.0
(() => {
  'use strict';
  const root = document.getElementById('verification');
  const status = document.getElementById('verification-status');
  const sendForm = document.getElementById('send-form');
  const verifyForm = document.getElementById('verify-form');
  const sendButton = document.getElementById('send-code');
  const cancelButton = document.getElementById('cancel-verification');
  const code = document.getElementById('verification-code');
  const email = document.getElementById('recipient-email').value;
  const key = root.dataset.key;
  let pending = null;
  let busy = false;
  let retryAt = 0;
  let finished = root.dataset.verified === 'true';

  function say(text) { status.textContent = text; }
  function save() {
    // Only a non-secret, subject-bound challenge handle and UX deadlines persist.
    // Never store the email, code, session or application continuation here.
    try {
      if (pending) sessionStorage.setItem(key, JSON.stringify(pending));
      else sessionStorage.removeItem(key);
    } catch (_) { /* The live page still works when storage is unavailable. */ }
  }
  function show() {
    document.getElementById('verification-actions').hidden = finished;
    verifyForm.hidden = !pending || finished;
    for (const button of root.querySelectorAll('button')) button.disabled = busy;
    const wait = Math.max(0, Math.ceil((retryAt - Date.now()) / 1000));
    sendButton.disabled = busy || wait > 0;
    sendButton.classList.toggle('secondary', Boolean(pending));
    sendButton.textContent = wait > 0 ? `Request another code in ${wait}s` : pending ? 'Send a new code' : 'Send verification code';
  }
  function failure(body) {
    if (body.error === 'reauthentication_required' || body.error === 'unauthenticated') return 'Sign in again from the application, then reopen email verification. Your account access has not changed.';
    if (body.error === 'retry_later') return 'Please wait before requesting another code. You can still enter the latest code you received.';
    if (body.error === 'recipient_not_verified') return 'This code or mailbox could not be verified for your signed-in account. Check the latest code, or contact your administrator if mailbox setup is incomplete.';
    return 'Verification is temporarily unavailable. Try again shortly. Your account access has not changed.';
  }
  async function request(operation, body) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 7000);
    try {
      const response = await fetch(`${root.dataset.base}/${operation}`, {
        method: 'POST', credentials: 'same-origin', redirect: 'error',
        headers: {'Content-Type': 'application/json', 'Accept': 'application/json'},
        body: JSON.stringify(body), signal: controller.signal,
      });
      const value = await response.json();
      return {ok: response.ok, value};
    } finally { clearTimeout(timer); }
  }
  try {
    const stored = JSON.parse(sessionStorage.getItem(key) || 'null');
    if (stored && typeof stored.id === 'string' && stored.id.length <= 128 &&
        Number.isFinite(stored.expires) && stored.expires > Date.now() &&
        Number.isFinite(stored.retryAt)) {
      pending = stored;
      retryAt = stored.retryAt;
      say('Enter the latest code you received. You can request a new one after the waiting period.');
    }
  } catch (_) { /* No usable saved challenge. */ }
  if (finished) {
    pending = null; save();
    say('Your email is verified. Continue to the application to finish joining.');
    document.getElementById('return-application').textContent = 'Continue to application';
  }
  sendForm.addEventListener('submit', async event => {
    event.preventDefault();
    if (busy || finished || Date.now() < retryAt) return;
    busy = true; show(); say('Requesting your code...');
    try {
      const result = await request('start', {email});
      const data = result.value;
      if (typeof data.challenge_id === 'string' && data.challenge_id.length <= 128 &&
          ['accepted', 'refused', 'uncertain'].includes(data.delivery)) {
        retryAt = Date.now() + 60000;
        pending = {id: data.challenge_id, expires: Date.now() + 300000, retryAt};
        save(); code.value = '';
        say(data.delivery === 'accepted'
          ? 'The mail server accepted your message. Check your inbox and spam folder for the code.'
          : data.delivery === 'uncertain'
          ? 'We could not confirm whether the message was accepted. Check your inbox before requesting a new code.'
          : 'The mail server refused this message. You can request a new code after the waiting period.');
      } else {
        if (data.error === 'retry_later') retryAt = Date.now() + 60000;
        say(failure(data));
      }
    } catch (_) {
      pending = null; save(); code.value = '';
      retryAt = Date.now() + 60000;
      say('The request result is unknown. Do not assume a code was sent. Wait one minute, then request a new code; the new request will replace any earlier code.');
    } finally { busy = false; show(); if (pending) code.focus(); }
  });
  verifyForm.addEventListener('submit', async event => {
    event.preventDefault();
    if (busy || finished || !pending || !/^[0-9]{8}$/.test(code.value)) return;
    busy = true; show();
    try {
      const result = await request('verify', {challenge_id: pending.id, code: code.value});
      code.value = '';
      if (result.ok && result.value.verified === true) {
        finished = true; pending = null; save();
        say('Your email is verified. Continue to the application to finish joining.');
        document.getElementById('return-application').textContent = 'Continue to application';
      } else say(failure(result.value));
    } catch (_) {
      code.value = '';
      say('The verification result is unknown. Reload this page to check your current verification before trying again.');
    } finally { busy = false; show(); status.focus(); }
  });
  cancelButton.addEventListener('click', async () => {
    if (busy || finished) return;
    busy = true; show();
    try {
      const result = await request('cancel', {});
      if (result.ok && result.value.cancelled === true) {
        pending = null; save(); code.value = ''; finished = true;
        say('Verification cancelled. Pending codes for this account can no longer be used. Existing verified ownership and application access are unchanged.');
      } else say(failure(result.value));
    } catch (_) { say('Cancellation is not confirmed. Retry cancellation before leaving this page.'); }
    finally { busy = false; show(); status.focus(); }
  });
  show();
  setInterval(() => {
    if (pending && pending.expires <= Date.now() && !busy) {
      pending = null; save(); code.value = '';
      say('That code has expired. Request a new code, or return to the application to sign in again.');
    }
    show();
  }, 1000);
})();
