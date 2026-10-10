// SPDX-License-Identifier: MIT OR Apache-2.0
(() => {
  const root = document.getElementById('account-profile');
  const form = document.getElementById('profile-form');
  const input = document.getElementById('profile-name');
  const save = document.getElementById('profile-save');
  const reload = document.getElementById('profile-reload');
  const status = document.getElementById('profile-status');
  let saved = input.value, expected = saved, pending = false, reading = false, leaveApproved = false, uncertain = null;
  const key = root.dataset.key;
  const dirty = () => input.value !== saved || uncertain !== null;
  function announce(message) { status.textContent = message; }
  function remember() {
    try {
      if (!dirty()) sessionStorage.removeItem(key);
      else sessionStorage.setItem(key, JSON.stringify({name: input.value, expected, uncertain}));
    } catch { announce('This browser cannot keep a recovery copy. Keep this tab open until your name is saved.'); }
  }
  function controls() {
    input.disabled = pending || uncertain !== null;
    save.disabled = pending || (!dirty() && uncertain === null);
    reload.disabled = pending;
    save.textContent = pending && !reading ? 'Saving...' : uncertain !== null ? 'Retry same save' : 'Save name';
    reload.textContent = reading ? 'Loading...' : 'Reload saved name';
  }
  try {
    const draft = JSON.parse(sessionStorage.getItem(key) || 'null');
    if (draft && typeof draft.name === 'string' && draft.name.length <= 320 && typeof draft.expected === 'string') {
      input.value = draft.name; expected = draft.expected;
      if (draft.uncertain && draft.uncertain.name === draft.name && draft.uncertain.expected_name === draft.expected) uncertain = draft.uncertain;
      announce(uncertain ? 'Your last save was not confirmed. Retry the same save or reload the saved name.' : 'Your unsaved name was restored.');
    }
  } catch { announce('Your recovery copy could not be read. The current saved name is shown.'); }
  controls();
  input.addEventListener('input', () => { remember(); controls(); });
  window.addEventListener('beforeunload', event => {
    if (!leaveApproved && (dirty() || pending)) { event.preventDefault(); event.returnValue = ''; }
  });
  const back = document.getElementById('profile-return');
  if (back) back.addEventListener('click', event => {
    if (pending || (dirty() && !window.confirm('Leave without confirming your display name? Your recovery copy stays in this browser tab.'))) event.preventDefault();
    else leaveApproved = true;
  });
  async function request(method, body) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    try {
      const response = await fetch(root.dataset.base, {method, credentials:'same-origin', cache:'no-store', signal:controller.signal,
        ...(body ? {headers:{'Content-Type':'application/json'},body:JSON.stringify(body)} : {})});
      const value = await response.json();
      return {response, value};
    } finally { clearTimeout(timer); }
  }
  form.addEventListener('submit', async event => {
    event.preventDefault(); if (pending) return;
    const name = input.value.trim();
    if (Array.from(name).length > 80 || /[\u0000-\u001f\u007f-\u009f]/u.test(name)) {
      announce('Use up to 80 characters without control characters.'); input.focus(); return;
    }
    const payload = uncertain || {expected_name:expected, name};
    input.value = payload.name; uncertain = payload; pending = true; remember(); controls();
    let message;
    try {
      const {response,value} = await request('POST', payload);
      if (response.ok && value.name === payload.name) {
        saved = value.name; expected = saved; input.value = saved; uncertain = null;
        message = saved ? 'Display name saved. Continue to your application to use it.' : 'Display name removed.';
      } else if (response.status === 409) {
        uncertain = null; message = 'Your saved name changed in another session. Your input is kept. Reload the saved name before trying again.';
      } else if (response.status === 400 || response.status === 422) {
        uncertain = null; message = 'Check your display name. Use up to 80 characters without control characters.';
      } else if (response.status === 401 || response.status === 403) {
        message = 'Sign in again from your application, then reopen your display name. Your unconfirmed save is kept in this tab.';
      } else { message = 'Save not confirmed. Retry the same save or reload the saved name.'; }
    } catch { message = 'Save not confirmed. Retry the same save or reload the saved name.'; }
    finally { pending = false; remember(); controls(); announce(message); status.focus(); }
  });
  reload.addEventListener('click', async () => {
    if (pending || (dirty() && !window.confirm('Replace your input with the current saved name?'))) return;
    pending = true; reading = true; controls();
    try {
      const {response,value} = await request('GET');
      if (!response.ok || typeof value.name !== 'string') throw new Error('read');
      saved=value.name; expected=saved; input.value=saved; uncertain=null; remember();
      announce('Current saved name loaded.');
    } catch { announce('Could not reload your saved name. Your input is kept. Try again after signing in.'); }
    finally { pending=false; reading=false; controls(); status.focus(); }
  });
})();
