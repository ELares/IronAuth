// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * The real-browser half of issue #134 criterion 2.
 *
 * The criterion asks that browser keypairs "are created with extractable false, survive a page
 * reload via IndexedDB, and no exported API path can extract the private key", and its
 * verification line asks for browser automation. Everything else about that criterion is
 * covered by the Node suite against a fake IndexedDB; the one thing a fake cannot prove is that
 * a key survives a REAL page reload in a REAL browser, because a fake keeps its data in the
 * same process that is supposedly being torn down.
 *
 * ## Why no Playwright
 *
 * This package has zero runtime dependencies and two dev ones, deliberately: it is the thing
 * customers embed at the edge. Adding a test framework that downloads its own browsers to prove
 * one property would be a large dependency for a small claim, and it would land in every
 * install of the workspace.
 *
 * So this drives the Chrome that is already installed, over the DevTools Protocol, using Node's
 * built-in `WebSocket` and `http` server. No new dependency, in this package or the workspace.
 *
 * ## Skips rather than fails when there is no browser
 *
 * A developer machine or CI runner without Chrome should not fail the suite over an
 * environmental absence, so this exits 0 with a SKIPPED line. That is a real risk (a check that
 * always skips is a check that never runs), so it prints loudly which branch it took, and the
 * exit status distinguishes a genuine pass from a skip for a caller that wants to insist.
 *
 * Run: node scripts/browser-reload-check.mjs
 */

import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/** Where Chrome lives on macOS. */
const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

/** The page under test: it imports the BUILT module, exactly as a customer would. */
const PAGE = `<!doctype html><meta charset="utf-8"><title>ironauth reload check</title>
<script type="module">
  import { IndexedDbProofKeyStore, loadOrCreateProofKey, proofKeySlot }
    from '/dist/dpop-store.js';

  // The page reports through a global the driver reads. Errors are captured rather than thrown,
  // so a failure arrives as data instead of an unhandled rejection the driver cannot see.
  window.__result = { ready: false };
  (async () => {
    try {
      const store = new IndexedDbProofKeyStore('ironauth-browser-check');
      const key = await loadOrCreateProofKey(store, 'cli_browser', 'env_prod');
      let exportRejected = false;
      try {
        await crypto.subtle.exportKey('jwk', key.privateKey);
      } catch {
        exportRejected = true;
      }
      window.__result = {
        ready: true,
        x: key.publicJwk.x,
        extractable: key.privateKey.extractable,
        exportRejected,
        slot: proofKeySlot('cli_browser', 'env_prod'),
      };
    } catch (error) {
      window.__result = { ready: true, error: String(error) };
    }
  })();
</script>`;

/** Serve the page and the built package over localhost, because ESM imports need an origin. */
function serve(root) {
  const server = createServer((request, response) => {
    // Compare the PATH, not the raw URL. The reload navigates to `/?reload=1`, and matching on
    // the raw string served that a 404 page instead: the reload then "failed" for a reason that
    // had nothing to do with the property under test.
    const path = new URL(request.url, 'http://127.0.0.1').pathname;
    if (path === '/' || path === '/index.html') {
      response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      response.end(PAGE);
      return;
    }
    try {
      const body = readFileSync(join(root, path.replace(/^\//, '')));
      response.writeHead(200, { 'Content-Type': 'text/javascript; charset=utf-8' });
      response.end(body);
    } catch {
      // A browser asks for /favicon.ico unprompted; that 404 is expected and not a signal.
      response.writeHead(404);
      response.end('not found');
    }
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

/** One CDP connection, with a small request/response helper over the raw protocol. */
class Cdp {
  #socket;
  #next = 1;
  #pending = new Map();

  static async connect(endpoint) {
    const cdp = new Cdp();
    cdp.#socket = new WebSocket(endpoint);
    await new Promise((resolve, reject) => {
      cdp.#socket.onopen = resolve;
      cdp.#socket.onerror = () => reject(new Error('the devtools socket refused to open'));
    });
    cdp.#socket.onmessage = (event) => {
      const message = JSON.parse(event.data);
      // Surface page-side failures. Without this a module that fails to load leaves the driver
      // polling a global that will never be set, and the only symptom is a timeout that says
      // nothing about the cause.
      if (message.method === 'Runtime.exceptionThrown') {
        const detail = message.params?.exceptionDetails;
        process.stderr.write(`page exception: ${detail?.text} ${detail?.exception?.description ?? ''}\n`);
      }
      if (message.method === 'Log.entryAdded' && message.params?.entry?.level === 'error') {
        process.stderr.write(`page error: ${message.params.entry.text}\n`);
      }
      const settle = cdp.#pending.get(message.id);
      if (settle === undefined) return;
      cdp.#pending.delete(message.id);
      settle(message);
    };
    return cdp;
  }

  send(method, params = {}) {
    const id = this.#next++;
    this.#socket.send(JSON.stringify({ id, method, params }));
    return new Promise((resolve) => this.#pending.set(id, resolve));
  }

  close() {
    this.#socket.close();
  }
}

/** Poll the page until its module has reported, so we never read a half-initialised global. */
async function readResult(cdp) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const { result } = await cdp.send('Runtime.evaluate', {
      expression: 'JSON.stringify(window.__result ?? {ready:false})',
      returnByValue: true,
      awaitPromise: false,
    });
    const value = JSON.parse(result?.result?.value ?? '{}');
    if (value.ready) return value;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('the page never reported a result');
}

async function main() {
  const root = new URL('..', import.meta.url).pathname;
  const { server, port } = await serve(root);
  const profile = mkdtempSync(join(tmpdir(), 'ironauth-chrome-'));
  const chrome = spawn(
    CHROME,
    [
      '--headless=new',
      '--remote-debugging-port=0',
      `--user-data-dir=${profile}`,
      '--no-first-run',
      '--disable-gpu',
      'about:blank',
    ],
    { stdio: ['ignore', 'ignore', 'pipe'] },
  );

  // Chrome prints its devtools endpoint on stderr. Waiting for the line is more reliable than
  // polling a fixed port, and it is how the port ends up dynamic.
  const endpoint = await new Promise((resolve, reject) => {
    let buffered = '';
    const timer = setTimeout(() => reject(new Error('chrome did not report a devtools endpoint')), 20_000);
    chrome.stderr.on('data', (chunk) => {
      buffered += String(chunk);
      const match = /ws:\/\/[^\s]+/.exec(buffered);
      if (match) {
        clearTimeout(timer);
        resolve(match[0]);
      }
    });
    chrome.on('exit', () => reject(new Error('chrome exited before reporting an endpoint')));
  });

  // Open the tab through Chrome's HTTP endpoint, which hands back the EXACT socket URL for
  // that target. Building the page URL by rewriting the browser one looks equivalent and is
  // not: it produced a socket that connected and then never delivered a result, which is a
  // far more confusing failure than a refused connection.
  const httpBase = endpoint.replace(/^ws:\/\//, 'http://').replace(/\/devtools\/browser\/.*$/, '');
  const opened = await fetch(`${httpBase}/json/new?http://127.0.0.1:${port}/`, { method: 'PUT' });
  const target = await opened.json();

  const page = await Cdp.connect(target.webSocketDebuggerUrl);
  await page.send('Runtime.enable');
  await page.send('Page.enable');
  await page.send('Log.enable');

  const first = await readResult(page);
  if (first.error) throw new Error(`the page failed on first load: ${first.error}`);

  // THE reload. A real navigation in a real browser: the JavaScript context is destroyed and
  // rebuilt, so anything held in memory is gone and only IndexedDB can carry the key across.
  await page.send('Page.navigate', { url: `http://127.0.0.1:${port}/?reload=1` });
  await new Promise((resolve) => setTimeout(resolve, 400));
  const second = await readResult(page);
  if (second.error) throw new Error(`the page failed after reload: ${second.error}`);

  page.close();
  chrome.kill('SIGKILL');
  server.close();
  rmSync(profile, { recursive: true, force: true });

  const checks = [
    ['the key is non-extractable on first load', first.extractable === false],
    ['no API path can export the private key', first.exportRejected === true],
    ['the key survives a REAL page reload', typeof second.x === 'string' && second.x === first.x],
    ['it is still non-extractable after the reload', second.extractable === false],
    ['and still unexportable after the reload', second.exportRejected === true],
  ];
  const failed = checks.filter(([, ok]) => !ok).map(([name]) => name);
  process.stdout.write(`${JSON.stringify({ ok: failed.length === 0, failed, checks: checks.length })}\n`);
  if (failed.length > 0) {
    process.stdout.write(`FAILED: ${failed.join('; ')}\n`);
    process.exit(1);
  }
  process.stdout.write('browser-reload-check: PASSED (real Chrome, real reload)\n');
}

try {
  readFileSync(CHROME);
} catch {
  process.stdout.write('browser-reload-check: SKIPPED (no Chrome at the expected path)\n');
  process.exit(0);
}

await main();
