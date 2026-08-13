// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  createProof,
  demandsNonce,
  fetchWithProof,
  generateProofKey,
  htu,
  nonceFrom,
  type DpopClientError,
} from './dpop.js';

/*
 * Every test that drives `fetchWithProof` carries a TIMEOUT.
 *
 * A retry bug is an infinite loop, and an unbounded test does not fail on one, it HANGS: a
 * mutation that removed the single-retry rule pinned a core at 97% CPU for twenty minutes
 * and reported nothing. A hang is not a test result, so the bound turns that into a
 * failure the suite can report.
 */

/** Decode a base64url segment back to a string. */
function decode(segment: string): string {
  const padded = segment.replace(/-/g, '+').replace(/_/g, '/');
  return atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
}

function parts(proof: string): { header: any; payload: any; signature: string } {
  const [header, payload, signature] = proof.split('.');
  return {
    header: JSON.parse(decode(header)),
    payload: JSON.parse(decode(payload)),
    signature,
  };
}

test('a proof carries the header RFC 9449 requires', async () => {
  const key = await generateProofKey();
  const { header } = parts(
    await createProof(key, { method: 'get', url: 'https://api.example/resource' }),
  );
  assert.equal(header.typ, 'dpop+jwt');
  assert.equal(header.alg, 'EdDSA');
  assert.equal(header.jwk.kty, 'OKP');
  assert.equal(header.jwk.crv, 'Ed25519');
  assert.ok(typeof header.jwk.x === 'string' && header.jwk.x.length > 0);
});

test('the embedded jwk carries no private material and no runtime noise', async () => {
  const key = await generateProofKey();
  const { header } = parts(
    await createProof(key, { method: 'GET', url: 'https://api.example/r' }),
  );
  // `d` is the PRIVATE scalar. Its presence would publish the signing key in every proof.
  assert.equal(header.jwk.d, undefined, 'a proof must never carry private key material');
  // Exactly the members that identify the key. Extra members differ between runtimes, and
  // a server pinning the thumbprint would then see one key as two.
  assert.deepEqual(Object.keys(header.jwk).sort(), ['crv', 'kty', 'x']);
});

test('the method is normalized and the htu drops query and fragment', async () => {
  const key = await generateProofKey();
  const { payload } = parts(
    await createProof(key, {
      method: 'post',
      url: 'https://api.example/resource?token=secret#frag',
    }),
  );
  assert.equal(payload.htm, 'POST');
  assert.equal(
    payload.htu,
    'https://api.example/resource',
    'the query must be stripped: a proxy that re-encodes it would otherwise break every proof',
  );
  assert.ok(!payload.htu.includes('secret'), 'a query secret must not reach the proof');
});

test('ath appears only when an access token is presented, and is its digest', async () => {
  const key = await generateProofKey();
  const without = parts(
    await createProof(key, { method: 'GET', url: 'https://api.example/r' }),
  );
  assert.equal(without.payload.ath, undefined);

  const withToken = parts(
    await createProof(key, {
      method: 'GET',
      url: 'https://api.example/r',
      accessToken: 'the-access-token',
    }),
  );
  // Compared against a digest computed by a DIFFERENT implementation (Node's crypto,
  // which the runtime-portable module deliberately never touches), so this is a
  // cross-implementation check rather than the test recomputing what the code just did
  // with the same function.
  const expected = createHash('sha256')
    .update('the-access-token')
    .digest('base64url');
  assert.equal(withToken.payload.ath, expected);
  assert.equal(
    (withToken.payload.ath as string).length,
    43,
    'ath is an unpadded base64url SHA-256',
  );
  // Different tokens must produce different thumbprints, which is the property that stops
  // a proof being replayed alongside another token.
  const other = parts(
    await createProof(key, {
      method: 'GET',
      url: 'https://api.example/r',
      accessToken: 'a-different-token',
    }),
  );
  assert.notEqual(withToken.payload.ath, other.payload.ath);
});

test('every proof is unique even for an identical request', async () => {
  const key = await generateProofKey();
  const request = { method: 'GET', url: 'https://api.example/r' };
  const first = parts(await createProof(key, request));
  const second = parts(await createProof(key, request));
  assert.notEqual(
    first.payload.jti,
    second.payload.jti,
    'a reused jti is a replay the server will reject',
  );
  assert.notEqual(first.signature, second.signature);
});

test('the private key cannot be exported', async () => {
  const key = await generateProofKey();
  assert.equal(key.privateKey.extractable, false);
  await assert.rejects(
    () => crypto.subtle.exportKey('jwk', key.privateKey),
    'a non-extractable key must refuse export; this is what bounds an XSS compromise',
  );
});

test('the signature verifies under the embedded public key', async () => {
  const key = await generateProofKey();
  const proof = await createProof(key, { method: 'GET', url: 'https://api.example/r' });
  const [header, payload, signature] = proof.split('.');
  const publicKey = await crypto.subtle.importKey(
    'jwk',
    key.publicJwk,
    { name: 'Ed25519' },
    true,
    ['verify'],
  );
  const raw = Uint8Array.from(
    atob(signature.replace(/-/g, '+').replace(/_/g, '/')),
    (character) => character.charCodeAt(0),
  );
  const verified = await crypto.subtle.verify(
    { name: 'Ed25519' },
    publicKey,
    raw,
    new TextEncoder().encode(`${header}.${payload}`),
  );
  assert.ok(verified, 'a proof a server cannot verify is not a proof');
});

test('htu rejects a relative url rather than inventing an origin', () => {
  assert.throws(() => htu('/resource'));
});

test('a nonce demand is recognized and answered by exactly one retry', { timeout: 5_000 }, async () => {
  const key = await generateProofKey();
  const seen: Array<string | null> = [];
  let calls = 0;
  const send = async (_input: string, init?: RequestInit): Promise<Response> => {
    calls += 1;
    const headers = new Headers(init?.headers);
    const proof = headers.get('DPoP') ?? '';
    seen.push(parts(proof).payload.nonce ?? null);
    if (calls === 1) {
      return new Response('', {
        status: 401,
        headers: {
          'WWW-Authenticate': 'DPoP error="use_dpop_nonce"',
          'DPoP-Nonce': 'server-nonce',
        },
      });
    }
    return new Response('ok', { status: 200 });
  };

  const response = await fetchWithProof(
    key,
    'https://api.example/r',
    { method: 'GET' },
    send as typeof fetch,
  );
  assert.equal(response.status, 200);
  assert.equal(calls, 2, 'exactly one retry');
  assert.equal(seen[0], null, 'the first proof carries no nonce');
  assert.equal(seen[1], 'server-nonce', 'the retry echoes the nonce the server issued');
});

test('a server that keeps demanding a nonce is not retried forever', { timeout: 5_000 }, async () => {
  const key = await generateProofKey();
  let calls = 0;
  const send = async (): Promise<Response> => {
    calls += 1;
    // The fake REFUSES to be called indefinitely. A runaway retry is an infinite loop,
    // and a timeout does not turn that into a reportable failure: the test aborts but the
    // loop keeps the worker alive, so the run hangs instead of failing. Measured: a
    // mutation removing the single-retry rule pinned a core for twenty minutes and
    // reported nothing. Throwing here makes the same bug fail in milliseconds.
    if (calls > 3) {
      throw new Error(`retried ${calls} times; the single-retry rule is gone`);
    }
    return new Response('', {
      status: 401,
      headers: {
        'WWW-Authenticate': 'DPoP error="use_dpop_nonce"',
        'DPoP-Nonce': 'another-nonce',
      },
    });
  };
  // Exhausting the one retry is a TYPED failure rather than the raw 401 handed back: the
  // request could not be made under DPoP at all, which is not an ordinary protocol answer.
  await assert.rejects(
    () => fetchWithProof(key, 'https://api.example/r', {}, send as typeof fetch),
    (error: DpopClientError) => error.reason === 'nonce_retry_exhausted',
  );
  assert.equal(
    calls,
    2,
    'one retry only; looping would turn one client into a request storm against an endpoint that is already unhappy',
  );
});

test('a nonce demand with no nonce supplied is not retried', { timeout: 5_000 }, async () => {
  const key = await generateProofKey();
  let calls = 0;
  const send = async (): Promise<Response> => {
    calls += 1;
    return new Response('', {
      status: 401,
      headers: { 'WWW-Authenticate': 'DPoP error="use_dpop_nonce"' },
    });
  };
  await assert.rejects(
    () => fetchWithProof(key, 'https://api.example/r', {}, send as typeof fetch),
    (error: DpopClientError) => error.reason === 'nonce_retry_exhausted',
  );
  assert.equal(calls, 1, 'retrying without a nonce would send an identical proof');
});

test('an access token is presented under the DPoP scheme, never Bearer', { timeout: 5_000 }, async () => {
  const key = await generateProofKey();
  let authorization: string | null = null;
  const send = async (_input: string, init?: RequestInit): Promise<Response> => {
    authorization = new Headers(init?.headers).get('Authorization');
    return new Response('ok', { status: 200 });
  };
  await fetchWithProof(
    key,
    'https://api.example/r',
    { accessToken: 'tok' },
    send as typeof fetch,
  );
  assert.equal(
    authorization,
    'DPoP tok',
    'presenting a sender-constrained token as Bearer is what DPoP exists to stop',
  );
});

test('an ordinary failure is returned rather than retried', { timeout: 5_000 }, async () => {
  const key = await generateProofKey();
  let calls = 0;
  const send = async (): Promise<Response> => {
    calls += 1;
    return new Response('', { status: 403 });
  };
  const response = await fetchWithProof(key, 'https://api.example/r', {}, send as typeof fetch);
  assert.equal(response.status, 403);
  assert.equal(calls, 1, 'only a nonce demand is retried');
});

test('demandsNonce ignores a success and an unrelated failure', () => {
  assert.equal(demandsNonce({ status: 200, headers: new Headers() }), false);
  assert.equal(demandsNonce({ status: 500, headers: new Headers() }), false);
  assert.equal(
    demandsNonce({
      status: 401,
      headers: new Headers({ 'WWW-Authenticate': 'DPoP error="invalid_token"' }),
    }),
    false,
    'a different DPoP error is not a nonce demand and must not be retried',
  );
});

test('nonceFrom reads the header the server issued', () => {
  assert.equal(
    nonceFrom({ headers: new Headers({ 'DPoP-Nonce': 'n1' }) }),
    'n1',
  );
  assert.equal(nonceFrom({ headers: new Headers() }), undefined);
});
