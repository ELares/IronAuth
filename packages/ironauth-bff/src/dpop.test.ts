// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * DPoP proof shape, and the discovery rules (issue #116).
 *
 * `scripts/bff-live.sh` proves these work against a real IronAuth, which is the evidence that
 * matters. It needs a compiled server and a Postgres, so it cannot run on every change to this
 * package; these tests pin the pieces a live lane would only tell you about in aggregate, and
 * they run in milliseconds.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { discover, forgetDiscovery } from './discovery.js';
import { dpopProof, newDpopKey, thumbprint } from './dpop.js';

const ISSUER = 'https://iss.example/t/ten_x/e/env_y';

function decode(segment: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as Record<string, unknown>;
}

test('a proof carries the header and claims RFC 9449 requires', async () => {
  const key = await newDpopKey();
  const [header, payload, signature] = (
    await dpopProof(key, 'POST', 'https://iss.example/token', 1000)
  ).split('.');

  const decoded = decode(header);
  assert.equal(decoded.typ, 'dpop+jwt');
  assert.equal(decoded.alg, 'ES256');
  // The PUBLIC key travels in the header; the private half must never appear anywhere in the
  // proof, which is the one mistake in this file that would be catastrophic and silent.
  assert.deepEqual(Object.keys(decoded.jwk as object).sort(), ['crv', 'kty', 'x', 'y']);
  assert.equal((decoded.jwk as Record<string, unknown>).d, undefined);

  const claims = decode(payload);
  assert.equal(claims.htm, 'POST');
  assert.equal(claims.htu, 'https://iss.example/token');
  assert.equal(claims.iat, 1000);
  assert.equal(typeof claims.jti, 'string');
  // No `ath` when no access token was named: the claim binds a proof to a token, and sending it
  // at the token endpoint (where no token exists yet) is meaningless.
  assert.equal(claims.ath, undefined);
  assert.ok(signature.length > 0);
});

test('htu drops the query and fragment', async () => {
  const key = await newDpopKey();
  const proof = await dpopProof(key, 'GET', 'https://api.example/orders?page=2#top', 1000);
  // RFC 9449 defines htu WITHOUT them. A proof carrying `?page=2` is refused for a reason that
  // looks nothing like its cause, so this is stripped rather than left to the caller.
  assert.equal(decode(proof.split('.')[1]).htu, 'https://api.example/orders');
});

test('ath binds a proof to one specific access token', async () => {
  const key = await newDpopKey();
  const first = decode((await dpopProof(key, 'GET', 'https://api.example/me', 1000, 'at-1')).split('.')[1]);
  const second = decode((await dpopProof(key, 'GET', 'https://api.example/me', 1000, 'at-2')).split('.')[1]);
  assert.equal(typeof first.ath, 'string');
  // DIFFERENT tokens, different ath. Without this a proof captured from one request could be
  // replayed with any other token, which is what ath exists to stop.
  assert.notEqual(first.ath, second.ath);
});

test('every proof carries a fresh jti', async () => {
  const key = await newDpopKey();
  const seen = new Set<unknown>();
  for (let i = 0; i < 20; i++) {
    seen.add(decode((await dpopProof(key, 'POST', 'https://iss.example/token', 1000)).split('.')[1]).jti);
  }
  // The server keeps a replay cache keyed on (jkt, jti) and refuses a repeat inside the
  // freshness window, so a reused jti would make the SECOND request of a session fail.
  assert.equal(seen.size, 20);
});

test('the thumbprint is stable for a key and different across keys', async () => {
  const key = await newDpopKey();
  assert.equal(await thumbprint(key.publicJwk), await thumbprint(key.publicJwk));
  assert.notEqual(await thumbprint(key.publicJwk), await thumbprint((await newDpopKey()).publicJwk));
});

test('discovery reads the endpoints rather than concatenating', async () => {
  forgetDiscovery();
  const metadata = await discover(ISSUER, fakeIssuer(), () => 1000);
  // The endpoints are at the HOST ROOT while the issuer carries an environment path. This is the
  // arrangement that made `${issuer}/token` a 404 against a real IronAuth.
  assert.equal(metadata.tokenEndpoint, 'https://iss.example/token');
  assert.notEqual(metadata.tokenEndpoint, `${ISSUER}/token`);
});

test('a document naming a different issuer is refused', async () => {
  forgetDiscovery();
  // Otherwise pointing the BFF at any URL yields a document naming an attacker-chosen issuer and
  // endpoints to match, and every later check passes against that name.
  await assert.rejects(
    () => discover(ISSUER, fakeIssuer({ issuer: 'https://attacker.example' }), () => 1000),
    /names issuer https:\/\/attacker.example/,
  );
});

test('a document missing an endpoint is refused rather than half-used', async () => {
  forgetDiscovery();
  await assert.rejects(
    () => discover(ISSUER, fakeIssuer({ omitToken: true }), () => 1000),
    /missing authorization_endpoint or token_endpoint/,
  );
});

test('the document is cached, and the cache expires', async () => {
  forgetDiscovery();
  let fetches = 0;
  const counting = ((...args: Parameters<typeof fetch>) => {
    fetches++;
    return fakeIssuer()(...args);
  }) as typeof fetch;

  await discover(ISSUER, counting, () => 1000);
  await discover(ISSUER, counting, () => 1000);
  assert.equal(fetches, 1, 'a second login must not refetch the document');
  // An hour later it is refetched, so an endpoint move takes effect without a redeploy.
  await discover(ISSUER, counting, () => 1000 + 3601);
  assert.equal(fetches, 2);
});

/** A discovery endpoint that answers the way IronAuth does. */
function fakeIssuer(options: { issuer?: string; omitToken?: boolean } = {}): typeof fetch {
  return (async (input: string | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url !== `${ISSUER}/.well-known/openid-configuration`) {
      return new Response('not found', { status: 404 });
    }
    const document: Record<string, unknown> = {
      issuer: options.issuer ?? ISSUER,
      authorization_endpoint: 'https://iss.example/authorize',
    };
    if (!options.omitToken) {
      document.token_endpoint = 'https://iss.example/token';
    }
    return new Response(JSON.stringify(document), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;
}
