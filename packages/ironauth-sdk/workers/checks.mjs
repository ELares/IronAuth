// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * The portability checks, shared by every runtime lane (issue #115).
 *
 * ONE set of checks, executed by Node, Deno, Bun and workerd, rather than each lane running
 * whatever its own test runner happens to discover. That matters: `deno test` and `bun test`
 * do not collect `node:test` cases, so pointing them at the compiled suite would run ZERO
 * tests and exit 0. A lane that passes by running nothing is worse than no lane, because it
 * reports coverage that does not exist.
 *
 * Narrow on purpose. Behaviour is covered by the Node suite; what only these can answer is
 * whether the modules LOAD and their crypto works where there is no Node.
 */

import { createProof, generateProofKey } from '../dist/dpop.js';
import { authorizationUrl, exchangeCode, generatePkce, refresh, userInfo } from '../dist/protocol.js';
import { maxAgeOf } from '../dist/verify.js';
import {
  MemoryProofKeyStore,
  NonceCache,
  loadOrCreateProofKey,
  proofKeySlot,
} from '../dist/dpop-store.js';
// The SNIPPET, not the SDK module. Its headline claim is that it "drops into a Cloudflare
// Worker, a Deno or Bun service, a Node 20+ handler, or a Lambda@Edge function unchanged",
// and until it ran in these lanes that sentence was untested everywhere except Node. The
// one file most likely to be copied into a Worker was the one file never executed in one.
import { VerifyError as SnippetVerifyError, createVerifier } from '../snippets/verify-webcrypto.mjs';
import corpus from '../vectors/verify-vectors.mjs';

/** Run every check, returning `{ ok, failed, count }`. */
export async function runChecks() {
  const checks = [];

  // Ed25519 generate and sign: the DPoP core's whole dependency.
  const key = await generateProofKey();
  const proof = await createProof(key, {
    method: 'GET',
    url: 'https://api.example/resource?drop=this',
    accessToken: 'token',
  });
  checks.push(['dpop proof has three segments', proof.split('.').length === 3]);
  const payload = JSON.parse(
    atob(proof.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')),
  );
  checks.push(['htu drops the query', payload.htu === 'https://api.example/resource']);
  checks.push(['ath is present', typeof payload.ath === 'string']);
  checks.push(['the private key is non-extractable', key.privateKey.extractable === false]);

  // SHA-256 and getRandomValues, via PKCE.
  const pkce = await generatePkce();
  checks.push(['pkce differs from its verifier', pkce.challenge !== pkce.verifier]);
  const url = authorizationUrl({
    discovery: { authorization_endpoint: 'https://issuer.example/authorize' },
    clientId: 'c',
    redirectUri: 'https://app.example/cb',
    scope: 'openid',
    state: 's',
    challenge: pkce.challenge,
  });
  checks.push([
    'authorization url is S256',
    new URL(url).searchParams.get('code_challenge_method') === 'S256',
  ]);

  // A pure function from the verify module, so it too is proven to LOAD here.
  checks.push([
    'maxAgeOf parses',
    maxAgeOf(new Headers({ 'Cache-Control': 'max-age=7' })) === 7,
  ]);

  // Key persistence and the nonce cache (issue #134). Both are pure state with no Node
  // dependency, so they must behave identically in every lane; the IndexedDB store is NOT
  // exercised here because the global exists in browsers only, which is the whole reason
  // the store is an interface with a memory default.
  const store = new MemoryProofKeyStore();
  const stored = await loadOrCreateProofKey(store, 'cli_1', 'env_prod');
  const reloaded = await loadOrCreateProofKey(store, 'cli_1', 'env_prod');
  checks.push(['a stored proof key is reused', stored.publicJwk.x === reloaded.publicJwk.x]);
  checks.push([
    'the reloaded private key is still non-extractable',
    reloaded.privateKey.extractable === false,
  ]);
  const otherEnvironment = await loadOrCreateProofKey(store, 'cli_1', 'env_staging');
  checks.push([
    'a second environment gets its own key',
    otherEnvironment.publicJwk.x !== stored.publicJwk.x,
  ]);
  checks.push([
    'slot names cannot be made to collide',
    proofKeySlot('a:b', 'c') !== proofKeySlot('a', 'b:c'),
  ]);
  const nonces = new NonceCache();
  nonces.observe('https://a.example/token', {
    headers: new Headers({ 'DPoP-Nonce': 'n1' }),
  });
  checks.push([
    'a nonce is cached per origin',
    nonces.get('https://a.example/userinfo') === 'n1' &&
      nonces.get('https://b.example/token') === undefined,
  ]);

  // A COMPLETE DPoP flow (issue #134 criterion 1): code exchange, refresh, and a protected
  // resource call, all with real proofs, against a fake server that enforces what a real one
  // enforces. Every earlier check here proves a piece works in isolation; this proves the
  // pieces work TOGETHER in a runtime with no Node, which is the criterion's actual wording
  // and the thing no unit test on Node can answer.
  const flowKey = await loadOrCreateProofKey(new MemoryProofKeyStore(), 'cli_flow', 'env_prod');
  const flowNonces = new NonceCache();
  const seen = { exchange: null, refresh: null, userinfo: null };

  // The fake server demands a nonce on the FIRST request, exactly as RFC 9449 section 8
  // permits, so the retry path is exercised in every runtime rather than only on Node.
  let issuedNonce = false;
  const flowServer = async (input, init) => {
    const headers = new Headers(init?.headers);
    const proof = headers.get('DPoP');
    if (!proof) {
      return new Response('{"error":"invalid_dpop_proof"}', {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    const payload = JSON.parse(
      atob(proof.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')),
    );
    if (!issuedNonce) {
      issuedNonce = true;
      return new Response('{"error":"use_dpop_nonce"}', {
        status: 400,
        headers: { 'Content-Type': 'application/json', 'DPoP-Nonce': 'n-1' },
      });
    }
    const url = String(input);
    if (url.endsWith('/token')) {
      const body = new URLSearchParams(String(init?.body));
      const grant = body.get('grant_type');
      seen[grant === 'refresh_token' ? 'refresh' : 'exchange'] = payload;
      return new Response(
        JSON.stringify({ access_token: 'at-1', token_type: 'DPoP', refresh_token: 'rt-1' }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    }
    seen.userinfo = { payload, authorization: headers.get('Authorization') };
    return new Response('{"sub":"usr_1"}', {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  };

  const discovery = {
    token_endpoint: 'https://issuer.example/token',
    userinfo_endpoint: 'https://issuer.example/userinfo',
  };
  const binding = { key: flowKey, nonces: flowNonces };

  const exchanged = await exchangeCode(
    {
      discovery,
      clientId: 'cli_flow',
      redirectUri: 'https://app.example/cb',
      code: 'the-code',
      verifier: 'the-verifier',
      dpop: binding,
    },
    flowServer,
  );
  checks.push(['dpop code exchange returns a bound token', exchanged.token_type === 'DPoP']);
  checks.push([
    'the exchange proof binds the token endpoint',
    seen.exchange?.htu === 'https://issuer.example/token' && seen.exchange?.htm === 'POST',
  ]);
  checks.push([
    'the exchange proof carries no ath',
    seen.exchange?.ath === undefined,
  ]);

  const refreshed = await refresh(
    { discovery, clientId: 'cli_flow', refreshToken: exchanged.refresh_token, dpop: binding },
    flowServer,
  );
  checks.push(['dpop refresh succeeds', refreshed.access_token === 'at-1']);
  checks.push([
    'the refresh proof carries the cached nonce',
    seen.refresh?.nonce === 'n-1',
  ]);

  const claims = await userInfo(
    { discovery, accessToken: exchanged.access_token, dpop: binding },
    flowServer,
  );
  checks.push(['dpop userinfo returns claims', claims.sub === 'usr_1']);
  checks.push([
    'the userinfo token is presented under the DPoP scheme',
    seen.userinfo?.authorization === 'DPoP at-1',
  ]);
  // `ath` must be the SHA-256 of the presented token. Recomputed here with WebCrypto rather
  // than copied from the SDK, so this is a cross-check and not the code agreeing with itself.
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('at-1'));
  let binary = '';
  for (const byte of new Uint8Array(digest)) binary += String.fromCharCode(byte);
  const expectedAth = btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  checks.push(['the userinfo proof ath matches the presented token', seen.userinfo?.payload?.ath === expectedAth]);

  // The edge snippet, executed IN THIS RUNTIME against the shared conformance corpus
  // (issue #118, criterion 1). A snippet that only ever runs on Node cannot support a
  // claim about Workers, and the vectors are the same ones the SDK's own verifier is held
  // to, so the two implementations are held to one standard rather than two.
  const snippetVerifier = (algorithms) =>
    createVerifier({
      issuer: corpus.issuer,
      audience: corpus.audience,
      jwksUri: 'https://issuer.example/jwks',
      algorithms,
      skewSeconds: 0,
      now: () => corpus.now,
      fetch: async () =>
        new Response(JSON.stringify(corpus.jwks), {
          headers: { 'Content-Type': 'application/json', 'Cache-Control': 'max-age=300' },
        }),
    });

  // The WHOLE corpus, not a sample. Every case names the outcome it expects, so running
  // all of them here costs one pass and makes this lane as strict as the Node suite.
  let accepted = 0;
  let rejected = 0;
  let mismatched = 0;
  for (const testCase of corpus.cases) {
    // ONE vector is judged against an EdDSA-only issuer. That is what makes it a test of
    // the ALLOW-LIST rather than of whether ES256 happens to be implemented: judged
    // against the full published set the token is legitimately acceptable, so a harness
    // that used one algorithm list everywhere would report a false mismatch here. The
    // Node suite makes the same distinction.
    const algorithms =
      testCase.name === 'alg_not_published_by_the_issuer'
        ? corpus.algorithmsEddsaOnly
        : corpus.algorithms;
    const snippetVerify = snippetVerifier(algorithms);
    let outcome;
    try {
      await snippetVerify(testCase.token);
      outcome = 'accept';
    } catch (error) {
      // A non-`VerifyError` escaping is itself a failure: it means the snippet threw
      // something a caller cannot branch on, which on an edge runtime is a 500.
      outcome = error instanceof SnippetVerifyError ? 'reject' : 'threw';
    }
    if (testCase.expect === 'accept') {
      if (outcome === 'accept') accepted += 1;
      else mismatched += 1;
    } else if (outcome === 'reject') {
      rejected += 1;
    } else {
      mismatched += 1;
    }
  }
  checks.push(['the edge snippet matches every conformance vector in this runtime', mismatched === 0]);
  // Both directions observed. A corpus that happened to contain only rejections would make
  // the check above pass for a verifier that refuses everything.
  checks.push([
    'the edge snippet both accepted and rejected in this runtime',
    accepted > 0 && rejected > 0,
  ]);

  const failed = checks.filter(([, ok]) => !ok).map(([name]) => name);
  return { ok: failed.length === 0, failed, count: checks.length };
}

/** The number of checks a lane must observe. A lower count means checks were skipped. */
export const EXPECTED_CHECKS = 22;
