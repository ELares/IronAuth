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
import { authorizationUrl, generatePkce } from '../dist/protocol.js';
import { maxAgeOf } from '../dist/verify.js';

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

  const failed = checks.filter(([, ok]) => !ok).map(([name]) => name);
  return { ok: failed.length === 0, failed, count: checks.length };
}

/** The number of checks a lane must observe. A lower count means checks were skipped. */
export const EXPECTED_CHECKS = 7;
