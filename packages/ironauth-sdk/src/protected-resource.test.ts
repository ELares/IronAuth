// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  DEFAULT_PRM_MAX_AGE_SECONDS,
  PrmConfigError,
  ProtectedResource,
  type ProtectedResourceConfig,
  type VerifiedTokenConfig,
  defineProtectedResource,
  forbidden,
  protectedResourceChallenge,
  protectedResourceMetadata,
  protectedResourceMetadataUrl,
  protectedResourceMiddleware,
  protectedResourceFromVerify,
  type ChallengeError,
  type DerivedResourceOverrides,
  unauthorized,
} from './protected-resource.js';

const RESOURCE = 'https://api.example/v1/mcp';
const ISSUER = 'https://auth.example';
const VERIFIES = { issuer: ISSUER, audience: RESOURCE };
const CONFIG = { resource: RESOURCE, authorizationServers: [ISSUER] };
const CHECKED = defineProtectedResource(CONFIG, VERIFIES);

function refusalCode(run: () => unknown): string {
  try {
    run();
  } catch (error) {
    assert.ok(
      error instanceof PrmConfigError,
      `expected a PrmConfigError, got ${error}`,
    );
    return error.code;
  }
  return assert.fail('expected a refusal');
}

test('the well-known segment is INSERTED, not appended', () => {
  // Invisible for a path-less identifier: both spellings agree until the first resource with
  // a path, which is how the wrong one reaches production.
  assert.equal(
    protectedResourceMetadataUrl('https://api.example/v1/mcp'),
    'https://api.example/.well-known/oauth-protected-resource/v1/mcp',
  );
  assert.equal(
    protectedResourceMetadataUrl('https://api.example'),
    'https://api.example/.well-known/oauth-protected-resource',
  );
});

test('nothing about the identifier is normalised, except the one thing the crate normalises', () => {
  // Every case here is one `new URL()` would silently rewrite, and the crate does not. The
  // default port is the sharpest: the crate pins `https://api.example:443` as NOT equal to
  // `https://api.example`, because the token endpoint compares audiences exactly, so
  // normalising would advertise a document at an origin the identifier does not name.
  //
  // The `HTTPS://` row is the EXCEPTION and it used to be pinned backwards. `Scheme2::parse`
  // (`http-1.5.0/src/uri/scheme.rs:266-280`) fast-paths a case-insensitive `http://` and
  // `https://` to `Protocol::Http`/`Https`, whose `as_str` returns the literal lowercase
  // (`scheme.rs:57-67`). So the crate DOES rewrite the scheme, for those two schemes only,
  // and this test asserted the opposite under a comment saying the crate does not rewrite.
  // The invariant this module exists to hold is that both sides publish at the same URL, so
  // pinning the SDK's answer rather than the crate's broke exactly the thing being tested.
  const cases: Array<[string, string]> = [
    [
      'https://api.example:443/v1',
      'https://api.example:443/.well-known/oauth-protected-resource/v1',
    ],
    [
      'http://api.example:80/v1',
      'http://api.example:80/.well-known/oauth-protected-resource/v1',
    ],
    [
      'https://user:pass@api.example/v1',
      'https://user:pass@api.example/.well-known/oauth-protected-resource/v1',
    ],
    // Scheme lowercased, HOST CASE PRESERVED, path case preserved: exactly what the crate does.
    [
      'HTTPS://API.EXAMPLE/V1',
      'https://API.EXAMPLE/.well-known/oauth-protected-resource/V1',
    ],
    [
      'Http://api.example/x',
      'http://api.example/.well-known/oauth-protected-resource/x',
    ],
    // A NON-special scheme keeps its case, because the fast path above covers http/https only.
    [
      'COAP://device.example/v1',
      'COAP://device.example/.well-known/oauth-protected-resource/v1',
    ],
    [
      'https://api.example/v1/../secret',
      'https://api.example/.well-known/oauth-protected-resource/v1/../secret',
    ],
    [
      'https://api.example/%2e%2e/x',
      'https://api.example/.well-known/oauth-protected-resource/%2e%2e/x',
    ],
  ];
  for (const [resource, expected] of cases) {
    assert.equal(protectedResourceMetadataUrl(resource), expected, resource);
  }
});

test('a non-special scheme composes a real URL, not the string null', () => {
  // `URL.origin` is literally "null" outside http/https/ws/wss/ftp, so composing through it
  // publishes `null/.well-known/...` for a resource identifier RFC 8707 permits.
  assert.equal(
    protectedResourceMetadataUrl('coap://device.example/v1'),
    'coap://device.example/.well-known/oauth-protected-resource/v1',
  );
});

test('every trailing slash is stripped, not just one', () => {
  // So `.../mcp`, `.../mcp/` and `.../mcp//` publish at ONE URL rather than several a cache
  // would treat as unrelated.
  for (const resource of [
    'https://api.example/v1/mcp',
    'https://api.example/v1/mcp/',
    'https://api.example/v1/mcp//',
  ]) {
    assert.equal(
      protectedResourceMetadataUrl(resource),
      'https://api.example/.well-known/oauth-protected-resource/v1/mcp',
      resource,
    );
  }
});

test('a request with no credentials gets a bare challenge, with no error code', () => {
  // RFC 6750 section 3.1: an error code here tells an unauthenticated caller that something
  // about its absent token was wrong.
  const challenge = unauthorized(CHECKED).headers['WWW-Authenticate'];
  assert.ok(challenge.startsWith('Bearer '), challenge);
  assert.ok(!challenge.includes('error='), challenge);
  assert.ok(challenge.includes('resource_metadata='), challenge);
});

// The shared fixture this comment used to anticipate now exists
// (`vectors/prm-challenge-vectors.json`, asserted below and by the crate suite), so this test
// is no longer the claim that the two agree. It stays as the READABLE statement of the wire
// format: a literal a reviewer can check against RFC 6750 by eye, where the corpus case is a
// JSON string. The corpus is what makes agreement falsifiable; this is what makes the format
// legible.
test('the challenge is the RFC 6750 wire format, spelled out', () => {
  assert.equal(
    unauthorized(CHECKED, { error: 'invalid_token' }).headers[
      'WWW-Authenticate'
    ],
    'Bearer resource_metadata="https://api.example/.well-known/oauth-protected-resource/v1/mcp", error="invalid_token"',
  );
  assert.equal(
    forbidden(CHECKED, 'mcp:tools').headers['WWW-Authenticate'],
    'Bearer resource_metadata="https://api.example/.well-known/oauth-protected-resource/v1/mcp", error="insufficient_scope", scope="mcp:tools"',
  );
});

test('a value RFC 6750 forbids is REFUSED, not escaped', () => {
  // Section 3 restricts these to %x20-21 / %x23-5B / %x5D-7E, which excludes the quote, the
  // backslash, DEL and every control character. Escaping a quote emits a backslash the spec
  // forbids; passing CR or LF is a header-splitting primitive.
  for (const bad of [
    'he said "no"',
    'back\\slash',
    'boom\r\nX-Injected: yes',
    'del\x7f',
    'tab\there',
  ]) {
    assert.equal(
      refusalCode(() =>
        protectedResourceChallenge(CHECKED, {
          error: 'invalid_token',
          errorDescription: bad,
        }),
      ),
      'challenge_value_not_representable',
      bad,
    );
  }
});

test('the document must not contradict what the server verifies', () => {
  // Both halves. A mismatched audience sends clients for a token this server rejects; an
  // advertised authorization server that is not the verified issuer is the same lie.
  assert.equal(
    refusalCode(() =>
      defineProtectedResource(CONFIG, {
        issuer: ISSUER,
        audience: 'https://api.example/v2/mcp',
      }),
    ),
    'resource_audience_mismatch',
  );
  assert.equal(
    refusalCode(() =>
      defineProtectedResource(
        { resource: RESOURCE, authorizationServers: ['https://other.example'] },
        VERIFIES,
      ),
    ),
    'authorization_server_not_the_verified_issuer',
  );
});

test('the audience comparison is exact, not normalised', () => {
  // The token endpoint compares exactly, so a pairing that only matches after normalisation
  // is one the endpoint still rejects.
  assert.equal(
    refusalCode(() =>
      defineProtectedResource(
        {
          resource: 'https://api.example:443/v1',
          authorizationServers: [ISSUER],
        },
        { issuer: ISSUER, audience: 'https://api.example/v1' },
      ),
    ),
    'resource_audience_mismatch',
  );
  assert.equal(
    refusalCode(() =>
      defineProtectedResource(
        { resource: 'https://API.example/v1', authorizationServers: [ISSUER] },
        { issuer: ISSUER, audience: 'https://api.example/v1' },
      ),
    ),
    'resource_audience_mismatch',
  );
});

test('every refusal has its own code, because each is fixed differently', () => {
  const cases: Array<[string, string[], string]> = [
    ['not-a-uri', [ISSUER], 'resource_not_absolute'],
    ['https:///v1', [ISSUER], 'resource_not_absolute'],
    [
      'https://api.example/v1?tenant=a',
      [ISSUER],
      'resource_has_query_or_fragment',
    ],
    ['https://api.example/v1#frag', [ISSUER], 'resource_has_query_or_fragment'],
    ['https://api.example/v1#', [ISSUER], 'resource_has_query_or_fragment'],
    ['https://api.example/a b', [ISSUER], 'resource_not_absolute'],
    ['https://ñ.example/v1', [ISSUER], 'resource_not_absolute'],
    [RESOURCE, [], 'no_authorization_servers'],
    [RESOURCE, ['auth.example'], 'issuer_not_absolute'],
  ];
  for (const [resource, servers, code] of cases) {
    assert.equal(
      refusalCode(() =>
        defineProtectedResource(
          { resource, authorizationServers: servers },
          { issuer: ISSUER, audience: resource },
        ),
      ),
      code,
      `${resource} / ${JSON.stringify(servers)}`,
    );
  }
});

test('an empty fragment is refused, like any other', () => {
  // The trap the crate calls out: parse-then-inspect lets `.../x#` through as a distinct
  // identity for the same resource, and an empty fragment is the form that slips past.
  assert.equal(
    refusalCode(() => protectedResourceMetadataUrl('https://api.example/x#')),
    'resource_has_query_or_fragment',
  );
});

test('a refusal message echoes no configured value', () => {
  const secret = 'https://internal.example/tenant-12345';
  try {
    defineProtectedResource(CONFIG, { issuer: ISSUER, audience: secret });
    assert.fail('expected a refusal');
  } catch (error) {
    assert.ok(error instanceof PrmConfigError);
    assert.ok(!error.message.includes(secret), error.message);
    assert.equal(error.value, secret);
  }
});

test('each refusal code carries its own message', () => {
  // Otherwise a code could be mapped to the wrong text and nothing would notice.
  const messages = new Set<string>();
  const codes: Array<() => unknown> = [
    () =>
      defineProtectedResource(
        { resource: 'nope', authorizationServers: [ISSUER] },
        VERIFIES,
      ),
    () =>
      defineProtectedResource(
        { resource: 'https://a.example/x#', authorizationServers: [ISSUER] },
        VERIFIES,
      ),
    () =>
      defineProtectedResource(
        { resource: RESOURCE, authorizationServers: [] },
        VERIFIES,
      ),
    () =>
      defineProtectedResource(
        { resource: RESOURCE, authorizationServers: ['nope'] },
        VERIFIES,
      ),
    () =>
      defineProtectedResource(CONFIG, {
        issuer: ISSUER,
        audience: 'https://other.example',
      }),
    () =>
      defineProtectedResource(
        { resource: RESOURCE, authorizationServers: ['https://x.example'] },
        VERIFIES,
      ),
    () =>
      protectedResourceChallenge(CHECKED, {
        error: 'invalid_token',
        errorDescription: '"',
      }),
  ];
  for (const run of codes) {
    try {
      run();
      assert.fail('expected a refusal');
    } catch (error) {
      assert.ok(error instanceof PrmConfigError);
      messages.add(error.message);
    }
  }
  assert.equal(
    messages.size,
    codes.length,
    'every code must describe itself distinctly',
  );
});

test('the document carries the required fields and omits empty optional ones', () => {
  assert.deepEqual(protectedResourceMetadata(CHECKED), {
    resource: RESOURCE,
    authorization_servers: [ISSUER],
  });
});

test('each optional field is advertised only when non-empty', () => {
  // Absent and empty are different claims: an empty array says "supports none".
  const withScopes = defineProtectedResource(
    { ...CONFIG, scopesSupported: ['mcp:tools'], bearerMethodsSupported: [] },
    VERIFIES,
  );
  const document = protectedResourceMetadata(withScopes);
  assert.deepEqual(document.scopes_supported, ['mcp:tools']);
  assert.ok(!('bearer_methods_supported' in document));

  const withMethods = defineProtectedResource(
    { ...CONFIG, scopesSupported: [], bearerMethodsSupported: ['header'] },
    VERIFIES,
  );
  const other = protectedResourceMetadata(withMethods);
  assert.deepEqual(other.bearer_methods_supported, ['header']);
  assert.ok(!('scopes_supported' in other));
});

test('the document does not alias the caller arrays', () => {
  const servers = [ISSUER];
  const document = protectedResourceMetadata(
    defineProtectedResource(
      { resource: RESOURCE, authorizationServers: servers },
      VERIFIES,
    ),
  );
  servers.push('https://sneaky.example');
  assert.deepEqual(document.authorization_servers, [ISSUER]);
});

test('the middleware serves the document at the well-known path, with cache headers', () => {
  const handle = protectedResourceMiddleware(CHECKED);
  const served = handle({
    path: '/.well-known/oauth-protected-resource/v1/mcp',
    outcome: 'no-token',
  });
  assert.ok(served);
  assert.equal(served.status, 200);
  assert.equal(
    served.headers['Cache-Control'],
    `public, max-age=${DEFAULT_PRM_MAX_AGE_SECONDS}`,
  );
  assert.deepEqual(JSON.parse(served.body ?? ''), {
    resource: RESOURCE,
    authorization_servers: [ISSUER],
  });
});

test('the middleware challenges, and gets out of the way when the token is good', () => {
  const handle = protectedResourceMiddleware(CHECKED);
  assert.equal(handle({ path: '/v1/mcp', outcome: 'ok' }), null);
  assert.equal(handle({ path: '/v1/mcp', outcome: 'no-token' })?.status, 401);
  assert.equal(
    handle({ path: '/v1/mcp', outcome: 'invalid-token' })?.status,
    401,
  );
  assert.ok(
    handle({ path: '/v1/mcp', outcome: 'invalid-token' })?.headers[
      'WWW-Authenticate'
    ].includes('invalid_token'),
  );
  const denied = handle({
    path: '/v1/mcp',
    outcome: { missingScope: 'mcp:tools' },
  });
  assert.equal(denied?.status, 403);
  assert.ok(denied?.headers['WWW-Authenticate'].includes('scope="mcp:tools"'));
});

test('a configured cache lifetime is honoured', () => {
  const handle = protectedResourceMiddleware(
    defineProtectedResource({ ...CONFIG, maxAgeSeconds: 60 }, VERIFIES),
  );
  const served = handle({
    path: '/.well-known/oauth-protected-resource/v1/mcp',
    outcome: 'ok',
  });
  assert.equal(served?.headers['Cache-Control'], 'public, max-age=60');
});

test('the middleware serves the path its own challenge advertises', () => {
  // The blocking defect this pins: the match path was derived through `new URL()`, which
  // resolves dot segments and decodes `%2e`, so for these identifiers the challenge named a
  // path the middleware then refused. The discovery chain dead-ending silently, produced by
  // the module written to prevent it.
  for (const resource of [
    'https://api.example/v1/../secret',
    'https://api.example/%2e%2e/x',
    'https://api.example/v1/./mcp',
    'https://api.example/v1/mcp',
  ]) {
    const checked = defineProtectedResource(
      { resource, authorizationServers: [ISSUER] },
      { issuer: ISSUER, audience: resource },
    );
    const advertised = protectedResourceMetadataUrl(resource);
    const path = advertised.slice(
      advertised.indexOf('/', advertised.indexOf('://') + 3),
    );
    const served = protectedResourceMiddleware(checked)({
      path,
      outcome: 'no-token',
    });
    assert.equal(
      served?.status,
      200,
      `advertised ${path} and did not serve it`,
    );
  }
});

test('the path table matches the crate: it accepts what http::Uri accepts', () => {
  // Measured against the crate's PATH_MAP. An earlier version ran one regex over the whole
  // identifier and refused all of these, which the crate accepts.
  for (const resource of [
    'https://api.example/v1/caf\u00e9',
    'https://api.example/tenants/{id}',
    'https://api.example/v1/a|b',
    'https://api.example/v1/a^b',
    'https://api.example/v1/a"b',
  ]) {
    assert.doesNotThrow(() => protectedResourceMetadataUrl(resource), resource);
  }
});

test('the authority table matches the crate: it refuses what http::Uri refuses', () => {
  // The other direction of the same defect: one regex over the whole string accepted these,
  // and the crate rejects every one.
  for (const resource of [
    'https://api.example:80:90/v1',
    'https://[not-ipv6/v1',
    'https://api%2eexample/v1',
    'https://user@/v1',
    'https://a]b/v1',
    'https://api.example\u00f1/v1',
    // Delimiters that change how an authority parses. `validate_authority_bytes` rejects
    // each of these, and without the delimiter half of the check they compose a URL.
    'https://api{example/v1',
    'https://api"example/v1',
    'https://api^example/v1',
    'https://api|example/v1',
  ]) {
    assert.equal(
      refusalCode(() => protectedResourceMetadataUrl(resource)),
      'resource_not_absolute',
      resource,
    );
  }
});

test('a spread of a validated config is refused', () => {
  // A brand survives a spread, so overriding `resource` afterwards produced a "validated"
  // configuration that was never validated, and every emitter accepted it. That is the one
  // line someone writes to derive a second resource from a first.
  const spread = {
    ...CHECKED,
    resource: 'https://attacker.example/x',
  } as ProtectedResource;
  assert.equal(
    refusalCode(() => unauthorized(spread)),
    'resource_not_validated',
  );
  assert.equal(
    refusalCode(() => forbidden(spread, 'mcp:tools')),
    'resource_not_validated',
  );
});

test('a cache lifetime that cannot reach a header is refused', () => {
  // Unchecked, these produced `max-age=-1`, `max-age=1.5`, `max-age=NaN`, `max-age=Infinity`.
  for (const maxAgeSeconds of [
    -1,
    1.5,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    1e21,
  ]) {
    assert.equal(
      refusalCode(() =>
        defineProtectedResource({ ...CONFIG, maxAgeSeconds }, VERIFIES),
      ),
      'cache_lifetime_not_representable',
      String(maxAgeSeconds),
    );
  }
});

test('a scope the spec forbids costs the parameter, not the response', () => {
  // `requiredScope` is a per-request input. Throwing here turns an intended 403 into a 500;
  // the challenge is still correct without the optional `scope` parameter.
  const challenge = forbidden(CHECKED, 'a\r\nSet-Cookie: x=1').headers[
    'WWW-Authenticate'
  ];
  assert.ok(challenge.includes('error="insufficient_scope"'), challenge);
  assert.ok(!challenge.includes('scope='), challenge);
});

test('a description with no error has its own code', () => {
  // The value is representable; the fault is that there is nothing to attach it to.
  assert.equal(
    refusalCode(() =>
      protectedResourceChallenge(CHECKED, { errorDescription: 'dropped?' }),
    ),
    'error_description_without_an_error',
  );
});

test('the middleware matches the well-known path regardless of trailing slashes', () => {
  const handle = protectedResourceMiddleware(CHECKED);
  for (const path of [
    '/.well-known/oauth-protected-resource/v1/mcp',
    '/.well-known/oauth-protected-resource/v1/mcp/',
  ]) {
    assert.equal(handle({ path, outcome: 'ok' })?.status, 200, path);
  }
});

test('the document is served as JSON', () => {
  const served = protectedResourceMiddleware(CHECKED)({
    path: '/.well-known/oauth-protected-resource/v1/mcp',
    outcome: 'ok',
  });
  assert.equal(served?.headers['Content-Type'], 'application/json');
});

test('the document path refuses an unvalidated config too', () => {
  // The guard was on the challenge builders only, so a spread was refused when asked for a
  // header and served happily when asked for the DOCUMENT, which is the artefact whose whole
  // job is to not lie.
  const spread = {
    ...CHECKED,
    resource: 'https://attacker.example/x',
  } as ProtectedResource;
  assert.equal(
    refusalCode(() => protectedResourceMetadata(spread)),
    'resource_not_validated',
  );
  assert.equal(
    refusalCode(() => protectedResourceMiddleware(spread)),
    'resource_not_validated',
  );
});

test('a prototype forgery is refused', () => {
  // `instanceof` is satisfied by this; a private field is not.
  const forged = Object.create(
    ProtectedResource.prototype,
  ) as ProtectedResource;
  assert.equal(
    refusalCode(() => unauthorized(forged)),
    'resource_not_validated',
  );
  assert.equal(
    refusalCode(() => protectedResourceMetadata(forged)),
    'resource_not_validated',
  );
});

test('there is no public construction path', () => {
  // This test asserted only that `ProtectedResource.build` was `undefined`, which pins the
  // removed SPELLING rather than the property its name claims, and the property was false:
  // `private constructor` is erased at emit, so `Reflect.construct` built one with no
  // diagnostic and rebuilt every configuration this module refuses. The constructor now
  // takes a module-scoped symbol, so these are refusals at RUNTIME.
  assert.equal(
    (ProtectedResource as unknown as Record<string, unknown>).build,
    undefined,
    'the removed `build` static must not come back',
  );

  const hostile = {
    resource: 'https://attacker.example/x',
    authorizationServers: [] as string[],
    maxAgeSeconds: Number.NaN,
  };
  const verifies = {
    issuer: 'https://attacker.example',
    audience: 'https://totally-different.example',
  };

  // `Reflect.construct` is the one TypeScript never flags: `new` is TS2673 and `extends` is
  // TS2675, but this compiles clean and needs no cast.
  assert.equal(
    refusalCode(() =>
      Reflect.construct(ProtectedResource, [hostile, verifies, Number.NaN]),
    ),
    'resource_not_validated',
    'Reflect.construct must not reach the constructor body',
  );
  // A plain-JS consumer, which has no type checking at all.
  assert.equal(
    refusalCode(
      () =>
        new (
          ProtectedResource as unknown as new (...args: unknown[]) => unknown
        )(hostile, verifies, Number.NaN),
    ),
    'resource_not_validated',
    'an untyped consumer must be refused the same way',
  );
  // A guessed token is still not the token.
  assert.equal(
    refusalCode(() =>
      Reflect.construct(ProtectedResource, [
        hostile,
        verifies,
        Number.NaN,
        Symbol('ironauth.prm.construct'),
      ]),
    ),
    'resource_not_validated',
    'a same-named symbol is a different symbol',
  );
  // THE REGISTRY, which the row above cannot see. `Symbol('x') !== Symbol('x')` is a
  // property of JavaScript rather than of this module, so it held no matter what the module
  // did; changing `Symbol(...)` to `Symbol.for(...)` at the declaration passed the whole
  // suite and reopened the construction hole in full. That edit is not far-fetched: a
  // dual-loaded copy of this module has a different token, so a "token mismatch across
  // bundles" report leads straight to it, and `Symbol.for` puts the token in a
  // process-global registry any caller can read.
  assert.equal(
    refusalCode(() =>
      Reflect.construct(ProtectedResource, [
        hostile,
        verifies,
        Number.NaN,
        Symbol.for('ironauth.prm.construct'),
      ]),
    ),
    'resource_not_validated',
    'the token must not be registry-reachable: Symbol.for must not obtain it',
  );
});

test('a config whose reads are not stable is validated and stored as one value', () => {
  // `defineProtectedResource` read every field straight off `config` at each step, so a
  // getter-backed config was checked on one value and stored on another, and the result
  // reported itself validated while disagreeing with the audience it was checked against.
  // No cast, no spread, no Reflect: an ordinary type-checked caller.
  let reads = 0;
  const shifty: ProtectedResourceConfig = {
    get resource() {
      reads += 1;
      // Honest on the FIRST read only. That threshold is the whole test: with the
      // snapshot, exactly one read happens and the value is honest; without it, the
      // constructor reads again and stores the hostile value. An earlier version allowed
      // two honest reads and the mutant reverting the snapshot survived, because the
      // second read was still inside the honest window.
      return reads <= 1 ? 'https://api.example/v1' : 'https://evil.example/x';
    },
    authorizationServers: ['https://auth.example'],
  };

  const defined = defineProtectedResource(shifty, {
    issuer: 'https://auth.example',
    audience: 'https://api.example/v1',
  });

  assert.equal(
    reads,
    1,
    'config.resource must be read exactly once, or a later read can differ from the checked one',
  );
  assert.equal(
    defined.resource,
    'https://api.example/v1',
    'the stored resource must be the one that was validated',
  );
  assert.equal(
    defined.resource,
    defined.audience,
    'a validated instance can never disagree with its own audience',
  );
  assert.ok(
    !JSON.stringify(protectedResourceMetadata(defined)).includes('evil'),
    'and the published document cannot carry the later read',
  );

  // The `verifies` side, which was read twice per field before the snapshot and which six
  // separate reverting mutations all survived, because nothing counted its reads.
  let issuerReads = 0;
  let audienceReads = 0;
  const shiftyVerifies: VerifiedTokenConfig = {
    get issuer() {
      issuerReads += 1;
      return issuerReads <= 1
        ? 'https://auth.example'
        : 'https://evil-iss.example';
    },
    get audience() {
      audienceReads += 1;
      return audienceReads <= 1
        ? 'https://api.example/v1'
        : 'https://evil.example/x';
    },
  };
  const fromVerifies = defineProtectedResource(
    {
      resource: 'https://api.example/v1',
      authorizationServers: ['https://auth.example'],
    },
    shiftyVerifies,
  );
  assert.equal(issuerReads, 1, 'verifies.issuer must be read exactly once');
  assert.equal(audienceReads, 1, 'verifies.audience must be read exactly once');
  assert.equal(fromVerifies.issuer, 'https://auth.example');
  assert.equal(fromVerifies.audience, 'https://api.example/v1');

  // The same through `authorizationServers`, which was read four times.
  let listReads = 0;
  const shiftyList: ProtectedResourceConfig = {
    resource: 'https://api.example/v1',
    get authorizationServers() {
      listReads += 1;
      return listReads <= 1
        ? ['https://auth.example']
        : ['https://evil-iss.example'];
    },
  };
  const second = defineProtectedResource(shiftyList, {
    issuer: 'https://auth.example',
    audience: 'https://api.example/v1',
  });
  assert.deepEqual(
    [...second.authorizationServers],
    ['https://auth.example'],
    'the stored issuers must be the ones that were validated',
  );
});

test('the optional arrays are also read exactly once', () => {
  // These two used a `config.x ? [...config.x] : undefined` ternary, which reads twice and
  // stores the SECOND read, so they were the last fields still carrying the defect the
  // snapshot exists to remove. Neither is validated, so nothing checked was reachable
  // through them, but "every field once" was the claim.
  let scopeReads = 0;
  let bearerReads = 0;
  // `maxAgeSeconds` was the one snapshot field with no read-count assertion. The shipped
  // code reads it once, but a regression would go unnoticed: a second read returning
  // something unrepresentable is stored AFTER the validation that would have refused it,
  // and the middleware then emits `Cache-Control: public, max-age=NaN`.
  let maxAgeReads = 0;
  const shifty: ProtectedResourceConfig = {
    resource: 'https://api.example/v1',
    authorizationServers: ['https://auth.example'],
    get maxAgeSeconds() {
      maxAgeReads += 1;
      return maxAgeReads <= 1 ? 60 : Number.NaN;
    },
    get scopesSupported() {
      scopeReads += 1;
      return scopeReads <= 1 ? ['read'] : ['evil:scope'];
    },
    get bearerMethodsSupported() {
      bearerReads += 1;
      return bearerReads <= 1 ? ['header'] : ['evil-method'];
    },
  };

  const defined = defineProtectedResource(shifty, {
    issuer: 'https://auth.example',
    audience: 'https://api.example/v1',
  });

  assert.equal(maxAgeReads, 1, 'maxAgeSeconds must be read exactly once');
  assert.equal(scopeReads, 1, 'scopesSupported must be read exactly once');
  assert.equal(
    bearerReads,
    1,
    'bearerMethodsSupported must be read exactly once',
  );
  assert.deepEqual([...(defined.scopesSupported ?? [])], ['read']);
  assert.deepEqual([...(defined.bearerMethodsSupported ?? [])], ['header']);
  assert.equal(
    defined.maxAgeSeconds,
    60,
    'the validated max-age is the stored one',
  );
  // And it reaches the wire as the validated value, which is where a second read showed.
  const served = protectedResourceMiddleware(defined)({
    path: '/.well-known/oauth-protected-resource/v1',
    outcome: 'no-token',
  });
  assert.equal(served?.headers['Cache-Control'], 'public, max-age=60');
});

test('a resource that cannot be put in a challenge is refused at startup', () => {
  // `resource_metadata` was the one challenge parameter never passed through
  // `challengeValue`, and the path table deliberately accepts `"` and `\\` to match the
  // crate's PATH_MAP, so both reached the RFC 6750 quoted string raw and a conforming
  // parser read two parameters where one was intended.
  //
  // Refused at DEFINE time rather than at challenge time: `resource` is configuration, so
  // this is a deployment fault that should surface at startup and not on the first 401.
  const injecting = 'https://api.example/v1",error="insufficient_scope';
  assert.equal(
    refusalCode(() =>
      defineProtectedResource(
        {
          resource: injecting,
          authorizationServers: ['https://auth.example'],
        },
        { issuer: 'https://auth.example', audience: injecting },
      ),
    ),
    'challenge_value_not_representable',
  );

  // An ordinary resource is unaffected, so the check is not refusing everything.
  const ok = defineProtectedResource(
    {
      resource: 'https://api.example/v1',
      authorizationServers: ['https://auth.example'],
    },
    { issuer: 'https://auth.example', audience: 'https://api.example/v1' },
  );
  assert.ok(
    protectedResourceChallenge(ok).startsWith('Bearer resource_metadata="'),
  );
});

test('every array on a validated instance is frozen and copied', () => {
  // The freeze test covered `this` and `authorizationServers` only, so deleting either
  // optional-array freeze passed the whole suite, as did deleting the constructor's copies
  // of them. Both are load-bearing: without the copy, freezing reaches into the CALLER's
  // array; without the freeze, `resource.scopesSupported.push(...)` changes the next
  // published document.
  const scopes = ['read'];
  const bearer = ['header'];
  const servers = ['https://auth.example'];
  const validated = defineProtectedResource(
    {
      resource: 'https://api.example/v1',
      authorizationServers: servers,
      scopesSupported: scopes,
      bearerMethodsSupported: bearer,
    },
    { issuer: 'https://auth.example', audience: 'https://api.example/v1' },
  );

  const instanceArrays: Array<[string, readonly string[] | undefined]> = [
    ['authorizationServers', validated.authorizationServers],
    ['scopesSupported', validated.scopesSupported],
    ['bearerMethodsSupported', validated.bearerMethodsSupported],
  ];
  for (const [name, array] of instanceArrays) {
    assert.ok(array, name + ' must be present');
    assert.ok(Object.isFrozen(array), name + ' must be frozen');
    assert.throws(
      () => (array as string[]).push('injected'),
      name + ' must not be appendable',
    );
  }

  // The caller's arrays are untouched: copied, not adopted and frozen in place.
  const callerArrays: Array<[string, string[]]> = [
    ['scopes', scopes],
    ['bearer', bearer],
    ['servers', servers],
  ];
  for (const [name, array] of callerArrays) {
    assert.ok(!Object.isFrozen(array), name + ' must not be frozen');
    array.push('still mine');
  }
  assert.deepEqual(
    [...(validated.scopesSupported ?? [])],
    ['read'],
    'and mutating the caller array afterwards changes nothing',
  );
});

test('a validated instance cannot be mutated after the fact', () => {
  // `readonly` is type-only. `Object.assign(validated, { resource })` type-checks with no
  // cast (the direct assignment is TS2540, this spelling is not) and mutated a value every
  // emitter had already accepted: the same "derive a second resource from a validated first"
  // shape the spread refusal exists to catch, in the one spelling still open.
  const validated = defineProtectedResource(
    {
      resource: 'https://api.example/v1',
      authorizationServers: ['https://auth.example'],
    },
    { issuer: 'https://auth.example', audience: 'https://api.example/v1' },
  );

  assert.ok(Object.isFrozen(validated), 'a validated instance is frozen');
  assert.throws(
    () => Object.assign(validated, { resource: 'https://attacker.example/x' }),
    'mutating a frozen instance throws in strict mode',
  );
  assert.equal(
    validated.resource,
    'https://api.example/v1',
    'and the original is unchanged',
  );
  // The arrays too: handing out a live reference lets a caller push an issuer in later.
  assert.ok(
    Object.isFrozen(validated.authorizationServers),
    'the servers array is frozen',
  );
  assert.throws(
    () =>
      (validated.authorizationServers as string[]).push(
        'https://attacker.example',
      ),
    'and cannot be appended to',
  );
});

test('the authority scan matches the crate arm for arm', () => {
  // Every row here was a SURVIVING mutant: the scan did the right thing and nothing held it
  // there. Each is derived from `http-1.5.0/src/uri/authority.rs:475-570` and cited to the
  // arm it pins, because that file has now been hand-read wrong twice in this PR's reviews.

  // `[` guards on `has_percent || start_bracket` (:524). Checking `endBracket` instead was
  // both dead (it implies startBracket) and wrong: this was accepted.
  assert.throws(() => protectedResourceMetadataUrl('https://a%25[b]/v1'));
  // ...and the startBracket half of that same guard.
  assert.throws(() => protectedResourceMetadataUrl('https://[a[b]/v1'));

  // `]` guards on `!start_bracket || end_bracket` (:529). Both halves.
  assert.throws(() => protectedResourceMetadataUrl('https://]a/v1'));
  assert.throws(() => protectedResourceMetadataUrl('https://[a]]/v1'));

  // `@` resets colons and percent, and does NOT touch the brackets (:538-545).
  assert.equal(
    protectedResourceMetadataUrl('https://a:1:2@b/v1'),
    'https://a:1:2@b/.well-known/oauth-protected-resource/v1',
    'the colons before an @ are userinfo, not ports',
  );
  assert.throws(
    () => protectedResourceMetadataUrl('https://aaa[@a/v1'),
    'an @ does not close an open bracket',
  );
  assert.equal(
    protectedResourceMetadataUrl('https://aaa[@]/v1'),
    'https://aaa[@]/.well-known/oauth-protected-resource/v1',
    'and does not clear one either, so this bracket pair is balanced',
  );

  // The userinfo boundary is the LAST `@`, not the first. `indexOf` and `lastIndexOf` agree
  // on every other fixture in this file, which is why the comment saying so went unmeasured.
  assert.equal(
    protectedResourceMetadataUrl('https://a@b@c.example/v1'),
    'https://a@b@c.example/.well-known/oauth-protected-resource/v1',
  );

  // MAX_COLONS is 8, checked mid-scan BEFORE any reset can forgive it (:486,518-522).
  assert.throws(() =>
    protectedResourceMetadataUrl('https://[::1:2:3:4:5:6:7:8]/v1'),
  );
  assert.throws(() => protectedResourceMetadataUrl('https://[:::::::::]/v1'));
  assert.throws(() =>
    protectedResourceMetadataUrl('https://a:1:2:3:4:5:6:7:8:9@b/v1'),
  );
  // Eight is still fine: a full IPv6 literal with a port is the case the cap is sized for.
  assert.equal(
    protectedResourceMetadataUrl(
      'https://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:80/v1',
    ),
    'https://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:80/.well-known/oauth-protected-resource/v1',
  );
});

test('the scheme grammar matches SCHEME_CHARS, not RFC 3986', () => {
  // `SCHEME_CHARS` (`scheme.rs:205-231`) permits a digit or `+ - . ~` in ANY position,
  // first included. Requiring a leading ALPHA was RFC 3986 correct and refused identifiers
  // the server accepts, which is a broken discovery chain even though it fails closed.
  for (const accepted of [
    '1http://api.example/v1',
    '+http://api.example/v1',
    '.http://api.example/v1',
    '-http://api.example/v1',
    'aa~://api.example/v1',
  ]) {
    assert.ok(
      protectedResourceMetadataUrl(accepted).includes('/.well-known/'),
      accepted,
    );
  }
  // A character outside the set is still refused.
  assert.throws(() => protectedResourceMetadataUrl('ht tp://api.example/v1'));
  assert.throws(() => protectedResourceMetadataUrl('ht_tp://api.example/v1'));

  // MAX_SCHEME_LEN is 64 (`scheme.rs:194`). Pinned at the BOUNDARY: only a 65-character
  // scheme was tested before, so narrowing the check to 63 survived.
  const scheme64 = 'a'.repeat(64);
  assert.ok(
    protectedResourceMetadataUrl(`${scheme64}://api.example/v1`).startsWith(
      `${scheme64}://`,
    ),
    '64 characters is the longest accepted scheme',
  );
  assert.throws(
    () => protectedResourceMetadataUrl(`${'a'.repeat(65)}://api.example/v1`),
    '65 is one too many',
  );
});

test('the authority scan matches the crate on order and percent resets', () => {
  // Counting could not express these: `has_percent` resets at `@` and at `]`, the userinfo
  // boundary is the LAST `@`, and bracket ORDER matters.
  for (const accepted of [
    'https://[fe80::1%25eth0]/v1',
    'https://a@b%25@c.example/v1',
  ]) {
    assert.doesNotThrow(() => protectedResourceMetadataUrl(accepted), accepted);
  }
  for (const refused of ['https://[a][b]/v1', 'https://]a[/v1']) {
    assert.equal(
      refusalCode(() => protectedResourceMetadataUrl(refused)),
      'resource_not_absolute',
      refused,
    );
  }
});

test('the path table refuses what the crate refuses', () => {
  // The accept side was pinned and the REFUSE side was not, so the half just corrected was
  // the half with no test.
  for (const refused of [
    'https://api.example/v1/a<b',
    'https://api.example/v1/a>b',
    'https://api.example/v1/a`b',
    'https://api.example/v1/a\x7fb',
    'https://api.example/v1/a\x01b',
  ]) {
    assert.equal(
      refusalCode(() => protectedResourceMetadataUrl(refused)),
      'resource_not_absolute',
      JSON.stringify(refused),
    );
  }
});

test('the scheme grammar is the only thing checking the scheme', () => {
  // Nothing else looks at it: the two tables run on the authority and the path.
  //
  // `1http://` was on this list and is NOT here any more. The crate's `SCHEME_CHARS`
  // (`scheme.rs:205-231`) allows a digit in any position, so refusing it was this module
  // being stricter than the thing it promises to agree with. See the boundary and charset
  // rows in `the scheme grammar matches SCHEME_CHARS, not RFC 3986`.
  for (const refused of [
    'ht tp://api.example/x',
    'ht_tp://api.example/x',
    `${'s'.repeat(65)}://api.example/x`,
  ]) {
    assert.equal(
      refusalCode(() => protectedResourceMetadataUrl(refused)),
      'resource_not_absolute',
      refused.slice(0, 20),
    );
  }
});

// --- Deriving the document from the verify configuration (issue #127 criterion 4) ---

const DERIVE_FROM: VerifiedTokenConfig = {
  issuer: 'https://auth.example/t/acme/e/prod',
  audience: 'https://api.example/v1/mcp',
};

test('a derived document restates nothing the caller already told verify', () => {
  const document = protectedResourceMetadata(protectedResourceFromVerify(DERIVE_FROM));
  assert.equal(document.resource, DERIVE_FROM.audience);
  assert.deepEqual(document.authorization_servers, [DERIVE_FROM.issuer]);
});

test('a derived mismatch is unreachable, not merely rejected', () => {
  // The point of deriving. `defineProtectedResource` REFUSES a caller-supplied mismatch, which
  // is right when the caller supplies both; deriving removes the opportunity. Two mechanisms,
  // and both are needed: the override type omits the derived fields, and the call spreads
  // overrides FIRST so a value smuggled past the types is overwritten rather than honoured.
  // A JavaScript caller has no types, so the second is what actually holds.
  const smuggled = {
    scopesSupported: ['mcp:read'],
    resource: 'https://evil.example/x',
    authorizationServers: ['https://evil.example'],
  } as unknown as DerivedResourceOverrides;
  const document = protectedResourceMetadata(protectedResourceFromVerify(DERIVE_FROM, smuggled));
  assert.equal(document.resource, DERIVE_FROM.audience);
  assert.deepEqual(document.authorization_servers, [DERIVE_FROM.issuer]);
  assert.deepEqual(document.scopes_supported, ['mcp:read']);
});

test('the fields verify cannot imply stay caller-supplied', () => {
  // A token's scopes are what ONE caller was granted; `scopes_supported` is what the server
  // offers. `verify` never learns the second, so deriving it would be an invention.
  const bare = protectedResourceMetadata(protectedResourceFromVerify(DERIVE_FROM));
  assert.equal('scopes_supported' in bare, false);
  assert.equal('bearer_methods_supported' in bare, false);
  const given = protectedResourceMetadata(
    protectedResourceFromVerify(DERIVE_FROM, {
      scopesSupported: ['mcp:read', 'mcp:write'],
      bearerMethodsSupported: ['header'],
    }),
  );
  assert.deepEqual(given.scopes_supported, ['mcp:read', 'mcp:write']);
  assert.deepEqual(given.bearer_methods_supported, ['header']);
});

test('an unstable verify configuration cannot make the derived pair disagree', () => {
  // The defect `defineProtectedResource` documents, aimed at the derivation path: a source
  // whose reads are not stable could feed one value to the document and another to the
  // audience comparison. Deriving reads each field ONCE into a local before either use, so
  // the second read never reaches the document.
  let reads = 0;
  const shifting: VerifiedTokenConfig = {
    get issuer() {
      return DERIVE_FROM.issuer;
    },
    get audience() {
      reads += 1;
      return reads === 1 ? DERIVE_FROM.audience : 'https://evil.example/x';
    },
  };
  const document = protectedResourceMetadata(protectedResourceFromVerify(shifting));
  assert.equal(document.resource, DERIVE_FROM.audience);
  assert.ok(reads >= 1, 'the getter really was read, so the fixture is not vacuous');
});

test('deriving is not a way around the identifier parse', () => {
  // A query or fragment in the audience is the caller's bug either way, and it must surface as
  // the same refusal rather than being waved through because the value came from `verify`.
  assert.throws(
    () => protectedResourceFromVerify({ ...DERIVE_FROM, audience: 'https://api.example/v1?x=1' }),
    PrmConfigError,
  );
  assert.throws(
    () => protectedResourceFromVerify({ ...DERIVE_FROM, issuer: 'not-a-url' }),
    PrmConfigError,
  );
});

// --- The challenge corpus shared with the crate (issue #127 criterion 3) ---

interface ChallengeCase {
  readonly name: string;
  readonly kind: 'challenge' | 'insufficient_scope';
  readonly error?: string | null;
  readonly error_description?: string | null;
  readonly scope?: string;
  readonly expected: string;
}

interface ChallengeCorpus {
  readonly resource: string;
  readonly metadata_url: string;
  readonly cases: readonly ChallengeCase[];
}

function challengeCorpus(): ChallengeCorpus {
  // Resolved from THIS module rather than the process cwd, so the suite does not depend on
  // where it was invoked from. `dist/` and `src/` are both one level under the package root,
  // so the same relative path works whether this runs from source or from the build output.
  const corpusPath = fileURLToPath(
    new URL('../vectors/prm-challenge-vectors.json', import.meta.url),
  );
  return JSON.parse(readFileSync(corpusPath, 'utf8')) as ChallengeCorpus;
}

test('the SDK builds every challenge in the shared corpus, byte for byte', () => {
  // The corpus is read by the crate test too, which is what makes "the SDK matches the crate"
  // falsifiable. The older assertion compared this builder against a string typed into this
  // file, so both sides could drift together and nothing would notice.
  const corpus = challengeCorpus();
  // The KINDS, not a count. A floor of three is satisfied by three challenge cases, which
  // would exercise one builder path while claiming to pin both.
  const kinds = new Set(corpus.cases.map((c) => c.kind));
  assert.ok(
    kinds.has('challenge') && kinds.has('insufficient_scope'),
    'the corpus exercises both challenge shapes',
  );
  // Bound to the KIND. `!c.error` alone is satisfied by the insufficient-scope case, whose
  // `error` member is absent and therefore `undefined`, so the predicate held whether or not
  // the bare case existed. Measured: with the bare case deleted, both suites stayed green.
  assert.ok(
    corpus.cases.some((c) => c.kind === 'challenge' && !c.error),
    'including the bare form, which is the answer to a request with no credential',
  );
  const resource = defineProtectedResource(
    { resource: corpus.resource, authorizationServers: [ISSUER] },
    { issuer: ISSUER, audience: corpus.resource },
  );
  assert.equal(
    protectedResourceMetadataUrl(corpus.resource),
    corpus.metadata_url,
    'the corpus states the URL this resource composes to, so a composition change is caught here',
  );

  for (const testCase of corpus.cases) {
    const built =
      testCase.kind === 'insufficient_scope'
        ? protectedResourceChallenge(resource, {
            error: 'insufficient_scope',
            scope: testCase.scope,
          })
        : protectedResourceChallenge(resource, {
            ...(testCase.error ? { error: testCase.error as ChallengeError } : {}),
            ...(testCase.error_description
              ? { errorDescription: testCase.error_description }
              : {}),
          });
    assert.equal(built, testCase.expected, `case ${testCase.name}`);
  }
});
