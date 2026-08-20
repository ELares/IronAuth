import assert from 'node:assert/strict';
import test from 'node:test';

import {
  PrmConfigError,
  defineProtectedResource,
  forbidden,
  protectedResourceChallenge,
  protectedResourceMetadata,
  protectedResourceMetadataUrl,
  unauthorized,
} from './protected-resource.js';

const CONFIG = {
  resource: 'https://api.example/v1/mcp',
  authorizationServers: ['https://auth.example'],
};

test('the well-known segment is INSERTED, not appended', () => {
  // The mistake this pins is invisible for a path-less identifier, which is why it survives
  // into production: both spellings agree until the first resource that has a path.
  assert.equal(
    protectedResourceMetadataUrl('https://api.example/v1/mcp'),
    'https://api.example/.well-known/oauth-protected-resource/v1/mcp',
  );
  assert.equal(
    protectedResourceMetadataUrl('https://api.example'),
    'https://api.example/.well-known/oauth-protected-resource',
  );
  assert.equal(
    protectedResourceMetadataUrl('https://api.example/'),
    'https://api.example/.well-known/oauth-protected-resource',
  );
});

test('a path-bearing identifier keeps its path in the challenge', () => {
  const challenge = protectedResourceChallenge(CONFIG);
  assert.match(
    challenge,
    /resource_metadata="https:\/\/api\.example\/\.well-known\/oauth-protected-resource\/v1\/mcp"/,
  );
});

test('a request with no credentials gets a bare challenge, with no error code', () => {
  // RFC 6750 section 3: an `error` here would tell an unauthenticated caller that something
  // about its absent token was wrong.
  const response = unauthorized(CONFIG);
  assert.equal(response.status, 401);
  const challenge = response.headers['WWW-Authenticate'];
  assert.ok(challenge.startsWith('Bearer '), challenge);
  assert.ok(!challenge.includes('error='), `bare challenge must carry no error: ${challenge}`);
  assert.ok(challenge.includes('resource_metadata='), challenge);
});

test('an invalid token gets error=invalid_token and still points at the metadata', () => {
  const challenge = unauthorized(CONFIG, { error: 'invalid_token' }).headers['WWW-Authenticate'];
  assert.ok(challenge.includes('error="invalid_token"'), challenge);
  assert.ok(challenge.includes('resource_metadata='), challenge);
});

test('a 403 advertises the scope the caller needs', () => {
  const response = forbidden(CONFIG, 'mcp:tools');
  assert.equal(response.status, 403);
  const challenge = response.headers['WWW-Authenticate'];
  assert.ok(challenge.includes('error="insufficient_scope"'), challenge);
  assert.ok(challenge.includes('scope="mcp:tools"'), challenge);
  assert.ok(challenge.includes('resource_metadata='), challenge);
});

test('a quoted-string value cannot end its parameter early', () => {
  // Without escaping, a configured value containing a quote closes the parameter and the rest
  // is parsed as further parameters, which is a parameter-injection primitive.
  const challenge = protectedResourceChallenge(CONFIG, {
    error: 'invalid_token',
    errorDescription: 'he said "no" \\ then left',
  });
  assert.ok(challenge.includes('error_description="he said \\"no\\" \\\\ then left"'), challenge);
});

test('a mismatched resource identifier and audience is refused at startup', () => {
  // The failure this prevents: discovery sends clients to obtain a token for one value while
  // the server rejects anything that does not carry the other, so every client fails and the
  // document says the configuration is fine.
  assert.throws(
    () =>
      defineProtectedResource({
        ...CONFIG,
        enforcedAudience: 'https://api.example/v2/mcp',
      }),
    (error: unknown) =>
      error instanceof PrmConfigError && error.code === 'resource_audience_mismatch',
  );
});

test('the audience defaults to the resource, so the common case cannot mismatch', () => {
  const checked = defineProtectedResource(CONFIG);
  assert.equal(checked.enforcedAudience, CONFIG.resource);
});

test('every refusal has its own code, because each is fixed differently', () => {
  const cases: Array<[Record<string, unknown>, string]> = [
    [{ resource: 'not-a-uri', authorizationServers: ['https://auth.example'] }, 'resource_not_absolute'],
    [
      { resource: 'https://api.example/v1?tenant=a', authorizationServers: ['https://auth.example'] },
      'resource_has_query_or_fragment',
    ],
    [
      { resource: 'https://api.example/v1#frag', authorizationServers: ['https://auth.example'] },
      'resource_has_query_or_fragment',
    ],
    [{ resource: 'https://api.example', authorizationServers: [] }, 'no_authorization_servers'],
    [
      { resource: 'https://api.example', authorizationServers: ['auth.example'] },
      'issuer_not_absolute',
    ],
  ];
  for (const [config, code] of cases) {
    assert.throws(
      () => defineProtectedResource(config as never),
      (error: unknown) => error instanceof PrmConfigError && error.code === code,
      `expected ${code} for ${JSON.stringify(config)}`,
    );
  }
});

test('a refusal message echoes no configured value', () => {
  // So it can be logged wherever convenient without deciding whether the value was sensitive.
  // The value is still available on the error for a caller that has decided.
  const secret = 'https://internal.example/tenant-12345';
  try {
    defineProtectedResource({ ...CONFIG, enforcedAudience: secret });
    assert.fail('expected a refusal');
  } catch (error) {
    assert.ok(error instanceof PrmConfigError);
    assert.ok(!error.message.includes(secret), `message leaked the value: ${error.message}`);
    assert.equal(error.value, secret);
  }
});

test('the document carries the required fields and omits empty optional ones', () => {
  const document = protectedResourceMetadata(CONFIG);
  assert.deepEqual(document, {
    resource: 'https://api.example/v1/mcp',
    authorization_servers: ['https://auth.example'],
  });
});

test('optional fields are advertised only when non-empty', () => {
  // Absent and empty are different claims: an empty array says "supports none".
  const document = protectedResourceMetadata({
    ...CONFIG,
    scopesSupported: ['mcp:tools'],
    bearerMethodsSupported: [],
  });
  assert.deepEqual(document.scopes_supported, ['mcp:tools']);
  assert.ok(!('bearer_methods_supported' in document));
});
