// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  DEFAULT_PRM_MAX_AGE_SECONDS,
  PrmConfigError,
  ProtectedResource,
  defineProtectedResource,
  forbidden,
  protectedResourceChallenge,
  protectedResourceMetadata,
  protectedResourceMetadataUrl,
  protectedResourceMiddleware,
  unauthorized,
} from "./protected-resource.js";

const RESOURCE = "https://api.example/v1/mcp";
const ISSUER = "https://auth.example";
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
  return assert.fail("expected a refusal");
}

test("the well-known segment is INSERTED, not appended", () => {
  // Invisible for a path-less identifier: both spellings agree until the first resource with
  // a path, which is how the wrong one reaches production.
  assert.equal(
    protectedResourceMetadataUrl("https://api.example/v1/mcp"),
    "https://api.example/.well-known/oauth-protected-resource/v1/mcp",
  );
  assert.equal(
    protectedResourceMetadataUrl("https://api.example"),
    "https://api.example/.well-known/oauth-protected-resource",
  );
});

test("nothing about the identifier is normalised, except the one thing the crate normalises", () => {
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
      "https://api.example:443/v1",
      "https://api.example:443/.well-known/oauth-protected-resource/v1",
    ],
    [
      "http://api.example:80/v1",
      "http://api.example:80/.well-known/oauth-protected-resource/v1",
    ],
    [
      "https://user:pass@api.example/v1",
      "https://user:pass@api.example/.well-known/oauth-protected-resource/v1",
    ],
    // Scheme lowercased, HOST CASE PRESERVED, path case preserved: exactly what the crate does.
    [
      "HTTPS://API.EXAMPLE/V1",
      "https://API.EXAMPLE/.well-known/oauth-protected-resource/V1",
    ],
    [
      "Http://api.example/x",
      "http://api.example/.well-known/oauth-protected-resource/x",
    ],
    // A NON-special scheme keeps its case, because the fast path above covers http/https only.
    [
      "COAP://device.example/v1",
      "COAP://device.example/.well-known/oauth-protected-resource/v1",
    ],
    [
      "https://api.example/v1/../secret",
      "https://api.example/.well-known/oauth-protected-resource/v1/../secret",
    ],
    [
      "https://api.example/%2e%2e/x",
      "https://api.example/.well-known/oauth-protected-resource/%2e%2e/x",
    ],
  ];
  for (const [resource, expected] of cases) {
    assert.equal(protectedResourceMetadataUrl(resource), expected, resource);
  }
});

test("a non-special scheme composes a real URL, not the string null", () => {
  // `URL.origin` is literally "null" outside http/https/ws/wss/ftp, so composing through it
  // publishes `null/.well-known/...` for a resource identifier RFC 8707 permits.
  assert.equal(
    protectedResourceMetadataUrl("coap://device.example/v1"),
    "coap://device.example/.well-known/oauth-protected-resource/v1",
  );
});

test("every trailing slash is stripped, not just one", () => {
  // So `.../mcp`, `.../mcp/` and `.../mcp//` publish at ONE URL rather than several a cache
  // would treat as unrelated.
  for (const resource of [
    "https://api.example/v1/mcp",
    "https://api.example/v1/mcp/",
    "https://api.example/v1/mcp//",
  ]) {
    assert.equal(
      protectedResourceMetadataUrl(resource),
      "https://api.example/.well-known/oauth-protected-resource/v1/mcp",
      resource,
    );
  }
});

test("a request with no credentials gets a bare challenge, with no error code", () => {
  // RFC 6750 section 3.1: an error code here tells an unauthenticated caller that something
  // about its absent token was wrong.
  const challenge = unauthorized(CHECKED).headers["WWW-Authenticate"];
  assert.ok(challenge.startsWith("Bearer "), challenge);
  assert.ok(!challenge.includes("error="), challenge);
  assert.ok(challenge.includes("resource_metadata="), challenge);
});

test("parameter order matches the crate, so a shared fixture can assert identity", () => {
  assert.equal(
    unauthorized(CHECKED, { error: "invalid_token" }).headers[
      "WWW-Authenticate"
    ],
    'Bearer resource_metadata="https://api.example/.well-known/oauth-protected-resource/v1/mcp", error="invalid_token"',
  );
  assert.equal(
    forbidden(CHECKED, "mcp:tools").headers["WWW-Authenticate"],
    'Bearer resource_metadata="https://api.example/.well-known/oauth-protected-resource/v1/mcp", error="insufficient_scope", scope="mcp:tools"',
  );
});

test("a value RFC 6750 forbids is REFUSED, not escaped", () => {
  // Section 3 restricts these to %x20-21 / %x23-5B / %x5D-7E, which excludes the quote, the
  // backslash, DEL and every control character. Escaping a quote emits a backslash the spec
  // forbids; passing CR or LF is a header-splitting primitive.
  for (const bad of [
    'he said "no"',
    "back\\slash",
    "boom\r\nX-Injected: yes",
    "del\x7f",
    "tab\there",
  ]) {
    assert.equal(
      refusalCode(() =>
        protectedResourceChallenge(CHECKED, {
          error: "invalid_token",
          errorDescription: bad,
        }),
      ),
      "challenge_value_not_representable",
      bad,
    );
  }
});

test("the document must not contradict what the server verifies", () => {
  // Both halves. A mismatched audience sends clients for a token this server rejects; an
  // advertised authorization server that is not the verified issuer is the same lie.
  assert.equal(
    refusalCode(() =>
      defineProtectedResource(CONFIG, {
        issuer: ISSUER,
        audience: "https://api.example/v2/mcp",
      }),
    ),
    "resource_audience_mismatch",
  );
  assert.equal(
    refusalCode(() =>
      defineProtectedResource(
        { resource: RESOURCE, authorizationServers: ["https://other.example"] },
        VERIFIES,
      ),
    ),
    "authorization_server_not_the_verified_issuer",
  );
});

test("the audience comparison is exact, not normalised", () => {
  // The token endpoint compares exactly, so a pairing that only matches after normalisation
  // is one the endpoint still rejects.
  assert.equal(
    refusalCode(() =>
      defineProtectedResource(
        {
          resource: "https://api.example:443/v1",
          authorizationServers: [ISSUER],
        },
        { issuer: ISSUER, audience: "https://api.example/v1" },
      ),
    ),
    "resource_audience_mismatch",
  );
  assert.equal(
    refusalCode(() =>
      defineProtectedResource(
        { resource: "https://API.example/v1", authorizationServers: [ISSUER] },
        { issuer: ISSUER, audience: "https://api.example/v1" },
      ),
    ),
    "resource_audience_mismatch",
  );
});

test("every refusal has its own code, because each is fixed differently", () => {
  const cases: Array<[string, string[], string]> = [
    ["not-a-uri", [ISSUER], "resource_not_absolute"],
    ["https:///v1", [ISSUER], "resource_not_absolute"],
    [
      "https://api.example/v1?tenant=a",
      [ISSUER],
      "resource_has_query_or_fragment",
    ],
    ["https://api.example/v1#frag", [ISSUER], "resource_has_query_or_fragment"],
    ["https://api.example/v1#", [ISSUER], "resource_has_query_or_fragment"],
    ["https://api.example/a b", [ISSUER], "resource_not_absolute"],
    ["https://ñ.example/v1", [ISSUER], "resource_not_absolute"],
    [RESOURCE, [], "no_authorization_servers"],
    [RESOURCE, ["auth.example"], "issuer_not_absolute"],
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

test("an empty fragment is refused, like any other", () => {
  // The trap the crate calls out: parse-then-inspect lets `.../x#` through as a distinct
  // identity for the same resource, and an empty fragment is the form that slips past.
  assert.equal(
    refusalCode(() => protectedResourceMetadataUrl("https://api.example/x#")),
    "resource_has_query_or_fragment",
  );
});

test("a refusal message echoes no configured value", () => {
  const secret = "https://internal.example/tenant-12345";
  try {
    defineProtectedResource(CONFIG, { issuer: ISSUER, audience: secret });
    assert.fail("expected a refusal");
  } catch (error) {
    assert.ok(error instanceof PrmConfigError);
    assert.ok(!error.message.includes(secret), error.message);
    assert.equal(error.value, secret);
  }
});

test("each refusal code carries its own message", () => {
  // Otherwise a code could be mapped to the wrong text and nothing would notice.
  const messages = new Set<string>();
  const codes: Array<() => unknown> = [
    () =>
      defineProtectedResource(
        { resource: "nope", authorizationServers: [ISSUER] },
        VERIFIES,
      ),
    () =>
      defineProtectedResource(
        { resource: "https://a.example/x#", authorizationServers: [ISSUER] },
        VERIFIES,
      ),
    () =>
      defineProtectedResource(
        { resource: RESOURCE, authorizationServers: [] },
        VERIFIES,
      ),
    () =>
      defineProtectedResource(
        { resource: RESOURCE, authorizationServers: ["nope"] },
        VERIFIES,
      ),
    () =>
      defineProtectedResource(CONFIG, {
        issuer: ISSUER,
        audience: "https://other.example",
      }),
    () =>
      defineProtectedResource(
        { resource: RESOURCE, authorizationServers: ["https://x.example"] },
        VERIFIES,
      ),
    () =>
      protectedResourceChallenge(CHECKED, {
        error: "invalid_token",
        errorDescription: '"',
      }),
  ];
  for (const run of codes) {
    try {
      run();
      assert.fail("expected a refusal");
    } catch (error) {
      assert.ok(error instanceof PrmConfigError);
      messages.add(error.message);
    }
  }
  assert.equal(
    messages.size,
    codes.length,
    "every code must describe itself distinctly",
  );
});

test("the document carries the required fields and omits empty optional ones", () => {
  assert.deepEqual(protectedResourceMetadata(CHECKED), {
    resource: RESOURCE,
    authorization_servers: [ISSUER],
  });
});

test("each optional field is advertised only when non-empty", () => {
  // Absent and empty are different claims: an empty array says "supports none".
  const withScopes = defineProtectedResource(
    { ...CONFIG, scopesSupported: ["mcp:tools"], bearerMethodsSupported: [] },
    VERIFIES,
  );
  const document = protectedResourceMetadata(withScopes);
  assert.deepEqual(document.scopes_supported, ["mcp:tools"]);
  assert.ok(!("bearer_methods_supported" in document));

  const withMethods = defineProtectedResource(
    { ...CONFIG, scopesSupported: [], bearerMethodsSupported: ["header"] },
    VERIFIES,
  );
  const other = protectedResourceMetadata(withMethods);
  assert.deepEqual(other.bearer_methods_supported, ["header"]);
  assert.ok(!("scopes_supported" in other));
});

test("the document does not alias the caller arrays", () => {
  const servers = [ISSUER];
  const document = protectedResourceMetadata(
    defineProtectedResource(
      { resource: RESOURCE, authorizationServers: servers },
      VERIFIES,
    ),
  );
  servers.push("https://sneaky.example");
  assert.deepEqual(document.authorization_servers, [ISSUER]);
});

test("the middleware serves the document at the well-known path, with cache headers", () => {
  const handle = protectedResourceMiddleware(CHECKED);
  const served = handle({
    path: "/.well-known/oauth-protected-resource/v1/mcp",
    outcome: "no-token",
  });
  assert.ok(served);
  assert.equal(served.status, 200);
  assert.equal(
    served.headers["Cache-Control"],
    `public, max-age=${DEFAULT_PRM_MAX_AGE_SECONDS}`,
  );
  assert.deepEqual(JSON.parse(served.body ?? ""), {
    resource: RESOURCE,
    authorization_servers: [ISSUER],
  });
});

test("the middleware challenges, and gets out of the way when the token is good", () => {
  const handle = protectedResourceMiddleware(CHECKED);
  assert.equal(handle({ path: "/v1/mcp", outcome: "ok" }), null);
  assert.equal(handle({ path: "/v1/mcp", outcome: "no-token" })?.status, 401);
  assert.equal(
    handle({ path: "/v1/mcp", outcome: "invalid-token" })?.status,
    401,
  );
  assert.ok(
    handle({ path: "/v1/mcp", outcome: "invalid-token" })?.headers[
      "WWW-Authenticate"
    ].includes("invalid_token"),
  );
  const denied = handle({
    path: "/v1/mcp",
    outcome: { missingScope: "mcp:tools" },
  });
  assert.equal(denied?.status, 403);
  assert.ok(denied?.headers["WWW-Authenticate"].includes('scope="mcp:tools"'));
});

test("a configured cache lifetime is honoured", () => {
  const handle = protectedResourceMiddleware(
    defineProtectedResource({ ...CONFIG, maxAgeSeconds: 60 }, VERIFIES),
  );
  const served = handle({
    path: "/.well-known/oauth-protected-resource/v1/mcp",
    outcome: "ok",
  });
  assert.equal(served?.headers["Cache-Control"], "public, max-age=60");
});

test("the middleware serves the path its own challenge advertises", () => {
  // The blocking defect this pins: the match path was derived through `new URL()`, which
  // resolves dot segments and decodes `%2e`, so for these identifiers the challenge named a
  // path the middleware then refused. The discovery chain dead-ending silently, produced by
  // the module written to prevent it.
  for (const resource of [
    "https://api.example/v1/../secret",
    "https://api.example/%2e%2e/x",
    "https://api.example/v1/./mcp",
    "https://api.example/v1/mcp",
  ]) {
    const checked = defineProtectedResource(
      { resource, authorizationServers: [ISSUER] },
      { issuer: ISSUER, audience: resource },
    );
    const advertised = protectedResourceMetadataUrl(resource);
    const path = advertised.slice(
      advertised.indexOf("/", advertised.indexOf("://") + 3),
    );
    const served = protectedResourceMiddleware(checked)({
      path,
      outcome: "no-token",
    });
    assert.equal(
      served?.status,
      200,
      `advertised ${path} and did not serve it`,
    );
  }
});

test("the path table matches the crate: it accepts what http::Uri accepts", () => {
  // Measured against the crate's PATH_MAP. An earlier version ran one regex over the whole
  // identifier and refused all of these, which the crate accepts.
  for (const resource of [
    "https://api.example/v1/caf\u00e9",
    "https://api.example/tenants/{id}",
    "https://api.example/v1/a|b",
    "https://api.example/v1/a^b",
    'https://api.example/v1/a"b',
  ]) {
    assert.doesNotThrow(() => protectedResourceMetadataUrl(resource), resource);
  }
});

test("the authority table matches the crate: it refuses what http::Uri refuses", () => {
  // The other direction of the same defect: one regex over the whole string accepted these,
  // and the crate rejects every one.
  for (const resource of [
    "https://api.example:80:90/v1",
    "https://[not-ipv6/v1",
    "https://api%2eexample/v1",
    "https://user@/v1",
    "https://a]b/v1",
    "https://api.example\u00f1/v1",
    // Delimiters that change how an authority parses. `validate_authority_bytes` rejects
    // each of these, and without the delimiter half of the check they compose a URL.
    "https://api{example/v1",
    'https://api"example/v1',
    "https://api^example/v1",
    "https://api|example/v1",
  ]) {
    assert.equal(
      refusalCode(() => protectedResourceMetadataUrl(resource)),
      "resource_not_absolute",
      resource,
    );
  }
});

test("a spread of a validated config is refused", () => {
  // A brand survives a spread, so overriding `resource` afterwards produced a "validated"
  // configuration that was never validated, and every emitter accepted it. That is the one
  // line someone writes to derive a second resource from a first.
  const spread = {
    ...CHECKED,
    resource: "https://attacker.example/x",
  } as ProtectedResource;
  assert.equal(
    refusalCode(() => unauthorized(spread)),
    "resource_not_validated",
  );
  assert.equal(
    refusalCode(() => forbidden(spread, "mcp:tools")),
    "resource_not_validated",
  );
});

test("a cache lifetime that cannot reach a header is refused", () => {
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
      "cache_lifetime_not_representable",
      String(maxAgeSeconds),
    );
  }
});

test("a scope the spec forbids costs the parameter, not the response", () => {
  // `requiredScope` is a per-request input. Throwing here turns an intended 403 into a 500;
  // the challenge is still correct without the optional `scope` parameter.
  const challenge = forbidden(CHECKED, "a\r\nSet-Cookie: x=1").headers[
    "WWW-Authenticate"
  ];
  assert.ok(challenge.includes('error="insufficient_scope"'), challenge);
  assert.ok(!challenge.includes("scope="), challenge);
});

test("a description with no error has its own code", () => {
  // The value is representable; the fault is that there is nothing to attach it to.
  assert.equal(
    refusalCode(() =>
      protectedResourceChallenge(CHECKED, { errorDescription: "dropped?" }),
    ),
    "error_description_without_an_error",
  );
});

test("the middleware matches the well-known path regardless of trailing slashes", () => {
  const handle = protectedResourceMiddleware(CHECKED);
  for (const path of [
    "/.well-known/oauth-protected-resource/v1/mcp",
    "/.well-known/oauth-protected-resource/v1/mcp/",
  ]) {
    assert.equal(handle({ path, outcome: "ok" })?.status, 200, path);
  }
});

test("the document is served as JSON", () => {
  const served = protectedResourceMiddleware(CHECKED)({
    path: "/.well-known/oauth-protected-resource/v1/mcp",
    outcome: "ok",
  });
  assert.equal(served?.headers["Content-Type"], "application/json");
});

test("the document path refuses an unvalidated config too", () => {
  // The guard was on the challenge builders only, so a spread was refused when asked for a
  // header and served happily when asked for the DOCUMENT, which is the artefact whose whole
  // job is to not lie.
  const spread = {
    ...CHECKED,
    resource: "https://attacker.example/x",
  } as ProtectedResource;
  assert.equal(
    refusalCode(() => protectedResourceMetadata(spread)),
    "resource_not_validated",
  );
  assert.equal(
    refusalCode(() => protectedResourceMiddleware(spread)),
    "resource_not_validated",
  );
});

test("a prototype forgery is refused", () => {
  // `instanceof` is satisfied by this; a private field is not.
  const forged = Object.create(
    ProtectedResource.prototype,
  ) as ProtectedResource;
  assert.equal(
    refusalCode(() => unauthorized(forged)),
    "resource_not_validated",
  );
  assert.equal(
    refusalCode(() => protectedResourceMetadata(forged)),
    "resource_not_validated",
  );
});

test("there is no public construction path", () => {
  // This test asserted only that `ProtectedResource.build` was `undefined`, which pins the
  // removed SPELLING rather than the property its name claims, and the property was false:
  // `private constructor` is erased at emit, so `Reflect.construct` built one with no
  // diagnostic and rebuilt every configuration this module refuses. The constructor now
  // takes a module-scoped symbol, so these are refusals at RUNTIME.
  assert.equal(
    (ProtectedResource as unknown as Record<string, unknown>).build,
    undefined,
    "the removed `build` static must not come back",
  );

  const hostile = {
    resource: "https://attacker.example/x",
    authorizationServers: [] as string[],
    maxAgeSeconds: Number.NaN,
  };
  const verifies = {
    issuer: "https://attacker.example",
    audience: "https://totally-different.example",
  };

  // `Reflect.construct` is the one TypeScript never flags: `new` is TS2673 and `extends` is
  // TS2675, but this compiles clean and needs no cast.
  assert.equal(
    refusalCode(() =>
      Reflect.construct(ProtectedResource, [hostile, verifies, Number.NaN]),
    ),
    "resource_not_validated",
    "Reflect.construct must not reach the constructor body",
  );
  // A plain-JS consumer, which has no type checking at all.
  assert.equal(
    refusalCode(
      () =>
        new (
          ProtectedResource as unknown as new (...args: unknown[]) => unknown
        )(hostile, verifies, Number.NaN),
    ),
    "resource_not_validated",
    "an untyped consumer must be refused the same way",
  );
  // A guessed token is still not the token.
  assert.equal(
    refusalCode(() =>
      Reflect.construct(ProtectedResource, [
        hostile,
        verifies,
        Number.NaN,
        Symbol("ironauth.prm.construct"),
      ]),
    ),
    "resource_not_validated",
    "a same-named symbol is a different symbol",
  );
});

test("a validated instance cannot be mutated after the fact", () => {
  // `readonly` is type-only. `Object.assign(validated, { resource })` type-checks with no
  // cast (the direct assignment is TS2540, this spelling is not) and mutated a value every
  // emitter had already accepted: the same "derive a second resource from a validated first"
  // shape the spread refusal exists to catch, in the one spelling still open.
  const validated = defineProtectedResource(
    {
      resource: "https://api.example/v1",
      authorizationServers: ["https://auth.example"],
    },
    { issuer: "https://auth.example", audience: "https://api.example/v1" },
  );

  assert.ok(Object.isFrozen(validated), "a validated instance is frozen");
  assert.throws(
    () => Object.assign(validated, { resource: "https://attacker.example/x" }),
    "mutating a frozen instance throws in strict mode",
  );
  assert.equal(
    validated.resource,
    "https://api.example/v1",
    "and the original is unchanged",
  );
  // The arrays too: handing out a live reference lets a caller push an issuer in later.
  assert.ok(
    Object.isFrozen(validated.authorizationServers),
    "the servers array is frozen",
  );
  assert.throws(
    () =>
      (validated.authorizationServers as string[]).push(
        "https://attacker.example",
      ),
    "and cannot be appended to",
  );
});

test("the authority scan matches the crate arm for arm", () => {
  // Every row here was a SURVIVING mutant: the scan did the right thing and nothing held it
  // there. Each is derived from `http-1.5.0/src/uri/authority.rs:475-570` and cited to the
  // arm it pins, because that file has now been hand-read wrong twice in this PR's reviews.

  // `[` guards on `has_percent || start_bracket` (:524). Checking `endBracket` instead was
  // both dead (it implies startBracket) and wrong: this was accepted.
  assert.throws(() => protectedResourceMetadataUrl("https://a%25[b]/v1"));
  // ...and the startBracket half of that same guard.
  assert.throws(() => protectedResourceMetadataUrl("https://[a[b]/v1"));

  // `]` guards on `!start_bracket || end_bracket` (:529). Both halves.
  assert.throws(() => protectedResourceMetadataUrl("https://]a/v1"));
  assert.throws(() => protectedResourceMetadataUrl("https://[a]]/v1"));

  // `@` resets colons and percent, and does NOT touch the brackets (:538-545).
  assert.equal(
    protectedResourceMetadataUrl("https://a:1:2@b/v1"),
    "https://a:1:2@b/.well-known/oauth-protected-resource/v1",
    "the colons before an @ are userinfo, not ports",
  );
  assert.throws(
    () => protectedResourceMetadataUrl("https://aaa[@a/v1"),
    "an @ does not close an open bracket",
  );
  assert.equal(
    protectedResourceMetadataUrl("https://aaa[@]/v1"),
    "https://aaa[@]/.well-known/oauth-protected-resource/v1",
    "and does not clear one either, so this bracket pair is balanced",
  );

  // The userinfo boundary is the LAST `@`, not the first. `indexOf` and `lastIndexOf` agree
  // on every other fixture in this file, which is why the comment saying so went unmeasured.
  assert.equal(
    protectedResourceMetadataUrl("https://a@b@c.example/v1"),
    "https://a@b@c.example/.well-known/oauth-protected-resource/v1",
  );

  // MAX_COLONS is 8, checked mid-scan BEFORE any reset can forgive it (:486,518-522).
  assert.throws(() =>
    protectedResourceMetadataUrl("https://[::1:2:3:4:5:6:7:8]/v1"),
  );
  assert.throws(() => protectedResourceMetadataUrl("https://[:::::::::]/v1"));
  assert.throws(() =>
    protectedResourceMetadataUrl("https://a:1:2:3:4:5:6:7:8:9@b/v1"),
  );
  // Eight is still fine: a full IPv6 literal with a port is the case the cap is sized for.
  assert.equal(
    protectedResourceMetadataUrl(
      "https://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:80/v1",
    ),
    "https://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:80/.well-known/oauth-protected-resource/v1",
  );
});

test("the scheme grammar matches SCHEME_CHARS, not RFC 3986", () => {
  // `SCHEME_CHARS` (`scheme.rs:205-231`) permits a digit or `+ - . ~` in ANY position,
  // first included. Requiring a leading ALPHA was RFC 3986 correct and refused identifiers
  // the server accepts, which is a broken discovery chain even though it fails closed.
  for (const accepted of [
    "1http://api.example/v1",
    "+http://api.example/v1",
    ".http://api.example/v1",
    "-http://api.example/v1",
    "aa~://api.example/v1",
  ]) {
    assert.ok(
      protectedResourceMetadataUrl(accepted).includes("/.well-known/"),
      accepted,
    );
  }
  // A character outside the set is still refused.
  assert.throws(() => protectedResourceMetadataUrl("ht tp://api.example/v1"));
  assert.throws(() => protectedResourceMetadataUrl("ht_tp://api.example/v1"));

  // MAX_SCHEME_LEN is 64 (`scheme.rs:194`). Pinned at the BOUNDARY: only a 65-character
  // scheme was tested before, so narrowing the check to 63 survived.
  const scheme64 = "a".repeat(64);
  assert.ok(
    protectedResourceMetadataUrl(`${scheme64}://api.example/v1`).startsWith(
      `${scheme64}://`,
    ),
    "64 characters is the longest accepted scheme",
  );
  assert.throws(
    () => protectedResourceMetadataUrl(`${"a".repeat(65)}://api.example/v1`),
    "65 is one too many",
  );
});

test("the authority scan matches the crate on order and percent resets", () => {
  // Counting could not express these: `has_percent` resets at `@` and at `]`, the userinfo
  // boundary is the LAST `@`, and bracket ORDER matters.
  for (const accepted of [
    "https://[fe80::1%25eth0]/v1",
    "https://a@b%25@c.example/v1",
  ]) {
    assert.doesNotThrow(() => protectedResourceMetadataUrl(accepted), accepted);
  }
  for (const refused of ["https://[a][b]/v1", "https://]a[/v1"]) {
    assert.equal(
      refusalCode(() => protectedResourceMetadataUrl(refused)),
      "resource_not_absolute",
      refused,
    );
  }
});

test("the path table refuses what the crate refuses", () => {
  // The accept side was pinned and the REFUSE side was not, so the half just corrected was
  // the half with no test.
  for (const refused of [
    "https://api.example/v1/a<b",
    "https://api.example/v1/a>b",
    "https://api.example/v1/a`b",
    "https://api.example/v1/a\x7fb",
    "https://api.example/v1/a\x01b",
  ]) {
    assert.equal(
      refusalCode(() => protectedResourceMetadataUrl(refused)),
      "resource_not_absolute",
      JSON.stringify(refused),
    );
  }
});

test("the scheme grammar is the only thing checking the scheme", () => {
  // Nothing else looks at it: the two tables run on the authority and the path.
  //
  // `1http://` was on this list and is NOT here any more. The crate's `SCHEME_CHARS`
  // (`scheme.rs:205-231`) allows a digit in any position, so refusing it was this module
  // being stricter than the thing it promises to agree with. See the boundary and charset
  // rows in `the scheme grammar matches SCHEME_CHARS, not RFC 3986`.
  for (const refused of [
    "ht tp://api.example/x",
    "ht_tp://api.example/x",
    `${"s".repeat(65)}://api.example/x`,
  ]) {
    assert.equal(
      refusalCode(() => protectedResourceMetadataUrl(refused)),
      "resource_not_absolute",
      refused.slice(0, 20),
    );
  }
});
