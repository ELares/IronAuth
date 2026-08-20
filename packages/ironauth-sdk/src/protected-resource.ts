// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * Protected-resource middleware (issue #127, RFC 9728).
 *
 * A resource server publishes a document naming the authorization servers it trusts, and
 * points clients at that document from its `WWW-Authenticate` challenge. Together those are
 * the discovery chain: a client holding neither can obtain a token knowing only the URL it
 * failed to reach.
 *
 * Every rule here MIRRORS `crates/ironauth-oidc/src/prm.rs`, including the refusal reasons
 * and the exact bytes of the published URL. A resource server built on this SDK and one built
 * on that crate must publish at the same place and refuse the same configurations, or the
 * chain works against one and silently not the other.
 *
 * # Why this does not use `new URL()` to compose
 *
 * It parses the identifier by hand. `URL` NORMALISES, and every normalisation it performs is
 * one the crate does not: it drops a default port, strips userinfo, lowercases the scheme and
 * host, resolves `..` segments, and decodes percent-escapes. `URL.origin` is also the literal
 * string `"null"` for any scheme outside http/https/ws/wss/ftp, so a `coap:` or `file:`
 * resource identifier composed through it yields `null/.well-known/...`, a URL no client can
 * resolve. Resource identifiers are absolute URIs of ANY scheme.
 *
 * The default-port case is the one that shows why this matters rather than being pedantry.
 * `prm.rs` has a test pinning `https://api.example:443` as NOT equal to `https://api.example`,
 * because the token endpoint compares audiences exactly; normalising here would advertise a
 * document at an origin the identifier does not name.
 */

/** Why a protected-resource configuration was refused. Mirrors `PrmConfigError`. */
export type PrmConfigErrorCode =
  | 'resource_not_absolute'
  | 'resource_has_query_or_fragment'
  | 'no_authorization_servers'
  | 'issuer_not_absolute'
  | 'resource_audience_mismatch'
  // The three below are SDK-only. `PrmConfigError` in the crate has five variants; these
  // three name failures that only exist on this side of the boundary.
  | 'authorization_server_not_the_verified_issuer'
  | 'challenge_value_not_representable'
  | 'cache_lifetime_not_representable'
  | 'error_description_without_an_error'
  | 'resource_not_validated';

/**
 * A refused configuration.
 *
 * One code per fixable cause, because "invalid configuration" puts the diagnosis back on
 * whoever reads the log. No configured value appears in `message`, so it can be logged
 * without deciding whether the value was sensitive; it is on `value` for a caller that has.
 */
export class PrmConfigError extends Error {
  readonly code: PrmConfigErrorCode;
  readonly value?: string;

  constructor(code: PrmConfigErrorCode, value?: string) {
    super(PRM_CONFIG_MESSAGES[code]);
    this.name = 'PrmConfigError';
    this.code = code;
    this.value = value;
  }
}

const PRM_CONFIG_MESSAGES: Record<PrmConfigErrorCode, string> = {
  resource_not_absolute:
    'the resource identifier must be an absolute URI with a scheme and host',
  resource_has_query_or_fragment:
    'the resource identifier must carry no query and no fragment',
  no_authorization_servers: 'at least one authorization server issuer must be advertised',
  issuer_not_absolute: 'every authorization server issuer must be an absolute URI',
  resource_audience_mismatch:
    'the advertised resource identifier and the enforced audience must be identical',
  authorization_server_not_the_verified_issuer:
    'the advertised authorization servers must include the issuer tokens are verified against',
  challenge_value_not_representable:
    'a challenge value must contain only characters RFC 6750 permits',
  cache_lifetime_not_representable:
    'the cache lifetime must be a non-negative whole number of seconds',
  error_description_without_an_error:
    'an error description needs an error code to attach to',
  resource_not_validated:
    'the configuration was not produced by defineProtectedResource',
};

const WELL_KNOWN = '/.well-known/oauth-protected-resource';

/** A resource identifier split the way `http::Uri` splits it, with nothing normalised. */
interface SplitResource {
  scheme: string;
  authority: string;
  path: string;
}

function splitResource(resource: string): SplitResource {
  // Fragment checked on the RAW string, before any parsing. `prm.rs` does the same and says
  // why: parse-then-inspect lets `https://api.example/x#` through as a distinct identity for
  // the same resource, and an EMPTY fragment is the form that slips past a parsed check.
  if (resource.includes('#')) {
    throw new PrmConfigError('resource_has_query_or_fragment', resource);
  }
  if (resource.includes('?')) {
    throw new PrmConfigError('resource_has_query_or_fragment', resource);
  }
  const schemeEnd = resource.indexOf('://');
  if (schemeEnd <= 0) {
    throw new PrmConfigError('resource_not_absolute', resource);
  }
  const scheme = resource.slice(0, schemeEnd);
  if (!/^[A-Za-z][A-Za-z0-9+\-.]*$/.test(scheme)) {
    throw new PrmConfigError('resource_not_absolute', resource);
  }
  const rest = resource.slice(schemeEnd + 3);
  const pathStart = rest.indexOf('/');
  const authority = pathStart === -1 ? rest : rest.slice(0, pathStart);
  const path = pathStart === -1 ? '' : rest.slice(pathStart);
  if (authority.length === 0) {
    throw new PrmConfigError('resource_not_absolute', resource);
  }
  // TWO tables, because `http::Uri` has two. An earlier version ran ONE regex over the whole
  // string and was wrong in both directions, measured against the crate's own tables: too
  // strict on the PATH, which accepts `{`, `}`, `"`, `\`, `^`, `|` and valid UTF-8, and too
  // lenient on the AUTHORITY, which rejects a second colon, mismatched brackets, a percent
  // outside userinfo, and an empty host after `@`. Its comment asserted the opposite.
  //
  // The authority: ASCII only, no delimiter that changes how it parses.
  if (/[^\x21-\x7e]/.test(authority) || /[\s"<>\\^`{|}]/.test(authority)) {
    throw new PrmConfigError('resource_not_absolute', resource);
  }
  const hostAndPort = authority.includes('@')
    ? authority.slice(authority.indexOf('@') + 1)
    : authority;
  if (hostAndPort.length === 0 || hostAndPort.includes('%')) {
    throw new PrmConfigError('resource_not_absolute', resource);
  }
  const opens = hostAndPort.match(/\[/g)?.length ?? 0;
  const closes = hostAndPort.match(/\]/g)?.length ?? 0;
  if (opens !== closes) {
    throw new PrmConfigError('resource_not_absolute', resource);
  }
  const afterHost = hostAndPort.includes(']')
    ? hostAndPort.slice(hostAndPort.lastIndexOf(']') + 1)
    : hostAndPort;
  if ((afterHost.match(/:/g)?.length ?? 0) > 1) {
    throw new PrmConfigError('resource_not_absolute', resource);
  }
  // The path: only what the crate's PATH_MAP calls invalid. Controls, DEL, SP, `<`, `>` and
  // the backtick. Notably NOT `{`, `}`, `"`, `\`, `^`, `|` or non-ASCII.
  if (/[\x00-\x20\x7f<>`]/.test(path)) {
    throw new PrmConfigError('resource_not_absolute', resource);
  }
  return { scheme, authority, path };
}

/**
 * The URL at which `resource`'s metadata is published.
 *
 * The well-known segment is INSERTED between the authority and the path, not appended. A
 * resource identified as `https://api.example/v1/mcp` publishes at
 * `https://api.example/.well-known/oauth-protected-resource/v1/mcp`. Appending instead is the
 * natural mistake and it is invisible for a path-less identifier: both spellings agree until
 * the first resource that has a path, which is how it reaches production.
 *
 * ALL trailing slashes are stripped, not one, so the same resource written `.../mcp`,
 * `.../mcp/` and `.../mcp//` publishes at one URL rather than several a cache treats as
 * unrelated.
 */
export function protectedResourceMetadataUrl(resource: string): string {
  const { scheme, authority, path } = splitResource(resource);
  return `${scheme}://${authority}${WELL_KNOWN}${path.replace(/\/+$/, '')}`;
}

/** What a resource server publishes, derived from what it already verifies. */
export interface ProtectedResourceConfig {
  /** The resource identifier this server publishes. Must equal the verified audience. */
  resource: string;
  /** The issuers whose tokens this server accepts. Must include the verified issuer. */
  authorizationServers: string[];
  /** Advertised only when non-empty. */
  scopesSupported?: string[];
  /** Advertised only when non-empty. */
  bearerMethodsSupported?: string[];
  /** How long the document may be cached, in seconds. Mirrors `PRM_MAX_AGE_SECS`. */
  maxAgeSeconds?: number;
}

/** The `verify` configuration this document must not contradict. */
export interface VerifiedTokenConfig {
  /** The exact issuer tokens are verified against, from `VerifyOptions`. */
  issuer: string;
  /** The audience tokens are verified against, from `VerifyOptions`. */
  audience: string;
}

/** Mirrors `PRM_MAX_AGE_SECS` in `prm.rs`. */
export const DEFAULT_PRM_MAX_AGE_SECONDS = 600;

/**
 * A configuration that has been checked against what the server actually verifies.
 *
 * A CLASS, not a branded object type, and the difference is measurable. A brand survives a
 * spread, so `{ ...checked, resource: 'https://attacker.example/x' }` typechecked and every
 * emitter accepted it: the one line a developer writes to derive a second resource from a
 * validated first, silently skipping every check. A spread loses the prototype, so the
 * emitters can refuse it at runtime as well as at the type level.
 */
export class ProtectedResource {
  readonly resource: string;
  readonly authorizationServers: readonly string[];
  readonly issuer: string;
  readonly audience: string;
  readonly maxAgeSeconds: number;
  readonly scopesSupported?: readonly string[];
  readonly bearerMethodsSupported?: readonly string[];

  /** @internal Constructed only by {@link defineProtectedResource}. */
  private constructor(config: ProtectedResourceConfig, verifies: VerifiedTokenConfig, maxAge: number) {
    this.resource = config.resource;
    this.authorizationServers = [...config.authorizationServers];
    this.issuer = verifies.issuer;
    this.audience = verifies.audience;
    this.maxAgeSeconds = maxAge;
    this.scopesSupported = config.scopesSupported ? [...config.scopesSupported] : undefined;
    this.bearerMethodsSupported = config.bearerMethodsSupported
      ? [...config.bearerMethodsSupported]
      : undefined;
  }

  /** @internal */
  static build(
    config: ProtectedResourceConfig,
    verifies: VerifiedTokenConfig,
    maxAge: number,
  ): ProtectedResource {
    return new ProtectedResource(config, verifies, maxAge);
  }
}

/**
 * Refuse anything that is not the real thing.
 *
 * A spread, a cast, or a hand-built lookalike all lose the prototype, and all of them mean
 * the configuration was never checked against what the server verifies.
 */
function assertValidated(resource: ProtectedResource): void {
  if (!(resource instanceof ProtectedResource)) {
    throw new PrmConfigError('resource_not_validated');
  }
}

/**
 * A configuration that has been checked against what the server actually verifies.
 *
 * Branded, so the challenge builders below CANNOT be handed a raw object. An earlier version
 * of this module validated on request and let every emitter take an unchecked config, which
 * made "refused at startup" opt-in: a server could emit challenges forever without ever
 * calling the validator.
 */


/**
 * Validate a configuration against the `verify` options it must agree with, or throw.
 *
 * DERIVED rather than restated. The audience and issuer come from the same `VerifyOptions`
 * the server validates tokens with, so the two cannot drift: an operator who types the
 * audience twice can type it differently twice, and then discovery lies while both objects
 * look correct.
 *
 * Both halves are checked. A document advertising an authorization server that is not the
 * issuer tokens are verified against sends clients to obtain tokens this server rejects,
 * which is the same lie as a mismatched audience and was unchecked until review pointed it
 * out.
 *
 * Called at STARTUP. A server whose document contradicts its own verification is broken for
 * every client, and discovering that on the first 401 means discovering it in production.
 */
export function defineProtectedResource(
  config: ProtectedResourceConfig,
  verifies: VerifiedTokenConfig,
): ProtectedResource {
  splitResource(config.resource);
  if (config.authorizationServers.length === 0) {
    throw new PrmConfigError('no_authorization_servers');
  }
  for (const issuer of config.authorizationServers) {
    splitIssuer(issuer);
  }
  // EXACT, never normalised, because the token endpoint compares exactly. `prm.rs` pins this
  // with a test: normalising here would pass a pairing the endpoint still rejects.
  if (config.resource !== verifies.audience) {
    throw new PrmConfigError('resource_audience_mismatch', verifies.audience);
  }
  if (!config.authorizationServers.includes(verifies.issuer)) {
    throw new PrmConfigError('authorization_server_not_the_verified_issuer', verifies.issuer);
  }
  // VALIDATED, because it reaches a `Cache-Control` header. Unchecked, this produced
  // `max-age=-1`, `max-age=1.5`, `max-age=NaN` and `max-age=Infinity`; the crate's
  // `PRM_MAX_AGE_SECS` is a `const u64` and cannot express any of them.
  const maxAge = config.maxAgeSeconds ?? DEFAULT_PRM_MAX_AGE_SECONDS;
  if (!Number.isSafeInteger(maxAge) || maxAge < 0) {
    throw new PrmConfigError('cache_lifetime_not_representable', String(maxAge));
  }
  return ProtectedResource.build(config, verifies, maxAge);
}

function splitIssuer(issuer: string): void {
  try {
    splitResource(issuer);
  } catch {
    throw new PrmConfigError('issuer_not_absolute', issuer);
  }
}

/** The metadata document, per RFC 9728 section 2. */
export function protectedResourceMetadata(
  resource: ProtectedResource,
): Record<string, unknown> {
  const document: Record<string, unknown> = {
    resource: resource.resource,
    authorization_servers: [...resource.authorizationServers],
  };
  // Absent rather than empty: an empty array advertises "supports none", which is a different
  // claim from "does not say". The crate makes the same distinction.
  if (resource.scopesSupported?.length) {
    document.scopes_supported = [...resource.scopesSupported];
  }
  if (resource.bearerMethodsSupported?.length) {
    document.bearer_methods_supported = [...resource.bearerMethodsSupported];
  }
  return document;
}

/** An RFC 6750 error code a challenge may carry. */
export type ChallengeError = 'invalid_token' | 'insufficient_scope';

export interface ChallengeOptions {
  /** Omitted on a bare 401, which is the right answer to a request with no credentials. */
  error?: ChallengeError;
  /** Optional, and never a place for a token or a claim value. */
  errorDescription?: string;
  /** Advertised on a 403 so the client knows what to ask for. */
  scope?: string;
}

/**
 * RFC 6750 section 3 restricts these values to `%x20-21 / %x23-5B / %x5D-7E`, which excludes
 * the double quote, the backslash, DEL, and every control character including CR and LF.
 *
 * So the remedy is REFUSAL, not escaping, and an earlier version of this module had that
 * wrong in a way that mattered. It escaped quotes and backslashes and passed CR and LF
 * straight through, which is a header-splitting primitive on any runtime that does not
 * itself reject them, and it emitted `\` bytes the spec forbids while claiming conformance.
 */
const CHALLENGE_VALUE = /^[\x20\x21\x23-\x5b\x5d-\x7e]*$/;

function challengeValue(value: string): string {
  if (!CHALLENGE_VALUE.test(value)) {
    throw new PrmConfigError('challenge_value_not_representable', value);
  }
  return value;
}

/**
 * Build a `WWW-Authenticate` value pointing at this resource's metadata.
 *
 * `resource_metadata` (RFC 9728 section 5.1) is what makes discovery work: a client that
 * receives it can fetch the document, learn the authorization server, and obtain a token
 * without being configured with any of that.
 *
 * A request with NO credentials gets a bare challenge with no `error`, per RFC 6750 section
 * 3.1: an error code there tells an unauthenticated caller that something about its absent
 * token was wrong.
 *
 * Parameter ORDER matches the crate (`resource_metadata` first). Order is not significant to
 * a conforming parser, but issue #127 asks for identical output from shared fixtures, and a
 * contract test cannot assert identity against a different order.
 */
export function protectedResourceChallenge(
  resource: ProtectedResource,
  options: ChallengeOptions = {},
): string {
  assertValidated(resource);
  const parameters = [`resource_metadata="${protectedResourceMetadataUrl(resource.resource)}"`];
  if (options.error) {
    parameters.push(`error="${challengeValue(options.error)}"`);
    if (options.errorDescription) {
      parameters.push(`error_description="${challengeValue(options.errorDescription)}"`);
    }
  } else if (options.errorDescription) {
    // Loud rather than silent. Dropping it quietly is a caller bug that never surfaces. Its
    // own code, because the value is perfectly representable and a log reader told otherwise
    // gets the wrong diagnosis.
    throw new PrmConfigError('error_description_without_an_error', options.errorDescription);
  }
  if (options.scope) {
    parameters.push(`scope="${challengeValue(options.scope)}"`);
  }
  return `Bearer ${parameters.join(', ')}`;
}

/** A ready-to-send challenge response. */
export interface ChallengeResponse {
  status: 401 | 403;
  headers: Record<string, string>;
}

/** The 401 for a request with no token, or one that failed validation. */
export function unauthorized(
  resource: ProtectedResource,
  options: Omit<ChallengeOptions, 'scope'> = {},
): ChallengeResponse {
  return {
    status: 401,
    headers: { 'WWW-Authenticate': protectedResourceChallenge(resource, options) },
  };
}

/** The 403 for a valid token that lacks the scope this endpoint needs. */
export function forbidden(
  resource: ProtectedResource,
  requiredScope: string,
): ChallengeResponse {
  // The scope is a PER-REQUEST input, so a value RFC 6750 forbids must not throw out of the
  // middleware and turn an intended 403 into a 500. The challenge is still correct without
  // the `scope` parameter, which is optional: the client learns it lacked scope, just not
  // which one, and that is a better answer than a server error.
  const advertisable = CHALLENGE_VALUE.test(requiredScope);
  return {
    status: 403,
    headers: {
      'WWW-Authenticate': protectedResourceChallenge(resource, {
        error: 'insufficient_scope',
        scope: advertisable ? requiredScope : undefined,
      }),
    },
  };
}

/** What the middleware answers with when it handles a request itself. */
export interface MiddlewareResponse {
  status: 200 | 401 | 403;
  headers: Record<string, string>;
  body?: string;
}

/**
 * The middleware itself: serve the document, or challenge.
 *
 * This is the part that makes the rest reachable. Given a request path and the result of
 * whatever token check the server already performs, it either serves the metadata document
 * at the well-known URL or returns the correct challenge, so a resource server does not
 * reimplement the URL rule, the cache headers, or the challenge format.
 *
 * Returns `null` when the request is not for the well-known path and the token was accepted,
 * which is the signal to carry on to the real handler.
 */
export function protectedResourceMiddleware(
  resource: ProtectedResource,
): (request: { path: string; outcome: 'ok' | 'no-token' | 'invalid-token' | { missingScope: string } }) => MiddlewareResponse | null {
  // SLICED from the composed URL, never parsed out of it. Deriving it through `new URL()` was
  // this module spending thirteen lines on why it does not compose through `URL`, and then
  // doing exactly that in the one function that decides which requests get the document.
  // `URL` still resolves dot segments and decodes `%2e`, so for an identifier containing
  // `..`, `.` or `%2e%2e` the challenge advertised a path this middleware then refused to
  // serve: the discovery chain dead-ending silently, produced inside the module written to
  // prevent that.
  const { scheme, authority } = splitResource(resource.resource);
  const wellKnownPath = protectedResourceMetadataUrl(resource.resource).slice(
    `${scheme}://${authority}`.length,
  );
  const body = JSON.stringify(protectedResourceMetadata(resource));
  return (request) => {
    if (request.path.replace(/\/+$/, '') === wellKnownPath.replace(/\/+$/, '')) {
      return {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': `public, max-age=${resource.maxAgeSeconds}`,
        },
        body,
      };
    }
    if (request.outcome === 'ok') {
      return null;
    }
    if (request.outcome === 'no-token') {
      return unauthorized(resource);
    }
    if (request.outcome === 'invalid-token') {
      return unauthorized(resource, { error: 'invalid_token' });
    }
    return forbidden(resource, request.outcome.missingScope);
  };
}
