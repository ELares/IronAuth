/**
 * Protected-resource middleware helpers (issue #127, RFC 9728).
 *
 * Two jobs, and both are things every resource server otherwise reimplements slightly wrong.
 *
 * It builds the `WWW-Authenticate` challenge that points a client at this resource's metadata
 * document, which is the whole discovery chain: a client that gets a 401 with a
 * `resource_metadata` parameter can find the authorization server without being told out of
 * band. And it refuses, at startup, a configuration whose advertised resource identifier
 * disagrees with the audience the server actually enforces, because that combination sends
 * clients to obtain tokens this server will then reject.
 *
 * The rules here MIRROR `crates/ironauth-oidc/src/prm.rs` deliberately, including the
 * refusal reasons. A resource server built on this SDK and one built on the Rust crate must
 * publish at the same URL and refuse the same configurations, or the discovery chain works
 * against one and not the other.
 */

/** Why a protected-resource configuration was refused. Mirrors `PrmConfigError`. */
export type PrmConfigErrorCode =
  | 'resource_not_absolute'
  | 'resource_has_query_or_fragment'
  | 'no_authorization_servers'
  | 'issuer_not_absolute'
  | 'resource_audience_mismatch';

/**
 * A refused configuration.
 *
 * Distinct codes because an operator fixes each one differently, and a single "invalid
 * configuration" would put the diagnosis back on whoever reads the log. No configured value
 * is echoed in `message`, so it can be logged without deciding whether the value was
 * sensitive; the offending value is on `value` for a caller that has already decided.
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
  no_authorization_servers:
    'at least one authorization server issuer must be listed',
  issuer_not_absolute: 'every authorization server issuer must be an absolute URI',
  resource_audience_mismatch:
    'the advertised resource identifier and the enforced audience must be the same value',
};

/** What a resource server publishes and enforces. */
export interface ProtectedResourceConfig {
  /** The resource identifier this server publishes, an absolute URI with no query or fragment. */
  resource: string;
  /** The issuers whose tokens this server accepts. At least one. */
  authorizationServers: string[];
  /**
   * The audience this server actually enforces when validating a token.
   *
   * Defaults to `resource`. Supplying a DIFFERENT value is the misconfiguration this module
   * exists to refuse: discovery would send clients to obtain a token for one value while the
   * server rejects anything that does not carry the other.
   */
  enforcedAudience?: string;
  /** Optional, advertised only when non-empty. */
  scopesSupported?: string[];
  /** Optional, advertised only when non-empty. Defaults to advertising nothing. */
  bearerMethodsSupported?: string[];
}

const WELL_KNOWN = '/.well-known/oauth-protected-resource';

/**
 * The URL at which `resource`'s metadata is published.
 *
 * The well-known segment is INSERTED between the authority and the path, not appended to the
 * end. A resource identified as `https://api.example/v1/mcp` publishes at
 * `https://api.example/.well-known/oauth-protected-resource/v1/mcp`. Appending instead is the
 * common mistake and it is invisible for a path-less identifier, which is exactly why it
 * survives into production: both spellings agree until the first resource with a path.
 */
export function protectedResourceMetadataUrl(resource: string): string {
  const parsed = parseResource(resource);
  const path = parsed.pathname === '/' ? '' : parsed.pathname.replace(/\/$/, '');
  return `${parsed.origin}${WELL_KNOWN}${path}`;
}

function parseResource(resource: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(resource);
  } catch {
    throw new PrmConfigError('resource_not_absolute', resource);
  }
  if (!parsed.protocol || !parsed.host) {
    throw new PrmConfigError('resource_not_absolute', resource);
  }
  if (parsed.search || parsed.hash) {
    throw new PrmConfigError('resource_has_query_or_fragment', resource);
  }
  return parsed;
}

/**
 * Validate a configuration and return it normalised, or throw.
 *
 * Called at STARTUP rather than per request, deliberately. A resource server whose advertised
 * identifier and enforced audience disagree is broken for every client, and finding that out
 * on the first 401 means finding it out in production.
 */
export function defineProtectedResource(
  config: ProtectedResourceConfig,
): Required<Pick<ProtectedResourceConfig, 'resource' | 'authorizationServers' | 'enforcedAudience'>> &
  ProtectedResourceConfig {
  parseResource(config.resource);
  if (config.authorizationServers.length === 0) {
    throw new PrmConfigError('no_authorization_servers');
  }
  for (const issuer of config.authorizationServers) {
    let parsed: URL;
    try {
      parsed = new URL(issuer);
    } catch {
      throw new PrmConfigError('issuer_not_absolute', issuer);
    }
    if (!parsed.protocol || !parsed.host) {
      throw new PrmConfigError('issuer_not_absolute', issuer);
    }
  }
  const enforcedAudience = config.enforcedAudience ?? config.resource;
  if (enforcedAudience !== config.resource) {
    throw new PrmConfigError('resource_audience_mismatch', enforcedAudience);
  }
  return { ...config, enforcedAudience };
}

/** The metadata document for a validated configuration, per RFC 9728 section 2. */
export function protectedResourceMetadata(
  config: ProtectedResourceConfig,
): Record<string, unknown> {
  const checked = defineProtectedResource(config);
  const document: Record<string, unknown> = {
    resource: checked.resource,
    authorization_servers: [...checked.authorizationServers],
  };
  // Absent rather than empty: an empty array advertises "supports none", which is a different
  // claim from "does not say", and the server crate makes the same distinction.
  if (checked.scopesSupported?.length) {
    document.scopes_supported = [...checked.scopesSupported];
  }
  if (checked.bearerMethodsSupported?.length) {
    document.bearer_methods_supported = [...checked.bearerMethodsSupported];
  }
  return document;
}

/** An RFC 6750 error code a challenge may carry. */
export type ChallengeError = 'invalid_token' | 'insufficient_scope';

export interface ChallengeOptions {
  /** Omitted on a bare 401, which is the correct answer to a request with no credentials. */
  error?: ChallengeError;
  /** Human-readable, optional, and never a place to put a token or a claim value. */
  errorDescription?: string;
  /** Advertised on a 403 so the client knows what to ask for. */
  scope?: string;
}

/**
 * Build a `WWW-Authenticate` value pointing at this resource's metadata.
 *
 * `resource_metadata` is the parameter that makes discovery work (RFC 9728 section 5.1): a
 * client that receives it can fetch the document, learn the authorization server, and obtain
 * a token, without being configured with any of that in advance.
 *
 * A request with NO credentials gets a bare challenge with no `error`, per RFC 6750 section
 * 3: an `error` code there would tell an unauthenticated caller that something about its
 * absent token was wrong.
 */
export function protectedResourceChallenge(
  config: ProtectedResourceConfig,
  options: ChallengeOptions = {},
): string {
  const metadataUrl = protectedResourceMetadataUrl(config.resource);
  const parameters: string[] = [`resource_metadata="${quote(metadataUrl)}"`];
  if (options.error) {
    parameters.unshift(`error="${quote(options.error)}"`);
    if (options.errorDescription) {
      parameters.splice(1, 0, `error_description="${quote(options.errorDescription)}"`);
    }
  }
  if (options.scope) {
    parameters.push(`scope="${quote(options.scope)}"`);
  }
  return `Bearer ${parameters.join(', ')}`;
}

/**
 * Escape a quoted-string parameter value per RFC 9110 section 5.6.4.
 *
 * A backslash or a double quote in a value would otherwise end the parameter early and let a
 * configured string inject another one.
 */
function quote(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

/** A ready-to-send challenge response. */
export interface ChallengeResponse {
  status: 401 | 403;
  headers: Record<string, string>;
}

/** The 401 for a request with no token, or one that failed validation. */
export function unauthorized(
  config: ProtectedResourceConfig,
  options: Omit<ChallengeOptions, 'scope'> = {},
): ChallengeResponse {
  return {
    status: 401,
    headers: { 'WWW-Authenticate': protectedResourceChallenge(config, options) },
  };
}

/** The 403 for a valid token that lacks the scope this endpoint needs. */
export function forbidden(
  config: ProtectedResourceConfig,
  requiredScope: string,
): ChallengeResponse {
  return {
    status: 403,
    headers: {
      'WWW-Authenticate': protectedResourceChallenge(config, {
        error: 'insufficient_scope',
        scope: requiredScope,
      }),
    },
  };
}
