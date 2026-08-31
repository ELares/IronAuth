// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * Where the issuer's endpoints come from (issue #116).
 *
 * # Why this file exists
 *
 * This BFF used to build endpoints by string concatenation: `${issuer}/token`. Against IronAuth
 * that is simply wrong, and MEASURABLY so. An IronAuth issuer is per-environment and carries a
 * path:
 *
 * ```text
 * issuer          https://iss.example/t/ten_x/e/env_y
 * token_endpoint  https://iss.example/token
 * ```
 *
 * The endpoints are NOT under the issuer path. `${issuer}/token` resolves to
 * `.../e/env_y/token`, which answers 404. The old code could never have completed a login
 * against a real IronAuth, and nothing noticed because every test answered from a fake that
 * replied to any URL it was given.
 *
 * # The general rule, not the IronAuth special case
 *
 * RFC 8414 exists precisely because the relationship between an issuer and its endpoints is not
 * a string operation. Any deployment that mounts its OAuth surface on a different host, a
 * different path, or behind a gateway breaks concatenation, and IronAuth is only the case that
 * happened to be at hand. So this reads the document, and there is no fallback to concatenation:
 * a fallback would restore exactly the bug, quietly, for whoever the discovery fetch failed for.
 */

/** The endpoints this BFF uses, as the issuer publishes them. */
export interface IssuerMetadata {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
}

/** Cached per issuer, with the instant the entry stops being trusted. */
interface CacheEntry {
  metadata: IssuerMetadata;
  expiresAt: number;
}

const cache = new Map<string, CacheEntry>();

/**
 * How long a discovery document is reused.
 *
 * Long enough that a busy BFF is not refetching on every login, short enough that an endpoint
 * move takes effect within an hour without a redeploy. Deliberately NOT honouring
 * `Cache-Control` here: the JWKS cache in the verifier core does, because a key rotation has a
 * correctness deadline, while an endpoint move does not.
 */
const CACHE_SECONDS = 3600;

/** Clear the cache. For tests, and for a deployment that wants to force a refetch. */
export function forgetDiscovery(): void {
  cache.clear();
}

/**
 * Fetch (or reuse) the issuer's metadata.
 *
 * @throws if the document cannot be fetched, is not JSON, or names a different issuer
 */
export async function discover(
  issuer: string,
  fetchImpl: typeof fetch,
  now: () => number,
): Promise<IssuerMetadata> {
  const cached = cache.get(issuer);
  if (cached && cached.expiresAt > now()) {
    return cached.metadata;
  }

  const url = `${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`;
  const response = await fetchImpl(url, { headers: { accept: 'application/json' } });
  if (!response.ok) {
    throw new Error(`discovery at ${url} returned ${response.status}`);
  }
  const document = (await response.json()) as Record<string, unknown>;

  // The document must name the issuer we asked for (RFC 8414 section 3.3). Without this,
  // pointing the BFF at any URL yields a document naming a different issuer and endpoints to
  // match, and every later check passes against that attacker-chosen name.
  if (document.issuer !== issuer) {
    throw new Error(`discovery names issuer ${String(document.issuer)}, not ${issuer}`);
  }
  const authorizationEndpoint = document.authorization_endpoint;
  const tokenEndpoint = document.token_endpoint;
  if (typeof authorizationEndpoint !== 'string' || typeof tokenEndpoint !== 'string') {
    throw new Error('discovery is missing authorization_endpoint or token_endpoint');
  }

  const metadata: IssuerMetadata = { issuer, authorizationEndpoint, tokenEndpoint };
  cache.set(issuer, { metadata, expiresAt: now() + CACHE_SECONDS });
  return metadata;
}
