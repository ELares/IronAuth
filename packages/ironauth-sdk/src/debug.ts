// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * The JWT debugger's diagnosis engine (issue #123).
 *
 * > The JWT debugger correctly diagnoses at least: valid token, expired, wrong issuer, unknown
 * > kid, and disallowed alg.
 *
 * Paste a token, see what it says and why it was refused. The hard part is not decoding -- every
 * JWT debugger on the web decodes -- it is saying something an integrator can ACT on when the
 * answer is no.
 *
 * ## It calls the real verifier, and that is the design
 *
 * `diagnose` decodes for display and then hands the token to {@link verifyToken}. It does not
 * reimplement a single check.
 *
 * A debugger with its own opinion of why a token failed is worse than no debugger: it tells you
 * one thing while your resource server does another, and you spend the afternoon fixing the
 * wrong end. Where the two could disagree, this one is defined to agree, because the verdict
 * IS the verifier's.
 *
 * The consequence is that the diagnosis can only ever be as specific as `VerifyFailureReason`,
 * which is deliberate. The extra value this adds is not a finer verdict; it is the CONTEXT
 * around the same verdict -- what the token said, what the issuer publishes, and what to change.
 *
 * ## Nothing here is a security boundary
 *
 * This runs against a token someone pasted into a tool. It grants nothing and authorizes
 * nothing. The one property it must have is that a token it calls valid is one the verifier
 * calls valid, which the delegation gives by construction.
 */

import { JwksCache, VerifyError, type VerifyFailureReason, verifyToken } from './verify.js';

/** What the debugger found. */
export interface Diagnosis {
  /** Whether the token verified against the chosen environment. */
  readonly valid: boolean;
  /** The decoded header, or `undefined` when the token is not decodable at all. */
  readonly header?: Record<string, unknown>;
  /** The decoded claims, or `undefined`. */
  readonly claims?: Record<string, unknown>;
  /** The verifier's own reason, when it refused. */
  readonly reason?: VerifyFailureReason;
  /** One sentence naming what is wrong. */
  readonly summary: string;
  /**
   * What to change, in the reader's own configuration.
   *
   * Separate from `summary` because they answer different questions -- "what happened" and "what
   * do I do" -- and a tool that only answers the first is a tool that sends people to the
   * forums.
   */
  readonly fix?: string;
  /** Facts worth showing beside the verdict, each already rendered. */
  readonly observations: readonly string[];
}

/** What the debugger is checking the token against. */
export interface DiagnoseOptions {
  /** The issuer the token must name. */
  readonly issuer: string;
  /** The audience it must carry. */
  readonly audience: string;
  /** The algorithms the issuer publishes. */
  readonly algorithms: readonly string[];
  /** The environment's key set. */
  readonly keys: JwksCache;
  /** Epoch seconds. Injectable so a test can pin the whole lifetime. */
  readonly now?: () => number;
  /** Tolerated skew, in seconds. */
  readonly skewSeconds?: number;
}

/** base64url-decode one segment into JSON, or `undefined`. */
function decodeSegment(segment: string | undefined): Record<string, unknown> | undefined {
  if (segment === undefined) {
    return undefined;
  }
  try {
    const padded = segment.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

/** Render an epoch-seconds claim, or `undefined` when it is not one. */
function instant(claims: Record<string, unknown> | undefined, name: string): string | undefined {
  const value = claims?.[name];
  if (typeof value !== 'number') {
    return undefined;
  }
  return `${name}: ${value} (${new Date(value * 1000).toISOString()})`;
}

/**
 * Diagnose a token.
 *
 * Never throws: a debugger that throws on a malformed token is a debugger that fails exactly
 * when it is most needed, because malformed is one of the things a person is trying to find out.
 */
export async function diagnose(token: string, options: DiagnoseOptions): Promise<Diagnosis> {
  const segments = token.trim().split('.');
  // DECODED FIRST, and shown even when the verdict is a refusal. Someone debugging a rejected
  // token needs to see what it claimed; withholding the header until it verifies would hide the
  // one thing that explains a `kid` or `alg` problem.
  const header = decodeSegment(segments[0]);
  const claims = decodeSegment(segments[1]);
  const observations: string[] = [];
  if (typeof header?.alg === 'string') {
    observations.push(`alg: ${header.alg}`);
  }
  if (typeof header?.kid === 'string') {
    observations.push(`kid: ${header.kid}`);
  }
  if (typeof claims?.iss === 'string') {
    observations.push(`iss: ${claims.iss}`);
  }
  const audiences = claims?.aud;
  if (typeof audiences === 'string') {
    observations.push(`aud: ${audiences}`);
  } else if (Array.isArray(audiences)) {
    observations.push(`aud: [${audiences.join(', ')}]`);
  }
  for (const name of ['iat', 'nbf', 'exp']) {
    const rendered = instant(claims, name);
    if (rendered !== undefined) {
      observations.push(rendered);
    }
  }

  try {
    const verified = await verifyToken(token, options.keys, {
      issuer: options.issuer,
      audience: options.audience,
      algorithms: options.algorithms,
      now: options.now,
      skewSeconds: options.skewSeconds,
    });
    return {
      valid: true,
      header: verified.header,
      claims: verified.claims,
      summary: 'The token verifies against this environment.',
      observations,
    };
  } catch (error) {
    const reason = error instanceof VerifyError ? error.reason : undefined;
    const { summary, fix } = explain(reason, header, claims, options);
    return { valid: false, header, claims, reason, summary, fix, observations };
  }
}

/**
 * Turn a refusal into a sentence and a next action.
 *
 * The match is EXHAUSTIVE over `VerifyFailureReason` with no default arm, so a reason added to
 * the verifier stops this file compiling until somebody writes what it means. A default arm
 * would render the newest and least understood failure as the vaguest message, which is the
 * opposite of useful.
 */
function explain(
  reason: VerifyFailureReason | undefined,
  header: Record<string, unknown> | undefined,
  claims: Record<string, unknown> | undefined,
  options: DiagnoseOptions,
): { summary: string; fix?: string } {
  const alg = typeof header?.alg === 'string' ? header.alg : '(absent)';
  const kid = typeof header?.kid === 'string' ? header.kid : '(absent)';
  const iss = typeof claims?.iss === 'string' ? claims.iss : '(absent)';
  switch (reason) {
    case 'malformed':
      return {
        summary: 'This is not a well-formed JWS: it needs three base64url segments of JSON.',
        fix: 'Check for a truncated copy-paste, a missing segment, or a JWE (five segments), which this verifier does not accept.',
      };
    case 'algorithm_not_allowed':
      return {
        summary: `The token is signed with ${alg}, which this issuer does not publish.`,
        // NAMES BOTH SIDES. "Algorithm not allowed" alone leaves the reader to guess whether
        // their token or their configuration is wrong, and it is usually the configuration.
        fix: `This environment publishes ${options.algorithms.join(', ')}. Either the token came from a different issuer, or the verifier's algorithm list is narrower than what the issuer actually signs with.`,
      };
    case 'unknown_key':
      return {
        summary: `No published key matches this token's kid (${kid}).`,
        fix: 'Usually a rotation the verifier has not refetched, or a token minted by a different environment. Refetch the JWKS; if the kid still is not there, check the issuer.',
      };
    case 'bad_signature':
      return {
        summary: 'The signature does not verify under the key this token names.',
        fix: 'The token was altered after signing, or it was signed by a key that is published but is not the one it names. Neither is a configuration problem on the verifying side.',
      };
    case 'wrong_issuer':
      return {
        summary: `The token names ${iss}, and this environment expects ${options.issuer}.`,
        fix: 'IronAuth issuers are per environment, so this is almost always a token from staging checked against production or the reverse.',
      };
    case 'wrong_audience':
      return {
        summary: `The token's audience does not include ${options.audience}.`,
        fix: "Check the client id or resource identifier the token was minted for. A token is valid only for the audience it names.",
      };
    case 'expired':
      return {
        summary: 'The token has expired.',
        fix: 'Mint a fresh one. If it looks recent, compare the exp above against this machine’s clock: a verifier whose clock is ahead rejects tokens that are still valid.',
      };
    case 'not_yet_valid':
      return {
        summary: 'The token is not valid yet: its nbf is in the future.',
        fix: 'Almost always clock skew between the minting host and this one. Compare the nbf above against this machine’s clock.',
      };
    case undefined:
      return {
        summary: 'Verification failed for a reason this tool does not recognise.',
        fix: 'This should not happen. It means something other than the verifier threw.',
      };
  }
}
