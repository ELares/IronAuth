// SPDX-License-Identifier: MIT OR Apache-2.0

// Access-token verification for a sample MCP resource server (issue #129).
//
// A resource server's whole job in the MCP authorization model is to decide whether THIS
// token was minted for THIS resource. The audience check below is therefore the load-bearing
// line: without it a token minted for another MCP server on the same authorization server
// verifies here just as well, which is precisely the cross-server replay the conformance
// bundle has to demonstrate is refused.

import { createPublicKey, verify as verifySignature } from "node:crypto";

/** Why a presented token was refused, in the terms RFC 6750 puts on the wire. */
export type Refusal =
  | { kind: "missing" }
  | { kind: "invalid_token"; description: string }
  | { kind: "insufficient_scope"; required: string };

/** A verified access token's claims, as far as this server reads them. */
export interface VerifiedToken {
  sub: string;
  aud: string[];
  scope: string[];
  iss: string;
  exp: number;
  raw: Record<string, unknown>;
}

/** One JSON Web Key, as the issuer's JWKS publishes it. */
interface Jwk {
  kty: string;
  kid?: string;
  crv?: string;
  x?: string;
  y?: string;
  n?: string;
  e?: string;
  alg?: string;
}

function base64UrlToBuffer(value: string): Buffer {
  return Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function decodeSegment(segment: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(base64UrlToBuffer(segment).toString("utf8"));
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("a JWT segment must be a JSON object");
  }
  return parsed as Record<string, unknown>;
}

/**
 * The `aud` claim as a list.
 *
 * RFC 9068 allows a single string or an array, and IronAuth emits the string form for a
 * single resource (byte-identical to the pre-resource-indicator wire shape). Treating only
 * the array form as valid would reject every single-audience token, which is the common case.
 */
function audienceList(claims: Record<string, unknown>): string[] {
  const aud = claims["aud"];
  if (typeof aud === "string") {
    return [aud];
  }
  if (Array.isArray(aud)) {
    return aud.filter((member): member is string => typeof member === "string");
  }
  return [];
}

function scopeList(claims: Record<string, unknown>): string[] {
  const scope = claims["scope"];
  return typeof scope === "string" ? scope.split(" ").filter(Boolean) : [];
}

/** Import one JWKS key as a verifier. Only the algorithms IronAuth signs with. */
function importKey(jwk: Jwk): { key: ReturnType<typeof createPublicKey>; alg: string } | null {
  if (jwk.kty === "OKP" && jwk.crv === "Ed25519" && jwk.x) {
    return {
      key: createPublicKey({ key: jwk as never, format: "jwk" }),
      alg: "EdDSA",
    };
  }
  // ES256 is P-256 AND NOTHING ELSE (RFC 7518 section 3.4). Accepting any EC curve would
  // let a P-384 or secp256k1 key verify under an `alg` of ES256, which is an algorithm the
  // key was never issued for.
  if (jwk.kty === "EC" && jwk.crv === "P-256" && jwk.x && jwk.y !== undefined) {
    return { key: createPublicKey({ key: jwk as never, format: "jwk" }), alg: "ES256" };
  }
  if (jwk.kty === "RSA" && jwk.n && jwk.e) {
    return { key: createPublicKey({ key: jwk as never, format: "jwk" }), alg: "RS256" };
  }
  return null;
}

/**
 * Verify `token` for `resource`.
 *
 * Checks, in order: the JWT parses; its `typ` is `at+jwt` (RFC 9068, so an ID token cannot be
 * presented as an access token); the signature verifies against the issuer's published JWKS;
 * it has not expired; the issuer matches; and the AUDIENCE contains this resource.
 */
export async function verifyAccessToken(
  token: string,
  options: { issuer: string; jwks: { keys: Jwk[] }; resource: string; now?: number },
): Promise<VerifiedToken | Refusal> {
  const parts = token.split(".");
  if (parts.length !== 3) {
    return { kind: "invalid_token", description: "the credential is not a JWT" };
  }
  let header: Record<string, unknown>;
  let claims: Record<string, unknown>;
  try {
    header = decodeSegment(parts[0]!);
    claims = decodeSegment(parts[1]!);
  } catch {
    return { kind: "invalid_token", description: "the credential does not decode" };
  }

  // RFC 9068 section 4: an access token is typed. Without this an ID token, which the same
  // issuer signs with the same key, is accepted as an access token.
  if (header["typ"] !== "at+jwt") {
    return { kind: "invalid_token", description: "not an at+jwt access token" };
  }

  const kid = typeof header["kid"] === "string" ? header["kid"] : undefined;
  const candidates = options.jwks.keys.filter((key) => kid === undefined || key.kid === kid);
  const signed = Buffer.from(`${parts[0]}.${parts[1]}`, "utf8");
  const signature = base64UrlToBuffer(parts[2]!);
  const verified = candidates.some((jwk) => {
    const imported = importKey(jwk);
    if (imported === null || imported.alg !== header["alg"]) {
      return false;
    }
    const digest = imported.alg === "EdDSA" ? null : imported.alg === "ES256" ? "sha256" : "sha256";
    try {
      return verifySignature(
        digest,
        signed,
        imported.alg === "ES256" ? { key: imported.key, dsaEncoding: "ieee-p1363" } : imported.key,
        signature,
      );
    } catch {
      return false;
    }
  });
  if (!verified) {
    return { kind: "invalid_token", description: "the signature does not verify" };
  }

  const now = options.now ?? Math.floor(Date.now() / 1000);
  const exp = typeof claims["exp"] === "number" ? claims["exp"] : 0;
  if (exp <= now) {
    return { kind: "invalid_token", description: "the credential has expired" };
  }
  if (claims["iss"] !== options.issuer) {
    return { kind: "invalid_token", description: "issued by another authorization server" };
  }

  // THE AUDIENCE CHECK. A token minted for a different MCP server on this same authorization
  // server verifies every check above: same issuer, same signing key, same type, unexpired.
  // Only this line separates them, which is why the conformance bundle drives it directly.
  const aud = audienceList(claims);
  if (!aud.includes(options.resource)) {
    return { kind: "invalid_token", description: "the credential is for another resource" };
  }

  return {
    sub: typeof claims["sub"] === "string" ? claims["sub"] : "",
    aud,
    scope: scopeList(claims),
    iss: options.issuer,
    exp,
    raw: claims,
  };
}
