// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The TypeScript `token.customize` hook, issue #114 criterion 1.
//
// This is a SAMPLE and it is also the fixture the integration suite runs, deliberately the
// same artifact. A sample that is not executed rots into a snippet that no longer compiles,
// and a fixture that is not the sample proves nothing about what a tenant would actually
// ship. So this file is both, and the cost is that it carries test modes a pure sample
// would not: see `TEST_MODE_CLAIM` below.

/** One claim, crossing the boundary as a name and its JSON encoding. */
interface Claim {
  /** The claim name. Reserved names are fenced by the HOST on the way back in. */
  name: string;
  /** The value, JSON-encoded. Text that is not valid JSON has the claim refused. */
  valueJson: string;
}

/** What the host hands the hook for one token issuance. Mirrors the WIT `request` record. */
interface Request {
  payloadVersion: number;
  grantType: string;
  clientId: string;
  subject?: string;
  idTokenClaims: Claim[];
  accessTokenClaims: Claim[];
}

/** What the hook hands back. The FULL claim set, never a delta. */
interface Response {
  idTokenClaims: Claim[];
  accessTokenClaims: Claim[];
}

// jco lowers a WIT `result<response, string>` to "return the ok value, throw for the error".
// The thrown value is the error payload, so a deliberate decline throws a string and is
// distinct from a trap, which is what a runtime TypeError would become.
type Customize = (req: Request) => Response;

/**
 * The claim that switches this hook into a test mode.
 *
 * A hook cannot take arguments beyond its request, and the integration suite needs a guest
 * that spins and one that declines. Building three TypeScript components would put three
 * copies of an eleven-megabyte JavaScript engine in the repository, so instead there is one
 * component and the suite selects a behaviour through an ordinary input claim.
 *
 * The mode is read from the ID-token claim set, and the claim is REMOVED from the output, so
 * the sample path is unaffected by its existence.
 */
const TEST_MODE_CLAIM = "ironauth_ts_hook_mode";

/** The claim the sample adds, and the thing criterion 1 is actually about. */
const SAMPLE_CLAIM = "ts_hook_tier";

function findMode(claims: Claim[]): string | undefined {
  const hit = claims.find((c) => c.name === TEST_MODE_CLAIM);
  if (hit === undefined) {
    return undefined;
  }
  // The value is JSON, so a mode of `spin` arrives as `"spin"` with the quotes.
  const parsed: unknown = JSON.parse(hit.valueJson);
  return typeof parsed === "string" ? parsed : undefined;
}

function withoutMode(claims: Claim[]): Claim[] {
  return claims.filter((c) => c.name !== TEST_MODE_CLAIM);
}

/**
 * Derive the tier from the request.
 *
 * Deliberately reads three DIFFERENT request fields -- the grant type, the client, and whether
 * a subject is present. A hook that echoed one field would leave a transport bug that dropped
 * the other two invisible, which is the same reason the Rust suite populates both claim sets.
 */
function tierFor(req: Request): string {
  if (req.subject === undefined) {
    return `service:${req.clientId}`;
  }
  return `${req.grantType}:${req.clientId}`;
}

export const tokenCustomize: { customize: Customize } = {
  customize(req: Request): Response {
    switch (findMode(req.idTokenClaims)) {
      case "spin":
        // Unreachable exit. Fuel counts the instructions, so this is what criterion 3's
        // abort has to stop -- in a JavaScript engine rather than in compiled Rust.
        for (;;) {
          /* intentionally empty */
        }
      case "decline":
        // The `err` arm of the WIT result: a deliberate refusal with a reason, which the host
        // logs and applies the per-hook failure policy to. NOT a trap.
        throw "the TypeScript sample declined on purpose";
      // There is deliberately NO mode that returns a reserved claim. One was written, to
      // "prove the fence applies to a TypeScript hook too", and nothing ran it -- so it was
      // undocumented behaviour sitting inside an eleven-megabyte artifact tenants are told to
      // copy, and the freshness check could not police it either. The fence operates on the
      // returned claim LIST and cannot see what language produced it; `claim_forger` in
      // ../guests already exercises it. A second copy in another language tests the same host
      // code twice and the guest not at all.
      default:
        break;
    }

    const idTokenClaims = withoutMode(req.idTokenClaims);
    idTokenClaims.push({
      name: SAMPLE_CLAIM,
      valueJson: JSON.stringify(tierFor(req)),
    });
    return {
      idTokenClaims,
      // Echoed unchanged, so a transport that dropped the access-token half would be caught by
      // the same invocation that proves the ID-token half works.
      accessTokenClaims: withoutMode(req.accessTokenClaims),
    };
  },
};
