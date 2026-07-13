# Will Not Implement, and Why

Deliberate refusals, published with reasons. A documented refusal list builds
more trust than silent absence: it tells integrators what to never wait for,
and it forces us to argue each refusal from evidence. Entries follow a fixed
format so refusals stay falsifiable.

Entry format:

- **What**: the feature or mechanism refused.
- **Why**: the evidence-based reason (attack class, ecosystem failure, dead
  spec, or scope trap), with citations where they exist.
- **Instead**: what IronAuth does in its place, if anything.
- **Revisit trigger**: the concrete condition under which the refusal would
  be reconsidered, or "none planned".

Two lists exist. Refused items have no planned path. Deferred items (kept in
the issue tracker, not here) have explicit triggers and stated shapes, for
example the SAML IdP role, which is deferred with a hostile-parser
precondition rather than refused; see issue #138 and the M14 milestone.

## Refused: protocol surface

- **Resource owner password credentials (ROPC), implicit access-token
  issuance, plain PKCE.** Why: codified anti-patterns per RFC 9700 and their
  removal in OAuth 2.1; a greenfield server has no migration excuse.
  Instead: authorization code with PKCE S256 everywhere. Revisit: none
  planned.
- **Wildcard or substring redirect URI matching.** Why: a recurring CVE class
  across the ecosystem; exactness is the only safe comparison. Instead:
  exact-string matching with the RFC 8252 loopback port exception. Revisit:
  none planned.
- **CIBA push mode.** Why: weakest security properties of the three CIBA
  modes and forbidden by the FAPI-CIBA profile; effectively uncertifiable.
  Instead: CIBA poll and ping (M13). Revisit: none planned.
- **Session Management iframe and Front-Channel Logout as real features.**
  Why: dependent on third-party cookies, which are blocked in every major
  browser; unreliable by construction in 2026. Instead: RP-initiated logout
  plus back-channel logout as the reliable pair; the iframe specs exist only
  as disabled-by-default certification flags (issue #39). Revisit: a browser
  reversal on third-party cookie blocking.
- **WebFinger issuer discovery.** Why: required by spec text, deployed by
  effectively nobody, irrelevant to how issuers are discovered in practice.
  Instead: documented discovery endpoints. Revisit: demonstrated ecosystem
  demand.
- **Aggregated and distributed claims.** Why: implemented by effectively one
  vendor; no interop ecosystem exists. Instead: claim_types_supported
  advertises normal claims only. Revisit: a real relying-party ecosystem
  appears.
- **UMA 2.0 and permission-ticket authorization services.** Why: one
  mainstream implementation exists and deviates from spec; interop energy
  moved to AuthZEN, which IronAuth ships instead (issue #100). Revisit: none
  planned.
- **SIOPv2.** Why: stagnant Implementer's Draft; the wallet ecosystem
  consolidated on OID4VP plus the browser Digital Credentials API. Instead:
  the OID4VC exploratory track (issue #164). Revisit: spec revival with
  deployments.
## Refused: JOSE algorithms

The hardened JOSE verification core (issue #8, `crates/ironauth-jose`, ADR 0004)
verifies exactly EdDSA (Ed25519), ES256/ES384, RS256/RS384/RS512, and
PS256/PS384/PS512, all backed by `ring`. Everything below is refused with cause.
Instead of these, IronAuth ships the supported matrix above with the EdDSA
default (issue #9). Each entry is revisitable only per-algorithm, with evidence
of real demand AND safety.

- **`alg: none` (unsecured JWS).** Why: an unauthenticated token is a forgery by
  construction; acceptance is the single most repeated JOSE CVE, and
  node-oidc-provider v9 removed it entirely with the ecosystem following.
  Instead: always rejected, in every case and whitespace variant, with no
  configuration to enable it, INCLUDING the OIDC Core code-flow-permitted
  variant. Revisit: never.
- **HMAC (`HS256`/`HS384`/`HS512`) in the verify core.** Why: a symmetric verify
  path next to asymmetric keys is exactly what enables RS/HS key confusion
  (verifying an `RS256` token as `HS256` with the RSA public key as the secret).
  Omitting HMAC makes that confusion inexpressible, not merely blocked. Instead:
  asymmetric verification only; the key-family check rejects any algorithm whose
  type does not match the trusted key. Revisit: never for the public-token verify
  core.
- **Ed448.** Why: no WebCrypto, Tink, or .NET support; it doubles the curve and
  test matrix for effectively zero relying-party demand. Instead: Ed25519 as the
  EdDSA default. Revisit: broad platform support plus demonstrated demand.
- **ES512 (ECDSA P-521).** Why: absent from `ring`; supporting it would force a
  second crypto backend into the tree, widening the trusted surface for a rarely
  used curve. Instead: ES256 and ES384. Revisit: a `ring` implementation, or
  demand that justifies a second vetted backend.
- **RS1 / RSA-SHA1 and any SHA-1 JWS.** Why: SHA-1 is a broken hash with
  practical collisions; a signature over it is not a security control. Instead:
  the SHA-256/384/512 RSA families. Revisit: never.
- **RSA1_5 (RSAES-PKCS1-v1_5 key encryption).** Why: the Bleichenbacher padding-
  oracle class, repeatedly re-exploited (ROBOT and successors); unsafe to offer
  even with countermeasures. Instead: no JWE key-management via RSA1_5. Revisit:
  never.
- **PBES2 / PBKDF2-based JWE (`PBES2-HS256+A128KW` and peers).** Why: a password-
  derived key-encryption whose iteration count (`p2c`) is an attacker-controlled
  work multiplier (a decompression-bomb cousin); wrong primitive for machine-to-
  machine tokens. Instead: rejected at the cap/parse stage before any derivation;
  the iteration cap bounds the cheap rejection. Revisit: none planned.
- **Compressed JWS/JWE (`zip`).** Why: the decompression-bomb class; a small
  token can inflate to exhaust memory. Instead: `zip` is rejected at the header
  stage before anything is inflated; a decompression-ratio cap is carried for any
  future compression path. Revisit: a concrete need with a hard ratio cap.

The exclusions are enforced by the core itself (unsupported algorithms never
parse to a supported one; `none`, HMAC, `zip`, PBES2, and in-token key material
are explicit rejects) and by property tests over the CVE regression corpus.

## Refused: architecture and scope

- **A Zanzibar/ReBAC engine in core.** Why: the specialist engines spent
  years fixing their own correctness; identity work would starve. Instead:
  first-class orgs, groups, roles, and permissions, an AuthZEN evaluation
  endpoint, and an ordered change feed for external FGA systems (M10).
  Revisit: none planned.
- **An event-sourced primary store, embedded consensus fabric, or
  microservice decomposition.** Why: each is a named incumbent's documented
  architectural wall. Instead: stateless binary, PostgreSQL as the sole
  source of truth behind a clean seam, optional accelerators. Revisit: none
  planned.
- **Multi-database support.** Why: a second engine costs more than it
  returns, as demonstrated by an incumbent's public retreat from exactly
  this. Instead: PostgreSQL only. Revisit: none planned.
- **Mandatory IronCache or IronBus.** Why: covenant; self-hosters count
  containers, and optionality is enforced by dual-mode CI. Instead:
  Postgres-only default with optional accelerators. Revisit: never.
- **In-process native plugin APIs and embedded JS interpreters.** Why: the
  upgrade tax of in-process plugin ABIs and the abandonment history of
  embedded JS runtimes in this field; both put third-party code inside the
  trust boundary without a version-stable contract. Instead: declarative
  claims mapping, signed HTTP targets, and WASM component hooks with a
  versioned ABI (M11). Revisit: none planned.
- **A GUI-first flow builder as the source of truth.** Why: exported-config
  fights and abandoned visual builders are the documented failure mode; flows
  must be versionable, diffable text. Instead: code-first flow orchestration;
  a visual editor may project over the text later (M9). Revisit: none
  planned.
- **Full IGA, PAM, and session recording.** Why: each is an entire product
  category; scope traps with IdP blast radius. Instead: be the best IGA data
  source via entitlement and grant export (M14). Revisit: none planned.
- **Billing, payments, ticketing, and website certificate management inside
  the IdP.** Why: every extra subsystem in the trust boundary is attack
  surface with IdP blast radius. Instead: clean APIs and events for external
  systems. Revisit: none planned.
- **First-party push-MFA app (v1), in-house identity verification, hard
  third-party CAPTCHA dependency, default-on SMS OTP.** Why: an app fleet,
  a compliance business, an availability dependency, and a NIST-restricted
  fraud channel respectively. Instead: passkeys as the phishing-resistant
  factor; IDV via integration; proof-of-work with CAPTCHA adapters; SMS off
  by default behind guardrails (M7, M8). Revisit: push MFA only with number
  matching if ever built.

## Deferred, tracked in the issue tracker (not refusals)

SAML IdP outbound (#138 precondition harness), WS-Fed, Kerberos, RADIUS and
CAS facades, FAPI 1.0 Advanced, Grant Management API, the Kubernetes
operator, LDAP write-back, and the strategic 2027 bets (post-quantum, DBSC,
OpenID Federation, OID4VC/HAIP) all carry explicit triggers in their issues
and the Non-Goals section of the planning corpus. They are absent from this
page because they have a planned path.
