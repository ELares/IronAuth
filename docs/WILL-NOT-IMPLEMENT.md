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
- **Excluded JOSE algorithms (detailed list lands with issue #8).** Why: the
  hardened JOSE core ships with a documented exclusion list (Ed448, ES512,
  RS1, alg none, RSA1_5, PBKDF2 JWE and peers): no ecosystem support, known
  attack classes, or doubled test matrix for zero demand. Instead: the
  supported matrix with EdDSA default (issue #9). Revisit: per-algorithm,
  with evidence of demand and safety.

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
