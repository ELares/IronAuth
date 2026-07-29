# IronAuth Threat Model

Per-surface STRIDE analysis. This document is a merge-gated artifact: no new
surface merges without its section landing in the same pull request, and CI
enforces the rule via the PR checklist for changes labeled as new surfaces.
The method follows the FAPI 2.0 attacker-model discipline: name the attacker
capabilities first, then show the structural control that defeats each threat,
or the tracked issue that will land it.

## Surfaces shipped today

As of milestone M1, the shipped surfaces are the repository and release
infrastructure, the HTTP server skeleton (dual-plane listener, observability, log
scrubbing, and the trusted-proxy policy), the persistence and tenant-isolation
substrate, the outbound fetcher, and the OpenAPI-first management API skeleton.
The protocol endpoints arrive in M2. The remaining sections are forward-looking:
they model the surfaces the later M1 and M2 issues are about to ship, so that
every implementation PR lands into an existing threat frame rather than inventing
one after the fact. Each mitigation cell cites the issue that owns it; a cell
without a citation is shipped.

## Attacker model

We assume: a network attacker who can read and inject traffic on untrusted
segments (defeated by TLS everywhere); a web attacker who can run script on
origins other than ours and lure users (the OAuth/OIDC attacker); a malicious
or compromised relying party; a malicious tenant attacking the platform or a
sibling tenant; and a curious-but-honest operator who must be auditable. We
do not assume a compromised host OS or hypervisor.

## Surface: repository and release infrastructure (shipped)

| STRIDE | Threat | Control |
|---|---|---|
| Spoofing | Impersonated release artifacts | Cosign keyless signing plus GitHub build provenance attestations on binary and image |
| Tampering | Dependency or action supply-chain injection | Committed lockfile, cargo-deny (sources restricted to crates.io), dependabot, OpenSSF Scorecard |
| Repudiation | Untraceable changes to main | Branch protection: PR-only, review required, linear history |
| Information disclosure | Secrets in repo or logs | GitHub secret scanning plus push protection enabled; no secrets in CI beyond GITHUB_TOKEN |
| Denial of service | CI-lane rot blocking releases | Job timeouts; per-artifact release lanes are independent |
| Elevation | Workflow permission escalation | Least-privilege per-job permissions; default contents: read |

## Surface: HTTP server skeleton (shipped)

The properties below are structural: they exist before any protocol endpoint,
so every later surface inherits them. Cells without a citation are shipped by
the skeleton; later issues extend, never weaken, them.

| STRIDE | Threat | Control |
|---|---|---|
| Spoofing | Forged `Forwarded`/`X-Forwarded-*`/`Host` to move the issuer, scheme, or client IP (the Zitadel forwarded-header account-takeover class) | Scheme, host, and issuer derive from `server.public_url` config, never from headers; forwarding is honored only under an exact trusted-hop topology (`proxy.trusted_hops`/`trust_forwarded`, default trust-nothing) and fails closed on any ambiguity |
| Tampering | Spoofed hop count or conflicting forwarding headers to smuggle a false client IP | Exactly `trusted_hops` entries are required; extra, missing, malformed, or conflicting (`Forwarded` and `X-Forwarded-For` together) entries fail closed to the transport peer and increment `ironauth_proxy_forwarding_rejected_total` |
| Repudiation | Unattributable request handling | Structured JSON request logs (method, route template, config-derived scheme, effective client IP, status) with an async writer; per-surface audit rows land with the persistence substrate (#7) |
| Information disclosure | Secrets, tokens, or PII in logs (the Okta 2023 HAR class) | Request logging carries route TEMPLATES and safe fields only, never query strings, `Authorization`, `Cookie`, other headers, or bodies; sensitive runtime values are typed `Redacted<T>`; a scrubbing corpus test asserts zero leaks; management plane (health/readiness/metrics) is bound separately and absent from the public data plane |
| Denial of service | Metric-label cardinality blow-up via crafted paths; unclean shutdown dropping in-flight work | Metric labels are route templates, never raw paths (unmatched requests collapse to one series); `SIGTERM`/`SIGINT` drains in-flight requests within `server.shutdown_grace_secs`; per-tenant rate limiting lands later (#50, M15) |
| Elevation | Public probing of privileged management endpoints | Health, readiness, and metrics live only on the management plane (`server.management_bind`, loopback by default) and 404 on the public plane |

## Surface: persistence and tenant isolation substrate (shipped)

The store layer parses untrusted resource identifiers and mediates every access
to tenant-scoped tables. It ships no network endpoint of its own, but every
later data surface inherits its isolation, so its controls are structural. See
docs/design/TENANCY.md. Cells without a citation are shipped by the substrate;
the same-transaction audit log is owned by #7.

| STRIDE | Threat | Control |
|---|---|---|
| Spoofing | Reaching another tenant's resource with a forged, guessed, or recycled identifier (the IDOR and recycled-identifier classes) | Typed scoped identifiers embed tenant and environment, are 128-bit non-guessable and random (never serial, never recycled), and parse cross-scope as a uniform not-found; a handler holding a scoped identifier cannot express a cross-tenant query |
| Tampering | Writing or updating a row that claims another tenant or environment | Scope-only repositories apply the `(tenant, environment)` filter to every write; Postgres row-level security `WITH CHECK` rejects a mis-scoped write beneath the application |
| Repudiation | Unattributable data changes | Same-transaction audit rows land with the relational primary store (#7) |
| Information disclosure | Cross-tenant reads (IDOR) and existence or error-shape oracles | Deny-by-default `(tenant, environment)` scope on every query; row-level security ENABLED and FORCED on every scoped table, verified by a low-privilege-role test; malformed, absent, and cross-scope lookups all return the identical not-found, so there is no oracle; the reusable IDOR harness probes every scoped operation in CI |
| Denial of service | Query and pagination abuse | Cursor pagination and per-tenant rate limits land with the surfaces that expose these repositories (#11, #50, M15) |
| Elevation | A raw unscoped query bypassing the repository to read across tenants | The pool and scoped tables are crate-private (no cross-crate raw access); repositories are constructible only from a scope (compile-fail tested); `scripts/query-audit.sh` fails CI on any scoped-table SQL outside the repository module |

## Surface: outbound fetcher (shipped)

The fetcher parses attacker-influenced URLs (a client's `jwks_uri`,
`sector_identifier_uri`, `logo_uri`, client-metadata documents, webhook targets)
and makes server-side HTTP requests to them, so its attacker is a client or
tenant who controls the URL and, through DNS, the address it resolves to. It
ships no inbound endpoint, but every later fetching feature consumes it, so its
controls are structural. See docs/adr/0003-outbound-fetch.md. Cells here are all
shipped; later features consume this dispatcher, they do not weaken it.

| STRIDE | Threat | Control |
|---|---|---|
| Spoofing | A URL or DNS answer pointing at the cloud metadata service or an internal host (the SSRF class; the Casdoor webhook-SSRF CVE) | The destination is validated by RESOLVED ADDRESS, not by hostname: loopback, private, link-local (`169.254.169.254`, `fe80::/10`), unique-local, shared-CGN, multicast, unspecified, documentation, and other special-use ranges are denied for IPv4, IPv6, and the IPv4-in-IPv6 forms; a host resolving to ANY denied address blocks the whole fetch |
| Tampering | A DNS record that flips between the validation lookup and the connect (DNS rebinding) | The host is resolved exactly once and the connection is pinned to a validated address by value; the socket layer never re-resolves the hostname, so there is no connect-time lookup for a flipped record to poison (proven by an injectable-resolver rebinding test) |
| Tampering | A redirect (3xx `Location`) steering a validated fetch to an internal address | Redirects are never followed; a 3xx with a `Location` is returned to the caller as an error |
| Repudiation | Unattributable outbound requests and blocks | Every fetch is metered by caller-declared `FetchPurpose` and outcome (`ironauth_outbound_fetch_requests_total`), and every block additionally by reason (`ironauth_outbound_fetch_blocked_total`), with a structured scrubbed log line per block |
| Information disclosure | The error as an oracle for internal network topology; the target URL leaking into logs | A blocked destination returns the single uniform `FetchError::Blocked` (scheme, denied address, DNS failure, and rebinding all collapse into it); the structured reason and purpose are bounded labels; the attacker-influenced host and URL are never logged as free-form fields |
| Denial of service | A size bomb, a slow-loris body, or a metadata-label blow-up via crafted URLs | A response size cap aborts mid-body and a total deadline aborts mid-flight (safe defaults, configurable); purpose, outcome, and reason labels are fixed closed sets, so an attacker URL cannot grow the series set |
| Elevation | A second, unhardened outbound path in another crate re-introducing the class | The connector and socket construction are module-private and the injectable seams are behind a test-only feature; no other crate may declare an HTTP-client dependency or construct an HTTP/TLS client, enforced by `scripts/http-audit.sh` |
| Elevation | Ambient credentials or proxy trust riding an outbound request | No cookie jar, no default credentials, no `HTTP_PROXY`/`NO_PROXY` trust, and userinfo in a URL is rejected; a request carries only what the caller set plus the destination `Host` |

## Surface: authorization endpoint (planned; lands with issue #12)

| STRIDE | Threat | Control (owning issue) |
|---|---|---|
| Spoofing | Client impersonation via forged redirect | Exact-string redirect_uri matching, no wildcards (#13); RFC 9207 iss parameter against mix-up (#13) |
| Tampering | Authorization code interception or injection | PKCE S256 required everywhere, single-use codes bound to client, redirect, nonce, and verifier, family revocation on reuse (#12, #13) |
| Repudiation | Untraceable grants | Same-transaction audit rows on every issuance (#7) |
| Information disclosure | Token leakage via URL, referrer, or history | No token-bearing response types; form_post mode; Referrer-Policy on code-bearing pages (#17, #38) |
| Denial of service | Unauthenticated request floods and state exhaustion | Pre-auth artifact TTL plus quotas; per-tenant fairness (#50 quota substrate, M15 full limiter) |
| Elevation | Cross-tenant issuance | Tenant and environment isolation enforced at the persistence layer with typed scoped IDs and forced row-level security (shipped; see the persistence and tenant isolation substrate above) |

## Surface: token endpoint (planned; lands with issues #12, #21, #22, #23)

| STRIDE | Threat | Control (owning issue) |
|---|---|---|
| Spoofing | Client authentication bypass or confusion | Full client-auth suite with hygiene: reject multiple methods, jti replay cache, aud policy (#25) |
| Tampering | Algorithm confusion, forged tokens | One hardened JOSE verify path, per-client alg allowlists, never trusting in-token key material (#8); EdDSA-default signing core (#9) |
| Repudiation | Unattributed token issuance | Audit rows in the issuing transaction (#7) |
| Information disclosure | Token theft and replay | Refresh rotation with reuse detection and family revocation (#21); sender-constraining lands with DPoP (#124) and mTLS (M16) |
| Denial of service | Hashing or signing resource exhaustion | Bounded pools with admission control (#62 for password hashing); rate limits per client and tenant (#50, M15) |
| Elevation | Grant-type confusion, ambient trust on exchange | Pluggable grant seams with per-grant revalidation; the no-ambient-trust rule (#9 seams; M13 token exchange) |

## Surface: management API (shipped)

The management API is the OpenAPI-first control plane on the management plane
(never the public data plane). It parses untrusted resource identifiers and admin
credentials and mutates the operator, tenant, and environment tables, so its
attacker is a holder of a stolen or wrong-scoped admin credential and a caller
probing for cross-tenant resources. See docs/adr/0005-management-api.md. Cells
without a citation are shipped by the skeleton; later milestones extend, never
weaken, them.

| STRIDE | Threat | Control |
|---|---|---|
| Spoofing | Stolen or replayed admin credentials; a credential used against the wrong environment or plane | Environment-scoped management keys (`mak_`, bound to `(tenant, environment)`) with only the token hash stored; a distinct control-plane database role (`ironauth_control`) separated from the data-plane role at the pool; a credential presented against the wrong environment or plane fails LOUD naming expected and actual scope; the full operator-plane credential class lands in M5 (#42) |
| Tampering | Unaudited mutation | Every management mutation writes its same-transaction audit row through the store's single audited-write primitive; a mutation without its audit row is structurally impossible |
| Repudiation | Untraceable admin actions | Same-transaction audit rows name the acting credential; the admin-action versus authn-event stream separation lands in M11 |
| Information disclosure | Cross-tenant reads (IDOR); an existence or error-shape oracle | Deny-by-default repository scoping, typed scoped IDs, and forced row-level security (shipped in the persistence substrate above); a cross-scope resource-ID probe is the UNIFORM not-found, registered with the #6 IDOR harness and run in CI |
| Denial of service | Pagination and query abuse | Cursor pagination on every list (opaque cursors, a config-capped page size, no offset); structured RateLimit and legacy X-RateLimit-* headers on every response, wired to a placeholder limiter until the real layered limiter lands (#50, M15) |
| Elevation | Overbroad admin roles; hidden privileged paths | The control role holds only the level tables plus append-only audit and the management tables, nothing on the data-plane scoped tables; every admin capability is a documented public API (the management-api-first rule), so there are no console-only or secret private paths; scoped admin roles and delegated administration land in M10 |

## Surface: organization roles and groups management API (shipped; issue #97)

Eleven endpoints nested under an organization: role CRUD, group CRUD, and a
dedicated `PUT .../groups/{group_id}/parent` that moves a group inside its
organization's group forest. They inherit the management API's authorization
(the operator, or a management key scoped to exactly that environment) and its
credential class, so the section above still governs spoofing and repudiation.
Three things are genuinely new and are analyzed here: a SECOND containment
boundary below the one row-level security enforces, two INFORMATIVE structural
refusals on a surface whose other refusals are deliberately uniform, and a
resource whose count is uncapped by covenant sitting behind a placeholder rate
limiter.

The attacker is the same as for the management API: a holder of a stolen or
wrong-scoped admin credential, and a caller probing for resources belonging to
another organization inside an environment they can legitimately reach.

| STRIDE | Threat | Control |
|---|---|---|
| Spoofing | An admin credential used against an organization it should not administer | Not yet separable, and stated plainly rather than implied: there is no per-organization authorization primitive today, so any credential that can reach an environment can administer EVERY organization in it. These endpoints are operator-or-exact-environment-key authorized through `Principal::require_environment`, exactly like the organization and membership endpoints. Delegated per-organization admin is issue #102; until it lands, the blast radius of an environment-scoped key is the whole environment |
| Tampering | A mutation addressed from one organization landing on a row in a SIBLING organization inside the same environment (row-level security fences `(tenant, environment)` and nothing finer, so it does NOT stop this) | The nested address is the PAIR `(organization_id, resource_id)` on every id-addressed endpoint. For groups the organization rides into the `UPDATE` statement itself as a predicate on all three mutations (rename, reparent, delete), so they share ONE addressing key and no mutation has an id-only path. For roles the pair is resolved by the read before the write, which is sound because `org_roles.organization_id` is immutable by GRANT (the control role may update only `display_name`, `metadata`, `updated_at`, `deleted_at`, and, since issue #98's migration 0093, `is_default`; none of the five is an addressing column), so the pair cannot come apart between the check and the use. Both are proved with a second organization holding its own rows, asserting each request returns and mutates exactly its own set |
| Tampering | A rename silently reshaping the group hierarchy | `PATCH` cannot write `parent_id`; moving a group is its own endpoint with its own audit action, so the structural refusals never ride a metadata edit |
| Repudiation | An unattributed reshaping of a hierarchy that changes who inherits which role | Every mutation writes its same-transaction audit row through the store's audited-write primitive, and the reparent audit detail records the RESULTING parent, because a reparent changes the effective roles of every descendant and the tree shape is otherwise unreconstructable from the log |
| Information disclosure | The cycle and depth refusals used as an existence AND STRUCTURE oracle over another organization's group graph (they are informative by design, so a caller who could see one for a group they cannot address would learn both that it exists and how it is nested) | Ordering, and it is load-bearing rather than stylistic. Both endpoints of a reparent are resolved as LIVE groups of THIS organization, under the per-organization advisory lock, BEFORE any cycle or depth reasoning runs. Every failure of that resolution is the uniform not-found across all four cases (absent, soft-deleted, foreign scope, foreign organization), and the same uniformity holds for a cross-organization `parent_id` on create. A caller who sees a 422 has already proved they can address both groups. Pinned by a test that compares the cross-organization answer byte for byte against the answer for an id that never existed |
| Information disclosure | The typed refusals leaking tenant data in their message | Neither message names an id. The cycle refusal carries nothing; the depth refusal carries only the configured bound and the attempted depth, both operator-supplied or structural numbers. The attempted depth is worded as a FLOOR ("at least N levels"), which is exact rather than hedging: both recursive walks stop one level past the bound, so against an already over-deep hierarchy the number saturates, and wording it as an exact value would have an operator raise the bound by the reported difference and watch the request refused again |
| Denial of service | An unbounded ancestor walk on the token-issuance path, reached by nesting groups arbitrarily deep or by importing a cyclic hierarchy | `max_group_depth` (deployment-wide `[organizations] max_group_depth`, default 8, hard ceiling 32) bounds tree DEPTH at write time, and every read-side walk carries the same bound plus a `deleted_at IS NULL` filter in every arm. The walks observe one level past the bound and stop, and that saturation FAILS CLOSED by construction: a saturated walk always refuses, never permits, so a pre-existing over-deep or cyclic hierarchy left by an import (or by an operator LOWERING the bound) cannot be extended. Reads truncate where writes refuse, deliberately: refusing on read would turn a data defect into an authentication outage |
| Denial of service | Write floods against a resource with no count cap | Stated as a KNOWN GAP, not a control. Roles and groups are uncapped in number by project covenant, and `crates/ironauth-admin/src/ratelimit.rs` is still a fixed-constant placeholder, so there is no real per-tenant write throttle behind this surface; the RateLimit headers describe a limiter that does not yet enforce. The real layered limiter is #50 (M15). What IS bounded here: the page size on every list (a clamp on ONE RESPONSE, never on the number of stored rows) and the tree depth. Nothing counted is capped, and no count check may be added to close this gap: the mitigation is the limiter |
| Elevation | A revoked role still riding an outstanding access token | Stated as a KNOWN GAP with a bounded window. Role and group changes take effect at the NEXT token issuance; they do not revoke tokens already issued, so a revoked role remains usable for at most one access token lifetime. What keeps that bound tight is that the REFRESH grant re-resolves the effective role set rather than replaying a frozen one, so the exposure is one access token lifetime and not one refresh family lifetime. Operators who need immediate withdrawal must revoke the session or refresh family. Active invalidation on a role change is tracked as a follow-up. The claim itself now ships (issue #97 PR 6): `roles` is emitted on the ACCESS token only, resolved fresh at both the code-exchange and refresh mint hooks, and a store fault during that resolution refuses the token request rather than issuing without roles, because a silently role-less token reads downstream as a successful authorization downgrade |
| Elevation | Deleting a mid-tree group silently escalating or cascading | A delete DETACHES rather than cascades: children keep their stored `parent_id` and are treated as ROOTS because every walk filters deleted rows. Detaching can only ever DECREASE a descendant's depth and can only ever REMOVE inherited roles, never add one. The consequence a consumer must respect is that a non-null `parent_id` may name a deleted group and must never be resolved without the liveness filter |
| Elevation | A DISABLED or soft-deleted organization still minting its roles, so the operator's coarsest kill switch has no effect on the authorization claim | Fenced in the membership seed of the ONE closure all FOUR effective-resolution projections share, so a disabled or deleted organization resolves to the EMPTY set for every member on every surface at once: the token claim, the flattened group closure, the console's provenance view, and (issue #98) the effective permission set. That seed is also the only thing fencing issue #98's DEFAULT role, which reaches the member through no assignment row and is therefore refused by nothing else. It has to sit there rather than in a caller because NEITHER mint hook is in a position to check it: the refresh grant never runs the authorize-time organization resolution at all (it reads the org context frozen onto the family's grant), and on a code exchange that resolution returns early for an already-bound session, which is every session that has an org. The answer is EMPTY rather than an error, because a disabled organization is an operator state and refusing would make an administrative action a token-endpoint outage. The residual is the same bounded window as the row above: tokens already issued are unaffected, so a disable takes effect within one access token lifetime |

## Surface: organization group members, role assignments, and effective roles (shipped; issue #97)

Ten more endpoints nested under an organization: binding memberships into groups
(`.../groups/{group_id}/members`), the two role-assignment surfaces
(`.../groups/{group_id}/roles` and `.../memberships/{membership_id}/roles`), and
the read that resolves them (`GET
.../memberships/{membership_id}/effective-roles`). They inherit the management
API's authorization and credential class, and the section above still governs
spoofing, repudiation, the uncapped-count gap, and the token-freshness gap, which
are not restated here.

Three things are genuinely new relative to the roles-and-groups surface, and are
what this section analyzes. First, these are the endpoints that actually GRANT
privilege: a role is inert until one of them is called, so the blast radius of a
single request here is a person gaining an authorization, not a configuration row.
Second, every request now names THREE ids rather than two, each of which can
independently be a row the caller may legitimately see, so containment has to
refuse a PAIRING and not merely an id. Third, the effective-roles view is a new
kind of read: it discloses a resolved authorization picture, and it discloses the
STRUCTURE that produced it.

The attacker is the same: a holder of a stolen or wrong-scoped admin credential,
and a caller probing for rows belonging to another organization inside an
environment they can legitimately reach.

| STRIDE | Threat | Control |
|---|---|---|
| Elevation | A stolen console credential granting itself, or an accomplice, a privileged role with no re-authentication. This is the sharpest elevation path in the whole management API: one request turns an existing role into real privilege for a real person | All six mutating endpoints are behind the sudo step-up gate (`crate::sudo::require_fresh_privilege`), so a credential whose recorded elevation has lapsed is challenged with the RFC 9470 `insufficient_user_authentication` error and writes nothing. Each of the six call sites is exercised in `tests/sudo.rs` against a seeded row that a missing gate would really have changed, and each is then re-run after a fresh elevation, so the challenge is attributable to the gate rather than to an unrelated refusal. The four READS are deliberately ungated and asserted so, because an operator must be able to see what they are about to change before elevating |
| Tampering | A cross-organization PAIRING: two ids that are each individually visible to the caller (each lives in an organization the same environment-scoped credential administers) combined into one request, for example this organization's group with a sibling organization's membership, or this membership with a sibling's role | Every one of the three ids is resolved TOGETHER against ONE organization, never one at a time. On the write paths the store resolves both endpoints as live rows of the addressing organization inside the audited write transaction (`require_live_group_in_org`, `require_live_membership_in_org`, `require_live_role_in_org`); on the read and remove paths one statement carries `organization_id`, the subject id, and the object id in a single predicate (`get_binding` / `get_assignment`), and the removal statement repeats `organization_id` independently of the read that addressed it. Row-level security fences `(tenant, environment)` and nothing finer, so these predicates are the whole control. Proved with a second organization in the same environment holding its own group, membership, and role under the SAME slugs, asserting every pairing is refused and mutates nothing |
| Tampering | A check-to-use window: the pair-addressed removals resolve the assignment id with a read and then write with a second statement | Not reachable, by GRANT rather than by locking. Migrations 0088 and 0089 grant the control role UPDATE on `updated_at` and `deleted_at` and on nothing else, so a binding's or an assignment's group, membership, role, organization, and scope are immutable: there is no reachable state in which a pair was valid at the read and names a different row at the write. A concurrent removal makes the write match no live row, which is the same not-found the read would have produced |
| Information disclosure | The nested paths used to enumerate a sibling organization's group, membership, or role ids | Uniform not-found on every endpoint, across all five shapes: never created, another organization's, another environment's, malformed, and one carrying a different resource's prefix. Asserted BYTE for byte against the never-created reference answer, on the reads, on the three POST bodies (where a handler that validated the body id separately would otherwise split a 400 from a 404), and on the three pair-addressed removals. A list under a group or membership the caller cannot address is the same 404 that reading it directly gives, never an empty 200 that would assert it exists here and is empty |
| Information disclosure | The effective-roles view disclosing the group STRUCTURE of an organization, through the `via_group_id` provenance it exists to report | Confined by the same containment as everything else: the membership is resolved as a live membership of THIS organization before resolution runs, and the resolution closure repeats `organization_id` in every arm including the recursive one, so no ancestor outside the addressing organization can enter the answer. Within an organization the disclosure is intended: any credential that can read this endpoint can already list the organization's groups and their assignments, so provenance reveals no id the caller could not enumerate directly. It is included because the alternative is worse than the disclosure: an operator shown only one of several grant paths withdraws it, sees the role survive, and concludes the withdrawal did not work |
| Information disclosure | A resolution fault rendered as an empty role set | Fails closed and LOUD: a store error is a 500, never an empty `roles` array. On this surface an empty set is indistinguishable from a member who legitimately holds nothing, so swallowing the error would render a silent, plausible-looking authorization downgrade in the console |
| Denial of service | The un-paginated effective-roles read used as an amplification lever, since roles, groups, and memberships are all uncapped by covenant | Bounded by construction rather than by a cap. The response is bounded by the roles the organization DEFINES, each contributing at most one direct entry, at most one default entry (issue #98, and at most ONE role per organization can carry it, by partial unique index), plus one entry per group in the member's ancestor closure that grants it; that closure is bounded by `max_group_depth` (default 8, ceiling 32) times the groups the member belongs to. The walk carries the same hard depth guard and `deleted_at IS NULL` filter in every arm as the token-issuance resolution, which it shares verbatim. No count is checked and no request is refused for being large: adding one would be a cap, and caps are forbidden here. The residual, as for the surface above, is that `crates/ironauth-admin/src/ratelimit.rs` is still a fixed-constant placeholder, so the real per-tenant write throttle is #50 (M15) |
| Repudiation | An unattributed privilege grant | Six distinct audit actions, one per mutation (`organization.group.member.add` / `.remove`, `organization.group.role.assign` / `.unassign`, `organization.membership.role.assign` / `.unassign`), each written in the same transaction as the write. A group grant and a direct grant are never folded into one action, because they have different blast radii and different remedies, and until M11 ships delivery the audit log IS the delta record. A REFUSED write audits nothing: the endpoint resolutions run inside the audited transaction, so a refusal rolls the attempted write and its audit row back together |
| Elevation | A membership removed from an organization silently keeping its groups and direct roles if it is later re-added | The membership row REVIVES on re-add, so its attachments would revive with it. Removing a membership therefore cascades a soft delete over its group bindings and direct role grants, from BOTH call sites (the admin remove and the invitation-accept side effect), so a re-added user starts with no groups and no roles. Shipped with the store layer (issue #97 PR 3) and stated here because it is the invariant these endpoints depend on |

## Surface: permission vocabulary management API (shipped; issue #98)

Five endpoints that define the named API CAPABILITIES an environment recognizes:
`POST` and `GET` on
`/v1/tenants/{tenant_id}/environments/{environment_id}/permissions`, and `GET`,
`PATCH`, and `DELETE` on `.../permissions/{permission_id}`. They inherit the
management API's authorization (the operator, or a management key scoped to
exactly that environment) and its credential class, so the management-API section
above still governs spoofing and repudiation, and the uncapped-count gap it
records is not restated here.

Two things are genuinely new relative to every #97 surface, and are what this
section analyzes.

First, these endpoints are NOT nested under an organization, and that is not a
convenience. `permissions` carries no `organization_id` (migration 0091, section
(1)), so the row-level-security policy is the COMPLETE fence for the table and
there is no second containment boundary of the kind the two sections above
analyze at length. There is correspondingly no per-organization predicate to
forget, and no cross-organization pairing to refuse. What remains is the
environment fence, which is why the tests for this surface prove cross
ENVIRONMENT containment (a tenant held fixed) rather than cross organization.

Second, this table's rows are the STRINGS a later access token will carry. A
permission is inert until a role maps to it, so no request here grants anybody
anything, but the vocabulary is what every later grant names.

The attacker is the same as for the management API: a holder of a stolen or
wrong-scoped admin credential, and a caller probing for the capability names
defined in an environment they cannot legitimately reach.

| STRIDE | Threat | Control |
|---|---|---|
| Spoofing | An environment-scoped management key administering a DIFFERENT environment's vocabulary | `Principal::require_environment`, reached through the single `crate::org_context::resolve_scope` call site, on all five endpoints. A management key whose scope is not exactly the `(tenant, environment)` the path names gets the LOUD 403 wrong-scope refusal, never a silent denial and never a success. Exercised rather than assumed: one test drives a real `mak_` key at all five endpoints twice, once inside its own environment (which must succeed) and once against a SIBLING ENVIRONMENT OF THE SAME TENANT (which must be the 403), and then pins the sibling environment's rows unchanged. The two environments share a tenant deliberately, so the environment half of the fence is the only thing that can be doing the work; deleting the environment conjunct from `require_environment` is confirmed to turn that test red |
| Spoofing | An admin credential used against a vocabulary it should not administer, at a granularity finer than the environment | Not separable, and stated plainly rather than implied: there is no per-organization or per-vocabulary authorization primitive today, so any credential that can reach an environment can define, relabel, and delete EVERY permission in it. This is the same gap the roles-and-groups section records, and it is the reason migration 0091 can argue that a per-environment vocabulary introduces no NEW escalation: there is no privilege boundary below the environment on the management plane for a shared vocabulary to breach. Delegated administration is issue #102 |
| Tampering | A permission's SLUG rewritten under live role mappings, silently repointing every grant that names it | Prevented one layer below this code and asserted at the edge. Migration 0091 grants the control role `UPDATE (display_name, metadata, updated_at, deleted_at)` and nothing else, so `slug` and `kind` are immutable BY GRANT: a statement naming either is refused as SQLSTATE 42501. The store's `update` therefore has no parameter for either, and a `PATCH` body that names one is refused at the edge as a typed 400 rather than being silently dropped, because a caller who believes they renamed a capability and did not is worse off than one who is told no. Both refusals are proved, including a body that names an immutable field ALONGSIDE a legitimate relabel, which must refuse the whole request and leave the legitimate half unapplied |
| Tampering | A stolen console credential redefining or deleting an environment's capability names with no re-authentication | All three mutating endpoints (define, relabel, delete) are behind the sudo step-up gate (`crate::sudo::require_fresh_privilege`), so a credential whose recorded elevation has lapsed is challenged with the RFC 9470 `insufficient_user_authentication` error and writes nothing. Each of the three call sites is exercised in `tests/sudo.rs` against seeded rows a missing gate would really have changed, and each is re-run after a fresh elevation so the challenge is attributable to the gate. The two READS are deliberately ungated and asserted so, because an operator must be able to see the vocabulary before elevating to change it |
| Tampering | A `PATCH` that supplies no mutable field, where the store write is skipped entirely and the read is the only guard left | The target is resolved as a LIVE permission of THIS environment BEFORE the body is parsed at all, so the empty patch and every other body answer on the ADDRESS. Asserted directly, including a cross-environment empty patch that must be the uniform not-found and must not echo the foreign row |
| Information disclosure | The item endpoints used to enumerate a sibling environment's capability names one id at a time | Uniform not-found across every shape: never created, soft-deleted, another environment's (a row that genuinely EXISTS there, so the probe is not passing because nothing was found), malformed, carrying another resource type's prefix, and a blank segment. Asserted BYTE for byte against the never-created reference, on the read and on BOTH mutations. Also asserted with bodies that the edge alone would refuse (a body naming the immutable slug, and a body that is not JSON), because a handler that validated the body before resolving the address would answer 400 for one caller and 404 for another and thereby separate "not yours" from "does not exist" |
| Information disclosure | The one shape that is NOT byte-identical, recorded rather than papered over | A path with an EMPTY final segment (`.../permissions/`) matches no route, so axum refuses it before any handler, scope check, or store read runs: the answer is a 404 with an EMPTY body rather than this API's structured one. It is not an oracle, and the test asserts the property that makes it not one: the refusal is identical whichever environment the path names, so it discloses only that no route exists, which is true for every caller alike |
| Information disclosure | A define into a well-formed but ABSENT or deleted environment answering differently from a define into a malformed one | The scope resolution proves only that the two path segments PARSE, so without a further check the composite foreign key to `environments` would refuse the insert and the caller would get an opaque 500 for an input they fully control, distinguishable from the 404 a malformed segment gets. The create resolves the environment as a LIVE row first, so absent, deleted, and malformed are one answer, asserted byte for byte. The check sits AFTER the Idempotency-Key replay, so retrying a request that already succeeded still returns the original response even if the environment was deleted meanwhile; that ordering is pinned by its own test. The reads need no counterpart and have none, because neither can reach a constraint |
| Information disclosure | A duplicate-slug refusal used as an existence oracle over the caller's OWN environment | Intended and not a leak. A 409 on a live slug tells the caller only about the environment they are already authorized to list, and it is the signal an operator creating by name asked for. A duplicate in ANOTHER environment is not a conflict at all, because the uniqueness index is scoped |
| Repudiation | An unattributed change to the vocabulary a token claim will name | Three distinct audit actions (`permission.create`, `permission.update`, `permission.delete`), each written in the same transaction as its write through the store's audited-write primitive, and none carrying an `organization.` prefix because the vocabulary is environment scoped. Until issue M11 ships delivery, the audit log IS the delta record for a permission. Asserted as a MULTISET at every step of the round trip, so an extra row is as visible as a missing one, and a REFUSED mutation is asserted to write none |
| Denial of service | Write floods against a resource with no count cap | The same KNOWN GAP the roles-and-groups section records, and it applies unchanged: permissions are uncapped in number by project covenant (migration 0091 carries no cap, no quota, and no counter for this code to enforce), and `crates/ironauth-admin/src/ratelimit.rs` is still a fixed-constant placeholder, so the RateLimit headers describe a limiter that does not yet enforce. The real layered limiter is #50 (M15). What IS bounded is the page size on the list, which clamps ONE RESPONSE and never the number of stored rows. No count check may be added to close this gap |
| Elevation | Deleting a permission leaving the capability usable, or restoring it silently | The delete is SOFT (`DELETE` is granted to nobody on either plane), and the row is retained so its id stays resolvable for the audit trail that names it. It is nonetheless immediately effective for authorization: the effective-permission projection selects only `deleted_at IS NULL` rows, so a deleted permission leaves every resolved set at the next issuance even though the mapping rows that named it survive. Re-creating the same slug mints a FRESH id rather than reviving the dead row, so those surviving mapping rows still point at the dead id and the re-created permission is NOT granted to anyone until it is mapped again. Asserted: the freed slug is accepted, the new id differs, and exactly one live row holds the slug |
| Elevation | A revoked capability still riding an outstanding access token | The same KNOWN GAP with the same bound the roles-and-groups section records: a vocabulary change takes effect at the NEXT token issuance and revokes no token already issued, so the exposure is at most one access token lifetime, kept to that bound because the refresh grant re-resolves rather than replaying. Operators needing immediate withdrawal must revoke the session or refresh family. (The claim itself lands later in issue #98; this row states the property the surface commits to) |

## Surface: role-to-permission mapping and the organization default role (shipped; issue #98)

Five endpoints. Three carry the MAPPING: `POST` and `GET` on
`/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles/{role_id}/permissions`,
and `DELETE` on `.../permissions/{permission_id}`. Two carry the per-organization
DEFAULT ROLE: `PUT` and `DELETE` on
`.../organizations/{organization_id}/default-role`. They inherit the management API's
authorization and credential class, so the management-API section still governs
spoofing and repudiation, and the uncapped-count gap it records is not restated here.

Three things are new relative to every surface above.

First, a mapping JOINS TWO RESOURCES AT DIFFERENT LEVELS. The role half is
organization scoped; the permission half is environment scoped and carries no
organization at all. So the containment question has two independent halves, and a
CROSS PAIRING has two directions: a role of a sibling ORGANIZATION under this
organization's path, and a permission of a sibling ENVIRONMENT attached to this
organization's role. Both must be refused, and refused ALIKE.

Second, these rows are what turn a capability NAME into a capability. A permission is
inert until a mapping names it; a mapping is the grant.

Third, the default role is the one designation in the product that grants a role
WITHOUT WRITING A ROW FOR ANYBODY. It reaches every live active member of an
organization at once, it is resolved at read rather than materialized (migration
0093), and it therefore appears in no membership's direct-assignment list. Its blast
radius is the largest of any single management write in this milestone.

The attacker is a holder of a stolen or wrong-scoped admin credential, and a caller
probing for the roles, permissions, and grants of an organization or environment they
cannot legitimately reach.

| STRIDE | Threat | Control |
|---|---|---|
| Spoofing | An environment-scoped management key administering a DIFFERENT environment's mappings or default role | `Principal::require_environment`, reached through the single `crate::org_context::resolve_scope` call site, on all five endpoints. A key whose scope is not exactly the `(tenant, environment)` the path names gets the LOUD 403 wrong-scope refusal, never a silent denial and never a success. Exercised rather than assumed: one test drives a real `mak_` key at all five endpoints twice, once inside its own environment (which must succeed) and once against a SIBLING ENVIRONMENT OF THE SAME TENANT (which must be the 403), then pins the sibling environment's mappings, its designation, and both audit multisets unchanged. The two environments share a tenant deliberately, so the environment half of the fence is the only thing that can be doing the work |
| Tampering | A nested route resolving a mapping through the ORGANIZATION-BLIND by-id read, and detaching a sibling organization's capability grant | Structural, and it is the sharpest control on this surface because row-level security fences `(tenant, environment)` and cannot see `organization_id` at all. The mapping is PAIR addressed, so its `rpm_` id never appears in any path and the by-id read has no caller in the module. The detach resolves through `get_assignment`, which carries `organization_id`, `role_id`, and `permission_id` in ONE predicate; the list resolves the role through `get_in_org` first and then reads through `list_for_role`, which takes the organization too. Asserted from both directions over a mapping that genuinely exists, with the uniform 404, the mapping still live, and the audit multiset unchanged |
| Tampering | A stolen console credential attaching a capability, detaching one, or changing which role every member of an organization holds, with no re-authentication | All four mutating handlers (attach, detach, designate, clear) are behind the sudo step-up gate, so a credential whose recorded elevation has lapsed is challenged with the RFC 9470 `insufficient_user_authentication` error and writes nothing. Each of the four is dropped INDIVIDUALLY in `tests/sudo.rs` against seeded rows a missing gate would really have changed, and each is re-run after a fresh elevation so the challenge is attributable to the gate. The reads are deliberately ungated and asserted so |
| Tampering | A second designation racing the first, leaving an organization with two default roles | Structurally impossible: `org_roles_org_default_live_uniq` is a partial unique index over `(tenant, environment, organization)` where `is_default AND deleted_at IS NULL`. The designate endpoint clears the incumbent and sets the new role in ONE transaction, so a second designation by a single caller MOVES the designation rather than colliding, which is what `PUT` on a single-valued property means. The index remains the backstop for two CONCURRENT designations, and the loser's unique violation is reported as a typed 409 rather than reaching the caller as an opaque 500 |
| Tampering | KNOWN GAP: a write nested under an organization of a SOFT-DELETED environment still lands | Measured on this surface rather than reasoned about, and recorded here because this document is where a reader will look for it. `resolve_scope` proves only that the two path segments PARSE and that the credential is scoped to them, and `resolve_live_org` then filters `deleted_at` on `organizations` alone, so nothing on an organization-nested path proves the ENVIRONMENT is live. `require_live_environment`, the one helper that does prove it, has exactly ONE caller in the admin crate: the environment-scoped `POST .../permissions` create, where it is there to turn a foreign-key violation into the uniform not-found rather than to enforce liveness. The reportable part is the INCONSISTENCY that leaves. In one soft-deleted environment `POST .../permissions` refuses, while `POST .../organizations/{org}/roles` and this surface's attach both succeed, because deleting an environment does not cascade to its organizations and the retained row still satisfies the constraint. `an_attach_into_an_unreachable_environment_is_never_a_server_error` drives the attach and the shipped role create side by side in ONE fixture and asserts they AGREE, so a change that closes the gap on one and not the other fails a test instead of leaving this prose stale. Tracked as issue #411. No endpoint on this surface may close it unilaterally, because a partial close deepens the inconsistency rather than fixing it |
| Information disclosure | The mapping endpoints used to enumerate a sibling organization's roles or a sibling environment's capability names | Uniform not-found, asserted BYTE for byte against a reference that is reachable and simply not attached, and stated per SEGMENT because the two halves are not addressed alike. Over the ROLE: a soft-deleted role, a sibling organization's role, a malformed id, an id carrying another resource type's prefix, and a blank segment, on the list, the attach, and the detach. Over the PERMISSION: on the ATTACH, where it arrives in the body, an absent id, a soft-deleted one, and a sibling environment's; on the DETACH, where it is the final path segment, a live but UNATTACHED permission, a sibling environment's, a malformed id, a wrong prefix, and a blank segment. The LIST has no permission dimension at all, so no cell is claimed for it there. The reference fixtures name rows that genuinely EXIST elsewhere, so a probe cannot pass merely because nothing was there. ONE cell is deliberately NOT the uniform not-found, and it is a decision rather than a gap: the pair-addressed DETACH resolves the role with `parse_role_id` alone where the list and the attach use `require_role_in_org`, so a mapping attached BEFORE its role was soft-deleted is still removable and answers 204. That is the rule the deleted-PERMISSION case already commits to, for the same reason: neither deletion cascades to the mapping table, so an orphan must stay removable through some supported path or the table accumulates rows nothing can clear. It crosses nothing, because `get_assignment` carries `organization_id` in its predicate: the same pair driven through a SIBLING organization's path is still the uniform 404 that writes no audit row, asserted over a mapping whose role is dead. The second-order consequence, stated because it is operationally real and follows from no other row: an orphan of a deleted PERMISSION stays both LISTABLE and detachable, while an orphan of a deleted ROLE is detachable ONLY by an operator who still holds the permission id, because the list refuses the dead role. `a_mapping_under_a_soft_deleted_role_stays_detachable_by_its_pair_while_the_list_refuses` pins all three answers over a mapping that really exists |
| Information disclosure | A body the edge alone would refuse, used to separate "not yours" from "does not exist" | Everything that is part of the mapping's ADDRESS resolves before the body is parsed: the organization through `resolve_live_org` and the role through `get_in_org`. A body that is not JSON and a body missing the required field are each asserted to answer on the address at an unreachable role AND at an unreachable organization. The designate endpoint carries the same ordering with the organization as its address. The PERMISSION is not part of the address and is refused by the store under the same uniform not-found |
| Information disclosure | The one shape that is NOT byte-identical, recorded rather than papered over | A path with an EMPTY final segment matches no route, so axum refuses it before any handler, scope check, or store read runs: the answer is a 404 with an EMPTY body. It is not an oracle, and the test asserts the property that makes it not one: the refusal is identical whichever ORGANIZATION the path names |
| Information disclosure | A duplicate-attach 409 used as an existence oracle over a permission the caller cannot see | The store resolves BOTH endpoints as live rows before any conflict reasoning, so the 409 is reachable only by a caller who has already proven they can see the role and the permission. A cross pairing is the uniform not-found and never a conflict |
| Repudiation | An unattributed change to what a role grants, or to the role every member holds | Four audit actions, each written in the same transaction as its write: `organization.role.permission.assign`, `organization.role.permission.unassign`, `organization.default_role.set`, and `organization.default_role.clear`. The two designation actions take the `org_roles` delta contract from three actions to five, which migration 0093's header states. Both are asserted as MULTISETS at every step of their round trips, so an extra row is as visible as a missing one, and every REFUSED mutation is asserted to write none. Moving the designation is ONE request, ONE transaction, and ONE `set` row naming the incoming role; the designation is a per-organization singleton, so that row states the whole of the new designation |
| Repudiation | An audit action whose ABSENCE is read as meaning a grant is still in force | Stated as a limit rather than controlled. Deleting a ROLE or a PERMISSION does not cascade to the mapping table and writes no `unassign`; deleting the default ROLE does not write a `clear`. In both cases the grant stops resolving on the endpoint's own liveness filter. An operator reconstructing what a role grants must read the rows, which ADR 0002 makes binding, and must not fold the audit stream |
| Denial of service | Write floods against resources with no count cap | The same KNOWN GAP the sections above record, unchanged. A role may carry unlimited permissions and a permission may be carried by unlimited roles, in both directions, by project covenant: migration 0092 carries no cap, no quota, and no counter for this code to enforce, and no count check may be added to close this gap. What IS bounded is the page size on the list |
| Elevation | A default role designated on a DISABLED organization | Permitted, deliberately, and stated so it reads as a decision. `OrganizationRepo::get` filters `deleted_at` and does NOT filter `state`, so a disabled organization is live for every management write, which is what an operator winding one down or back up needs. It grants nothing while the organization is disabled: the closure seed is the only organization-liveness fence on the issuance path, and a disabled organization resolves no roles at all |
| Elevation | A detached capability, or a cleared designation, still riding an outstanding access token | The same KNOWN GAP with the same bound the sections above record: a change takes effect at the NEXT token issuance and revokes no token already issued, so the exposure is at most one access token lifetime, kept to that bound because the refresh grant re-resolves rather than replaying. Operators needing immediate withdrawal must revoke the session or refresh family |
| Elevation | A detached mapping quietly revived, undoing a withdrawal in place | Not reachable. A detach is a soft delete and is NEVER revived: re-attaching the same pair inserts a FRESH row with a FRESH id, asserted directly, so the audit history of the detachment is not overwritten by the row that replaces it. Migration 0092 grants the control role `UPDATE` on exactly `updated_at` and `deleted_at`, so an existing mapping can never be repointed at a different role, permission, organization, or scope |

## Surface: hosted pages (planned; bootstrap with issue #20, full in M9)

| STRIDE | Threat | Control (owning issue) |
|---|---|---|
| Spoofing | Phishing lookalikes of auth pages | Per-environment custom domains with automated TLS (M5); passkey origin binding defeats credential replay (M7) |
| Tampering | XSS on the auth origin | Strict nonce-based CSP, frame-ancestors none, no customer HTML or script on the auth origin ever, sanitized branding tokens only (#20 baseline, M9 full) |
| Repudiation | Disputed logins | Authentication event stream with device and geo context (M8, M11) |
| Information disclosure | Reflected parameters, account enumeration | HTML-escape every reflected parameter including error_description (M9); uniform responses and timing across login, registration, and recovery (M7) |
| Denial of service | Bot-driven form floods | Proof-of-work challenges with pluggable adapters, never a hard third-party dependency (M8) |
| Elevation | Session fixation or cookie theft | __Host- prefixed, Secure, HttpOnly, SameSite cookies; session ID rotation on privilege transitions (#32 session model) |

## Process rule

Every PR that ships a new surface (a network-facing endpoint family, a new
parser over untrusted input, or a new privileged plane) must extend this
document in the same PR. Reviewers block merges that add a surface without
its STRIDE section. This rule is stated in CONTRIBUTING.md and enforced by
the PR template checklist.
