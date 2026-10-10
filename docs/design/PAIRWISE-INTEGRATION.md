# Production pairwise subjects (#19)

The original #19 and hosted-profile #1385 criteria remain open. This branch
integrates durable client identity policy with issuance, credential consumers,
dynamic registration and the management API. It has not been deployed. Legacy
identity reconciliation, operational cutover and live relying-party qualification
remain required; generic hashing tests alone do not qualify those behaviors.

## Durable salt prerequisite

The store now provides `EnvelopeRepo::pairwise_salt` and the audited
`ActingEnvelopeRepo::ensure_pairwise_salt`. They use the existing forced-RLS
`encrypted_secrets` table and envelope keys, with the reserved purpose
`oidc.pairwise.subject-salt.v1`. The unique scope/purpose key settles concurrent
creation; only the winner commits the secret-creation audit. Ordinary
`put_secret` refuses the reserved purpose. Re-encryption changes ciphertext,
never salt bytes. Reads and retries refuse corrupt or shredded material instead
of silently replacing identity. Debug output redacts the 256-bit value.

Real PostgreSQL tests cover eight independent concurrent pools, read/retry and
pool restart, KEK/DEK rotation, ciphertext replay across scopes, corruption,
crypto-shredding, rollback on audit failure, and byte-identical configuration
exports before and after provisioning. Backup/restore qualification and live
token integration are still required. No network endpoint exposes this salt.

## Sector selection

Core 8.1 uses the hostname, not the HTTP Host header or its port. The shared
resolver infers one host only if every redirect has that host. Empty or hostless
native sets require an explicit sector document. A supplied HTTPS document is
always fetched through the hardened fetcher and must contain every redirect
exactly, even if the redirects already share a host. The document's host is the
sector. Explicit and inferred sectors use the same canonical URL hostname,
including IPv6 brackets/compression. Registration still owns web/native redirect
validation.

Sources: [Core 8.1](https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg)
and [Registration section 5](https://openid.net/specs/openid-connect-registration-1_0.html#SectorIdentifierValidation).

## Required persistence and integration

1. Store a validated per-client subject policy through the documented management
   API and dynamic registration. Redirect updates must validate against the
   current policy and cannot silently change an issued identity. Fetch outside
   the write transaction, then compare the policy/redirect revision under lock.
2. Persist one random 256-bit salt per environment, envelope-encrypted with
   scope/purpose/version binding. First-writer races must converge on the stored
   salt. A process restart, another replica and backup restore must read the
   same material. Salt is environment identity, excluded from config promotion;
   ordinary encryption-key rotation must preserve the salt plaintext.
3. Preserve already-issued identity bindings and define policy-transition
   semantics explicitly. Public-to-pairwise conversion changes the external
   identifier by definition; preserving a previously public value for an old
   user is a legacy exception to full pairwise privacy. Historical migration and
   operational cutover remain incomplete. Do not claim an immutable public policy has
   fulfilled the issue's requested switching behavior.
4. Keep local user IDs as all authorization/store keys. Client-aware derivation
   belongs only at the external identity boundary. Direct public-resolver sites
   include authorize, code/refresh, UserInfo (JWT and opaque), introspection
   (JWT and opaque), device, CIBA, FedCM, recipient proof and native SSO checks.
   Token exchange also has direct subject issuance paths; searching only for
   `resolve_public_subject` is insufficient. Audit logout hints/backchannel
   delivery, asserted subjects, session token templates and delegation actors.
5. Every credential consumer must compare a verified external subject against
   the correct local account/client binding. Do not parse a pairwise hash as a
   local user ID or authenticate it without the grant/session's local authority.
6. Prove registered-client token/UserInfo/introspection parity, refresh stability,
   scoped profile release, public compatibility, cross-sector/environment
   separation, replicas/restart/restore and a real relying-party browser flow.
   Existing issuer/JWKS issue criteria also need their own evidence.

## Delivery constraints

Do not enable pairwise registration before every serving path understands its
policy. Schema expansion alone does not make an old binary pairwise-capable;
plan rollout and rollback around that fact. No current application identity or
live provider configuration is changed by this branch yet. The complete original
Civio U01/U02/U04/U07 objective is unchanged.


## Integration work in progress after PR #1492

Migration 0251 and the scoped client repository now persist identity policy,
a revision shared with redirect edits, and immutable client/user bindings. The
revision trigger also detects redirects changed and then restored (ABA). A
pairwise row pins the exact validated redirect set; a legacy writer cannot edit
that set without atomically updating its validated policy. Failed audits roll
back both policy revisions and binding inserts. Bindings carry composite scoped
foreign keys and no direct UPDATE/DELETE grants.

The OIDC adapter reads durable policy/salt and binds through the shared derivation.
Code/refresh issuance, UserInfo, opaque/refresh introspection, front-channel ID
tokens, device and CIBA grants, FedCM assertions, recipient proofs, mapped JWT
bearer users and native SSO now use registered-client identities. FedCM account
selection remains a provider-scoped browser handle. Workload mappings retain
their existing principal identifiers.

Token exchange recovers the local principal from the verified token's scoped
stored grant and checks its original client binding before authorizing it. New
subject/actor identifiers follow the receiving client policy; historical actor
chains remain the verified history. Access rules and audit/storage attribution
use local principals, including transaction tokens. Mint request types now carry
local and client-facing subjects separately.

Session impersonation resolves scoped user actors under the receiving client
policy for code/refresh, device, implicit/hybrid and FedCM. The original local
actor and written justification remain in session/family storage; only the
structured reason accompanies the client-facing actor. Non-user operator and
workload identifiers retain their existing representation. A missing or unreadable
session at the actor lookup refuses issuance instead of silently dropping `act`.
Local user actors must still be eligible to authenticate even when they already
have a stable client identity binding.

Session templates are an independent credential profile with dedicated keys,
audiences and token type, not registered OIDC clients. Their subject remains the
local account; a template audience does not select an OIDC client identity policy.
Logout hints and backchannel delivery select sessions by `sid`, independently of
pairwise subjects. Protocol regressions cover cross-browser hint targeting and
per-client backchannel delivery without a local-subject claim.
Dynamic registration now accepts and returns `subject_type` and an optional
`sector_identifier_uri`. Create and full-replacement update validate the sector
through the shared hardened HTTPS fetcher, then commit policy, redirects and
registration-token rotation in one audited transaction. Updates compare both the
policy/redirect revision and the authenticating registration-token hash, so a
concurrent policy edit or token rotation cannot be overwritten after validation.
The existing registration rate/window settings also bound authenticated updates,
using a scoped client key that survives token rotation. A zero limit retains its
existing explicit opt-out meaning.

Omitting `subject_type` in a registration update selects the public default;
clients retaining pairwise policy must include it in replacement metadata.
`sector_identifier_uri` is accepted only with explicit pairwise policy. Existing
user bindings survive either policy transition; only previously unbound users
receive an identity from the replacement policy. Protocol tests exercise actual
ID tokens and UserInfo before and after updates and a pool/registry restart,
real TLS sector validation, private/link-local refusal and the update fetch budget.
Store tests exercise concurrent updates and audit-failure rollback. These are
local integration checks, not evidence of a live rollout or a real browser flow.
Management now exposes GET/PUT
`/v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/subject-policy`.
The response includes policy, sector, redirects and revision. PUT requires
`expected_revision` and explicit `subject_type`; it cannot edit redirects or
issued bindings. Read/write management permissions, fresh privilege and live
scope resolution run before metadata validation. Explicit sector URLs use the
same hardened resolver as DCR; missing fetcher configuration returns 503.
Migration 0252 grants the control role only the four policy columns, with no
redirect, secret or runtime-binding authority. The writer locks and rechecks a
live environment and the original policy/redirect revision before its audited
update. Historical identity migration and full rollout qualification are still
required before deployment.

A bound public identifier survives a later pairwise switch as a documented legacy
privacy exception. Historical identities issued before binding persistence are
not reconstructed by these methods. Explicit rollout/migration semantics remain
required; no live client has been switched. Configuration snapshots now carry
stored policy and redirects from one coherent read, excluding salts, runtime
bindings and revisions. Offline validation checks policy shape without fetching;
it cannot certify current sector-document ownership. Older snapshots default to
public policy. The promotion engine still excludes all OAuth clients because
their IDs are scoped. Database qualification checks that a real promotion retains
the target's identity policy, salt and existing user binding without a reset.
Algorithm policy remains promotable as required by #19.

### Retained public history backfill primitive

The store now exposes `backfill_public_subject_history` for one client's retained
history while its policy is still public. It unions grant subjects, refresh-family
subjects and impersonators, client-session subjects and impersonators, and
impersonators on sessions referenced by grants. Every edge is scope constrained
and joined to a registered user in that scope. Service principals and foreign
subjects do not become user bindings. Revocation, expiry and soft deletion do not
erase history; recovering a binding does not restore login eligibility.

Each audited transaction locks and compares the expected public policy revision
and redirects, then inserts at most 500 immutable bindings. Existing bindings,
including pairwise bindings on a client later changed back to public, remain
unchanged. The response counts examined users separately from inserted bindings
and returns an exclusive user cursor when another page exists. Retrying a page
is safe and records another attributed backfill attempt. Failed audits roll back
the entire page. The page limit bounds output and writes, not total source scan
cost; production-size query qualification remains required.

This is not yet an operator API, rollout certification, or automatic migration.
Quiesce old issuers before the final pass and policy cutover: an old binary can
write new public history without consulting immutable bindings. The retained
edges can also include authorization attempts that never returned a token, so
their public bindings conservatively preserve recorded relationships rather
than prove token receipt.

Retained history is incomplete for some legacy paths. The transaction-token
prototype records issuance only in the audit log, which retention can prune;
external exchanged actor chains can lack a durable receiving-client/user edge.
Owner-level history removal and tenant purges are not repaired by this primitive.
Do not infer completeness from reaching the last page. An explicit strategy for
these gaps, operational cutover, and live relying-party qualification remain
prerequisites to enabling pairwise on existing clients. No live client has been
switched by this work.

### Legacy activation guard

Migration 0253 gives every existing client `subject_history_ready=false` and
keeps that default for old INSERT shapes. All five current creation paths set
it true on INSERT because their clients begin with the binding-aware issuer.
This requires every serving issuer to be upgraded before activation; creation
readiness is not a claim that old binaries understand the new policy.

The database refuses pairwise policy while readiness is false. Both policy
repositories recheck readiness under their client lock, and readiness changes
advance the shared policy revision to invalidate outstanding validation.
Neither ordinary runtime role receives UPDATE authority for the new field.
The management policy view reports `history_ready`; a pending pairwise PUT
returns 409 before sector fetching. DCR checks the effective metadata after its
saved policy chain and refuses pending pairwise activation before fetching or
registration-token rotation. Public issuance, public metadata updates and
history backfill remain available. A caller cannot set readiness through either
policy request, and finishing the last history page never sets it implicitly.

The migration intentionally refuses a pre-existing pairwise row from an
unsupported partial deployment rather than declaring its history complete or
rewriting its identity. Existing supported deployments have public policy. Do
not manually flip readiness to bypass reconciliation: the audited operator
workflow to import relying-party evidence, cover retained history and finalize
cutover is still to be implemented. This guard is an intermediate rollout
protection, not completion of existing-client pairwise support. Readiness is
runtime migration state and is not a configuration snapshot or promotion field.
