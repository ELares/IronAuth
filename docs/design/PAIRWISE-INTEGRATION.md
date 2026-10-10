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

The management workflow below exposes this primitive. It is not rollout
certification or automatic migration.
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
The data plane receives no UPDATE authority for the new field. Migration 0254
adds that authority only to the control plane for the audited reconciliation
workflow below.
The management policy view reports `history_ready`; a pending pairwise PUT
returns 409 before sector fetching. DCR checks the effective metadata after its
saved policy chain and refuses pending pairwise activation before fetching or
registration-token rotation. Public issuance, public metadata updates and
history backfill remain available. A caller cannot set readiness through either
policy request, and finishing the last history page never sets it implicitly.

The migration intentionally refuses a pre-existing pairwise row from an
unsupported partial deployment rather than declaring its history complete or
rewriting its identity. Existing supported deployments have public policy. Do
not manually flip readiness to bypass reconciliation. Use the audited workflow
below. Readiness and its receipt are runtime migration state, excluded from
configuration snapshots and promotion. The workflow is locally qualified; a
live cutover has not yet been performed.


### Operator reconciliation workflow

All paths below are relative to
`/v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}`.
GET requires `management.read`. Each PUT requires `management.write_config`,
configured fresh privilege, a live environment, and the current policy revision.
Every successful PUT writes an attributed audit in the same transaction.

1. Stop every legacy issuer before the final recovery pass. Deploy only binaries
   that persist client bindings, and retain a restorable database/key backup.
   Neither an API checkbox nor a database scan can prove that an old process has
   stopped. Do not activate pairwise while an old issuer can serve this client.
2. Read `GET /subject-policy` and `GET /subject-history`. A legacy client starts
   public with `history_ready=false`. History reports retained users, missing
   bindings, non-public conflicts and any existing receipt. These counts are not
   a complete relying-party roster. New clients are ready without a legacy receipt.
3. Recover retained history using `PUT /subject-history/backfill` with
   `{"expected_revision":N,"limit":100}`. Use the returned opaque `next_cursor`
   in the next request until it is null. The configured page maximum and a hard
   cap of 500 bound each page. Cursors bind the client, scope and revision, not
   completion authority. Retrying a page is safe and reports zero newly inserted
   bindings where rows already exist. Each successful retry records an attempt.
4. Reconcile the relying party's historical public account/actor identifiers with
   retained grants, sessions and available audit evidence. Cover audit-only
   transaction tokens and external exchanged actors explicitly. Where necessary,
   call `PUT /subject-history/bindings` with
   `{"expected_revision":N,"user_ids":["<scoped account ID>"]}` in batches of
   1..500 rows. Duplicates collapse. Only existing users in the client's scope
   are accepted, including soft-deleted accounts without reactivating them. An
   unknown account or conflicting binding refuses the whole batch. This API
   accepts only local IDs whose historical public value is that same ID; it
   cannot assign an arbitrary external subject. The audit records a SHA-256 of
   the sorted, unique IDs joined by newline, plus the count, rather than the roster.
5. Retain an evidence artifact describing the client/scope, relying-party sources,
   recovered public IDs, excluded non-user actors, any historical limitations,
   and confirmation that old issuers are stopped. Compute its SHA-256. If missing
   history cannot be reconciled, keep the client pending; use a new pairwise client
   for a new integration rather than claiming the old client is fully recovered.
6. Call `PUT /subject-history/reconciliation` with the current revision, lowercase
   `evidence_sha256`, and explicit true values for `legacy_issuers_stopped`,
   `external_history_reconciled`, and `public_identifiers_retained`. The server
   independently rescans all retained edges under the client lock; skipped pages,
   a forged cursor or an earlier zero count cannot bypass missing/conflicting
   bindings. It checks digest syntax, not the artifact's contents: external
   completeness is the authorized operator's attestation, never an automatic
   server guarantee. Readiness, evidence digest, application-clock time and audit
   commit together. Failure leaves all of them unchanged.
7. Read the returned new revision and receipt. Reconciliation leaves the client
   public. Use the ordinary `PUT /subject-policy` to activate the validated pairwise
   policy. Existing public bindings remain unchanged; previously unbound users
   receive pairwise identifiers. Verify ID tokens, UserInfo, token consumers and
   relying-party account continuity before exposing the change to users.

A repeated successful reconciliation cannot replace its receipt. A stale repeat
returns 409; GET reports committed status after an ambiguous response. Import
and reconciliation refuse an already-ready client. History import is a union of
public bindings, never a replacement roster. No endpoint updates or deletes an
existing binding. Mutation failures roll back their audit and writes together.
Migration 0254 grants the control role SELECT/INSERT on bindings and UPDATE on
only the readiness/receipt columns; it grants no binding UPDATE/DELETE and no
readiness mutation to the authentication data plane. The policy repository stays
separate from the recovery repository.

Local qualification covers real control-role HTTP requests, rejected permission
and scope combinations, fresh-privilege requirements, opaque cursor context,
retries, missing/conflicting history, audit rollback, concurrent finalization,
and a reconciled legacy client issuing stable verified token/UserInfo identities.
The encrypted CLI backup/restore harness additionally recovers three scopes
(two environments in one tenant and an environment in another tenant) after
DEK rotation, salt re-encryption and KEK rotation. Fresh restricted-role pools
and OIDC identity resolvers retain the exact salt, policy, history receipt and
existing public/pairwise bindings. A previously unbound account derives the
expected identity from restored material; a second pool reads that binding.
Missing or wrong envelope master keys refuse derivation without creating a
binding or replacing the salt. Database grants and forced RLS survive recovery.
This is local database/identity-resolver evidence, not browser or HTTP token
issuance against a restored deployment. Follow the separate role/key recovery
requirements in [operations](../OPERATIONS.md#upgrade-back-up-and-recover).

The grant-heavy source workload below provides local scale evidence. A live
relying-party cutover still needs separate evidence. The scan limit bounds
output and inserts, not total
query work. This API must not be treated as proof that all original #19 or Civio
milestone requirements have been completed.

### Retained-history scale qualification

The opt-in `grant_heavy_history_scale_qualification` test registers 10,000
accounts, seeds 100,000 revoked grants for the selected client, and adds up to
one million revoked grants for another client in the same environment. It calls
the actual control-role repositories, checks exact retained coverage, recovers
all users in 20 pages of 500 and completes reconciliation with zero missing or
conflicting bindings. A restricted-role `EXPLAIN (ANALYZE, BUFFERS)` records the
grant access path with forced RLS. Run it explicitly:

```sh
scripts/with-test-db.sh cargo test -p ironauth-store --all-features \
  --test client_subject_identity grant_heavy_history_scale_qualification \
  -- --ignored --nocapture
```

Before migration 0255, the grant access path scanned all 1.1 million rows and
discarded one million unrelated rows. With `grants_client_history_idx`, it uses
the scoped client index; the observed grant access time changed from 97 ms to
12 ms and shared blocks accessed fell from 45,834 to 4,256. In these local runs,
the complete 20-page recovery changed from 2.88 seconds to 1.02 seconds with the
index alone. These are individual local observations, not latency guarantees or
a concurrent production-load qualification. The additional batched insert sends
one statement per page instead of up to 500 individual insert statements;
with both changes, the same complete recovery took 0.56 seconds locally.

Migration 0255 builds a normal transactional index and blocks grant writes while
building it. Apply it during the migration maintenance window and allow capacity
for the index. It neither prunes history nor changes permissions. Refresh-family
and client-session source edges already have scoped client indexes. Functional
tests exercise all history edge types, but this large dataset is specifically
grant-heavy; it does not establish equivalent timings for every source mix.
Each page can still scan the selected client's history to deduplicate users.
Neither the row limit nor this index bounds total work for an arbitrarily large
client, and the externally reconciled history requirement remains unchanged.
