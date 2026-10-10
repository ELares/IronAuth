# Production pairwise subjects (#19)

The original #19 and hosted-profile #1385 criteria remain open. At merged base
`9d31109c`, production uses `resolve_public_subject` and `ClientRecord` has no
persisted subject policy. Generic hashing tests do not qualify token/UserInfo
parity. The sector resolver changes in this branch are prerequisites, not a
production pairwise implementation.

## Sector selection

Core 8.1 uses the hostname, not the HTTP Host header or its port. The shared
resolver infers one host only if every redirect has that host. Empty or hostless
native sets require an explicit sector document. A supplied HTTPS document is
always fetched through the hardened fetcher and must contain every redirect
exactly, even if the redirects already share a host. The document's host is the
sector. Registration still owns web/native redirect validation.

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
   user is a legacy exception to full pairwise privacy. No migration choice has
   been approved or implemented. Do not claim an immutable public policy has
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
