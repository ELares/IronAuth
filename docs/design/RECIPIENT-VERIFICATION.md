# Subject-bound recipient verification core

This is the gated prerequisite for recipient-bound invitations, tracked by
[IronAuth #1436](https://github.com/ELares/IronAuth/issues/1436) and
[Civio #456](https://github.com/encryptixio/civio/issues/456).
The testing-only delivery is tracked separately by
[child #1437](https://github.com/ELares/IronAuth/issues/1437).
It does not complete either invited-user journey. Production has no installer or
configuration switch for this flow. All routes return `503
recipient_verification_unavailable` by default. The only installer is behind the
`testing` feature and accepts an owned local transport fixture.

## Supported identity and authority

An ordinary email/password signup can verify its own stored primary mailbox.
The subject comes from its current session, never the request body. Start and
verify require a matching Origin, direct non-impersonated session, and an
`auth_time` no more than five minutes old. Active account state is checked again
inside the verification transaction. A wrong, ambiguous, inactive, replaced or
out-of-scope owner gets a uniform refusal.

Primary user inserts now record the existing email canonicalizer's blind index.
This index is non-unique: raw login lookup and existing uniqueness policy are
unchanged. Typed identifiers use the same canonicalizer. Verification refuses
multiple canonical primary or typed owners, even when a scope's general login
policy permits non-unique identifiers. The two user insertion seams, typed
identifier insertion and recipient ownership checks share a transaction lock,
so a verification cannot race an insertion of an ambiguous owner. No raw address
is added to the new index or challenge tables.

Delivery always targets the account's stored primary address, never a submitted
alternative spelling. Additional-mailbox enrollment is not supported by this
core. A correct code creates or verifies this same subject's typed email row,
records its exact identifier ID and verification revision, consumes the challenge,
and appends the audit event in one transaction. Session rows, passwords, token
issuance and authentication strength do not change.

Every new verification gets a new revision. A current proof checks the current
subject, complete canonical index, absence of ambiguity, exact current identifier
ID and verified flag. An arbitrary stored OIDC `email_verified` claim or an
admin-created verified identifier does not create a purpose-bound verification
record. Removing/replacing the identifier invalidates its prior record.

## Gated HTTP contract

All paths are beneath `/t/{tenant}/e/{environment}/account`. Bodies are JSON,
limited to 2048 bytes, with unknown fields refused. Query parameters are refused.
Responses contain `Cache-Control: no-store`; no code, address or raw transport
error is returned. GET does not issue or consume a challenge.

| POST suffix | Input | Accepted result |
| --- | --- | --- |
| `email-verification/start` | `{"email":"owner@example.test"}` | 202 with `challenge_id`, `delivery:"accepted"`, `expires_in:300`, `retry_after_seconds:60` |
| `email-verification/verify` | `{"challenge_id":"rcp_...","code":"12345678"}` | 200 with `verified:true` and `verification_revision`; no Set-Cookie |
| `recipient-proof` | `{"email":"expected@example.test","nonce":"<32-128 base64url characters>"}` | 200 online match bound as described below; no Set-Cookie |

Start hands an eight-digit code to a purpose-specific transport through a
five-second deadline. Its database representation is an Argon2id verifier, and
hashing uses the existing bounded pool. A challenge lasts five minutes, allows
five attempts, and is replaced by reissue. A database-enforced one-minute
cooldown bounds cross-node sends. The ordinary regulation and request-quota
checks also apply.

`delivery:"accepted"` means transport acceptance, not inbox delivery. A refusal
or uncertain result is HTTP 503 with `delivery:"refused"` or `"uncertain"` and the
challenge handle. Timeout is uncertain. The challenge is not falsely marked
verified and a received code remains usable. A lost response/reload recovery
journey is still required before enablement. No implementation can obtain
readiness by wrapping the existing null/logging sender or ordinary message
outbox; those do not implement the new purpose-specific contract.

## Online relying-party proof

This is an online TLS response, not a transferable or signed bearer credential.
The caller presents an end-user JWT access token. The existing UserInfo JWT
validation checks signature, issuer, client audience, token/grant revocation,
openid scope and DPoP. DPoP is bound to this endpoint's actual scoped URL and
POST method, not UserInfo's URL. The new door additionally requires a currently
live, non-impersonated session on an authorization-code grant and refuses an
`act` claim. Machine, token-exchange and opaque credentials are outside this
first supported profile. Opaque resolution lacks the actor provenance needed
for a direct-user guarantee; it is refused rather than guessed. Existing
UserInfo support for opaque credentials is unchanged.

The response carries `purpose:"invitation_recipient"`, `iss`, `aud`, `sub`, the
caller nonce, `recipient_matches:true`, `verification_revision`, and
`verified_at_unix_micros`, `checked_at_unix_micros`, `expires_at_unix_micros`.
Expiry is at most 30 seconds and never later than token expiry. Stored OIDC
claim documents are not read on this path. A relying party must bind every
field to its configured provider/client, exact signed-in subject, expected
recipient and freshly generated nonce. It must make a new online check for a
new acceptance, not persist this response as an evergreen profile claim.
The endpoint proves current provider-recorded ownership, not real-time inbox
possession on each read; the verification timestamp is explicit.

## Remaining enablement acceptance

Issue #1436 remains open until the following integration is qualified:

1. A real bounded secret-safe transport, with configured sender/recipient
   restrictions, private credentials and truthful refusal/unknown outcomes.
   Plaintext challenge secrets must not enter ordinary outbox/audit/log records.
   Actual owned-mailbox receipt must be demonstrated before claiming delivery.
2. A hosted verification and recovery journey for normal password-signup users,
   including sign-in/reauth return, wrong account, resend/cooldown, wrong/expired
   code, lost response/reload and keyboard/narrow-screen behavior.
3. A controlled index backfill for existing scopes. Existing rows remain
   `recipient_email_indexed=false`; no verified backfill is inferred. Inspect
   every retained primary identifier, collision and decryption failure. All
   writers must be upgraded before enablement, including import/admin writers;
   mixed old writers can create unindexed rows and are not a ready profile.
   The new ceremony fails closed if any row in the scope is unindexed.
4. A deliberate production installer after those gates, an isolated deployment
   with source/build provenance, and owned-account acceptance evidence. This
   core does not upgrade or reseed a running provider.
5. Civio's transactional recipient/project invitation acceptance and recovery,
   using this online proof and current inviter/project authority. Nothing in
   this provider core creates Civio workspace membership or project access.

## Required historical migration repair

Upstream migration 0237 attempted to replace column five of
`environment_guardrails`, introduced by 0062 as `auto_link_posture`, with
`fapi_hardened`. PostgreSQL refuses that replacement, so a fresh chain could
never reach a later appended repair. The corrected 0237 retains the prior
column and appends its new one.

The one explicit checksum compatibility exception admits only version 237,
name `fapi_hardened`, and this exact pair of SQL digests:

- Recorded old bytes: `02bd786d62041c24c5a6268b8c33bf53cdcdc6610701b42a509c514dbd6f2530`.
- Corrected source: `68cd229209d09ff7045ac02c3a16d60b9ec705b3c633617862f3b75d335dd81b`.

Existing ledger entries are never rewritten. Every other altered checksum,
including another edit to 0237, remains an error. The migration immutability
gate admits only the same exact path and old/new digest pair; its temporary
Git-fixture tests reject other edits, paths, missing files and symlinks.
Forward migration 0241
validates the precise old/corrected view projection and parsed definition. It
appends the missing old column for an operator who previously worked around
0237, while preserving existing column positions, view owner, grants, options
and compatible dependent objects. No table data is rewritten and there is no
DROP/CASCADE of the serving view. An unexpected view definition or shape is
refused for explicit operator review. Fresh corrected chains take the no-op
branch. Migration 0242 supplies the missing column-scoped UPDATE grant for
`clients.userinfo_signed_response_alg`, added by upstream 0238 and always
written by the existing dynamic-client metadata updater. Only `ironauth_app`
and `ironauth_control` receive that one-column grant. Migration 0243 adds the
recipient-verification core.
