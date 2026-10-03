# Recipient mailbox verification

The subject-bound mailbox ceremony is separate from email OTP login. It proves
ownership for the signed-in account without creating a session, bypassing a
stronger factor or changing workspace/project access. Integration is under
qualification in #1475; external mailbox delivery and the complete Civio
invitation journey have not yet been established.

## Operator configuration

The default is disabled. Opt-in configuration requires OIDC, an HTTPS public URL
and a fixed SMTP relay with verified TLS:

```toml
[server]
public_url = "https://auth.example.test"

[oidc]
enabled = true

[oidc.recipient_verification]
enabled = true

[oidc.recipient_verification.smtp]
host = "smtp.example.test"
port = 587
security = "start_tls"
sender = "verification@example.test"
message_id_domain = "auth.example.test"
username = { env = "RECIPIENT_SMTP_USER" }
password = { file = "/run/secrets/recipient-smtp-password" }
max_in_flight = 4
```

Use `implicit` for TLS from connection establishment, normally on port 465.
There is no plaintext or certificate-verification bypass. Username and password
are optional together for a relay that does not require client authentication.
Unreadable credentials refuse startup; secrets are redacted from configuration
serialization and transport errors. Relay host, sender and credentials are
operator configuration, never request inputs.

The relay and its certificate chain must be trusted by the operating system.
Each delivery has a four-second overall deadline, a three-second SMTP command
timeout, and a concurrency limit from 1 through 32 with no waiting queue.
Saturation refuses before network activity. The adapter makes one attempt and
does not automatically retry or fail over. Its challenge-bound Message-ID is a
correlation key, not a promise of relay-side deduplication.

## Hosted flow and continuation

Open `/t/{tenant}/e/{environment}/account/email-verification?return_to=...` with
an encoded local `/authorize?...` request. Its client must belong to the same
scope and its callback must exactly match a registered HTTP(S) redirect. External
URLs, duplicate authorization fields and indirect PAR/JAR resumes are refused.
The normal authorization endpoint validates the resumed request again.

The page requires a direct session authenticated within five minutes. It displays
that account's stored primary mailbox, sends a code only after an explicit user
action, and accepts an eight-digit code. A stale or absent session asks the user
to return to the application, sign in and reopen verification. All mutation
requests require the exact same Origin; the request cannot select a subject.

Delivery states are literal:

- `accepted`: the SMTP relay accepted the message; this does not prove inbox receipt.
- `refused`: the attempt was explicitly refused, including local saturation.
- `uncertain`: acceptance could not be established, such as a lost SMTP reply.

The page retains only a non-secret challenge handle and display deadlines in
session storage. It never stores a code, email address, token or application
continuation there. A lost send response does not trigger an automatic retry.
The user can explicitly request another code after the durable one-minute
cooldown; a new challenge invalidates its predecessor. A lost verification
response is recovered by reloading and reading current server-owned verification.

Cancellation consumes only the authenticated subject's pending challenge under
the same ownership lock used by issue/verify, with a same-transaction audit row.
It works after a lost send response without requiring the challenge handle.
Repeating cancellation is harmless. Cancellation does not revoke an already
verified identifier or change application access.

## Current ownership and relying parties

Existing accounts are not presumed verified or indexed. The scoped store refuses
recipient operations if primary-identifier indexing is incomplete or ownership
is ambiguous. Prepare existing scopes through the management API below; direct
edits to verified flags or arbitrary OIDC claims are not substitutes.

After verification, the relying party must obtain a fresh online result from
`POST /t/{tenant}/e/{environment}/account/recipient-proof` using the current direct
end-user access token, expected email and a fresh nonce. Validate issuer, client
audience, public subject, nonce, purpose, ownership revision and the short expiry.
The proof checks current identifier ownership and direct live-session provenance;
profile labels and arbitrary stored OIDC claim documents do not establish it.
Recheck for a new invitation acceptance rather than treating a retained email
claim as an indefinitely current assertion.

The application still owns atomic invitation acceptance, permitted grants, audits
and the saved destination. Mailbox verification alone grants none of those.

## Preparing an existing environment

Upgrade every identity-writing process before preparation. Apply migration 0247
through the normal migration workflow. It grants only the control-plane role
permission to update the two primary-recipient index columns; the serving role
cannot rewrite them. Retained deleted users are included because their canonical
identifiers still reserve ownership.

1. Read `GET /v1/tenants/{tenant}/environments/{environment}/recipient-verification/index?limit=100`
   with an unconfined environment-authorized credential carrying `management.read`. The
   preview decrypts the next bounded batch without changing index or verification
   data, and remains readable in a soft-deleted environment. It returns counts, never identifiers, hashes or mailbox addresses.
2. Apply `POST` to the same path with `management.write_users`, fresh privilege
   when sudo is configured, an `Idempotency-Key`, and the JSON body
   `{"limit":100,"all_writers_upgraded":true}`. The acknowledgement records the
   caller's rollout prerequisite; it is not server attestation of deployed binary
   versions. The allowed batch size is 1 through 100, default 100.
3. Retry a lost response using exactly the same key and body. A replay returns
   the original batch result without advancing. Use a new key for each subsequent
   batch until `unindexed_users` is zero. Each batch's index updates, audit entry
   (`recipient_verification.index_backfill`) and replay receipt commit together.
4. Inspect `ambiguous_indexed_mailboxes`. This covers currently indexed primary
   and typed-email ownership; later batches can reveal further conflicts. The
   operation never merges accounts, chooses an owner, rewrites credentials, or
   marks a mailbox verified. `index_complete=true` means metadata coverage only.
   Affected ambiguous accounts remain unable to obtain recipient proof.
5. Complete the hosted mailbox ceremony and test a fresh relying-party proof.
   A pre-existing verified flag alone does not satisfy that ceremony.

Unreadable ciphertext aborts the entire batch, preserving all account data and
its existing indexes. Repair its underlying key/data problem through the normal
recovery process before retrying. A five-second per-statement timeout bounds
queries and lock waits; failed requests do not commit partial batches. The
preview/apply and normal identity writers share the scoped ownership lock.
An older writer can introduce another unindexed user after preparation; current
proof checks then fail closed again. A completed report is not a permanent
readiness certificate. Credentials, permissions, unconfined scope, current environment
liveness and configured privilege freshness are checked before a POST replay.

## Qualification boundaries

Local TLS SMTP tests prove acceptance/refusal/timeout handling, certificate and
STARTTLS checks, formatting and concurrency bounds. Scoped PostgreSQL/HTTP tests
prove the challenge, cancellation, current-proof and hosted-page authentication
boundaries. Rendered-page Chrome fixtures prove UI behavior only. None substitutes
for actual permitted-mailbox delivery, source/build/schema-matched deployment,
representative users or the completed Civio invitation journey.
