# Hosted password recovery

Status: implementation plan for #1479. This document does not describe a shipped
password-reset capability. Civio onboarding issue encryptixio/civio#455 depends
on the complete browser journey, not merely the recovery acknowledgement.

## Observed gap

At main `903be846e86370c61e94706a183b1172f4e6ee4a`, the hosted login page links to
`/recover`. Its POST initiates the existing recovery subsystem and returns a
notice without a code form, new-password form or continuation. The normal server
wires a logging verification sender, optionally wrapped by the coarse notice
producer. Recipient-verification SMTP is a separate, purpose-specific adapter.
The authenticated account password-change endpoint correctly requires the old
password and cannot substitute for lost-password recovery.

A dedicated verified account reproduced this on the owned evaluation deployment:
actual mailbox-verification mail arrived, then the forgot-password request
returned 200 with no additional message or usable completion action. No existing
account credential was changed. This is a functional reproduction, not evidence
that recovery completed or that internet delivery works.

## Required user journey

1. Follow Forgot your password from the current hosted authorization interaction.
   Preserve its validated client, scope and return destination server-side.
2. Enter the identifier. Give the same acknowledgement and code-entry shape for
   known, unknown and ineligible accounts. When delivery is not configured, show
   an honest deployment-wide unavailable state before looking up an identifier.
3. Deliver a short-lived, purpose-specific code to the account's current verified
   channel. A logging or no-op sender cannot enable this ceremony. Show clear
   expiry, retry and cancellation guidance without revealing account existence.
4. Submit the code and a new password through the hosted form. Enforce password
   normalization, strength, screening and bounded hashing. Do not send either
   secret to the relying party, query strings, logs or plaintext persistence.
5. Atomically consume the reset authority and change the credential, with audit
   and required invalidation. Return to ordinary authentication for the original
   application destination. Recovery must not itself grant an application role.
6. After an interrupted response, distinguish a committed completion from an
   unused or expired attempt without applying another credential change. A fresh
   browser must have a usable route to sign in with the chosen password or
   explicitly request fresh recovery; it must not depend on an operator edit.

## Authority and state

Use a dedicated scoped reset challenge and browser-bound ceremony. Do not turn
recipient-verification codes or ordinary login OTPs into password-reset tokens.
The challenge must bind the subject, current verified identifier and ownership
revision, original credential generation, recovery case, authorization context,
expiry and bounded attempt budget. Generate randomness and timestamps through
`ironauth-env`; hash codes through the existing admission-controlled pool.

Known and unknown requests must preserve the existing recovery-path regulation,
risk and anti-enumeration work. An unknown-account ceremony must not gain a
completion oracle merely because its page or stored shape differs. A real
recipient is selected from current store-owned verified identifiers, not an
untrusted address supplied with the completion request.

A successful credential mutation needs a single audited database transaction:

- Lock and revalidate the scoped challenge, current subject/credential generation,
  current verified channel, and applicable recovery case/cancellation/delay state.
- Reject stale, exhausted, cancelled, expired, cross-purpose or already-consumed
  authority. A concurrent password change must invalidate an older reset.
- Consume the authority and persist the new verifier and completion fact together.
- Reuse the existing session-ended cascade for all sessions and refresh families;
  apply the documented token/device invalidation policy and retain actual actors.
- Roll everything back on a store failure. Retain a bounded completion receipt so
  a lost response cannot leave a reusable code or an untracked password change.

The existing `users().change_password(..., None, ...)` has the required session
cascade, but calling it after independently consuming a code is not atomic.
Factor out transaction-owned primitives rather than composing separate writes.
Do not treat a consumed code or a minted ordinary session as reusable reset
permission. Retry/status reads must not reveal a new verifier or another user's
completion, and must not silently reinterpret an edited new-password request.

## Stronger factors and notification

Password reset changes only the password credential. It must not remove passkeys,
TOTP, recovery codes or required factors, set a password on a passkey-only account
through a weaker path, or issue a weaker primary session. Subsequent login still
passes the existing authentication and step-up gates. Preserve applicable
recovery cancellation, notified-delay and factor-change rules; inability to
satisfy a required rule is a refusal, not an implicit opt-in to downgrade.

Reuse SMTP connection/TLS mechanics where appropriate while retaining distinct
message and challenge types. Operator configuration must explicitly enable a
real, bounded transport. Keep accepted, refused and uncertain delivery facts
separate from account recovery completion. Do not enqueue plaintext reset secrets
in the ordinary notice ledger. Required cancellation/completion notices must carry
usable actions and must not be represented as delivered by a logging fallback.

## Delivery and validation

Implement the store contract and atomic completion first, then explicit delivery,
configuration and hosted handlers, followed by the browser journey. Update the
per-surface STRIDE section and owning changelogs in the implementation PR. Any
administrator capability remains management-API-first.

Real-store coverage must include wrong/expired/replayed proof, bounded attempts,
concurrent completion/cancellation/password changes, scope/subject/ownership
changes, rollback and lost completion responses, and session/token/device
invalidation. Transport checks must cover TLS validation, refusal, timeout and
uncertain acceptance without logging secrets. Hosted checks must cover CSRF,
validated return destinations, uniform ineligible responses and preserved
stronger-factor gates.

Run the repository gate before the fixed-head review. Then qualify a dedicated
account through real SMTP and headed Chrome: recovery mail, code and new password,
old-password refusal, new-password success, interrupted recovery and original
Civio destination, with no implicit Civio membership or project grant. Retain the
actual build, store, fixture and failures. An isolated inbox is not internet
mail delivery; automated browser observations are not the required human study.
