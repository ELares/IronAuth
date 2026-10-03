# Hosted password recovery

Status: implementation in progress for #1479. This document does not describe a shipped
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

The existing `users().change_password(..., None, ...)` has the browser-session
cascade, but preserves offline refresh families. Recovery must also revoke those
families and their grants through the subject-wide hard-kill cascade in the same
transaction. Calling ordinary password change after independently consuming a
code is not atomic.
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

## Storage implementation progress

Migration 0249 and `PasswordResetChallengeId` introduce only the storage boundary.
The table separates pending, completed, cancelled and refused metadata, requires
an indivisible real-account binding, and bounds attempts and expiry. Real-store
schema tests exercise forced row-level security and runtime column grants.
Hosted delivery orchestration and the reset form remain unimplemented. The repository now
implements completion as described below; deployment remains disabled. A valid
metadata row is not proof that a password was changed; the audited completion
transaction and its credential/invalidation effects must be verified together. No deployment is activated by this additive migration alone.

The existing account password change now delegates its verifier write and session
cascade to a private transaction-owned primitive. The public account endpoint
still requires its existing authentication. This refactor does not confer reset
authority or revoke offline families on ordinary password changes. Reset completion
uses it within its own larger audited transaction.

Scoped reset issuance now derives the verified mailbox revision and original
password digest under the shared recipient-ownership and user locks, requires a
pending standard lost-password case for that subject, and persists its browser
binding and validated authorization continuation. Reissue is subject to a durable
one-minute cooldown and cancels the prior pending challenge; completed receipts
are retained. Decoys carry no account binding. Hashing-input reads require the
matching browser binding, scope and expiry. Pending rows need remaining attempts;
completed rows permit only exact-request receipt evaluation.
Neither issuance nor a read is permission to mutate a credential. Completion must
recheck all bound generations and the case delay/cancellation under the same lock
order. A long held case also needs a usable fresh-code path after the delay; a
short code must not be treated as bypassing or satisfying that delay.

Atomic completion now rechecks the browser binding, exact verifier snapshot,
current verified ownership and password generation, pending case and delay under
ordered locks. Wrong codes consume at most five attempts; stale authority closes
the challenge. Correct proof cannot bypass a held case. Completion changes the
password, consumes proof, persists a keyed request receipt and resulting password
digest, completes the case, revokes sessions and offline refresh families/grants,
and invalidates every remembered device in one audited transaction. Lost-password
recovery deliberately invalidates remembered devices even where an ordinary
authenticated password change is configured to preserve them.

Within the original challenge expiry, the same browser can reread the completed
verifier and retry. Only a matching code, keyed request digest, still-current
verified owner and resulting credential returns the previous continuation. A retry
does not rewrite the verifier, reset its timestamp, or emit another completion.
Expired receipts require ordinary sign-in or a fresh recovery request. The hosted
caller must compute the keyed digest from the exact normalized request, enforce
password policy and screening, admit hashing, and satisfy actual required recovery
notifications before calling completion. These caller obligations are not wired yet.
Further race/invalidation coverage and transport/hosted qualification remain before
the full gate, review and deployment.

The real-store authority checks also cover a newly verified mailbox revision
invalidating both pending proof and a completed receipt, receipt refusal after a
later password change, and wrong-browser/scope/verifier requests leaving the
attempt budget untouched. A forced final audit failure leaves offline families,
their grants, remembered devices and the session-ended outbox unchanged. Concurrent
completion/cancellation and completion/password-change checks assert the committed
winner and current credential, with a deadline to catch lock hangs. These checks
exercise isolated database fixtures; they do not establish delivered recovery mail,
Internet delivery, or a completed hosted browser journey.


Purpose-specific reset SMTP now renders a code with its exact expiry and a
provider-origin cancellation link, or a separate completion notice without a code.
Both reuse the existing bounded certificate-verified relay mechanics, while keeping
reset types and message identities separate from mailbox verification. Constructor
validation currently requires the root HTTPS public provider URL, not a scoped
issuer path. Actual TLS fixture tests cover accepted/refused/uncertain outcomes and
certificate refusal; they do not establish Internet delivery. Independent default-off operator configuration and concrete state installation
are now wired; hosted orchestration remains unwired. The caller must
supply the actual recovery case's cancellation capability and send a completion
notice only after the credential transaction commits.


The transport is configured separately with `oidc.password_recovery.enabled` and
`oidc.password_recovery.smtp`. SMTP fields and secret references follow the shared
relay contract in the generated configuration reference. Enabling requires OIDC,
a root HTTPS `server.public_url` and valid relay settings. The binary resolves
credentials only when enabled and refuses startup if they cannot be read. The
state availability method reports configured delivery, not tested relay reachability
or a completed hosted reset. No live deployment has been enabled by this change.


The reset challenge now records an audited terminal delivery result and accepted
channel count before credential completion is permitted. Pending, refused and
uncertain delivery cannot authorize completion or receipt replay. A terminal result
cannot be relabelled through the repository; late results for an expired, cancelled
or consumed challenge fail. Incorrect codes retain the same five-attempt budget
for undelivered real and decoy challenges. Schema constraints also require accepted
delivery for a completed challenge. The trusted hosted caller must aggregate actual
transport acknowledgements for the code and every required owner notice; the
existing recovery logging sender cannot establish this result. Store tests simulate
adapter outcomes and do not establish actual notification delivery. Hosted wiring
and delayed-case reissue with a usable cancellation action remain outstanding.


Fresh-code cancellation is stored as a separate immutable SHA-256 token digest on
each real reset challenge. The hosted caller must generate a fresh high-entropy
cancellation token naming the existing case for every reissue; a digest of a public
handle is not acceptable production input. Decoys have no cancellation digest.
Resolution accepts both the original case token and retained reset-token digests,
with matching scope, subject, standard method and lost-password entry point.
The case remains the owner of delay and terminal status. Expiring or replacing a
code does not revoke its cancellation link, reset the delay or create a new case.
Terminal cases cannot be cancelled again or authorize a new password change.
Challenge cleanup must retain these digests while the associated case is pending.
This avoids storing recoverable cancellation secrets or requiring another operator
key. The repository tests exercise reissue after the original code expires and
both cancellation and completion outcomes; hosted orchestration remains pending.


The browser-binding helper now generates a separate 256-bit secret through Env.
Only its SHA-256 digest is stored with the reset challenge. The wire cookie is
`__Host-ironauth_reset`, Secure, HttpOnly, SameSite=Lax, Path=/, with no Domain and
a fixed ten-minute maximum age. Its header is marked sensitive. Parsing bounds
all Cookie headers together and rejects duplicate reset names or malformed values.
The authoritative row expiry can be shorter; reading the cookie never proves a
live case. Do not renew it on reads or erase it immediately after completion,
since the original browser needs its bounded exact-response retry opportunity.

CSRF uses HMAC-SHA256 keyed by the browser secret and bound to the scoped challenge.
The completion receipt uses a different domain and length-prefixed challenge,
exact code and already normalized new password. A restored cookie reproduces the
receipt across provider restarts without storing plaintext or adding an operator
key. A changed browser, challenge, code or normalized password produces another
digest. The handler must still validate same-origin POST, bound the form, enforce
policy/screening and admitted hashing, and recheck the store-owned scope/lifetime.
These helpers do not yet expose a reset route or complete the browser journey.


A held case's initial horizon is provisional until actual required notifications
are durably accepted. Recording the first accepted reset delivery extends that
horizon to at least acceptance time plus the original configured waiting period.
The case lock precedes the challenge write, matching completion's lock order, and
the horizon, delivery result and audit commit together. A failed delivery or failed
audit cannot consume the notified delay. Once an accepted challenge exists for
the case, resends preserve its established horizon, including fresh codes after
the delay. Retain accepted delivery evidence while the case is pending as well as
its cancellation aliases. Missing/malformed or terminal real cases cannot record
accepted delivery. These real-store tests simulate transport acceptance; the hosted
caller still must establish it from actual required channel acknowledgements.

The SMTP content contract now has a separate requested-owner notice with a usable
cancellation action and a distinct message identity. It contains no reset code.
The primary verified mailbox receives the purpose-specific code; other required
verified channels must receive owner warnings. An email-only adapter must refuse
completion if a required phone channel cannot be notified, not silently omit it.
Selection, fan-out and durable aggregation are still hosted caller obligations.


`password_reset_delivery::send_reset_request` now claims a newly issued real
challenge under its resolved subject before any send. The audited
`delivery_started_at` is set once. Concurrent calls have one winner, and a new
process cannot re-claim an interrupted attempt. No page read, completion or
automatic retry should invoke delivery. A lost claim/outcome response requires
explicit fresh recovery through the usual resend cooldown, not another send of
the same code. A failed outcome write never triggers mail retry.

The coordinator reads currently verified identifiers and schema-permitted recovery
channels. It requires the verified primary returned by issuance, canonicalizes and
deduplicates recipients through the shared identifier policy, bounds the set to
32, and refuses unsupported required channels before sending. Required secondary
email warnings are attempted first; only acknowledgement of every warning permits
the primary code send. Refusal never overwrites uncertainty. A 16-second total
transport budget bounds the batch, retains the acknowledged prefix count, and
records uncertainty for an interrupted attempt. The terminal result is persisted
through the existing delay/audit gate. Schema/channel reads and SMTP facts do not
replace the completion transaction's current ownership/case checks. The hosted
caller must use store-issued subject, primary address, code and case cancellation
capability, and still enforce risk, regulation and authorization-context checks.
Unit adapters test fan-out and timeout semantics. The integrated test below now
covers primary-code SMTP outcomes and durable records; the actual hosted browser
path and integrated secondary-channel fan-out remain outstanding.


The coordinator is now exercised against isolated PostgreSQL and the actual
certificate-verified TLS relay fixture for primary-code acceptance, explicit
refusal and disconnection after transmission. Each case checks the durable claim,
terminal outcome and accepted count, exactly one claim/result audit pair, refusal
of a repeated coordinator call, and an unchanged password verifier. The fixture
sets up verified ownership and verifier metadata through store APIs; it does not
perform hosted registration, verify a reset code, or change a credential. Its
cancellation URL is test content, not evidence of a usable hosted cancellation
journey. This is local delivery integration evidence, not Internet mail or browser
recovery qualification. The test is included with the OIDC `testing` feature.


The reset page renderers now provide an existence-uniform code/new-password form
and distinct server-resolved completion, waiting-period, unavailable-attempt and
deployment-unavailable notices. The form supports password managers and one-time
code entry, retains leading zeros, labels its fields and associates policy/expiry
help. It posts only CSRF proof, code, new password and confirmation; subject, client
and challenge are never trusted hidden form fields. Submitted passwords/codes are
not renderer inputs, so error responses cannot refill them. Configuration-derived
password guidance and the stored expiry/horizon must be supplied by the handler.

Navigation retains the validated application continuation. A missing/expired
attempt explains that an interrupted successful reset can be followed by ordinary
sign-in with the chosen password. Waiting pages explain that fresh codes preserve
the established delay and offer an explicit request page; no notice automatically
submits or sends mail. Completion wording concerns IronAuth sign-in sessions and
does not claim immediate revocation of every relying party's cached access token.
The response helper applies the shared strict CSP, no-store and same-origin referrer
policy. This retains usable Origin metadata for form submissions while refusing
cross-origin referrer disclosure; reset codes and passwords never enter URLs.
These renderers are not mounted yet; semantics/header tests do not establish a
rendered browser journey, manual accessibility qualification or live recovery.


`password_reset().context()` now reads immutable server-owned client, continuation,
code expiry and internal audit subject under the original browser digest and scope.
It accepts no posted account or redirect. Its fixed lifetime is ten minutes from
issuance, matching the maximum cookie window; the shorter code/receipt expiry is
still independently enforced by `challenge()` and completion. Expired or replaced
codes can therefore keep sign-in navigation without becoming usable reset proof.
The context type has no Debug or serialization and its optional subject must never
change the existence-uniform public form. The hosted handler must validate the
stored authorization interaction/client and use the subject only for appropriate
internal audit attribution, never render account existence. Context reads perform
no mutation or audit and return nothing for another scope/browser or at the exact
end of the window. The regression test covers both real and decoy attempts.


The hosted reset module now connects GET/POST processing to the stored context,
browser binding, purpose-specific CSRF, independent recovery-path regulation,
password normalization/confirmation, configured sole-factor policy and strength,
breach screening, admitted code verification/new-password hashing, keyed request
receipt and atomic completion. It rejects browser-supplied authority fields and
retains hash-admission rate/retry headers in HTML error responses. No result mints
a session; successful and replayed completions lead to ordinary sign-in guidance.
The route factory bounds forms to 16 KiB but is deliberately not merged into the
provider router yet. Case preparation/issuance, post-commit notifications and
real-store successful HTTP flows remain required before enablement. Exact retry
across changed or unavailable screening policy also needs qualification: the
current handler repeats screening before it reaches the stored receipt.
