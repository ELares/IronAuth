# Hosted password recovery

Status: implementation in progress for #1479. The branch mounts request, reset and
cancellation handlers in the provider router, with local HTTP/TLS qualification.
This document does not describe a shipped password-reset capability. Civio onboarding issue encryptixio/civio#455 depends
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
Delivery coordination, page rendering and completion handlers are implemented as
described below. The qualification router connects initial hosted issuance; completion notices
and main-router activation remain unwired. Deployment remains disabled. A valid
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
notifications before calling completion. Completion handlers enforce policy,
screening and hashing; initial issuance and post-commit notices remain unwired.
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
The completion handlers below use these helpers. The routes remain unmounted
until the full recovery journey is integrated.


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
The delivery coordinator below implements selection, fan-out and durable
aggregation; initial hosted issuance must invoke it with store-owned authority.


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
provider router yet. Initial issuance and a successful HTTP reset are covered by
the qualification router below; post-commit notices and browser qualification
remain required before enablement. An independent
receipt read now precedes policy/screening as described below.


`password_reset().receipt()` confirms only an already-completed exact request,
using the same locked current-owner, mailbox revision, resulting credential,
completed-case, accepted-delivery, code snapshot and expiry checks as completion.
It accepts no new-password verifier or screening result and performs no mutation,
attempt consumption or audit. Both correct and incorrect code-check results take
the same account/receipt reads; a pending challenge never becomes a receipt.

The hosted handler now normalizes and compares password confirmation, verifies
the code through admission, and checks this keyed receipt before enforcing current
password policy and calling breach screening. Only a matching committed receipt
can return completion at this stage. Every new credential change still passes
policy/strength, mandatory screening and admitted new-password hashing before the
atomic completion write. This separates acknowledgement of an existing result
from permission to make a new change; current ownership and credential changes
still invalidate the old receipt. No receipt grants an authentication session.


An actual HTTP integration test against isolated PostgreSQL confirms that a pending
reset is refused during a fail-closed screening outage without changing its
credential. After a store-fixture completion models an earlier committed response
that was lost, exact HTTP retries succeed both during the outage and under a newly
stricter password policy. Neither retry changes the verifier, adds an audit record,
reflects submitted secrets, or issues a session cookie. This test simulates delivery
acceptance and the initial committed transaction; it does not establish initial
hosted issuance, SMTP delivery or the complete browser journey.


Case preparation now serializes hosted requests under the shared ownership and
account locks. It reuses the newest pending password-rung standard lost-password case and checks
the same current verified-owner/password-holder binding as issuance. If no case
exists, the configured new-case cooldown is checked inside that transaction and
the recipient is selected from the stored primary address and sealed at rest.
Ineligible accounts or audit failures roll back preparation. Reuse does not change
case identity, original cancellation digest or initiation time. The code-issuance
cooldown remains separate and still applies to every fresh challenge.

The required delay duration is stored separately from the absolute horizon. Actual
first accepted delivery anchors the full duration; ordinary resends preserve it
even after the wait has elapsed. Stronger policy can increase the total required
wait from the original accepted notification; weaker policy cannot shorten it.
Legacy pending cases conservatively import their prior duration, and unnotified
cases retain a provisional horizon until actual acceptance. Existing accepted
notification evidence must remain available while the case is pending.

The OIDC preparation helper evaluates current recovery risk and strongest-factor
policy, suppresses blocked/ineligible requests internally, and creates a fresh
high-entropy cancellation token naming the returned case. It calls no logging
sender and claims no delivery. The request qualification handler below invokes it, binds its cancellation
digest to a fresh challenge, and calls actual delivery through the existing
coordinator with the same public form for eligible and ineligible accounts.


Real-store tests exercise concurrent case creation returning one identity, no-op
reuse without duplicate initiation audits, preservation of expired/renewed-code
cancellation aliases, acceptance-anchored delay, and stricter/weaker policy changes.
They also cover rollback of ineligible creation and audit-failed policy updates,
foreign scope, invalid delay and cancellation followed by new-case cooldown. The
OIDC integration fixture verifies risk blocking before mutation, forced delay on
the reused case, and fresh provider-origin cancellation tokens naming that case.
These are preparation/receipt tests, not successful initial hosted issuance or
actual reset-email delivery.


The request qualification router now combines bounded GET/POST `/recover` with
completion routes, without mounting them on the main provider. Before identifier
lookup it revalidates the registered client, exact callback, PKCE and authorization
parameters through the shared validator, peeks live PAR without consuming it, and
checks resource policy and the environment issuer. Direct request objects must
first pass through normal authorization resolution. Invalid/ambiguous context does
not set a reset cookie or issue a challenge. Disabled transport gives an honest
deployment-wide unavailable response. GET renders only; POST checks origin,
proof-of-work when required, and independent recovery regulation.

Each admitted request hashes a fresh eight-digit code, then stores either a real
challenge using current verified ownership and the prepared case, or a decoy for
unknown/ineligible/cooldown-suppressed requests. Both redirect to the same code form
with the same cookie shape. A recent valid browser binding imposes an independent
one-minute resend delay before identifier lookup; the notice links to the current
code form and does not replace or extend its cookie. Context now includes immutable
issuance time for that check. This prevents an accidental repeat click from making
a delivered code unusable by overwriting its cookie with a cooldown decoy.

Actual delivery runs in a transient task through the existing bounded coordinator,
after successful real challenge persistence. SMTP response latency is therefore
absent from the public request response. The task retains secrets only in memory,
uses the durable single-attempt delivery claim, and has no automatic retry or
plaintext queue. A crash requires an explicit fresh request. The unknown branch
still performs the existing decoy risk/store work; identical public form responses
do not establish equal timing for every account-dependent database operation.

The integrated HTTP/TLS/PostgreSQL fixture exercises a real request, receives its
actual code from the local TLS inbox, submits the code and a new password, and
checks the new verifier accepts the new password and rejects the old one without
issuing a session cookie. Registered callback/PKCE/duplicate/fragment rejection,
unknown/unverified code-form equivalence and browser resend protection are covered.
Registration, mailbox verification and an empty breach corpus are test fixtures.
Completion notices, full headed-browser continuation and main-router enablement
remain outstanding; local TLS evidence is not Internet email delivery.


The final request fixture also rejects an unregistered resource indicator, confirms
that request GET creates no challenge/cookie, and checks disabled recovery returns
the same unavailable page for known and unknown identifiers. Cross-origin and
oversized requests set no reset cookie and issue no challenge. These checks do not
replace end-to-end PAR, regulation/PoW, crash/restart or headed-browser qualification.


Completion-notice persistence now shares the credential transaction. The internal
outbox payload contains only the challenge ID; no email, password, code or
cancellation capability is queued. Exact receipt retries do not enqueue again.
An audited claim rechecks original mailbox ownership before any external send.
The code-free notice has no reset-code expiry requirement. Delivery results are
terminal, and a claimed attempt is never automatically resent. The consumer lets
an overlapping bounded SMTP attempt finish, then classifies an unresolved claim
as uncertain after thirty seconds instead of claiming success or duplicating mail.

Store qualification covers pre-completion refusal, one queue row after receipt
replay, concurrent single-winner claims, terminal-result immutability and rollback
of password/case/audit changes when the completion queue insert fails. This is
store evidence only. Worker boot/shutdown wiring, actual completion SMTP delivery,
stale-claim restart behavior and mailbox-reassignment qualification remain pending.


The server now starts the completion consumer when password recovery is enabled,
using the same OIDC state and concrete transport as the serving plane. Enabled
recovery refuses boot without that state or a working control-plane connection
that can enumerate scopes. The worker uses shared outbox settings and optional
IronBus wakeups; it is retained through serving and included in graceful shutdown.
Main-router activation remains separate and has not been enabled yet.

The boot helper qualification uses an isolated database and the actual registered
consumer to drain malformed internal work to a dead letter, without contacting
SMTP. It checks default-off behavior, missing serving state, absent production
control DSN and an insufficient data-plane role. This is helper-level evidence,
not a full binary process restart or signal/shutdown qualification.


The request HTTP/TLS fixture now drains the actual persisted completion job through
`OutboxWorker`, receives a code-free completion email and confirms a second drain
has no work. Refused SMTP and disconnect-after-DATA fixtures retain the committed
password change and exact receipt, record refusal or uncertainty, and do not resend.
These are isolated TLS/PostgreSQL tests, not Internet delivery or a headed browser.
Crash/restart classification, mailbox reassignment, full binary lifecycle and main
route activation remain outstanding before release.


Additional completion-notice fault qualification now exercises a persisted delivery
claim with newly constructed worker instances. A recent unresolved claim schedules
a retry; after the bounded attempt and retry jitter window, the next worker records
uncertainty and dead-letters the work without contacting the accepting TLS fixture.
The committed password and exact receipt remain valid. This simulates loss of a
worker between claim and result; it is not an operating-system process crash test.
Store fixtures separately verify foreign-scope refusal, delivery eligibility after
code expiry, refusal after mailbox reverification, and audited rollback of claim
and outcome writes without reverting the completed password change.

The cancellation page still uses the existing recovery notifier and claims that
registered channels were alerted. Actual cancellation delivery must replace that
legacy path before this ceremony is enabled; completion-notice tests do not prove
cancellation delivery or mailbox transfer to a different account.


Hosted cancellation now queues a code-free owner warning inside the existing case
cancellation transaction. Only a successful pending-to-cancelled transition queues
work, and reissued challenges sharing a case produce one warning using the newest
bound challenge. The internal terminal-kind marker chooses cancellation versus
completion content; the payload still carries only a challenge ID. Superseding a
code alone does not mark a notice due. Cancellation-notice ownership lookup may
read a cancelled case, while issuance/completion retain their original case rules.
The completion worker also drains these terminal cancellation notices with the
same single-attempt claim and outcome policy. Legacy recovery notifier hooks are
retained for other integrations; they are not evidence of SMTP delivery.

The cancellation POST now preserves transaction failure as a generic retryable
503 response rather than reporting success. Successful/invalid/repeated requests
retain uniform acknowledgement without claiming that mail has already arrived.
Queue failure rolls back cancellation, allowing the original link to be retried.


Qualification now covers the actual HTTP cancellation link from a locally delivered
TLS code email: scanner GET preserves the pending case, injected queue failure
returns retryable 503 and preserves the link, successful POST plus repeat queue one
code-free TLS warning, and the original password remains valid. The full 38-test
reset store suite and two existing legacy cancellation tests pass. This does not
claim Internet mail, browser qualification, or full process restart evidence.


The provider router now merges the bounded request/reset routes. The legacy
logging-only request handlers are removed, so disabled delivery reports unavailable
instead of suggesting instructions were sent. The existing HTTP/TLS/outbox suite
now uses `oidc_router` for requests, completion, cancellation and body/origin checks.
The independent password-spray and hard-lockout suite uses the same configured
recovery router/store/limiter; its unverified-account fixtures issue decoys and do
not claim SMTP delivery. The generated endpoint inventory and RFC 9700 coverage
mapping include `/recover/reset`, with explicit limits on timing evidence.

Production mounting in this branch does not mean deployment. Remaining release
work includes PAR/PoW/rate/fault matrices, real browser continuation, full binary
restart/shutdown, the complete gate, fixed-head review, PR merge and rollout.


The successful reset fixture also posts both passwords to the ordinary mounted
login handler: the old password creates no session, while the new password issues
the normal session cookie and redirects to the original authorization URL. The
reset response itself issues no session cookie. This is HTTP-level continuation
evidence; it is not headed-browser, application callback or membership evidence.


PAR qualification now pushes a real request through the main `/par` endpoint,
uses its reference through recovery, receives the reset code over local TLS,
completes the password change and signs in to the original authorization URL.
The pushed request remains live and unconsumed until authorization. The fixture
also rejects another client, duplicate client parameters, external request URIs,
direct authorization when the client requires PAR, and an expired PAR reference.
This does not prove successful application callback after a long recovery delay;
PAR expiry remains authoritative and must not be silently extended.

A remaining hosted usability gap was confirmed by reading the current recovery
renderer: when optional proof-of-work is required, POST validates the proof but
the recovery form has no challenge solver or proof fields. Reloading the form
cannot satisfy that gate. The built-in solver and its browser qualification are
required before enabling that policy in this hosted ceremony. External challenge
widgets require their own explicit client integration; none is claimed here.


The built-in proof-of-work form gap is now addressed in the branch. When built-in
verification is enabled, the recovery renderer includes the solver under an
Env-generated script nonce and the existing strict hosted-login CSP. Submission
fetches a challenge from the validated scope on the same origin, solves SHA-256
locally, and submits the proof once. It rejects malformed challenge responses and
changed form input, suppresses overlapping submissions, limits fetch/solve time,
and exposes progress/retry text through an accessible status region. No external
script, challenge service or automatic reset-code resend is introduced.

The server fixture covers the rendered nonce/CSP, missing proof for known/unknown
accounts, successful decoy issuance with a valid proof and refusal of proof replay.
A separate headed Chrome check serves the actual Rust-rendered HTML and CSP with
local challenge/submission fixtures; it verifies the browser's SHA-256 proof,
duplicate-submit suppression, rate-limit retry, malformed challenges and changed
input. This is browser solver evidence with fixture endpoints, not a full live
Rust/browser recovery or Internet email test. External-provider widget integration
remains outstanding. The main-router store matrix now rejects changed identifier
or continuation inputs, foreign scope/endpoint challenges and expired proofs.
The server recomputes the SHA-256 context from the exact submitted UTF-8 JSON
array before consuming a built-in proof. Rejected input substitutions preserve
the correctly bound proof, and only the valid submission issues a reset challenge.


Recovery strength follows persisted passkeys even when WebAuthn login is disabled.
The real-store regression covers synced and device-bound credentials, verifies
that email recovery remains held, and checks that the credential is retained.
This does not enable passkey login or claim a browser authenticator ceremony.


Natural-expiry Chrome qualification found that dropping the ten-minute reset
cookie removed every navigation action. Code authority itself lasts five minutes.
The reset redirect and form action now retain a presentation-only continuation
query, independently of the browser credential. Missing or expired binding may
render sign-in and fresh-code links only after registered authorization validation;
that query never resolves a challenge or authorizes a credential change. Neither
code expiry nor cookie lifetime is extended. Untrusted external targets receive
no link. Expired PAR continuations still require an application restart and remain
a separate qualification gap. Civio's five-minute authentication-flow expiry also
loses project context; that application-side navigation gap remains outstanding.


Migration 0250 removes unused data-plane DELETE authority from reset challenges.
Recovery operations retain receipts and cancellation aliases and have no delete
caller. A forward migration preserves the 0249 checksum already applied in the
isolated qualification deployment. The production-chain inventory includes both
migrations; historical upgrade fixtures remove the 0249 table and delay column
before replaying the complete chain, while the delete-permission allowlist stays
unchanged and an actual app-role DELETE is required to fail.

The producer census includes `enqueue_password_reset_completion`: it uses the
transactional outbox under the dedicated `password-reset-completion` consumer,
with challenge ID as the sole payload field, challenge-key idempotency and
subject ordering. It is not a new public webhook type. Reset/cancellation
transaction rollback and duplicate-notice tests exercise this producer.
