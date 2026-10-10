# Optional hosted display names

Work in progress for #1385 and Civio onboarding #455. This document is an
implementation contract, not deployment or issue-completion evidence.

The provider owns an optional standard `name` claim. Its display label is not a
login identifier, verified mailbox, account key or authorization input. Equal
names do not merge accounts. Removing a name leaves a valid empty profile.

## Implemented backend and hosted form

- GET `/t/{tenant}/e/{environment}/account/profile` returns only `name` for the
  authenticated own account. It refuses impersonation and never returns the
  stored claim bag.
- POST at the same path accepts only `expected_name` and `name` strings, requires
  a present same-origin Origin, and binds the target to the current session.
  Names are trimmed, at most 80 Unicode characters, and contain no control
  characters. An empty name removes the standard claim.
- The store rechecks the active subject and stable human actor, locks the row,
  reads the current sealed claims and DEK version, compares the expected label,
  changes only `name`, reseals and writes the owner-attributed audit atomically.
  A changed label also queues the canonical `user.updated` event in the same
  transaction, with only the user ID and `fields: ["claims"]`; no label is copied
  into the event. A retry of the same value does not queue another change event.
  A different current name returns a conflict. Repeating the desired current
  value is harmless and may append a further audit record.
- GET `/t/{tenant}/e/{environment}/profile` hosts the own-name form. Its optional
  `return_to` must resolve a registered in-scope authorization request. Other
  app URLs, cross-scope requests and indirect unvalidated contexts are refused.
- The form retains input after errors, freezes uncertain saves for exact retry,
  offers an explicit reload of current state, guards navigation, and keeps a
  sessionStorage recovery copy keyed by the scoped subject. Confirmed saves or
  explicit reload clear the copy. Storage unavailability is visible. An expired
  page offers a continuation only after validating the registered in-scope
  authorization request; it does not render the editable profile without a session.

Existing UserInfo claim selection remains authoritative. The name becomes
available on a fresh permitted profile read; a relying party may cache its own
label until reauthentication. This feature does not establish email ownership.

## Connected hosted flow and local evidence

Successful browser registration, through both the legacy handler and the flow
engine, now offers the optional name step before the validated application
return. API registration keeps its prior return behavior. The legacy consent
screen offers "Edit your display name" when profile access is requested; the
link reuses the same registered scope/authorization validation. The account
form uses the shared shell without another card, compact desktop actions and
44px narrow/touch actions.

Local disposable-PostgreSQL checks cover wrong scope, inactive users, refused
impersonation, canonical events, event-insertion rollback, concurrent changes,
forged fields, claim preservation and public-subject UserInfo selection. These
are not pairwise-client qualification.

A headed Chrome run on October 10, 2026 used actual registration and the HTTP
router backed by disposable PostgreSQL. It selected a name, dropped a committed
save's response, retried the exact request after reload, recovered a draft,
explicitly reloaded the saved name and continued through consent to the client
callback. The actual token exchange and UserInfo read returned the selected
name and matching public subject, with no page JavaScript errors. No user or
profile was seeded for this journey. The fixture forwards browser requests to
loopback and uses test signing keys; it is not evidence of the deployed provider,
Civio's authenticated UI or a physical device. Artifacts are kept privately under
`hosted-profile-201/browser-001`; credentials, callbacks and tokens are not
committed. A second real-registration run (`browser-002`) checked the compact
form at 1280px and 390px, followed the consent edit link, removed the name and
returned through consent to the callback. The screenshots show no horizontal
overflow, 32px desktop buttons and 44px narrow actions. The shared provider
default remains light under a dark system preference; no separate dark-theme
implementation or physical-device check is claimed.

## Civio integration status

Civio PRs #882 and #883 preserve up to 320 UTF-8 bytes, covering the provider's
80-character maximum without changing identity or grant lookup. PR #884 adds
a compact account-settings entry behind `CIVIO_IRONAUTH_HOSTED_PROFILE`. It
rechecks the same signed-in account before editing and before refreshing the
existing session label. The update cannot recreate a concurrently revoked
session. These changes are merged and deployed. The capability is enabled in the two
local qualification workspaces with the connected checks recorded below.

## Deployed connected browser evidence

An October 10, 2026 Chrome run used the actual TLS provider and Civio settings
entry, without route interception. Editing, an 80-character non-ASCII name
(320 UTF-8 bytes), removing the name and returning all refreshed the same Civio
account subject. Clearing only the provider cookie produced a real refused
save; reloading offered the registered return, signing in returned to Civio,
and reopening settings recovered the unconfirmed draft. Explicit reload
reconciled the saved name. The original qualification account name was restored.
The 390px layout had no horizontal overflow. Artifacts are retained privately
under `hosted-profile-201/civio-profile-connected-004`.

This evidence does not establish fresh registration on the deployed provider,
pairwise subjects, physical-device accessibility or the original cohort goals.
The provider's supported default remains light. The API response's session
expiry changed during the browser journey; only the same user, subject and
CSRF value were asserted there. Session-update invariants have separate backend
checks and are not inferred from that browser expiry comparison.

## Required before integrated completion

1. Qualify the implemented Civio account-settings entry and interrupted/expired
   sign-in recovery, including the validated relying-party return. Do not require
   users to assemble provider URLs or seed their profile through management APIs.
2. Run fresh registration, name selection, later editing/removal and Civio return
   in a real browser. Inspect narrow layouts, keyboard/focus, both provider page
   styling variants as supported, retained input and lost-response reconciliation.
3. Retain the authority, rollback, audit, event and scoped UserInfo checks when
   integrating the application entry and current-session recovery.
4. Qualify the implemented 320-byte application boundary in the connected
   browser journey, including non-ASCII names, without changing account identity
   or grant lookup.
5. Qualify the original pairwise requirement. Current production token and
   UserInfo code calls `resolve_public_subject`; the separate generic pairwise
   helper is not an integrated pairwise registration/token/UserInfo path. Do not
   check this criterion from public-subject tests.
6. Run the required local gate and one fixed-head review, fix blockers with
   targeted validation, deploy a reviewed candidate, qualify the connected
   browser journey and merge a regular PR. Preserve all remaining original
   #1385 and Civio U01/U02/U04/U07 criteria until their evidence is complete.
