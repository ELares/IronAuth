# User lifecycle fence and #52 scope boundaries

This note records two things about the admin user CRUD and lifecycle work (issue
#52): the completeness guarantee of the authentication fence, and the acceptance
items that #52 deliberately DEFERS to the milestones that own the systems they need.

## The lifecycle authentication fence is complete on every path

The invariant is: after a user is blocked, disabled, or deleted, it can obtain NO new
tokens by ANY path (authorize, refresh, or an already-issued `offline_access` refresh
token).

Three surfaces enforce it:

1. **Authorize / login.** The interactive login and the device-verification login
   read the user's `state` and refuse a user that cannot authenticate
   (`UserState::can_authenticate` is true only for `active` and
   `scheduled_offboarding`). The password is still verified, so a fenced account is
   timing-indistinguishable from a wrong password, and a soft-deleted user resolves
   as absent.

2. **Session cascade.** Blocking, disabling, or deleting a user ends its live
   sessions and its non-offline refresh families and fans out the session-ended event
   (issue #35), driving back-channel logout.

3. **Refresh grant (the fence-completeness fix).** An `offline_access` refresh family
   DELIBERATELY survives the session cascade (issue #21: an offline token outlives an
   RP logout). Without a re-check, a user blocked, disabled, or deleted AFTER the
   family was opened would keep minting fresh access tokens through that surviving
   token, so the account would not actually be fenced. The `refresh_token` grant
   therefore RE-CHECKS the token subject's lifecycle state (`state_for_subject`)
   before minting and FAILS CLOSED (`invalid_grant`) when the subject is not
   authenticatable or is absent/deleted. A store fault is fail-closed too, never
   fail-open. This is the same fence-completeness class as the issuer live-fence
   (issue #46): a suspended subject must stop authenticating on the NEXT request.

### Why the surviving offline family is left in place (not auto-purged)

The refresh-grant re-check is the single AUTHORITATIVE fence: it renders a surviving
`offline_access` token INERT the moment the user is fenced, so the security invariant
holds without also revoking the offline family rows. We deliberately do NOT force a
hard cascade of the offline families on block/disable, for two reasons:

- It preserves the issue #21 offline-survives semantic as a coherent single rule (the
  cascade preserves offline; the re-check fences the account), rather than making
  block/disable a special second exception to it.
- It keeps the operator's `hard_kill` knob meaningful and reversible (the tunability
  principle: an environment-dependent teardown is a knob with a safe default, not a
  baked-in one-way choice). An operator who wants the offline family rows purged AND
  the already-issued access tokens killed immediately passes `hard_kill` on the
  block / disable / delete call; the default leaves them, inert, for a later unblock.

The net effect either way satisfies the invariant: a fenced user mints nothing.

## `can_transition_to` permits blocked/disabled -> scheduled_offboarding (intended)

The state machine permits every move between live states except a no-op and a move
back into `pending_verification` (a creation-time-only state). In particular a
`blocked` or `disabled` user MAY be moved to `scheduled_offboarding`. This is
intended: scheduling the offboarding of an already-blocked or already-disabled
employee is a normal operator action (an HR offboarding date is set for an account
that security already suspended). The offboarding executor disables and cascades on
the scheduled instant, so it never resurrects authentication for such a user, and
`can_authenticate` continues to gate every data-plane read regardless of the schedule.
No tightening is warranted.

## Acceptance items deferred out of #52 met-scope

Two items from the #52 acceptance list depend on systems that do not exist yet. They
are DEFERRED, not stubbed: a silent no-op would misrepresent the surface as done.

- **Roles / groups assigned at user creation.** RBAC (roles and groups) is a separate
  M6 issue that builds ON this one; #52 ships the user entity that roles will attach
  to, but not the role model. `POST /users` therefore accepts no role/group field
  yet. Owner: the M6 RBAC issue (the roles/groups model), which extends the create
  surface once it lands.

- **`external_id` in webhook / event payloads.** IronAuth has no webhook / eventing
  delivery surface yet; that is M11. The external id IS stored, blind-indexed, and
  readable on the user surfaces now; emitting it in event payloads is deferred to the
  M11 eventing work, which owns the payload schema. Until then there is no event
  channel to carry it, so there is nothing to stub.

Both are tracked against their owning milestones; #52's met-scope is the user entity,
its lifecycle, and external-id correlation on the management and data planes.
