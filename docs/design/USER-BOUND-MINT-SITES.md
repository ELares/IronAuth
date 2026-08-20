# The user-bound token mint registry

Issue #52 established the invariant: after a user is blocked, disabled, or deleted it
obtains NO new tokens by ANY path. [`USER-LIFECYCLE.md`](USER-LIFECYCLE.md) records what
that means and how the account state machine works. This note records something narrower
and more mechanical: WHICH code mints a token, for WHOSE account, and what stops that mint
once the account is fenced.

## Why a registry, and why now

The invariant was written down in two sentences and enforced in a handful of places, and
the gap between those two facts is the whole problem.

Issue #52 shipped the fence and named three enforcing surfaces. A follow-up review found
two user-bound mint paths outside all three, judged both narrow, and recorded them in
issue #241 as accepted deferred defense-in-depth. They then sat there. When #241 was implemented, the
sweep it demanded turned up a THIRD path that no issue, comment, or review had ever
mentioned: an authorization code whose grant carries no `session_ref` (the shape an older
build persists, redeemable across a rolling upgrade inside the code TTL) reached the mint
with the ENTIRE fence bypassed, on EVERY scope.

That last clause is the part worth stating precisely, because the code exchange's fence
was understood as a ladder of four reads whose height varied by scope. All four are
conditioned on the grant HAVING a session. Rungs one and two sit behind
`resolve_code_exchange_sid`'s `let Some(session_ref) = .. else { return Ok(None) }`. Rung
three, `lock_bound_session_live`, returns `Ok(true)` outright for a NULL `session_ref`
("not session-bound: open unconditionally"). Rung four's `INSERT ... SELECT` predicate
reads `AND ($9 OR g.session_ref IS NULL OR EXISTS(..))` and is satisfied by the middle
disjunct. So the ladder was not shorter for a session-less grant, it was absent, and a
blocked or deleted user's legacy code minted an access token, an ID token, and a refresh
family on an ordinary `openid` scope, not only on `offline_access`.

None of the three was hidden. Each was a few lines under a doc comment describing what it
did. What was missing was any place where all the mints were listed against the invariant
at once, so "is that everything?" was a question nobody could answer without redoing the
sweep. This file plus [`user-bound-mint-sites.txt`](user-bound-mint-sites.txt) is that
place.

The shape is copied from [`SESSION-MINT-SITES.md`](SESSION-MINT-SITES.md) and its
`session-mint-registry` lint, which does the same job one layer up (who mints a primary
SESSION). Copied on purpose: the mechanism is proven here, the failure mode is identical,
and a second registry that worked differently would be a second thing to learn.

## What the lint does

`scripts/invariant-lints.sh`, rule `user-token-mint-registry`, walks
`crates/ironauth-oidc/src` and counts every call to one of the five `crate::tokens`
functions that produce a token artifact:

| function | produces |
|---|---|
| `mint` | an ID token AND an access token |
| `mint_access_token` | an access token |
| `mint_id_token` | an ID token |
| `mint_refresh_token` | a refresh token |
| `mint_client_credentials_access_token` | a machine-shaped access token |

It writes `<count>\t<path>` per file and diffs the result against the committed inventory.
A new call in an existing file bumps its count; a call in a new file adds a row. Either
way the diff is non-empty and CI fails until an author regenerates the inventory AND names
the file in the table below. The inventory is generated, so the count lives there rather than in this sentence: an earlier version of it read "ten call sites across six files" and went stale the moment CIBA landed, which is the same failure mode as a hand-written count beside a computed one.

The doc check matches the FULL PATH, which is why the table below carries full paths. It
matched a BASENAME first, and that was a hole of its own: a NEW mint file whose basename
collided with one already listed passed the doc check unexamined, so the rule degraded to a
bare count for exactly the file an author is least likely to have thought about. Measured by
creating a second `token.rs` under a subdirectory with a mint call in it: the inventory diff
fired, and after regenerating, the doc check passed because `token.rs` was already named.
The `session-mint-registry` rule had the identical bug and was fixed with it.

The count matches the QUALIFIED spelling `tokens::<name>(`, because `mint(` unqualified
also matches English prose and two unrelated functions. That qualification would be an
easy thing to evade by accident, so a companion rule (`user-token-mint-qualified`) refuses
a `use` that would let a mint be CALLED without the `tokens::` prefix: importing a mint
function by bare name (`use crate::tokens::mint_refresh_token;`, in the braced, mixed, and
renamed spellings too), from a `super::`/`self::` path or a crate-root re-export as much as
from `crate::`, and aliasing the module itself (`use crate::tokens as t;`, after which
`t::mint(..)` is invisible to the count). Every mint caller already imports
`crate::tokens::{self, ..}` and calls through the module, so the rule costs nothing today.

The inventory diff compares against the git INDEX, so the rule additionally refuses an
inventory git does not TRACK. That is not hypothetical tidiness: it was measured. With the
file untracked, adding a second mint call to a file already listed left the lint clean,
because `git diff` on an untracked path reports nothing and the comparison had nothing to
compare. A rule whose job is to catch an unexamined mint must not itself be defeated by
forgetting to `git add`. That guard now lives in `scripts/lib/generated-artifact.sh` and is
applied by every freshness gate in `scripts/` that ends in a `git diff --exit-code`, because
the shape is identical at all of them and the failure is silent at all of them.

Five honest limits, stated because a registry believed to be stronger than it is would be
worse than none:

- It is a COUNT, not a proof. It cannot tell a fenced mint from an unfenced one. What it
  buys is that no token mint is added silently: the author has to come here and write down
  whose account can revoke what they just minted.
- It counts LINES that contain a mint call, not calls. Measured: a SECOND mint call added to
  a line already counted leaves the inventory unchanged and the lint clean. A mint on a new
  line is caught, and `cargo fmt` puts each call on its own line, so the residual is a
  deliberately compressed line rather than ordinary code.
- The companion `user-token-mint-qualified` rule is a grep, and grep is LINE based. A `use`
  statement rustfmt has split across lines (which it does past 100 columns, and a braced list
  of these five names is longer than that) puts the imported names on continuation lines
  carrying no `use ... tokens`, where the rule does not see them.
- Its scope is `crates/ironauth-oidc/src`, and a future crate that minted would need adding
  to the walk, exactly as the `session-mint-registry` and the time and entropy rules would.
  `ironauth-server` mints nothing (measured). `ironauth-admin` mints no user-bound OAuth or
  OIDC token, which is the thing this registry is about, but it does mint two bearer
  CREDENTIALS that are out of scope by kind rather than absent: the RFC 7591 dynamic
  client-registration initial access token (`dcr.rs`) and the admin invitation token
  (`invitations.rs`). Neither carries a user subject and neither is presented to the token
  endpoint; both are management-plane secrets governed by their own expiry and revocation.
- It only sees mints routed through `crate::tokens`. Two files INSIDE the walked directory
  sign a JWS directly through `ironauth_jose::sign_jws*` and are therefore invisible to it:
  `crates/ironauth-oidc/src/backchannel.rs` (an OIDC back-channel LOGOUT token) and
  `crates/ironauth-oidc/src/federation_client_secret.rs` (a `private_key_jwt` client
  assertion IronAuth sends UPSTREAM to an external IdP). Neither authenticates a user to
  IronAuth: one asserts that a session ENDED, the other authenticates IronAuth itself as a
  client to somebody else. So neither belongs in the table below on today's code. A third
  such caller would not announce itself, so a new direct `sign_jws` caller has to be checked
  by hand against the question this file exists to answer.

## The registry

`sub` names the principal the token is minted for. "The session cascade" means block,
disable, and delete each revoke all of the subject's `sessions` rows and the
`client_sessions` derived from them, in the SAME audited transaction as the lifecycle
write, so a read of live-session state IS a read of the account's liveness one hop away.

That "one hop away" is an equivalence, not a definition, and it is worth being exact about
what holds it up, because four of the mints below depend on it. It holds while every state
that (a) can be transitioned INTO and (b) cannot authenticate also (c) ends the user's
sessions. Today `UserState::ends_sessions` is exactly {blocked, disabled} and
`UserState::can_authenticate` is exactly {active, scheduled-offboarding}, which leaves an
apparent gap at pending-verification and waitlisted: neither authenticates and neither ends
sessions. The gap is closed by a THIRD predicate rather than by the second.
`UserState::can_transition_to` refuses both as transition TARGETS, so a user is only ever in
one of them from creation, holding no session and no authorization code, and there is nothing
for the cascade to have failed to end.

Three predicates in three places, with nothing tying them together. A new state that is
non-authenticatable, a valid transition target, and not session-ending would reopen the code
exchange, the device grant, the front-channel ID token, and the FedCM assertion at once, with
no compile error anywhere. `every_reachable_non_authenticatable_state_ends_sessions` in
`crates/ironauth-store/src/repository.rs` drives that relation over `UserState::ALL` and is
what stops it.

| File | Mints | `sub` | Fenced by |
|------|-------|-------|-----------|
| `crates/ironauth-oidc/src/token.rs` (4) | The code exchange's ID + access token and its refresh token; the refresh grant's rotated access token and its successor refresh token | The `usr_` id frozen onto the code, or the one carried by the refresh family | **Refresh grant: directly.** `ensure_subject_can_authenticate`, the explicit `state_for_subject` read, because an `offline_access` family deliberately survives the session cascade (issue #21) and nothing else would reach it. **Code exchange: the session cascade**, through the two reads in `resolve_code_exchange_sid` plus two further rungs inside `RefreshFamilyRepo::issue` that run on an `openid` scope only; that function's doc comment counts the rungs per scope and states the residual. Its `session_ref IS NULL` branch is the third path issue #241 found, and it now calls `ensure_subject_can_authenticate` directly |
| `crates/ironauth-oidc/src/device.rs` (2) | The device grant's ID + access token and its refresh token | The `usr_` id of the human who approved at the verification page | The session cascade, via `resolve_device_sid`'s live-session read. Its `session_ref IS NULL` branch (a grant approved before the session was recorded, in flight across an upgrade) is one of the two paths issue #241 was filed for, and now calls `ensure_subject_can_authenticate` directly |
| `crates/ironauth-oidc/src/authorize.rs` | The implicit and hybrid front-channel ID token | The `usr_` id of the browser SSO session | The session cascade. `resolve_front_channel_sid` has no session-less branch to fence: `Resolved::session_ref` is a non-optional `&str`, so a front-channel mint without a session is unrepresentable. MEASURED by `a_fenced_user_mints_no_front_channel_id_token` in `crates/ironauth-oidc/tests/response_types.rs`: blocked and disabled get no implicit `id_token`, and a deleted user gets neither the hybrid `id_token` nor the authorization code beside it, against an ACTIVE control that reaches and verifies the signed token |
| `crates/ironauth-oidc/src/fedcm.rs` | The FedCM id-assertion ID token | The `usr_` id of the browser SSO session | The session cascade, twice over: `resolve_session` resolves a live `sessions` row before anything else, and `ensure_sid` fails closed on a dead one. No session-less branch. MEASURED by `a_fenced_user_gets_no_fedcm_assertion` in `crates/ironauth-oidc/tests/fedcm.rs`, blocked and deleted, against an ACTIVE control that verifies the token it receives |
| `crates/ironauth-oidc/src/jwt_bearer.rs` | The RFC 7523 assertion grant's access token | **Operator-authored.** The `principal` string on a registered subject-mapping rule, which may be a lifecycle-bearing `usr_` user OR a workload identity (SPIRE, Kubernetes, GitHub Actions) | **Directly, and CONDITIONALLY.** The other path issue #241 was filed for. There is no session and no user credential here, so neither the cascade nor anything else reached it. `fence_mapped_principal` classifies the principal through `MappedPrincipal` and applies `subject_can_authenticate` to a user, refuses a user id from another scope as unfenceable, and deliberately SKIPS a workload. The skip is not laxity: `state_for_subject` queries the `users` table, so fencing a workload would fail closed on every legitimate workload assertion in the deployment |
| `crates/ironauth-oidc/src/client_credentials.rs` | The RFC 6749 4.4 machine access token | An `sva_` service-account id | **Nothing, and correctly.** Not user bound. Its subject is not operator-authored the way jwt-bearer's is: it comes from `service_accounts().ensure()`, which mints an `sva_` id keyed to the client, so a `usr_` principal is unreachable here by construction rather than by convention. The client's own revocation is the fence |
| `crates/ironauth-oidc/src/token_exchange.rs` | The RFC 8693 exchange's access token | **Whatever the subject token carried.** A `usr_` id when the subject token came from a user flow, an `sva_` service account when it came from the client-credentials grant | **Directly, and CONDITIONALLY**, like jwt-bearer and for the same reason: there is no live session between the presented subject token and this mint, so the cascade cannot reach it, and the subject token stays cryptographically valid for its full lifetime after the account is fenced. `fence_principal` classifies through the SAME `MappedPrincipal` and applies `subject_can_authenticate` to a user, refuses a user id from another scope as unfenceable, and skips a workload (fencing one would query `users` for an id that is not there and fail closed on every legitimate machine exchange). It is applied to BOTH principals: the subject, and in a delegation the ACTOR, because the issued token names the actor as the party driving it and fencing only the subject would leave open the half that hands out somebody else's authority. What makes this mint distinctive is that it REPEATS: an exchange yields a token that can itself be exchanged, so an unfenced path here does not merely outlive the block once, it renews indefinitely. MEASURED by `a_fenced_user_cannot_have_their_token_exchanged` (blocked and disabled) and `a_fenced_actor_cannot_delegate`, each against an ACTIVE control that mints first |
| `crates/ironauth-oidc/src/ciba_grant.rs` | The CIBA grant's ID + access token | The `usr_` id the backchannel request named, resolved from the `login_hint` to a live `users` row by `ciba.rs` before the request is stored | **Directly, and UNCONDITIONALLY.** A third path of the shape issue #241 was filed for, and the one where BOTH existing mechanisms miss rather than one. The session cascade cannot reach it: `cascade_user_sessions_ended` updates `sessions`, `client_sessions` and `refresh_families`, and a backchannel request records no session at all (`decide` inserts its grant with `session_ref = NULL`). Grant revocation cannot either: `verify_redemption_grant`'s only liveness term is `revoked_at IS NULL`, and `cascade_families_for_subject` revokes a grant only under `hard_kill` and only when a `refresh_families` row names it. This grant issues no refresh token, so it has no family, so even `delete_user` leaves the approval live. `issue_ciba_tokens` therefore calls `ensure_subject_can_authenticate` before `mint_ciba_tokens`. Unconditional rather than shape-gated, for the reason `resolve_device_sid` gives on its session-less branch: the subject is a `usr_` id by construction and nothing operator-authored reaches here. MEASURED by `a_fenced_user_cannot_redeem_an_approved_backchannel_request` in `crates/ironauth-oidc/tests/ciba_grant.rs` across every `UserState` plus a soft delete, against an ACTIVE control that mints. Before the fence existed, a Blocked and a soft-deleted user each answered 200 with a live ID token and access token. What makes this mint distinctive is that there is no way to take one back: the access token is a self-contained `at+jwt`, and the ID token carries no `sid`, so back-channel logout has nothing to target |
## Adding a token mint
