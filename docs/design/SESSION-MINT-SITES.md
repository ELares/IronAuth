# The session-mint site registry

Every primary session in IronAuth is minted by one function,
`crate::interaction::establish_session`, which carries the central account-lifecycle fence
(issues #80 and #52). That funnel is old and load-bearing. What did not exist until issue #295
is a record of WHO calls it.

## Why a registry, and why now

Issue #267 shipped `factor_downgrade::GatedSessionPath`, a structural registry of the surfaces
where a WEAK POSSESSION factor can reach a primary session. It is enforced hard: eight separate
sweeps iterate `GatedSessionPath::ALL` and drive every member end to end over HTTP, and the
exhaustive matches on `factor()` and `as_str()` mean a new variant does not compile until it is
classified.

That registry is deliberately narrower than "everything that mints". It answers one question
(may a mailbox or a phone number stand in for a passkey), so the password login, the federated
login, the device-flow login, and the WebAuthn ceremonies are all outside it on purpose. The
consequence is that a NEW session-minting surface gets neither a sweep nor a compiler error
from `GatedSessionPath`: it simply exists.

Issue #295 added exactly such a surface. `advanced_recovery::finalize` mints a primary session
over a passkey-protected account, deliberately and correctly (it is the terminus of a
delay-held, notified, mode-gated recovery case), and it is deliberately NOT registered in
`GatedSessionPath::ALL`, because several of the sweeps over `ALL` demand NO SESSION for exactly
the protected accounts recovery exists to serve. Registering it would fail them by design.

So the deliberate exception needed a name and a count, rather than being the one path that
escapes both. The name is `factor_downgrade::UngatedSessionMint`, which is unit-tested against
the two things that would make it stale. The count is
[`session-mint-sites.txt`](session-mint-sites.txt), regenerated and diffed by
`scripts/invariant-lints.sh` under rule `session-mint-registry`, exactly the way
`scripts/rfc9700-scan.sh` pins the mounted endpoint inventory. There are 13 call sites across
10 files today.

## What the lint does

`scripts/invariant-lints.sh` walks `crates/ironauth-oidc/src`, counts every call to
`establish_session(` (the definition itself and the private `establish_session_page` wrapper
are not calls and are excluded), writes `<count>\t<path>` per file, and diffs the result
against the committed inventory. A new call in an existing file bumps its count; a call in a
new file adds a row. Either way the diff is non-empty and CI fails until an author regenerates
the inventory AND names the file in the table below.

The lint is a COUNT, not a proof of correctness. What it buys is that no session-minting call
site can be added silently: the author has to come here and write down what mints and under
what gate.

The doc check matches the FULL PATH from the inventory, which is why the table below carries
full paths rather than the bare file names it used to. It matched a BASENAME until issue #241,
and that degraded the rule to a bare count for any new mint file whose basename collided with
one already listed: the inventory diff fired, the author regenerated, and the doc check then
passed on a file nobody had written a row for. Measured on the sibling
`user-token-mint-registry` rule, whose check had the identical bug, by adding a second
`token.rs` under a subdirectory.

## The registry

| File | What mints there | Gated by |
|------|------------------|----------|
| `crates/ironauth-oidc/src/login.rs` (3) | The hosted password login, the MFA continuation, and the trusted-device continuation | The password credential itself; MFA where enrolled. Not a `GatedSessionPath`: a password is not a weak possession factor, and whether enrolling a passkey should raise the floor for a password login is issue #267's stated non-question |
| `crates/ironauth-oidc/src/register.rs` | The self-service registration completion | The registration itself (a brand-new account holds no stronger factor to downgrade past) |
| `crates/ironauth-oidc/src/email_otp.rs` | `POST /otp/verify` | `GatedSessionPath::EmailOtpVerify` |
| `crates/ironauth-oidc/src/magic_link.rs` | `POST /magic/consume` | `GatedSessionPath::MagicLinkConsume` |
| `crates/ironauth-oidc/src/sms_otp.rs` | `POST /otp/sms/verify` | `GatedSessionPath::SmsOtpVerify` |
| `crates/ironauth-oidc/src/flow/mod.rs` | The headless flow engine's completion mint (login, registration, recovery, MFA) | `GatedSessionPath::FlowRecoveryVerify` on the recovery journey; the flow's own step preconditions otherwise |
| `crates/ironauth-oidc/src/webauthn.rs` (2) | The passkey authentication ceremony and the passkey-first registration ceremony | The ceremony. A passkey is the TOP of the ladder, so there is no downgrade to gate |
| `crates/ironauth-oidc/src/federation.rs` | The upstream-IdP callback | The verified upstream assertion |
| `crates/ironauth-oidc/src/saml_signin.rs` | The SAML assertion consumer, after `saml_acs::consume` (issue #139) | The verified assertion: signature against the connection's PINNED certificates, every condition, a one-time spend of an outstanding request this deployment issued, and a one-time admission of the assertion id. Plus a BROWSER BINDING ON THE SOLICITED PATH ONLY -- an unsolicited response answers no request, so there is no row to have recorded a digest and the check passes with nothing to compare; that path's gates are the signature, the conditions and the assertion-id replay cache, and it is off by default for exactly this reason. On the solicited path the binding is what the other federated site does not need and this one does: the SAML POST binding is an unauthenticated CROSS-SITE form submission, so without a cookie tying the response to the browser its `AuthnRequest` was issued to, an attacker could auto-submit a genuine assertion for their OWN account into a victim's browser. Not a `GatedSessionPath`: nothing here presents a weak possession factor, because this server presents no factor at all -- the identity provider decided who the human is |
| `crates/ironauth-oidc/src/device_verify.rs` | The device-authorization user-code approval | The approving user's own session |
| `crates/ironauth-oidc/src/advanced_recovery.rs` | `POST /recover/finalize` (issue #295) | **The deliberate exception.** Gated by `finalize_recovery`: the mode precondition AND the store `complete`'s `hold_until <= now` delay guard. NOT in `GatedSessionPath::ALL`, named instead by `factor_downgrade::UngatedSessionMint::RecoveryFinalize`. See that type's doc for why registering it would fail the issue #267 sweeps by construction |

## Adding a session-minting surface

1. Write the call. `scripts/invariant-lints.sh` fails.
2. Decide whether the surface presents a WEAK POSSESSION factor. If it does, add a
   `GatedSessionPath` variant and drive it in `tests/factor_downgrade.rs`; the exhaustive
   matches and the registry-length assertion will not let you skip either.
3. If it does not, say why in the table above.
4. Regenerate the inventory (run the lint; it rewrites the file) and commit it.
