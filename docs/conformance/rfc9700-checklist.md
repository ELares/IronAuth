# RFC 9700 conformance checklist

[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) (OAuth 2.0 Security Best
Current Practice, January 2025) codified a decade of OAuth attack lessons into the
baseline auditors now cite. IronAuth encodes each applicable item as a NAMED,
executable CI invariant that drives the live authorization, token, discovery, and
interaction endpoints and asserts the security property, so a future refactor
cannot silently reopen a closed CVE class.

This document is the traceability map from each RFC 9700 requirement to the test(s)
that cover it. It is checked for freshness on every PR by `scripts/rfc9700-scan.sh`,
which binds every mounted OAuth endpoint to this map so a new endpoint cannot ship
uncovered while the checklist still reads complete. The design rationale (including
the 302-vs-303 and Referrer-Policy decisions and the non-vacuity argument) is in
[docs/design/rfc9700-conformance.md](../design/rfc9700-conformance.md).

## How to read this

- The conformance tests live in `crates/ironauth-oidc/tests/rfc9700.rs` and run on
  every PR in the workspace `test` lane.
- Each header- or shape-based item reduces its assertion to a pure predicate that
  the conformance test runs against the LIVE response. A paired **non-vacuity**
  (mutation) test in the same binary feeds that same predicate the exact shape a
  flipped guard would produce and asserts it is rejected, so no conformance test can
  pass vacuously. A predicate that went vacuous would fail its mutation test in
  normal CI.
- Behavioral items (single-use, downgrade, reuse) assert an exact outcome
  (`invalid_grant`, `unsupported_grant_type`); a regressed guard would change that
  outcome and fail the test.

## Traceability: RFC 9700 requirement to test

<!-- rfc9700:traceability -->

| Item | Requirement | Spec | Conformance test(s) | Non-vacuity test |
|------|-------------|------|---------------------|------------------|
| R1 | Exact-string `redirect_uri` matching everywhere a URL is echoed; an unregistered or unvalidated target is refused by a page, never redirected (no open redirector). | RFC 9700 2.1; RFC 6749 4.1.2.1 | `rfc9700_exact_redirect_uri_unregistered_is_error_page`, `rfc9700_exact_redirect_uri_comparator_rejects_cve_corpus` | `rfc9700_mutant_error_page_detects_open_redirect`, `rfc9700_mutant_loopback_detects_host_swap` |
| R2 | The RFC 8252 loopback-port and private-use-scheme exception stays exact: only the port of an `http` loopback IP literal may vary; host, path, and scheme never broaden into open redirect or SSRF. | RFC 9700 2.1; RFC 8252 7.1, 7.3 | `rfc9700_loopback_exception_varies_only_the_port`, `rfc9700_native_redirect_exception_stays_exact` | `rfc9700_mutant_loopback_detects_host_swap`, `rfc9700_mutant_error_page_detects_open_redirect` |
| R3 | No endpoint is an open redirector: the interaction pages refuse a non-local `return_to` (a scheme-relative `//host` or an absolute URL). | RFC 9700 2.1 | `rfc9700_interaction_return_to_open_redirect_is_refused` | `rfc9700_mutant_error_page_detects_open_redirect` |
| R4 | Discovery advertises S256 as the only PKCE method (`plain` structurally excluded). | RFC 7636; RFC 9700 2.1.1 | `rfc9700_discovery_advertises_s256_only_pkce` | `rfc9700_mutant_pkce_methods_detects_plain` |
| R5 | PKCE is mandatory with downgrade prevention in BOTH directions: a challenge-bound code is unredeemable without the verifier, and a no-challenge code is unredeemable WITH a verifier; `plain` is `invalid_request`. | RFC 7636; RFC 9700 2.1.1 | `rfc9700_pkce_challenge_bound_code_needs_the_verifier`, `rfc9700_pkce_no_challenge_code_rejects_a_verifier`, `rfc9700_pkce_plain_method_is_invalid_request` | `rfc9700_mutant_invalid_grant_detects_success` |
| R6 | No access token in the front channel: token-bearing response types are unsupported and a code-flow success carries no `access_token`. | RFC 9700 2.1.2 | `rfc9700_no_front_channel_access_token` | `rfc9700_mutant_front_channel_detects_access_token` |
| R7 | RFC 9207 `iss` on EVERY authorization response, success and error (mix-up defense). | RFC 9207; RFC 9700 4.4 | `rfc9700_authorization_response_carries_iss` | `rfc9700_mutant_iss_detects_missing_iss` |
| R8 | Refresh tokens are one-time-use with rotation, and reuse of a superseded token beyond the grace window revokes the whole family. | RFC 9700 2.2.2 | `rfc9700_refresh_token_rotates_and_reuse_revokes_family` | `rfc9700_mutant_invalid_grant_detects_success` |
| R9 | Access tokens are audience-restricted, and a token is never PLACED in a URL (delivered only in the JSON response body with `Cache-Control: no-store`; no URL-valued header is set and no issued token value appears in any response header) nor ACCEPTED from one (a valid access token in a query string is refused, with no claims). | RFC 9068; RFC 8707; RFC 6750 2.3; RFC 9700 2.3 | `rfc9700_access_token_is_audience_restricted`, `rfc9700_token_endpoint_never_delivers_a_token_in_a_url`, `rfc9700_access_token_in_a_url_query_is_refused` | `rfc9700_mutant_audience_detects_missing_aud`, `rfc9700_mutant_token_in_url_detects_location`, `rfc9700_mutant_token_in_query_detects_acceptance`, `rfc9700_mutant_cache_control_detects_missing_no_store` |
| R10 | A credential-bearing redirect uses `303 See Other`, never the legacy `302` and never a body-preserving `307`/`308`. | RFC 9700 2.6 | `rfc9700_credential_bearing_redirect_uses_303_see_other` | `rfc9700_mutant_redirect_status_detects_307_and_302` |
| R11 | Every code-carrying response sets `Referrer-Policy: no-referrer`, so the code is not leaked through `Referer`; the form-hosting interaction pages set `same-origin` instead, which strips the `Referer` from every cross-origin request WITHOUT blanking the `Origin` on their own form POST (see the provider decision below). | RFC 9700 2.1, 4.2 | `rfc9700_code_carrying_response_sets_referrer_policy`, `rfc9700_interaction_page_referrer_policy_preserves_the_origin_header` | `rfc9700_mutant_referrer_policy_detects_missing_header`, `rfc9700_mutant_page_referrer_policy_detects_no_referrer` |
| R12 | CORS is disabled on the authorization endpoint: no `Access-Control-Allow-Origin` on `/authorize`, even for a real cross-origin preflight. | RFC 9700 2.1 | `rfc9700_authorize_endpoint_has_no_cors` | `rfc9700_mutant_no_cors_detects_allow_origin` |
| R13 | Authorization codes are single-use and SHORT-LIVED, bound to the client, the `redirect_uri`, and the PKCE verifier; replay or a binding mismatch is `invalid_grant`, and a reuse beyond the grace window revokes the GRANT CHAIN (every token already minted from the code). | RFC 6749 4.1.2, 4.1.3; RFC 9700 2.1.1 | `rfc9700_authorization_code_is_single_use`, `rfc9700_authorization_code_is_short_lived`, `rfc9700_authorization_code_is_bound_to_client_and_redirect_uri`, `rfc9700_authorization_code_reuse_revokes_the_grant_chain` (verifier binding: R5) | `rfc9700_mutant_invalid_grant_detects_success` |
| R14 | The token endpoint is sender-uniform: distinct redemption failures render byte-identically, so it is never an oracle for which check failed. | RFC 6749 5.2; RFC 9700 2.4 | `rfc9700_token_error_is_sender_uniform` | `rfc9700_mutant_uniform_errors_detects_divergent_bodies`, `rfc9700_mutant_invalid_grant_detects_success` |
| R15 | The resource-owner password-credentials grant (ROPC) is absent: a request naming it is `unsupported_grant_type`. | RFC 9700 2.4 | `rfc9700_ropc_password_grant_is_unsupported` | inherent (the test pins the exact `unsupported_grant_type` outcome a regressed guard would change) |
| R16 | CSRF: a conclusively cross-site POST to a credential-bearing interaction endpoint (login, registration, consent) is refused with a `403` BEFORE any state change; a genuine same-origin browser submission, including the opaque `Origin: null` a real user agent sends, is accepted. | RFC 9700 4.7 | `rfc9700_interaction_post_rejects_cross_site_submissions` (full matrix, including that a blocked POST creates no account, session, or consent: the `interactive` suite) | `rfc9700_mutant_csrf_detects_an_allowed_cross_site_post` |
| R17 | Clickjacking: every interaction page refuses to be framed, with CSP `frame-ancestors 'none'` AND `X-Frame-Options: DENY` (so a legacy browser that ignores the CSP directive still refuses). | RFC 9700 4.16 | `rfc9700_interaction_pages_deny_framing` (the full page-hardening set: the `interactive` suite's `assert_hardened`) | `rfc9700_mutant_framing_detects_a_frameable_page` |
| R18 | A redirect URI that is not REGISTRABLE (a non-loopback `http` URL, a `javascript:` or `data:` URL, a fragment-carrying or relative URI) is refused at REGISTRATION, so an insecure or code-stealing target can never become an exactly-matched (and therefore trusted) redirect. | RFC 9700 2.1; RFC 8252 7.1 | `rfc9700_insecure_redirect_uri_is_not_registrable` | `rfc9700_mutant_registrable_detects_an_accepted_insecure_redirect` |
| R19 | A client cannot influence its own identifier: `client_id` is minted by the server in its own namespace, so a registering client can never take an identifier that could be confused with a resource owner. | RFC 9700 4.15 | `rfc9700_a_client_cannot_choose_its_own_client_id` | inherent (the test pins the exact minted-namespace outcome a regressed guard would change) |

<!-- rfc9700:end-traceability -->

## Endpoint coverage

Every endpoint mounted by the crate's routers is listed here: the protocol router,
the discovery router, and the issuer/JWKS router. The inventory is generated from
every `.route()` under `crates/ironauth-oidc/src` into `rfc9700-endpoints.txt` and
diffed on every PR, so it is bound to the whole mounted surface rather than to any
single router. A new route must be added here, mapped to a covering item or an
explicit not-applicable reason.

<!-- rfc9700:endpoints -->

| Endpoint | BCP relevance | Covered by |
|----------|---------------|------------|
| `/authorize` | Redirect validation, PKCE, front-channel, `iss`, 303, Referrer-Policy, CORS | R1, R2, R4, R5, R6, R7, R10, R11, R12 |
| `/token` | Code single-use and binding, PKCE downgrade, refresh reuse, audience, uniform errors, no token in a URL, ROPC absent | R5, R8, R9, R13, R14, R15 |
| `/par` | Pushed request validation shares the `/authorize` redirect and PKCE rules | R1, R2, R5 (validated at push by the `par` suite) |
| `/revoke` | Token revocation (sender-uniform, no existence oracle) | Covered by the `revocation_introspection` suite (issue #22); shares R14 uniformity |
| `/introspect` | Introspection auth and audience reporting | Covered by the `revocation_introspection` suite (issue #22); shares R9 |
| `/userinfo` | The ONLY CORS resource, and only for exactly-registered origins (contrast with R12 on `/authorize`) | Covered by the `userinfo` suite (issue #15); the R12 contrast is asserted by `rfc9700_authorize_endpoint_has_no_cors` |
| `/login` | Credential-bearing interaction: 303 redirect, no open redirect via `return_to`, CSRF, clickjacking, page hardening | R3, R10, R11, R16, R17 |
| `/login/mfa` | RFC 9470 step-up second-factor challenge (issue #72): shown when an authorization request needs an authentication context (an `acr` floor / max auth age) the current session has not achieved. Same credential-bearing interaction seam as `/login` (303 redirect, no open redirect via `return_to`, same-origin CSRF gate before any verification, page hardening); on a verified TOTP or recovery code it UPGRADES the session with a FRESH `acr`/`auth_time` (issue #14 honesty), never an asserted value | R3, R10, R11, R16, R17; the step-up loop, the honest fresh-`acr`/`auth_time`, and the failure semantics are covered by the `step_up` suite (issue #72) |
| `/register` | Human account registration interaction (same interaction redirect seam; the only one with no cookie backstop, so R16 is its primary CSRF defense) | R3, R10, R11, R16, R17 |
| `/recover` | Human account-recovery request interaction (issue #64): anti-enumeration UNIFORM (present vs absent identifier byte-identical in body, status, and work), governed on the INDEPENDENT recovery path so failed-password spray cannot throttle it. Not an OAuth token endpoint (no grant, no bearer token). R16 CSRF | R14 (uniformity), R16; the anti-enumeration uniformity, per-path independence, and closed-registration send suppression are covered by the `abuse` suite (issue #64) |
| `/consent` | Consent interaction (same interaction redirect seam) | R3, R10, R11, R16, R17 |
| `/device_authorization` | RFC 8628 device grant back channel (cross-device BCP) | Covered by the `device` suite (issue #24); shares R9 audience and R14 uniformity |
| `/end_session` | RP-Initiated Logout: `id_token_hint` verified through the JOSE core, exact-match `post_logout_redirect_uri` (no open redirector), logout targeting bound to the hint `sid` (no cross-user forced logout), same-origin-gated confirmation | Covered by the `logout` suite (issue #33); shares R10 exact-redirect and R16 CSRF discipline |
| `/connect/check_session` | OIDC Session Management 1.0 `check_session_iframe` (issue #39), mounted ONLY when session management is enabled (default off). It is the ONE page deliberately framable cross-origin (an RP embeds it), so it carries the scoped framing carve-out; its inline script is SHA-256 hash-pinned by CSP and replies ONLY to the sender's exact `postMessage` origin (never `*`), folding that origin into the recomputed `session_state`, so no other page's anti-clickjacking posture is weakened. It carries no credential and echoes no reflected input | Not applicable to the RFC 9700 credential items (a static, per-deployment iframe with no request credential and no reflected input); the framing carve-out, the hash-pinned script, and the postMessage-origin posture are covered by the `logout` suite and the `pages` unit tests (issue #39) |
| `/t/{tenant_id}/e/{environment_id}/device` | Device verification page (explicit approval, page hardening) | Covered by the `device` suite (issue #24) |
| `/t/{tenant_id}/e/{environment_id}/connect/register` | Dynamic Client Registration: registered redirects must pass the R1/R2/R18 rules, and the client may not choose its identifier; abuse controls gate registration | R1, R2, R18, R19; abuse controls covered by the `dcr_abuse` suite (issue #31) |
| `/t/{tenant_id}/e/{environment_id}/connect/register/{client_id}` | RFC 7592 registration management (rotating registration access token). An UPDATE re-validates `redirect_uris` through the same registrable rule as registration, so R18 cannot be bypassed by editing a client after the fact | R18; otherwise covered by the `client_registration` and `dcr_abuse` suites (issues #30, #31) |
| `/t/{tenant_id}/e/{environment_id}/.well-known/openid-configuration` | Discovery (OIDC Discovery 1.0, appended form): the document is what a client's PKCE and endpoint choices are driven from, so `code_challenge_methods_supported` must advertise `S256` only | R4; the rest of the document (per-environment issuer, JWKS URI, single source of truth) is covered by the `discovery` and `live_wiring` suites (issues #17, #194) |
| `/.well-known/openid-configuration/t/{tenant_id}/e/{environment_id}` | Discovery (RFC 8414 host-inserted form, the variant MCP clients probe): the SAME document from the SAME builder, so a divergence between the two forms is itself a defect | R4; form equivalence covered by the `discovery` suite and `scripts/discovery-scan.sh` |
| `/.well-known/oauth-authorization-server/t/{tenant_id}/e/{environment_id}` | OAuth 2.0 Authorization Server Metadata (RFC 8414, host-inserted): same document, same S256-only PKCE advertisement | R4; as above |
| `/t/{tenant_id}/e/{environment_id}/jwks.json` | The environment's public JWK Set. It is PUBLIC by design (verification keys only, never a private key or a secret) and carries no credential, so no RFC 9700 credential-leak item applies to it | Not applicable to the RFC 9700 credential items (public verification keys, no credential in the request or the response); key isolation, rotation, and cross-environment leakage are covered by the `issuer_http` and `live_wiring` suites (issues #17, #194) |
| `/.well-known/webauthn` | The WebAuthn Level 3 Related Origin Requests document (issue #67): a public `{"origins": [...]}` list a browser fetches from the RP ID's own origin to accept a passkey ceremony from a configured related origin. It is a WebAuthn well-known, NOT an OAuth/OIDC endpoint: it carries no credential, no `client_id`, no token, and no reflected input, and 404s uniformly on an unconfigured domain. The security-relevant behaviour (an unlisted origin still fails the ceremony with the non-enumerating error; the RP-ID-hash, signature, and single-use-challenge checks are unchanged; the served list is generated from validated config) is covered by the `webauthn_ceremony` and `webauthn_related_origins` suites and the `ironauth-config` origin/label-budget unit tests (issue #67) | Not applicable to the RFC 9700 credential items (a public related-origins document; no OAuth grant, no credential in the request or the response) |
| `/t/{tenant_id}/e/{environment_id}/account/sessions` | Self-service: the authenticated user lists ONLY their own sessions (subject-bound, never addressable by another user's id) | Covered by the self-service `account` suite (issue #61); shares R16 CSRF discipline on state changes |
| `/t/{tenant_id}/e/{environment_id}/account/sessions/revoke` | Self-service session revoke, bound to the authenticated subject; a cross-user session id is uniform not-found | Covered by the self-service `account` suite (issue #61); state change is CSRF-guarded (R16) |
| `/t/{tenant_id}/e/{environment_id}/account/sessions/revoke-others` | Self-service revoke-all-others (keeps the current session), subject-bound | Covered by the self-service `account` suite (issue #61); R16 CSRF |
| `/t/{tenant_id}/e/{environment_id}/account/password` | Self-service password change: verifies the current password (Argon2id), never returns the hash, revokes other sessions (session-fixation defense), subject-bound | Covered by the self-service `account` suite (issue #61); R16 CSRF |
| `/t/{tenant_id}/e/{environment_id}/account/credentials` | Self-service credential list, bound to the authenticated subject; no credential value is returned | Covered by the self-service `account` suite (issue #61) |
| `/t/{tenant_id}/e/{environment_id}/account/credentials/remove` | Self-service credential removal, authenticated and subject-bound; cannot remove another user's credential | Covered by the self-service `account` suite (issue #61); R16 CSRF |
| `/t/{tenant_id}/e/{environment_id}/account/mfa/totp/enroll` | TOTP enrollment begin (issue #69): authenticated by the caller's OWN session cookie and subject-bound, it mints a fresh seed from the entropy seam, seals it under the scope DEK (issue #48) in a PENDING row, and returns the `otpauth://` provisioning URI plus the grouped Base32 secret. The pending row cannot satisfy MFA. Fails closed with a 404 when TOTP is disabled. R16 CSRF | Not an OAuth token endpoint (no `client_id`, no redirect, no grant): it mints no bearer token. The sealed-seed-at-rest, no-partial-active-factor, subject binding, and disabled-is-404 properties are covered by the `totp` suite (issue #69) |
| `/t/{tenant_id}/e/{environment_id}/account/mfa/totp/verify-enrollment` | TOTP enrollment verify/activate (issue #69): authenticated and subject-bound, it activates the pending factor ONLY after the user proves possession with a valid current code (an abandoned/failed enrollment leaves no active factor), then mints the one-time recovery codes shown exactly once. R16 CSRF | Not an OAuth token endpoint. The code-verified activation, single-use seeding of the consumed step, and recovery-code minting are covered by the `totp` suite (issue #69) |
| `/t/{tenant_id}/e/{environment_id}/account/mfa/totp/verify` | TOTP second-factor verify (issue #69): authenticated and subject-bound, it verifies a code with a bounded drift window and constant-time compare, and enforces single-use at the store (a replay within the window is refused with the SAME uniform invalid-code response, never an oracle), recording the drift offset for resync. Gated by the #64 abuse-defense throttle seam. R16 CSRF | Not an OAuth token endpoint. The single-use replay rejection, drift-window resync, constant-time compare, and uniform non-enumerating error are covered by the `totp` suite (issue #69) |
| `/t/{tenant_id}/e/{environment_id}/account/mfa/totp/remove` | TOTP factor removal (issue #69): authenticated and subject-bound; another user's factor is the uniform not-found. TOTP is a second factor, so removal never strands the account. R16 CSRF | Not an OAuth token endpoint. The subject binding and uniform not-found are covered by the `totp` suite (issue #69) |
| `/t/{tenant_id}/e/{environment_id}/account/mfa/recovery-codes` | Recovery-code regeneration (issue #69): authenticated and subject-bound, behind fresh authentication (step-up seam), it replaces the whole set (invalidating every prior code) and returns the fresh set exactly once. R16 CSRF | Not an OAuth token endpoint. The regenerate-invalidates-prior and shown-once properties are covered by the `totp` suite (issue #69) |
| `/t/{tenant_id}/e/{environment_id}/account/mfa/recovery-codes/redeem` | Recovery-code redemption (issue #69): authenticated and subject-bound, it verifies a presented code against the stored Argon2id hashes (through the admission-controlled pool) and redeems it single-use, audited DISTINCTLY from a TOTP verification. A wrong or spent code is the uniform invalid-code response. Gated by the #64 abuse-defense throttle seam. R16 CSRF | Not an OAuth token endpoint. The hashed-at-rest, single-use redemption, distinct auditing, and uniform error are covered by the `totp` suite (issue #69) |
| `/t/{tenant_id}/e/{environment_id}/account/mfa/plan` | Factor-orchestration plan (issue #69): authenticated and subject-bound, it reports the per-tenant ordered factor steps (which factor is offered or required first) and whether a second-factor enrollment is required, the flow step the hosted login consumes. Read-only (no state change, no CSRF surface) | Not an OAuth token endpoint: it returns a per-tenant flow plan, mints no token. The per-tenant ordering behavior is covered by the `totp` suite (issue #69) |
| `/t/{tenant_id}/e/{environment_id}/invitations/accept` | Public invitation accept (issue #60): the invitee redeems a single-use, expiring, unguessable token (stored only as its digest) to enroll a credential and activate the pending-verification user. The TOKEN is the sole authenticator (never a cookie, so no CSRF surface to guard), the redeem is atomic and single-use (a concurrent double-accept redeems at most once), and a forged/expired/redeemed/revoked/cross-scope token is the uniform not-found (no token-guessing or existence oracle) | Not applicable to the RFC 9700 credential items (it is not an OAuth token endpoint: no `client_id`, no redirect, no OAuth grant; the invitation token carries no ambient authority and rides no cookie). The single-use, atomic-redeem, uniform-error, hashed-at-rest, and cross-tenant-isolation properties are covered by the `invitations` suite (issue #60) |
| `/t/{tenant_id}/e/{environment_id}/otp/send` | Email-OTP send (issue #68): issues a fresh 6-8 digit code (hashed via the #62 pool, single active per (user, purpose): reissue invalidates the predecessor) and delivers it through the verification seam. Abuse-throttled per recipient and per tenant on the #64 layer; a send to an unknown recipient is SUPPRESSED with an IDENTICAL acknowledgment (the anti-enumeration contract). R14 uniformity, R16 CSRF n/a (no cookie authority) | Not an OAuth token endpoint (no `client_id`, no redirect, no grant): it mints no bearer token. The single-active-per-purpose reissue, hashed-at-rest, per-recipient/per-tenant throttle, and anti-enumeration send suppression are covered by the `email_otp` suite (issue #68) |
| `/t/{tenant_id}/e/{environment_id}/otp/verify` | Email-OTP verify (issue #68): verifies a presented code against the stored Argon2id hash (constant-time, through the admission-controlled pool), enforces a per-code attempt counter (the code dies after N wrong guesses) and single-use consumption, and on success establishes a session with an honest `otp` amr. A wrong, expired, over-attempted, or absent code is the uniform invalid-code response. Gated by the #64 abuse throttle | Not an OAuth token endpoint (it establishes the session the code flow later reads, like the password login). The constant-time compare, attempt-counter death, single-use consumption, honest amr, and uniform non-enumerating error are covered by the `email_otp` suite (issue #68) |
| `/t/{tenant_id}/e/{environment_id}/magic/send` | Scanner-safe magic-link send (issue #68): issues a single-use link token (CSPRNG entropy, stored only as its SHA-256 digest) plus a printed cross-device short code (Argon2id-hashed), sets the same-device binding cookie (for EVERY request, so cookie presence is never an existence oracle), and delivers through the verification seam. Abuse-throttled per recipient and per tenant; a send to an unknown recipient is SUPPRESSED with an identical acknowledgment | Not an OAuth token endpoint: it mints no bearer OAuth token. The digest-only single-use token, per-recipient/per-tenant throttle, uniform binding cookie, and anti-enumeration suppression are covered by the `magic_link` suite (issue #68) |
| `/t/{tenant_id}/e/{environment_id}/magic/confirm` | Scanner-safe magic-link confirmation page (issue #68): a GET renders a CONFIRMATION PAGE ONLY and NEVER consumes the link, so a prefetching email security scanner (GET/HEAD/bot) cannot consume a single-use link before the human clicks. Consumption happens only on the POST from this page. Per deployment the token rides the URL FRAGMENT (read by a nonce-guarded page script), keeping it out of server access logs and scanner request paths. Page hardening (CSP, no-store, nosniff, frame-deny) | Not an OAuth token endpoint: a read-only hosted page. The scanner-safe GET-does-not-consume property and the fragment-token option are covered by the `magic_link` suite (issue #68) |
| `/t/{tenant_id}/e/{environment_id}/magic/consume` | Scanner-safe magic-link consume (issue #68): the POST from the confirmation page consumes the single-use link (guarded single-use UPDATE), binding consumption to the requesting browser via the same-device cookie; when the cookie is absent (link opened on another device) it renders the cross-device page and completes login via the printed short code entered on the originating device. On success establishes a session with an honest `otp` amr. Same-origin CSRF gate before any consumption; a forged/expired/consumed link is the uniform invalid page. Gated by the #64 abuse throttle. R16 CSRF | Not an OAuth token endpoint (it establishes the session the code flow later reads). The scanner-safe POST-only consumption, single-use guarantee, same-device binding + cross-device short-code fallback, honest amr, and uniform errors are covered by the `magic_link` suite (issue #68) |
| `/t/{tenant_id}/e/{environment_id}/webauthn/register/options` | WebAuthn passkey registration challenge (issue #65): authenticated by the caller's OWN session cookie and subject-bound, it issues a single-use challenge (minted from the entropy seam, consumed exactly once) and returns the creation options with `excludeCredentials` populated from the subject's existing passkeys. R16 CSRF (same-origin header allowlist) | Not an OAuth token endpoint (no `client_id`, no redirect, no grant): it mints no bearer token and returns a public challenge nonce. The single-use challenge, subject binding, and non-enumerating errors are covered by the `webauthn` suite (issue #65) |
| `/t/{tenant_id}/e/{environment_id}/webauthn/register/verify` | WebAuthn passkey registration verify (issue #65): authenticated and subject-bound, it consumes the single-use challenge and verifies the ceremony (origin, RP ID hash, flags) before persisting the credential; a used/expired challenge, an origin/RP-ID mismatch, or a duplicate authenticator is refused. R16 CSRF | Not an OAuth token endpoint. The single-use challenge, origin/RP-ID verification, no-partial-row-on-failure, database dedupe, and non-enumerating errors are covered by the `webauthn` suite (issue #65) |
| `/t/{tenant_id}/e/{environment_id}/webauthn/authenticate/options` | WebAuthn passkey sign-in challenge (issue #65): the discoverable-credential (conditional UI) sign-in start. It issues a single-use challenge and returns the request options with an empty `allowCredentials` (the authenticator offers whatever passkeys it holds for the RP ID). R16 CSRF | Not an OAuth token endpoint: it returns a public challenge nonce, mints no token. The single-use challenge and non-enumerating errors are covered by the `webauthn` suite (issue #65) |
| `/t/{tenant_id}/e/{environment_id}/webauthn/authenticate/verify` | WebAuthn passkey sign-in verify (issue #65): consumes the single-use challenge, verifies the assertion signature/origin/RP-ID/flags against the resolved credential, applies the sign-count clone-detection policy, enforces backup-eligibility immutability (a BE flip is refused and audited), and establishes the sign-in session recording an honest `phr`/`phrh` acr derived from the STORED BE with an amr that reflects whether user verification happened. A missing credential is indistinguishable on the wire from a bad signature. R16 CSRF | Not an OAuth token endpoint (it establishes the session the code flow later reads, like the password login): the assertion carries no `client_id` and rides no OAuth grant. The signature/origin/RP-ID verification, single-use challenge, clone detection, BE-immutability enforcement, and uniform non-enumerating errors are covered by the `webauthn` suite (issue #65) |
| `/t/{tenant_id}/e/{environment_id}/webauthn/credentials` | Self-service passkey list (issue #65): the authenticated caller lists ONLY their OWN passkeys (subject-bound, never addressable by another user's id) with the live BE/BS, discoverability, and clone-detected flags; no secret (never the COSE key) is returned. The same list is also folded into `GET /account/credentials` so a user sees every credential in one place | Not an OAuth token endpoint (no `client_id`, no redirect, no grant): a read of the caller's own credential metadata. The subject-binding/IDOR and non-enumerating not-found are covered by the `webauthn` suite (issue #65) |
| `/t/{tenant_id}/e/{environment_id}/webauthn/credentials/rename` | Self-service passkey nickname change (issue #65): authenticated and subject-bound, it reseals the nickname and audits the mutation; another user's credential is the uniform not-found. R16 CSRF | Not an OAuth token endpoint. The subject-binding/IDOR, uniform not-found, and mutation audit are covered by the `webauthn` suite (issue #65) |
| `/t/{tenant_id}/e/{environment_id}/webauthn/credentials/remove` | Self-service passkey removal (issue #65): authenticated and subject-bound, it removes the caller's OWN passkey and audits the mutation; another user's credential is the uniform not-found and is never removed. R16 CSRF | Not an OAuth token endpoint. The subject-binding/IDOR, uniform not-found, and mutation audit are covered by the `webauthn` suite (issue #65) |

<!-- rfc9700:end-endpoints -->

## Not applicable in this milestone

These RFC 9700 items are intentionally not asserted here. Every one is listed with
its reason; nothing applicable is dropped.

- **Sender-constrained ACCESS tokens (DPoP / mTLS, RFC 9700 2.2.1).** RFC 9700 2.2.1
  requires an access token to be either sender-constrained OR audience-restricted.
  IronAuth ships the audience-restricted alternative, with a short lifetime, and that
  is asserted (R9). Proof-of-possession binding (DPoP, mTLS) is FAPI 2.0 hardened-mode
  work (milestone M16), so no conformance test is asserted for it here. The REFRESH
  token requirement is a different clause (RFC 9700 2.2.2) and is not deferred: it is
  fully covered by R8 (one-time use with rotation and family revocation on reuse).
- **Resource-server posture (RFC 9700 4.9, 4.10: token leakage at, and misuse of a
  stolen token by, a resource server).** These are requirements on a PROTECTED
  RESOURCE, not on the authorization server. The one resource surface this provider
  ships is `/userinfo`, whose token handling (header-only presentation, uniform
  `invalid_token`, scope enforcement) is covered by R9 and the `userinfo` suite; the
  general RS hardening of a deployment's own APIs is that deployment's to make, and
  the audience restriction it needs to do so is R9.
- **TLS-terminating reverse proxies (RFC 9700 4.13).** A DEPLOYMENT property (which
  forwarded headers a proxy is trusted to set), not a protocol behavior this suite can
  drive through the router. It is owned by the server crate's proxy-trust
  configuration and its own tests.
- **The CLIENT half of the redirect-based flow (RFC 9700 4.5, 4.7, 4.14: `state` or
  PKCE handling, refresh-token storage, browser-based-apps BCP posture).** Owned by
  the SDK milestone. This suite tests the provider surface. The provider-side
  obligations that make those client defenses possible are asserted: PKCE is mandatory
  and downgrade-proof (R5), `iss` rides every authorization response (R7), and the
  interaction POSTs are CSRF-checked server-side (R16).
- **OIDF / FAPI 2.0 conformance profiles.** Owned by the certification wave (the
  OIDF conformance suite as a merge gate) and M16; this suite is the RFC 9700
  checklist, not those profiles.

## Provider decisions this checklist enforces

- **303, not 302 (R10).** The authorization-response and interaction redirects were
  changed from `302 Found` to `303 See Other`. `303` mandates that the user agent
  re-issue the follow-up as a `GET` with no request body, so a credential in a
  submitted login/consent POST body is never replayed to the redirect target and a
  code-carrying redirect is never method-ambiguous. `307`/`308` are forbidden.
- **Referrer-Policy at the single seam (R11).** `Referrer-Policy: no-referrer` is
  now emitted by the one redirect builder that carries the code in the `Location`
  query, closing the gap where a `query`-mode redirect previously set only
  `Cache-Control`. The `form_post` interstitial already carried it.
- **Referrer-Policy on a FORM-HOSTING page is `same-origin`, not `no-referrer`
  (R11, R16).** A page's referrer policy also decides what `Origin` the browser puts
  on that page's own form POST: per the Fetch standard, a non-`GET`/`HEAD`, non-CORS
  request from a `no-referrer` document has its serialized origin set to `null`. A
  `no-referrer` login, registration, consent, or device-approval page therefore makes
  every real browser submit with the opaque `Origin: null`, which the same-origin CSRF
  check (R16) cannot distinguish from a hostile cross-origin post. `same-origin`
  preserves the property `no-referrer` was there for (an authorization URL carrying
  `state`, `nonce`, and the `redirect_uri` is never disclosed to any cross-origin
  destination, because no `Referer` is sent cross-origin at all) while keeping a real,
  checkable `Origin` on the same-origin POST. The code-carrying responses (the
  query-mode redirect and the `form_post` interstitial) host no form that posts back to
  this origin, so they keep `no-referrer`, which is strictly stronger and costs nothing
  there. In defense in depth, the CSRF check ALSO resolves an opaque `Origin: null` by
  fetch metadata: `Sec-Fetch-Site` is a forbidden header name that page script cannot
  set, so `null` is accepted only alongside a user-agent-authored `same-origin` or
  `same-site`, and is rejected when the metadata is absent or says `cross-site`.
