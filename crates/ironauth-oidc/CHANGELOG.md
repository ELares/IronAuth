# ironauth-oidc changelog

All notable changes to the `ironauth-oidc` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- PKCE enforcement, exact redirect matching, native-app redirect rules, and the
  RFC 9207 `iss` (issue #13). Hardens the #12 authorization and token endpoints;
  the provider stays gated off (`oidc.enabled` unchanged).
  - **PKCE is S256-only and mandatory.** `plain` is structurally absent (no
    registry variant, no config), so any method but `S256` (and a challenge with a
    defaulted method) is `invalid_request`. A PUBLIC client
    (`token_endpoint_auth_method` = none) MUST use PKCE (RFC 9700 2.1.1); a
    CONFIDENTIAL client follows the per-environment policy
    `oidc.require_pkce_for_confidential_clients` (default required). Downgrade
    prevention holds BOTH ways: a challenge-bound code needs the matching verifier,
    and a no-challenge code is never redeemable WITH one.
  - **redirect_uri is matched by EXACT string** against the client's registered set
    (via `ironauth_store`), with only the RFC 8252 loopback port exception; native
    private-use-scheme and claimed-`https` redirects are accepted, and a malformed
    scheme is rejected at authorization time as it is at registration. An
    unregistered or malformed redirect NEVER receives a redirect (an error page),
    so it cannot become an open redirector, and this holds on error paths too.
  - **RFC 9207 `iss`** is emitted on EVERY authorization response, success and
    error, assembled mode-independently (`src/response.rs`) so it covers the
    fragment and `form_post` modes issue #17 enables; discovery now advertises
    `authorization_response_iss_parameter_supported = true` via
    `DiscoveryCapabilities::from_config`.
- Initial OIDC core provider: the authorization endpoint and the
  `authorization_code` grant (issue #12), mounted on the PUBLIC listener.
  - **Authorization endpoint** (`GET`/`POST /authorize`) and the token endpoint's
    `authorization_code` grant (`POST /token`), against a per-environment issuer.
  - **Single-use codes bound at issuance and re-checked BEFORE the code is
    burned.** Each `ac_` code binds its `client_id`, `redirect_uri`, `nonce`, and
    PKCE `code_challenge`. The token endpoint reads the code without consuming it,
    re-checks every binding INCLUDING the `client_id` (the 2026 Zitadel advisory
    class, RFC 6749 4.1.3), and pre-signs the tokens; only then does the atomic
    redeem consume the code. A wrong-binding presentation or a signing failure
    therefore never burns the one-time code, and any mismatch is a uniform
    `invalid_grant` that never says which binding failed.
  - **Single use across N stateless nodes** via one atomic DB statement under READ
    COMMITTED (`UPDATE ... WHERE consumed_at IS NULL RETURNING ...`), which also
    records the issued tokens and the redeem audit in the SAME transaction as the
    consume; zero rows affected is a miss that is then classified. No in-memory
    marker; a seam is left for a future cache accelerator.
  - **Reuse revokes the grant chain; a benign retry does not.** A second
    presentation within a configurable grace window (`oidc.reuse_grace_secs`,
    default 10s) is a benign double-submit or client retry: it is `invalid_grant`
    but does NOT revoke. Beyond the window it is a genuine reuse: the grant is
    revoked (flipping the observable active state of every token issued from the
    code, per an introspection/active-state check; it does not cryptographically
    invalidate an already-minted JWT) and the reuse is audited (RFC 9700).
  - **Grant record** links code, session, consent, and issued tokens: the spine
    for revocation and the M3 refresh families.
  - **Error handling.** `redirect_uri` and `client_id` are validated BEFORE any
    redirect; an invalid one renders an error page and never redirects. All other
    errors are spec-exact codes with `error_description` via the redirect (or the
    OAuth token-error JSON at the token endpoint).
  - **Forbidden flows are structurally absent.** There is no ROPC handler, no
    access-token issuance from the authorization endpoint, and no plain PKCE code
    path: the grant-type, response-type, and PKCE-method registries cannot express
    them, proved by a structural test.
  - Tokens (ID token and access token) are minted through the #9 signing core
    (`ironauth-jose`). ID-token claim contents are minimal here; the conditional
    claim rules are #14. PKCE plumbing is the minimal correct bind-and-verify; the
    S256-only enforcement hardening is #13.
  - **Hardening.** `redirect_uri` validation rejects any non-printable-ASCII byte
    (control characters, raw whitespace, non-ASCII), closing header-splitting and
    look-alike-authority smuggling before the `Location` header is written. The
    authorization-code and issued-token identifiers redact their payload in
    `Debug` so a struct dump or a `tracing` field cannot leak a live bearer
    secret. Issue and redeem audit rows are attributed to the client the flow is
    for, not a throwaway identity. Emits `ironauth_oidc_code_reuse_total` and
    `ironauth_oidc_redeem_error_total` counters.
- New persistence (issue #12, in `ironauth-store`): migration `0004`, the
  tenant-scoped `grants`, `authorization_codes`, and `issued_tokens` tables (RLS
  enabled and forced, nonempty-scope CHECK, and isolation-preserving COMPOSITE
  `(grant_id, tenant_id, environment_id)` foreign keys so a code or token can only
  reference a grant in its own scope), the scoped `authorization` repository, and
  the `authorization_codes.redeem` / `issued_tokens.token_status` IDOR probes.
