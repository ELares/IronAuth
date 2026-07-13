# ironauth-oidc changelog

All notable changes to the `ironauth-oidc` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- Initial OIDC core provider: the authorization endpoint and the
  `authorization_code` grant (issue #12), mounted on the PUBLIC listener.
  - **Authorization endpoint** (`GET`/`POST /authorize`) and the token endpoint's
    `authorization_code` grant (`POST /token`), against a per-environment issuer.
  - **Single-use codes bound at issuance and re-checked at redemption.** Each
    `ac_` code binds its `client_id`, `redirect_uri`, `nonce`, and PKCE
    `code_challenge`; the token endpoint re-checks every binding, INCLUDING the
    `client_id` (the 2026 Zitadel advisory class, RFC 6749 4.1.3), and any
    mismatch is a uniform `invalid_grant` that never says which binding failed.
  - **Single use across N stateless nodes** via one atomic DB statement (`UPDATE
    ... WHERE consumed_at IS NULL RETURNING ...`); zero rows affected is a replay.
    No in-memory marker; a seam is left for a future cache accelerator.
  - **Reuse revokes the grant chain.** A replayed code revokes its grant, so every
    token already issued from it becomes inactive, and the reuse is audited.
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
- New persistence (issue #12, in `ironauth-store`): migration `0004`, the
  tenant-scoped `grants`, `authorization_codes`, and `issued_tokens` tables (RLS
  enabled and forced, nonempty-scope CHECK), the scoped `authorization`
  repository, and the `authorization_codes.redeem` / `issued_tokens.token_status`
  IDOR probes.
