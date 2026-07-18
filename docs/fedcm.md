# IdP-side FedCM (experimental, issue #83)

IronAuth ships the IdP side of the W3C
[Federated Credential Management API (FedCM)](https://www.w3.org/TR/fedcm/) behind an
experimental feature flag. FedCM is the browser-mediated replacement for the
third-party-cookie iframes that silent federated sign-in used to rely on: a relying
party calls `navigator.credentials.get({identity: ...})` and the **browser**, not the
RP, drives the fetches to the IdP.

This is an EXPLORATORY bet on a standard that is not yet broadly shipped. It exists as
cheap optionality: nothing in the certifiable core depends on it.

## Redirect flows are UNAFFECTED

FedCM is a purely ADDITIVE surface behind the flag. The authorize, token, UserInfo, and
the certified conformance surfaces are unchanged by this feature, on by neither default
nor side effect. With the flag off, ZERO behavior changes: no FedCM route answers (every
one is a uniform 404), OIDC discovery advertises nothing about FedCM, and no `Set-Login`
header is emitted. Turning FedCM on or off never alters a redirect login.

## Browser support matrix (honest)

FedCM support is lopsided. This is the whole reason it stays experimental.

| Browser | Status |
|---------|--------|
| Chrome / Chromium (Edge) | Shipping. FedCM is mandatory for Google Identity Services One Tap since August 2025, so the pattern has production proof at the largest scale. |
| Firefox | Implementation paused / behind a preference. Not shipped. |
| Safari | Absent. No implementation. |

Because only Chromium ships FedCM in practice, an IronAuth deployment cannot rely on it
for sign-in; it is an enhancement for the browsers that support it, with the redirect
flow the universal fallback.

## Graduation triggers

FedCM stays `experimental` (no graduation to `preview` or `supported`) until one of:

- **Firefox ships FedCM** (real cross-browser support), OR
- **real embedding demand** (a concrete deployment that needs IdP-side FedCM).

Until then it is not promoted, so it never becomes open-ended maintenance on a standards
bet that did not pay off.

## Enabling it

FedCM is gated by the `fedcm` experimental feature on the maturity ladder. It is off by
default and BOOT-REFUSES when enabled without the exact version acknowledgment (review
`crates/ironauth-oidc/CHANGELOG.md` before enabling; a breaking version bump invalidates
an old ack).

```toml
[features]
"fedcm" = { enabled = true, ack = "0.1.0-exp.1" }

[oidc.fedcm]
# The SINGLE (tenant, environment) this origin exposes over FedCM (Fork A1): FedCM's
# well-known is origin-level, but IronAuth serves everything per (tenant, environment),
# so one env per origin is designated. Both ids together, or neither.
designated_tenant = "ten_..."
designated_environment = "env_..."
# Branding the browser account chooser renders (all optional, non-secret).
provider_name = "Example"
background_color = "#0b1220"
text_color = "#ffffff"
icon_url = "https://auth.example.com/icon.png"
```

Enabling it emits a startup notice. The arming switch is the feature flag resolved to a
state-builder bool at boot, NEVER a plain `[oidc]` toggle, so the experimental ack gate
can never be bypassed: an `[oidc.fedcm]` designated env with the feature disabled still
answers 404 everywhere.

## Endpoints (PR 1: the read surface)

| Surface | Path | Notes |
|---------|------|-------|
| Well-known | `GET /.well-known/web-identity` | Origin-level. Points at the designated env's scoped config. |
| Config | `GET /t/{t}/e/{e}/fedcm/config.json` | The designated env only; a non-designated env is a 404. |
| Accounts | `GET /t/{t}/e/{e}/fedcm/accounts` | Answered from the OP session; empty + uncacheable when logged out. |

The credential-issuing `POST /t/{t}/e/{e}/fedcm/assertion` endpoint is PR 2.

Per the FedCM optional-endpoint set, `client_metadata_endpoint` and `disconnect_endpoint`
are omitted (a login completes without them).

### Security posture

- **`Sec-Fetch-Dest: webidentity` is required** on every FedCM fetch. It is a forbidden
  header name that page script cannot set or forge, so this gate makes the endpoints
  answer ONLY the browser's FedCM machinery, never a page `fetch`.
- The **accounts** response is answered on the SameSite `__Host-` session cookie alone
  (no client-supplied origin or account is ever trusted), is always `Cache-Control:
  no-store` (a logged-out browser can never be served a stale populated body), and a
  request with no session gets an empty `{"accounts": []}` (never leaks account data).
- The account `id` is the per-ENV PUBLIC subject (the pairwise subject if configured),
  through the one shared subject function, never the raw local user id.

## Login Status API

FedCM tracks OP session state via the `Set-Login` response header, emitted only when the
flag is on:

- `Set-Login: logged-in` on session ESTABLISHMENT (every login factor funnels through the
  one establish path).
- `Set-Login: logged-out` on the caller's OWN logout (the paths that terminate the
  presenting browser's session).

A crafted CROSS-USER logout (a request that clears nothing for the presenting browser)
deliberately emits NO `logged-out`, so it can never flip a victim's FedCM login state.

## Testing posture

The CI-permanent gate is the Rust HTTP contract test suite
(`crates/ironauth-oidc/tests/fedcm.rs`): flag-off 404s + discovery unchanged, the
well-known / config shapes, the accounts endpoint (public-subject id, sealed-PII
name/email, uncacheable, empty when no session, `Sec-Fetch-Dest` gated), and the
`Set-Login` wiring (logged-in on login, logged-out on the caller's own logout, never on
a cross-user logout). Boot refusal without the exact ack is covered in
`crates/ironauth-config`.

### Manual Chromium E2E (DEFERRED, not a CI gate)

FedCM is a browser-mediated API with no scriptable surface outside Chrome's
`navigator.credentials.get`, so a literal end-to-end login is a documented manual step,
NOT a CI gate. To exercise it by hand:

1. Boot IronAuth with `"fedcm" = { enabled = true, ack = "0.1.0-exp.1" }` and an
   `[oidc.fedcm]` designated env, over HTTPS on the origin the browser will fetch.
2. From a test RP page in Chrome (a registered client whose config URL is the designated
   env's `.../fedcm/config.json`), call:

   ```js
   const credential = await navigator.credentials.get({
     identity: { providers: [{ configURL, clientId, nonce }] }
   });
   ```

3. Confirm the account chooser renders the seeded account, the login completes, and the
   Login Status transitions (`Set-Login: logged-in` after login, `logged-out` after the
   caller's own logout) are observed.

This satisfies acceptance criterion #1 (a FedCM login completing in Chrome) out of band.
