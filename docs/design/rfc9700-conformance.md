# RFC 9700 conformance suite: design and rationale

This is the design note for issue #38: encoding the RFC 9700 (OAuth 2.0 Security
Best Current Practice) checklist as CI conformance tests. The public-facing
traceability map is
[docs/conformance/rfc9700-checklist.md](../conformance/rfc9700-checklist.md); this
note records the engineering decisions behind it.

## Goal

Convert each RFC 9700 item the shipped M2/M3 surface implements into a named
executable invariant that fails CI if the behavior regresses. The suite doubles as
a verifiable public security-posture statement, stronger than a hardening doc,
because every claim is an assertion that runs on every PR.

## Structure

- `crates/ironauth-oidc/tests/rfc9700.rs` drives the LIVE authorization, token,
  discovery, and interaction endpoints over a real database (the shared
  `tests/common` harness) and asserts each property. It is a registered `[[test]]`
  (the crate sets `autotests = false`, so an unregistered test file would be dead).
- `docs/conformance/rfc9700-checklist.md` maps every requirement to its test(s).
- `scripts/rfc9700-scan.sh` is the freshness lint (see below).

## Non-vacuity: the shared-predicate mutation harness

A conformance test that can pass but never fail is worthless, so every header- or
shape-based item reduces its assertion to a PURE PREDICATE in the `checks` module:
the conformance test extracts the security-relevant facts from the live response and
asserts `checks::<item>(facts).is_ok()`. A paired test in the `mutation` module
feeds that SAME predicate the exact shape a flipped guard would produce (a `307`
where a `303` is required, a stripped `iss`, an injected `Access-Control-Allow-Origin`,
a `200` success where a reuse must be `invalid_grant`) and asserts it returns `Err`.

Why this proves non-vacuity: the conformance test's verdict IS the predicate's
verdict on the live response. If the live guard flipped, the live response would
become the violating shape, the predicate would return `Err`, and the conformance
test would go RED. The mutation test proves the predicate rejects precisely that
shape. Each mutation test also confirms the predicate ACCEPTS a conforming shape, so
a predicate that always errs (which would already fail the live conformance test) is
pinned from both sides. Behavioral items (single-use, downgrade, reuse) assert an
exact outcome (`invalid_grant` / `unsupported_grant_type`); the `is_invalid_grant`
predicate's mutation test proves that accepting a reused or mis-bound code (a `200`
with a token) is caught.

Both the conformance tests and the mutation tests run in the ONE integration-test
binary on every PR, so CI continuously enforces both directions with no extra job.

### Why the harness is provably absent from every shipped artifact

The task requires that any seeded-violation code path be test-only and provably
absent from the release and musl builds. This design introduces NO seeded-violation
code path into the library or the server at all: the violating inputs are
constructed in memory inside `tests/rfc9700.rs`. Integration test files under
`tests/` are compiled into their own test-only crates and are never linked into the
library or the binary. The musl lane builds `cargo build --release -p ironauth`,
which compiles the `ironauth` binary and its library dependencies and never compiles
any `tests/*.rs`; the same is true of every release build. There is therefore no
cargo feature, no `cfg`, and no guard in `src/` that a release could accidentally
enable. The invariant-lints, dash-scan, and musl lanes are unaffected because
nothing in `src/` changed to support the harness.

## The 302-vs-303 decision (R10)

RFC 9700 requires `303 See Other` for a credential-bearing redirect and forbids
`307`/`308`. The concrete attack it closes is a body-preserving redirect (`307` or
`308`) replaying a submitted POST body (which may carry the user's password from a
login form, or the authorization code) to the redirect target. `303` mandates that
the user agent re-issue the follow-up as a `GET` with no body; the legacy `302`
leaves that method conversion browser-dependent.

Before this change, every IronAuth redirect used `302 Found`, emitted by exactly
three builders: `error.rs::redirect_response` (the authorization success and error
responses, in `query` and `fragment` modes) and `interaction.rs::redirect` /
`redirect_setting_cookie` (the login, registration, and consent interaction
redirects). Because all redirects funnel through those three builders, the change is
contained: all three now emit `303 See Other`.

The change is safe for the shipped issue #13 flows and is strictly more correct:

- `GET /authorize` -> redirect to `redirect_uri`: a GET-sourced redirect that every
  OAuth client already follows as a GET; `303` makes the code-carrying redirect
  unambiguous.
- The post-login / post-consent redirects follow a credential-bearing POST. This is
  the textbook Post/Redirect/Get case where `303` is exactly right: it guarantees
  the browser does not re-submit the password to the `return_to` target. Under `302`
  this depended on browser behavior; `307` here would be an actual credential-replay
  bug.

Every existing test that asserted `StatusCode::FOUND` on a redirect was updated to
`StatusCode::SEE_OTHER`; the assertions are not weakened (an exact status-code
assertion), only corrected to the new, spec-mandated behavior. The rejected
alternative was to keep `302` and test only "not 307", which the issue explicitly
warns is a vacuous check that stays green at `302`; choosing `303` lets the
conformance test assert the exact required status, which is maximally non-vacuous
(its mutation test rejects `302`, `307`, and `308`).

## The Referrer-Policy decision (R11)

RFC 9700 wants `Referrer-Policy: no-referrer` on every response that carries an
authorization code, so the code cannot leak onward through the `Referer` header. The
HTML and `form_post` responses already set it (via `pages::secure_html` /
`form_post_response`), but the `query`-mode redirect, which carries the code in the
`Location` query string, previously set only `Cache-Control: no-store`. That was the
gap.

The fix adds `Referrer-Policy: no-referrer` to the single redirect seam
(`redirect_response`, plus the interaction `redirect` / `redirect_setting_cookie`),
so the header rides every code-carrying redirect from one place and cannot drift.
This is a one-seam change, consistent with the codebase's rule that a security
header is attached in exactly one place.

## The freshness lint (`scripts/rfc9700-scan.sh`)

The lint mirrors the existing freshness scripts (`compat-matrix.sh` generate-and-diff
and `discovery-scan.sh` single-source assertion) and binds coverage so a future
BCP-relevant endpoint cannot ship uncovered:

1. It asserts `tests/rfc9700.rs` is a registered `[[test]]`.
2. It regenerates the endpoint inventory (`docs/conformance/rfc9700-endpoints.txt`)
   from the live `oidc_router` and `git diff --exit-code`s it, so adding a `.route()`
   makes the committed inventory stale and fails CI until it is regenerated and
   committed.
3. It asserts every generated endpoint is named in the checklist doc, so a new
   endpoint must be mapped to a covering test (or an explicit not-applicable reason).
4. It asserts the checklist doc and the suite reference the SAME set of `rfc9700_*`
   tests (every test the doc claims exists, and every test that exists is traced), so
   neither can drift from the other.

It is wired into `scripts/gate.sh` and the `invariants` CI job next to
`discovery-scan.sh`.

## Adding a new item or endpoint

1. Add the conformance test (named `rfc9700_*`) to `tests/rfc9700.rs`; for a
   header/shape item, add a `checks::` predicate and a paired `rfc9700_mutant_*`
   test.
2. Add a row to the traceability table and, for a new route, a row to the endpoint
   coverage table in the checklist doc.
3. Run `scripts/rfc9700-scan.sh`; it regenerates the endpoint inventory and fails
   until the doc and the suite agree.
