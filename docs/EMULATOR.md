# The local emulator: `ironauth dev`

One command brings up a real IronAuth server for development and CI, using local
PostgreSQL binaries with no separately running services and no accounts to create.
The seeded development workflow uses no external provider. Some production
features perform outbound requests when explicitly exercised, such as the online
breached-password check; do not treat dev mode as a network sandbox.

```
ironauth dev
```

It is the same binary and the same code paths a deployment runs. It is not a mock, and it is
not a second implementation that can drift from the real one.

## Prerequisites and a first launch

Install the repository's pinned Rust toolchain and PostgreSQL binaries, including
`initdb`, `pg_ctl`, and `psql`. Run as an ordinary user; PostgreSQL initialization
refuses root. The emulator looks at `PG_BIN` first, then installed binary paths.
For Homebrew PostgreSQL 17, set `PG_BIN="$(brew --prefix postgresql@17)/bin"` if
automatic discovery fails.

From the repository root:

```sh
cargo build --locked -p ironauth
env -u DATABASE_URL ./target/debug/ironauth dev --seed 1
```

Removing `DATABASE_URL` for this command selects the managed throwaway cluster.
Use the printed issuer URL and management port; they are not interchangeable.
The default public bind is `127.0.0.1:8080`, and `--bind 127.0.0.1:8081` can
select another loopback port. The admin console is not enabled in the generated
development configuration. See [operations](OPERATIONS.md) and
[console setup](ADMIN-CONSOLE.md) for a dashboard deployment.

## What you get

```
ironauth dev: fake upstream IdP at http://127.0.0.1:58724
ironauth dev: issuer http://127.0.0.1:8080/t/ten_.../e/env_...
ironauth dev: client_id cli_... (public, redirect http://127.0.0.1/callback)
ironauth dev: machine identity sva_... (owned by client cli_...)
ironauth dev: operator token ironauth-dev-operator-token-not-for-production
ironauth dev: management http://127.0.0.1:58729
ironauth dev: user dev@example.test / dev-password-not-for-production
ironauth dev: captured messages at http://127.0.0.1:58737/
```

- **A throwaway database**, brought up by this process and deleted on normal shutdown.
  Set `DATABASE_URL` only to use a separately managed local development database.
- **A seeded identity landscape**: an operator, tenant, environment, organization, a public
  client registered for the loopback redirect, and a user with a known password.
- **Capture sinks instead of providers.** Email and SMS are not sent anywhere; they are
  recorded and served as JSON at the sink endpoint, so a test can read a one-time code
  without a mail server.
- **A fake upstream IdP** on its own loopback listener, for exercising federation offline.

The identifiers and ephemeral ports above are illustrative. Discovery and hosted
login routes use the printed `/t/<tenant>/e/<environment>` issuer. Management
calls use the separately printed URL with the development operator bearer; never
put that bearer into browser configuration. The seeded machine identity belongs
to a separate workload client.

When `DATABASE_URL` is supplied, the emulator does **not** provision roles, apply
migrations, seed identities, or print the seeded issuer/client/management values.
Prepare that database yourself and inspect the generated development
configuration for its management listener. This mode is for a database whose
lifecycle you already manage, not a shortcut for seeding persistent installations.
Ctrl-C or SIGTERM performs normal cluster cleanup. A hard kill cannot run cleanup;
an interrupted cluster may need manual removal from the temporary directory.

## Determinism, and what it is for

Seeded identifiers and runtime entropy derive from `--seed` (default `1`).
The same seed produces the same tenant
id, the same client id, and the same one-time codes for the same request sequence.
Listener ports are ephemeral and the clock remains real so expiry works normally.
That is what lets a CI job assert an exact code rather than whatever happened to
be generated:

```
ironauth dev --seed 1
```

Change the seed and the seeded tenant, environment, and client identifiers change.
The published development user password and operator token remain fixed constants.
Pin the seed in CI so the job fails loudly if reproducibility breaks.

## Reading a one-time code

The sink endpoint returns every captured message, newest last:

```
curl -s http://127.0.0.1:58737/
```

```json
{"messages":[{"kind":"email","recipient":"dev@example.test","body":"334158"}]}
```

`kind` is `email` or `sms`. `body` is the code, the magic link, or the SMS text, **in
plaintext** -- that is the whole point, and it is why the sink is loopback-only and exists
only in dev mode.

## A GitHub Actions recipe

This runs a complete email-OTP login against the emulator, offline, and fails if the code is
not the deterministic one for the seed. It needs the Postgres *binaries* (`initdb`, `pg_ctl`)
but no Postgres service: the emulator brings up its own cluster, which is the cold path a
developer actually experiences.

```yaml
name: auth integration

on: [push, pull_request]

jobs:
  login:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: dtolnay/rust-toolchain@stable

      # The emulator starts its own throwaway cluster, so install the binaries,
      # not a service container.
      - name: Install PostgreSQL binaries
        run: |
          sudo apt-get update
          sudo apt-get install -y postgresql

      - name: Build the server
        run: cargo build --locked -p ironauth

      - name: Start the emulator
        run: |
          env -u DATABASE_URL \
            PG_BIN=$(dirname $(ls /usr/lib/postgresql/*/bin/pg_ctl | head -1)) \
            ./target/debug/ironauth dev --bind 127.0.0.1:8080 --seed 1 > dev.log 2>&1 &
          for _ in $(seq 1 100); do
            issuer=$(grep -o 'issuer http://[^ ]*' dev.log | head -1 | sed 's/issuer //')
            if [ -n "$issuer" ] && curl -sf -o /dev/null \
                 "$issuer/.well-known/openid-configuration"; then
              echo "ISSUER=$issuer" >> "$GITHUB_ENV"
              echo "SINK=$(grep -o 'captured messages at http://[^ ]*' dev.log \
                            | sed 's/.*at //')" >> "$GITHUB_ENV"
              exit 0
            fi
            sleep 0.2
          done
          echo "the emulator never served"; tail -20 dev.log; exit 1

      - name: Complete an email-OTP login
        run: |
          set -euo pipefail

          # 1. Request the code. A 200 here proves only that the request was accepted:
          #    the response is identical whether or not the account exists, which is the
          #    anti-enumeration contract. The real assertion is the captured code.
          curl -sf -X POST "$ISSUER/otp/send" \
            -H 'content-type: application/json' \
            --data '{"identifier":"dev@example.test"}' -o /dev/null

          # 2. Read it out of the sink. This is the step a mail server would otherwise be
          #    required for, and it is the reason the emulator exists.
          code=$(curl -s "$SINK" | jq -r '[.messages[] | select(.kind=="email")][-1].body')

          # 3. Assert the DETERMINISTIC code for this seed. Without this the job passes
          #    against any code at all, and a reproducibility regression goes unnoticed.
          [ "$code" = "334158" ] || {
            echo "code $code is not the expected 334158 for seed 1"; exit 1; }

          # 4. Complete the login. The status code alone is not the claim: assert
          #    authenticated, so a future 200 carrying a refusal body cannot read as success.
          body=$(curl -sf -X POST "$ISSUER/otp/verify" \
            -H 'content-type: application/json' \
            --data "{\"identifier\":\"dev@example.test\",\"code\":\"$code\"}")
          [ "$(printf '%s' "$body" | jq -r '.authenticated')" = "true" ] || {
            echo "verify did not authenticate: $body"; exit 1; }
```

The equivalent of this runs in this repo's own CI as `scripts/dev-otp-login.sh`, alongside
`scripts/dev-no-egress.sh` (which asserts the emulator opens no outbound connections) and
`scripts/dev-boot-time.sh` (which fails if boot to serving exceeds five seconds).

## Guardrails

Dev mode is loudly non-production, and the guardrails are structural rather than flags
nobody re-reads.

- **It refuses a non-loopback bind.** Deterministic secrets are safe only on a machine that
  cannot be reached; making the bind address the gate means the unsafe combination cannot be
  assembled by setting one flag and forgetting another.
- **It refuses a `DATABASE_URL` on another machine.** That is the same hazard in the other
  direction, and the one reached by accident, because `DATABASE_URL` is often already
  exported in a shell. Dev mode would otherwise seed a fixed identity landscape, including a
  user whose password is a published constant, into that database.
- **A hostname is never treated as local**, in either guard. `localhost` resolves wherever
  the host's resolver says it does; a guard that trusts a name is a guard that can be talked
  out of its answer.
- **The capture sink and the fake IdP run on their own listeners**, not as routes on the
  server. A production deployment therefore has no such route to leak, whatever a future
  refactor does to a conditional.

## The fake upstream IdP

A built-in OIDC provider that authenticates one fixed identity immediately, with no login
page and no consent, so a federation flow can be driven by a test. `ironauth dev` seeds a
connector pointing at it under the slug `dev-upstream`.

It serves a real discovery document and a real JWKS, and signs its ID tokens through the same
JOSE path the server's own endpoints use. It keeps no state, so the `nonce` bound at the
authorization request rides inside the authorization code it issues and comes back in the ID
token from there.

**Known limitation.** The provider is reachable by a browser and by tests, but `ironauth
dev`'s own federation legs cannot currently reach it: the outbound fetcher is https-only and
its SSRF policy denies loopback destinations, while this provider is plaintext on `127.0.0.1`.
A federation attempt through the emulator answers `503` today. The provider is covered
end to end by `crates/ironauth-oidc/tests/fake_idp_federation.rs`.
