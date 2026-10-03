# The air-gap parity guarantee (issue #163)

This page is the written guarantee. It is a **maintained guarantee, not an
accident**: the no-egress CI lane ([`scripts/dev-no-egress.sh`](../scripts/dev-no-egress.sh)
plus [`scripts/dev-core-flows.sh`](../scripts/dev-core-flows.sh)) boots the
server with egress blocked and drives the core-flow battery - discovery, JWKS
fetch, email-OTP login, the code+PKCE authorization, token issuance, and an
admin API call - on every run. A feature that needs a reachable third party to
function breaks that lane, and the lane fails.

## The property, stated precisely

Every IronAuth feature works in a deployment with **no outbound network access
at all**: no phone-home, no license callbacks, and no telemetry required for
functionality. The single binary plus PostgreSQL is a complete deployment.
IronCache and IronBus remain strictly optional and are documented for offline
use where deployed.

The guarantee explicitly covers the environments the public-sector procurement
vocabulary calls **DDIL** - denied, disrupted, intermittent, and limited
communications environments. A deployment that can reach nothing still issues,
validates, and manages credentials.

What the guarantee does **not** cover: integrations whose entire purpose is a
reachable third party - social IdP federation, external email/SMS providers,
online breach databases (the offline HIBP corpus covers that path), and
remote-signing backends you choose to reach over a network. Those are
documented where they are configured.

## Why it is maintained, not accidental

Three covenants make this structural rather than a posture claim:

1. **No mandatory first-party infrastructure.** Nothing in the product
   requires an ELares-operated service to function.
2. **No unexportable data.** Every write is to the deployment's own database.
3. **The no-egress CI lane.** The enforcement mechanism above: the battery runs
   against a booted server inside a window in which the process's connections
   are inspected (lsof) and asserted to be loopback-only.

## The offline security-advisory feed

Disconnected deployments are exactly the ones that miss security advisories.
The signed advisory feed ([`[security]` config](./CONFIG.md)) works in both
worlds with one verification path:

- **Online**: the server polls the feed (opt-out, never load-bearing - a fetch
  or verification failure only logs).
- **Air-gapped**: the same signed bundle is imported through the management API
  (`POST .../security/advisories/import`).

A feed that fails signature verification is rejected **entirely** in both paths
- a tampered bundle cannot inject one advisory while the rest fails - and the
rejection is logged as a security event. The banner surface
(`GET .../security/advisories`) renders only accepted advisories.

The accepted set is deployment-wide, so offline imports require deployment-operator
credentials. Environment-scoped management keys cannot import, including keys with
`management.write_config`; reads retain their existing permission checks.
Replacement writers serialize so concurrent
polls or imports leave one complete verified set. Migration 0248 completes the
control role's replacement grant; the serving role remains read-only. An offline
import publishes `security_advisory.imported` in the requesting management scope's
event stream in the same transaction as the replacement. Its aggregate payload
contains only `advisory_count` and `deployment_global: true`; it does not contain
advisory contents or claim to fan out to every environment. A failed event write
rolls back the replacement, and a failed replacement publishes nothing.


## The air-gapped install, end to end

The procedure below is the one the no-egress lane exercises (loopback instead
of a transfer into an enclave; the flows are identical).

1. **The artifact.** The single `ironauth` binary (cosign-signed images and
   the CycloneDX SBOM ship with the release pipeline). Transfer it into the
   enclave by whatever media your air gap uses; no checksum download at
   runtime is ever needed.
2. **The registry.** If you deploy from containers, mirror the image into your
   offline registry (`docker pull` outside the enclave, then `docker save` /
   transfer / `docker load` inside, or a registry-mirror pattern). The image
   contains nothing that fetches at first start.
3. **Postgres.** Provision PostgreSQL inside the enclave. The binary migrates
   its own schema at boot (a real migration chain, applied in order, each
   reversible). No external DNS is consulted; the database is reached by
   whatever address your enclave resolves locally.
4. **Configuration.** `ironauth.toml` is written without any external
   reference: database URL, listeners, signing keys (local or the Vault
   transit backend if your enclave runs one), and the optional
   `[security] advisory_verification_key` for the offline bundle import.
5. **Battery.** Run the core-flow battery against the new deployment before
   service: discovery answers, a code+PKCE login completes, a token issues,
   JWKS serves, the admin API answers. In CI this is the no-egress lane; in an
   enclave it is your acceptance run.
6. **Advisories.** Import the signed advisory bundle through the management
   API (`POST .../security/advisories/import`); banners render in the admin
   console, and certificate/expiry warnings come from the deployment's own
   state.

## Offline capabilities at a glance

| Capability | Offline status |
| --- | --- |
| Discovery, JWKS, authorization code + PKCE, device code, client credentials | Full |
| Token issuance, refresh, revocation | Full |
| OTP login (codes captured in the sink, not a mail server) | Full |
| Security-advisory feed | Imported bundle (same verification as online) |
| Breached-password screening | Configured offline corpus |
| Social IdP federation, external email/SMS | Requires the third party (documented) |