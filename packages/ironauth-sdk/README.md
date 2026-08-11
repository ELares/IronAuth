# @ironauth/sdk

A uniform authorization `check()` (issue #100, criterion 6).

One call shape, three resolvers, chosen by configuration and not by the call site:

- `claims`  reads the permission out of the access token the caller already holds
- `authzen` asks IronAuth's AuthZEN policy decision point
- `pdp`     asks the customer's own PDP or FGA over the same AuthZEN wire shape

Application code is written once and a deployment decides later where the answer comes
from. A team that starts with claims and outgrows the token budget changes a config value,
not every call site. See `docs/design/COARSE-CLAIMS-FINE-PDP.md` for when to use which.

## Why this is not in the reference app

`packages/reference-app` is a PURE CLIENT of the public flow API, and `scripts/route-audit.sh`
enforces that structurally: only its `api.ts` may perform a network call and only its
`endpoints.ts` may contain a URL literal, so it can never be forked into hitting a private
or management endpoint. An SDK that calls an operator-configured PDP is precisely what that
lint exists to keep out of that package, so the SDK lives here instead. The lint was right
and this package is the consequence.

## Fail closed

Every failure is a DENY: a network error, a non-2xx, a malformed body, a missing claim. This
function IS the authorization decision, so its absence must never grant. That is the
opposite direction from the claims-enrichment hook, which only ADDS claims and therefore
fails open.
