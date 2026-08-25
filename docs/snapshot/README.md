# IronAuth config snapshot format (v1)

A **config snapshot** is a canonical, deterministic, secret-free export of one
environment's promotable configuration (issue #43). It is the substrate the
config-promotion flagship builds on: the promotion engine (issue #44) diffs and
applies snapshots, a snapshot committed to a git repository makes an
environment's config diffable and reviewable in ordinary code review, and the
Terraform provider and CLI consume this format.

- **Published schema:** [`snapshot.schema.json`](snapshot.schema.json) (JSON
  Schema draft 2020-12).
- **Format version:** `ironauth.config-snapshot/v1` (the `schema_version` field).
- **Export endpoint:**
  `GET /v1/tenants/{tenant_id}/environments/{environment_id}/config/snapshot`
  (management plane; operator, or the environment's own management key).
- **Engine:** `ironauth_store::snapshot` (`export`, `validate_document`,
  `to_canonical_string`).

## The two load-bearing properties

### Deterministic / canonical

Two exports of the same configuration produce **byte-identical** output, so a
snapshot is diffable and reviewable.

- Object keys are recursively **sorted** (by Unicode code point; RFC 8785-aligned
  for the ASCII key space the document uses).
- Collections are ordered by a **stable natural key**: clients by `client_id`,
  resource servers by `audience`, DCR policies by `name`, and so on for every
  type in the table below.
- Compact separators, **no insignificant whitespace**.
- **No volatile fields**: no timestamps, counters, row insertion order, or
  internal scoped ids leak into the document. Nothing is drawn from wall-clock
  time or entropy, so an export is reproducible across builds and machines.

### Secret-free

A snapshot carries **no secret material**: no client secret (nor its stored
hash), no signing private key, no management credential, no encrypted-secret
ciphertext. The export projects only the non-secret columns of each resource, so
a secret cannot leak even in principle.

Where a promotable resource references a secret (a confidential client's secret),
the document carries a **named reference** into the environment-scoped secret
store, never the value:

```json
"secret": { "reference": "client_secret" }
```

Import resolves the reference against the **target** environment's secret store
(issue #45), so promoting dev to prod uses prod's secret, never dev's.

`jwks` carries only **public** verification keys; the validator rejects any
private JWK parameter (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k`).

## What a snapshot contains

The set of resource types is not a hand-maintained list: it is exactly the types
the resource-model classification (issue #41) marks **promotable**. Today that is
twelve types:

| Resource type          | Key                                | Natural order              |
| ---------------------- | ---------------------------------- | -------------------------- |
| `client`               | `resources.client`                 | `client_id`                |
| `resource_server`      | `resources.resource_server`        | `audience`                 |
| `dcr_policy`           | `resources.dcr_policy`             | `name`                     |
| `variable`             | `resources.variable`               | `name`                     |
| `connector`            | `resources.connector`              | `connector_slug`           |
| `org_connection`       | `resources.org_connection`         | `(organization_id, connector_id)` |
| `routing_rule`         | `resources.routing_rule`           | `(rule_kind, selector, org_connection_id)` |
| `upstream_token_grant` | `resources.upstream_token_grant`   | `(client_id, org_connection_id)` |
| `brand`                | `resources.brand`                  | `slug`                     |
| `locale_bundle`        | `resources.locale_bundle`          | `locale`                   |
| `signup_form`          | `resources.signup_form`            | `client_id`                |
| `flow_version`         | `resources.flow_version`           | `(journey_id, version)`    |
| `message_template`     | `resources.message_template`       | `(kind, locale)`           |

Environment-identity types (the environment itself, its signing keys, its
management credentials, its issuer) and runtime types (users, sessions, grants,
audit) are **excluded by construction**: the export never reads them, and a
document that references one is rejected. When a new promotable type is added to
the classification, a store test fails until the snapshot covers it, so coverage
cannot silently drift.

`message_template` is the one type whose table holds rows a snapshot must NOT
carry. Templates are stored at three levels in one table, and only the
**environment** level is per-environment config: a tenant default is wider than
the environment, and a per-organization override is runtime data that travels
with its organization's export. Both the export and the promotion writer pin
`level = 'environment'` in SQL rather than filtering afterwards, because all
three levels can share a `(kind, locale)`: a level-blind writer would overwrite a
target's own tenant default with a promoted environment body, and the only
symptom would be mail quietly falling back to the built-in template.

### Exported is not the same as promoted

Every type above is EXPORTED. A strict subset of them is also applied by the
transactional promotion engine (issue #44): `resource_server`, `dcr_policy`,
`variable`, `brand`, `locale_bundle`, `flow_version` and `message_template`. The
other six are
carried for export, diff and review but are left untouched in a target:

- `client` and `signup_form` are keyed by an authorize `client_id`, which is a
  **scope-embedded** identifier: the same logical application has a different
  `client_id` in every environment, so a source key cannot address the target's
  resource. This is a **deliberate, measured exclusion, not a later slice**, and
  the difference matters. Promoting a signup form would create a row in the
  target keyed by a client that provably cannot exist there **and** delete the
  target's own form (its client's key reads as a source deletion), so it is not
  merely incomplete, it is destructive. Unlike an unresolved variable or a
  missing asset byte, there is **no action a target-environment operator could
  take** to make it resolve, so even a fail-closed gate would be a permanent
  block rather than a safety net. The blocker is precisely the absence of a
  **stable, scope-independent public client identity**, the same missing
  primitive that blocks `client` promotion. Minting one is an owner-level
  snapshot-format decision, not an engine one, and a store test measures the
  blocker (a source client id does not parse under the target scope) rather than
  describing it.
- `connector`, `org_connection`, `routing_rule` and `upstream_token_grant` carry
  references (an upstream secret, an organization, a connector, a client) that
  must resolve against the target environment. Those four ARE later slices: the
  work is merely unwritten, and no missing primitive blocks it.

`ironauth_store::promotion::PROMOTED_RESOURCE_TYPES` is the single declaration of
the promoted subset; the apply dispatch is generated from it, so the two cannot
drift, and a store test measures that the promoted set is a subset of this one.

### A promoted brand is held to the same ingest wall as a brand write

A promotion apply is a full **writer** of the `brands` table, so a submitted
document is not merely shape-checked. Before a plan is built and before an apply
runs, every brand the document carries is validated against exactly the grammar
`PUT .../brands/{slug}` enforces, and a fault is a **400** naming it:

- `tokens` and `tokens_dark` must fit the closed typed design-token grammar
  (hex-only colors, an allowlisted font enum, clamped numerics). Never CSS.
- every `slots` key must be a known slot id, within the per-slot size cap, and
  the value must already be **sanitizer output**. The export emits sanitizer
  output and the sanitizer returns a **fixed point** of its own allowlist, so an
  exported document round-trips; raw markup is refused rather than silently
  rewritten, because a rewritten
  document would mean the plan an operator reviewed and the bytes the apply
  stored were different documents.
- no two brands may claim the same host, and no two may be the environment
  default. Within an environment each selects at most one brand, so a document
  that names two could never converge.

A brand's `host_pattern` is **canonicalized** (trimmed, port-stripped,
lowercased) on the way in, by the same fold the brand write and the per-domain
selection matcher use. Without it a promoted `LOGIN.Acme.Test:8443` would sit
beside a stored `login.acme.test` under a unique index that cannot see they are
the same host, and both would resolve for the same request.

`client_id`, the per-**client** selection key, is the one brand field a
promotion never carries: it embeds its environment, so it can only name a client
of the source. The target-environment admin sets it deliberately.

### Brand assets cross by content reference, never as bytes

A snapshot carries a brand's logo and favicon as **metadata** (kind, sniffed
content type, sha256, size), never as inline bytes: a snapshot stays a small,
diffable text document and is never a binary side channel. A promotion therefore
materializes an asset only from bytes the **target** already holds under that
exact digest, content type and size. When the target holds no such bytes, the
apply **fails closed** (422 `brand_asset_bytes_unavailable`) and changes nothing,
rather than leaving the target with metadata pointing at bytes it does not have,
or binding the promoted brand to some different image. The operator uploads the
asset to the target environment (creating the brand there first through
`PUT .../brands/{slug}`) and re-plans.

Every digest the promotion needs is resolved in ONE pass **before any change is
applied**, so the refusal is order-independent and cannot be false. Resolving
per brand inside the apply loop was neither: the loop runs in natural-key order
and a brand delete sweeps that brand's asset rows, so a source that merely
RENAMED a brand while keeping its logo was refused whenever the departing slug
happened to sort first, and told to upload an asset it had already uploaded.

## Validation and import

`ironauth_store::snapshot::validate_document` validates a full document
**before any state change** and enumerates **every** violation with an RFC 6901
JSON Pointer path (not just the first), so an invalid document changes nothing and
the caller learns all faults at once. It fails closed on:

- a document that is not valid JSON or not the expected shape;
- a `schema_version` it does not recognize;
- an unknown resource-type key under `resources`;
- a missing required field, a wrong type, or a bad enum value; and
- **raw secret-shaped material** anywhere (a forbidden secret key, a raw string
  in the `secret` reference slot, or a private JWK parameter).

### Version compatibility policy

- The version is embedded in every document (`schema_version`).
- An importer **rejects** a `schema_version` it does not recognize (fail closed),
  rather than guessing at an unknown shape.
- The version is bumped only on a **backward-incompatible** change to the document
  shape; additive, ignorable fields do not bump it. Within a version, unknown
  top-level resource-type keys are rejected (they would reference a
  non-promotable type), and the schema pins `additionalProperties: false` on each
  resource so an unexpected field is caught rather than silently dropped.

## Scope: what this format does NOT yet cover

- **Promotion of the six exported-but-not-applied types** listed above: a stable
  cross-environment client identity (for `client` and `signup_form`) and
  target-side reference resolution (for `connector`, `org_connection`,
  `routing_rule` and `upstream_token_grant`).
- **User / identity data**: out of scope (the exit-friendliness covenant, M6).

The diff / plan / transactional apply engine (issue #44) and secret / variable
reference resolution against a target environment (issue #45) DO ship; this format
is the input they consume, and it defines where references appear.
