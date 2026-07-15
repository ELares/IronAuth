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
  resource servers by `audience`, DCR policies by `name`.
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
three types:

| Resource type     | Key               | Natural order |
| ----------------- | ----------------- | ------------- |
| `client`          | `resources.client`          | `client_id` |
| `resource_server` | `resources.resource_server` | `audience`  |
| `dcr_policy`      | `resources.dcr_policy`      | `name`      |

Environment-identity types (the environment itself, its signing keys, its
management credentials, its issuer) and runtime types (users, sessions, grants,
audit) are **excluded by construction**: the export never reads them, and a
document that references one is rejected. When a new promotable type is added to
the classification, a store test fails until the snapshot covers it, so coverage
cannot silently drift.

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

- **Diff / plan / transactional apply** between environments: the promotion engine
  (issue #44). This format is the input it consumes.
- **Secret and variable reference resolution** against a target environment: issue
  #45. This format only defines *where* references appear.
- **User / identity data**: out of scope (the exit-friendliness covenant, M6).
