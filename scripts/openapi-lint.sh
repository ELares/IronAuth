#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Quality gate for the published management API spec (issue #122).
#
# scripts/openapi-check.sh already proves the committed artifact matches the handlers.
# That is a DRIFT check: it says the spec is current, never that it is good enough to
# generate a client from. A spec can be perfectly current and still be unusable, and an
# untyped field is exactly the shape that passes drift and then produces `any` in every
# generated SDK, which is the thing #122 exists to stop.
#
# So this checks three properties the generator depends on:
#
#   1. every operation carries an operationId, because that is the generated method name;
#   2. every response that carries a body declares a schema, because a client cannot
#      decode a body whose shape is unstated;
#   3. no schema node is untyped, because an untyped node degrades to `any` and silently
#      removes the type safety the contract is supposed to publish.
#
# Properties 2 and 3 carry RATCHETS rather than being clean today. The counts below are
# the measured debt, and the gate fails if a number goes UP. Lowering one is a line in the
# diff, which is the point: #122 criterion 1 requires zero untyped schemas, and a ratchet
# makes progress toward that visible instead of aspirational.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

SPEC="docs/openapi/management.json"

# The measured debt. LOWER these as fields are typed; never raise them. The untyped count
# includes ARRAY ELEMENT schemas, not just object properties: a first pass that walked only
# `properties` reported 28 and missed three `items` nodes, which would have shipped a
# ceiling that quietly excused them. A raise means a new
# untyped field reached the published contract, which is the regression this gate exists to
# catch, so it is a failure and not a number to edit.
#
# The untyped count is now ZERO, which is #122 criterion 1 met rather than approached. The
# ceiling stays as a ceiling because reaching zero is not the same as staying there: the
# next `serde_json::Value` field added without a `value_type` lands here, and it lands as a
# failure rather than as a number somebody bumps.
#
# Typing them was per-field work, not a sweep, and one of them proves why. `client_secret`
# is a UNION (a bare string, or `{ "file": ... }` / `{ "env": ... }`) and carries a custom
# `oneOf` schema. Calling it `type: object` would have cleared the count while telling every
# generated client a plain string is invalid, which is a WORSE contract than saying nothing:
# untyped makes a generator emit `any` and the caller stays correct, wrongly typed makes it
# emit a type that rejects valid input.
MAX_RESPONSES_WITHOUT_SCHEMA=7
MAX_UNTYPED_SCHEMA_NODES=0

python3 - "$SPEC" "$MAX_RESPONSES_WITHOUT_SCHEMA" "$MAX_UNTYPED_SCHEMA_NODES" <<'PY'
import json
import sys

spec_path, max_bodyless, max_untyped = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
spec = json.load(open(spec_path))

METHODS = ("get", "post", "put", "patch", "delete", "head", "options", "trace")
# 204 and 304 are defined to carry no body, so a missing schema is correct, not debt.
BODYLESS_BY_DEFINITION = {"204", "304"}
# A node is typed if it says what it is in any of the ways OpenAPI 3.1 allows.
TYPE_KEYS = ("type", "$ref", "allOf", "oneOf", "anyOf", "enum", "const")

operations = [
    (path, method, op)
    for path, item in (spec.get("paths") or {}).items()
    for method, op in item.items()
    if method in METHODS
]

failures = []

missing_operation_id = [
    f"{method.upper()} {path}" for path, method, op in operations if not op.get("operationId")
]
if missing_operation_id:
    failures.append(
        "operations without an operationId (the generated method name):\n  "
        + "\n  ".join(sorted(missing_operation_id))
    )

bodyless = []
for path, method, op in operations:
    for code, response in (op.get("responses") or {}).items():
        content = response.get("content") or {}
        if not content:
            if code not in BODYLESS_BY_DEFINITION:
                bodyless.append(f"{method.upper()} {path} -> {code} (no content)")
            continue
        for media_type, media in content.items():
            if not (media or {}).get("schema"):
                bodyless.append(f"{method.upper()} {path} -> {code} ({media_type}, no schema)")


def untyped_nodes(name, schema, found):
    if not isinstance(schema, dict):
        return
    if not any(key in schema for key in TYPE_KEYS):
        found.append(name)
    for prop, sub in (schema.get("properties") or {}).items():
        untyped_nodes(f"{name}.{prop}", sub, found)
    items = schema.get("items")
    if isinstance(items, dict):
        untyped_nodes(f"{name}[]", items, found)


untyped = []
for name, schema in ((spec.get("components") or {}).get("schemas") or {}).items():
    untyped_nodes(name, schema, untyped)


def ratchet(label, found, ceiling, hint):
    if len(found) > ceiling:
        return (
            f"{label}: {len(found)}, ceiling {ceiling}. {hint}\n  "
            + "\n  ".join(sorted(found)[:20])
        )
    if len(found) < ceiling:
        return (
            f"{label}: {len(found)}, ceiling {ceiling}. The debt SHRANK, which is the "
            f"point, but the ceiling has to come down with it or it stops measuring "
            f"anything. Lower it to {len(found)} in this change."
        )
    return None


for problem in (
    ratchet(
        "responses declaring a body without a schema",
        bodyless,
        max_bodyless,
        "A client cannot decode a body whose shape is unstated.",
    ),
    ratchet(
        "untyped schema nodes",
        untyped,
        max_untyped,
        "An untyped node becomes `any` in every generated SDK.",
    ),
):
    if problem:
        failures.append(problem)

if failures:
    print("openapi-lint: the published contract is not generator-ready:\n")
    for failure in failures:
        print(f"  {failure}\n")
    sys.exit(1)

print(
    f"openapi-lint: clean ({len(operations)} operations, all with an operationId; "
    f"{len(bodyless)}/{max_bodyless} bodyless responses; "
    f"{len(untyped)}/{max_untyped} untyped schema nodes)"
)
PY
