#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Terraform provider coverage, GENERATED from the committed OpenAPI document
# (issue #51, criterion 6: "Provider resource coverage is generated from OpenAPI;
# a CI check fails when a new promotable API resource lacks provider coverage").
#
# The inventory is derived, never hand written. A PROMOTABLE resource is a
# collection with a create AND a sibling item path with a delete: that pair is what
# makes a thing Terraform could own, because a resource it cannot destroy is a
# resource it cannot manage.
#
# What this enforces, and what it deliberately does not:
#
#   * Every resource the PROVIDER implements must still be promotable. A resource
#     whose API was removed is a provider resource that can only fail.
#   * The uncovered count may only go DOWN. It is a FLOOR that ratchets, the same
#     shape scripts/test-registration.sh uses, because "add a resource, add
#     coverage" is unenforceable in the abstract and "never get worse" is not.
#
# It does NOT demand full coverage today. Twenty of twenty one resources are
# uncovered as this lands, and a gate that failed on that would simply be disabled.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

SPEC="docs/openapi/management.json"
PROVIDER_DIR="terraform-provider-ironauth/internal/provider"

# The ratchet. LOWER it in the same change that adds a resource; raising it needs a
# reason in the diff, which is the point of it being a number in a file.
#
# RAISED 20 -> 21 for `createLogStream` (issue #110), and the reason is that the resource
# is genuinely new surface rather than coverage slipping: the log stream configuration API
# did not exist before this change, so the denominator grew. A Terraform resource for it
# belongs with the rest of the provider work and is not something to bolt on inside the
# API's own change; doing that would mean shipping a provider resource with no acceptance
# test alongside it.
# RAISED 21 -> 22 for `createFlowTarget` (issue #112), for the same reason and on the same
# terms as the log-stream raise above: HTTP flow targets are new surface, so the denominator
# grew rather than coverage slipping. A Terraform resource for registering a flow target
# belongs with the provider work, and bolting one on inside the API's own change would mean
# shipping a provider resource with no acceptance test beside it.
# RAISED 22 -> 24 for `registerExternalIssuer` and `createSubjectMapping` (issue #126), on the
# same terms again: workload-federation trust anchors and subject mappings are new surface, so
# the denominator grew by two rather than coverage slipping.
#
# Worth naming what actually moved, because it was not the POST. Both operations existed one
# commit earlier and neither counted, because "promotable" here means a collection POST with a
# SIBLING ITEM DELETE and the surface shipped only create plus a disable toggle. Review found
# that was a defect rather than a design: both tables carry a UNIQUE constraint on their
# natural key with no `enabled` predicate, so a parked row keeps its key and an issuer that
# rotated its signing keys could never be repointed. Adding the DELETE fixed that and, as a
# side effect, made both resources promotable. So this raise records real new provider debt
# that the earlier shape was hiding, not new debt this change created.
UNCOVERED_CEILING=24

python3 - "$SPEC" "$PROVIDER_DIR" "$UNCOVERED_CEILING" <<'PY'
import collections, json, pathlib, re, sys

spec, provider_dir, ceiling = sys.argv[1], sys.argv[2], int(sys.argv[3])
doc = json.loads(pathlib.Path(spec).read_text(encoding="utf-8"))

paths = collections.defaultdict(dict)
for path, operations in doc["paths"].items():
    for method, operation in operations.items():
        if method in ("get", "post", "put", "patch", "delete"):
            paths[path][method] = operation.get("operationId")

# A promotable resource: a collection POST plus a sibling item DELETE.
promotable = {}
for path, methods in paths.items():
    if "post" not in methods or path.endswith("}"):
        continue
    for candidate, candidate_methods in paths.items():
        if (
            candidate.startswith(path + "/{")
            and candidate.count("/") == path.count("/") + 1
            and "delete" in candidate_methods
        ):
            promotable[methods["post"]] = candidate_methods["delete"]
            break

# What the provider implements: every `resp.TypeName = req.ProviderTypeName + "_x"`.
implemented = set()
for source in pathlib.Path(provider_dir).glob("*.go"):
    for match in re.finditer(
        r'ProviderTypeName\s*\+\s*"_([a-z0-9_]+)"', source.read_text(encoding="utf-8")
    ):
        implemented.add(match.group(1))

# Map a provider resource name onto the create operation it should cover:
# `ironauth_tenant` -> `createTenant`.
def create_op(resource: str) -> str:
    return "create" + "".join(part.capitalize() for part in resource.split("_"))

covered, orphaned = set(), []
for resource in sorted(implemented):
    operation = create_op(resource)
    if operation in promotable:
        covered.add(operation)
    else:
        orphaned.append((resource, operation))

if orphaned:
    for resource, operation in orphaned:
        print(
            f"provider-coverage: `ironauth_{resource}` maps to `{operation}`, which is not "
            f"a promotable resource in {spec}. Either the API changed under the provider or "
            f"the resource is misnamed."
        )
    sys.exit(1)

uncovered = sorted(set(promotable) - covered)
count = len(uncovered)
print(
    f"provider-coverage: {len(covered)} of {len(promotable)} promotable resources covered; "
    f"{count} uncovered (ceiling {ceiling})"
)
if count > ceiling:
    print()
    print(
        f"provider-coverage: the uncovered count ROSE to {count}, above the ceiling of "
        f"{ceiling}. A new promotable API resource landed without provider coverage."
    )
    print("  Uncovered:")
    for operation in uncovered:
        print(f"    {operation}")
    print()
    print(
        "  Add a resource to the provider, or raise UNCOVERED_CEILING in "
        "scripts/provider-coverage.sh with a reason. The ceiling is a ratchet: it exists "
        "so coverage cannot silently regress, not to demand completeness today."
    )
    sys.exit(1)
if count < ceiling:
    print()
    print(
        f"provider-coverage: coverage IMPROVED ({count} < {ceiling}). Lower "
        f"UNCOVERED_CEILING to {count} in scripts/provider-coverage.sh so the gain is "
        f"locked in; a ratchet that is never tightened is a ceiling nobody notices."
    )
    sys.exit(1)
PY
echo "provider-coverage: clean"
