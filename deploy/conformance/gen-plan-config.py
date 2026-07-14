#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Render the OIDF runner's plan config from profile-matrix.yaml (issue #37).

The runner (``run-test-plan.py``) takes a plan id plus a JSON config describing
the OP under test. That config used to be referenced but never produced, so the
live drive pointed at a ``plan-config.json`` that nothing in the repo generated:
a latent run-time failure that no static check noticed. It is generated here
instead, from the reviewed matrix, so there is exactly ONE source of truth for
the issuer, the discovery URLs, and the login credential.

Two modes, both consumed by run-conformance.sh:

    gen-plan-config.py --profile <id> --out <path>   write the config JSON
    gen-plan-config.py --profile <id> --print-plan   print "<id>[k=v,...]"

The plan spec is the runner's variant syntax: the per-profile ``variant`` block
from the matrix, rendered onto the plan id.

scripts/conformance-check.sh runs this on every PR against every enabled profile
and asserts the output's shape, so a matrix that can no longer produce a valid
config is a RED STATIC CHECK rather than a surprise at live-run time.
"""

import argparse
import json
import os
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only where PyYAML is absent
    sys.exit("gen-plan-config: PyYAML is required (pip install -r requirements.txt)")

HERE = os.path.dirname(os.path.abspath(__file__))
MATRIX = os.path.join(HERE, "profile-matrix.yaml")


def load_profile(plan_id):
    """Return (matrix, profile) for plan_id, or exit non-zero if it is unusable."""
    with open(MATRIX, encoding="utf-8") as handle:
        matrix = yaml.safe_load(handle)

    for profile in matrix["profiles"]:
        if profile["id"] == plan_id:
            break
    else:
        sys.exit(f"gen-plan-config: profile {plan_id} is not in the matrix")

    if not profile.get("enabled", False):
        blocked = profile.get("blocked_by", "unspecified")
        sys.exit(
            f"gen-plan-config: profile {plan_id} is not enabled "
            f"(blocked by {blocked}); a disabled profile is never driven"
        )
    return matrix, profile


def build_config(matrix, profile):
    """Render the matrix into the runner's config schema.

    The issuer and the discovery URL come from the matrix's `op` block, so the
    exact-string issuer the suite checks (the #194 divergence surface) has a
    single definition. The login credential is passed by ENVIRONMENT variable
    name, so the password never lands in a generated file on disk.
    """
    op = matrix["op"]
    issuer = op["issuer"]
    if issuer.endswith("/"):
        sys.exit("gen-plan-config: issuer must not have a trailing slash (#194)")

    well_known = op["well_known"]
    if not well_known:
        sys.exit("gen-plan-config: the matrix op block lists no well_known URL")

    login = op["login"]
    password_env = login["password_env"]
    password = os.environ.get(password_env)
    if not password:
        sys.exit(
            f"gen-plan-config: ${password_env} is unset; the suite cannot log the "
            f"cert user in without it"
        )

    return {
        "alias": f"ironauth-{profile['id']}",
        "description": f"IronAuth OIDF conformance: {profile['name']}",
        "server": {
            "issuer": issuer,
            "discoveryUrl": well_known[0],
        },
        # Every enabled profile registers its own client through DCR
        # (client_registration: dynamic_client), so no static client is pinned
        # here; the suite creates what it needs against the cert environment's
        # open registration.
        "client": {},
        "consent": {},
        # Browser automation for the interactive login the suite drives.
        "browser": [
            {
                "match": f"{issuer}/login*",
                "tasks": [
                    {
                        "task": "Login",
                        "match": f"{issuer}/login*",
                        "commands": [
                            ["text", "id", "username", login["username"]],
                            ["text", "id", "password", password],
                            ["click", "id", "login-submit"],
                        ],
                    }
                ],
            },
            {
                "match": f"{issuer}/consent*",
                "tasks": [
                    {
                        "task": "Consent",
                        "match": f"{issuer}/consent*",
                        "commands": [["click", "id", "consent-approve"]],
                    }
                ],
            },
        ],
        "variant": dict(profile.get("variant", {})),
    }


def plan_spec(profile):
    """The runner's plan id with its variant suffix: id[k=v,k=v]."""
    variant = profile.get("variant", {})
    if not variant:
        return profile["id"]
    rendered = ",".join(f"{key}={value}" for key, value in sorted(variant.items()))
    return f"{profile['id']}[{rendered}]"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, help="the plan id from the matrix")
    parser.add_argument("--out", help="write the config JSON here")
    parser.add_argument(
        "--print-plan",
        action="store_true",
        help="print the plan id with its variant suffix instead of writing a config",
    )
    args = parser.parse_args()

    matrix, profile = load_profile(args.profile)

    if args.print_plan:
        print(plan_spec(profile))
        return

    if not args.out:
        sys.exit("gen-plan-config: --out is required unless --print-plan is given")

    config = build_config(matrix, profile)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2, sort_keys=True)
        handle.write("\n")


if __name__ == "__main__":
    main()
