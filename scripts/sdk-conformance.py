#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""The published SDK conformance suite (issue #122, criterion 2).

Criterion 2 asks that a from-scratch client "passes the published conformance suite against
the emulator". This is that suite. It runs the reference client in `clients/reference` against
a live emulator and asserts the things the PUBLISHED artifacts promise -- the spec in
`docs/openapi/management.json` and the contract in `docs/SDK-CONTRACT.md`.

# Why it is spec-DRIVEN and not a list of endpoints

The issue is titled "spec-driven generation", and a suite that hand-listed its cases would
have the defect the issue exists to remove: it would keep passing when the spec grew an
operation nobody tested. So the coverage cases are DERIVED. Every GET operation the spec
declares as callable without path parameters is discovered and exercised, and the count is
asserted non-zero -- a discovery pass that silently found nothing would otherwise report a
clean suite having tested no endpoint at all.

# What it does NOT do

It does not re-test the OIDC plane, which the emulator's own OTP and federation jobs cover.
It does not attempt all 162 paths: most need a path parameter naming a resource that has to be
created first, and a suite that created 162 resources would be measuring the emulator's seed
data rather than the client's conformance. It drives one real administrative journey
end to end and asserts the cross-cutting mechanics on it.

Usage:
    sdk-conformance.py --management-url URL --token TOKEN
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(
    subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True
    ).stdout.strip()
)
sys.path.insert(0, str(ROOT / "clients" / "reference"))

from ironauth_reference import ApiError, ReferenceClient  # noqa: E402

SPEC = json.loads((ROOT / "docs" / "openapi" / "management.json").read_text())

_failures: list[str] = []
_passed = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global _passed
    if condition:
        _passed += 1
        print(f"  ok   {name}")
    else:
        _failures.append(f"{name}: {detail}")
        print(f"  FAIL {name}: {detail}")


def parameterless_gets() -> list[str]:
    """Every GET the spec says needs no path parameter and no required query parameter."""
    found = []
    for path, operations in SPEC["paths"].items():
        if "{" in path:
            continue
        operation = operations.get("get")
        if operation is None:
            continue
        if any(p.get("required") for p in operation.get("parameters", [])):
            continue
        found.append(path)
    return sorted(found)


def declared_statuses(path: str, method: str) -> set[int]:
    return {int(s) for s in SPEC["paths"][path][method].get("responses", {}) if s.isdigit()}


def _tenant_id(body: object) -> str | None:
    """The tenant id out of a `TenantCreated` body."""
    if not isinstance(body, dict):
        return None
    tenant = body.get("tenant")
    return tenant.get("id") if isinstance(tenant, dict) else None


def run(management_url: str, token: str) -> int:
    client = ReferenceClient(base_url=management_url, token=token)

    print("== the spec's security scheme is enforced ==")
    # The spec declares a `bearer` scheme. A client has to know that an unauthenticated call
    # is refused rather than answered with an empty list, because those look identical to a
    # caller that only checks for an exception.
    check(
        "the spec declares exactly one security scheme, named bearer",
        list(SPEC["components"]["securitySchemes"]) == ["bearer"],
        str(list(SPEC["components"]["securitySchemes"])),
    )
    try:
        client.request("GET", "/v1/operators", token=None)
        check("an unauthenticated read is refused", False, "it answered 2xx")
    except ApiError as error:
        check("an unauthenticated read is refused", error.status == 401, f"status {error.status}")
        # The envelope shape matters as much as the status: an SDK surfaces `error` as its
        # typed code, and a 401 carrying no code leaves it with nothing to map.
        check(
            "the refusal carries the documented error envelope",
            error.code is not None and error.message is not None,
            f"code={error.code!r} message={error.message!r}",
        )
    try:
        client.request("GET", "/v1/operators", token="not-the-operator-token")
        check("a wrong credential is refused", False, "it answered 2xx")
    except ApiError as error:
        check("a wrong credential is refused", error.status == 401, f"status {error.status}")

    print("== every parameterless GET the spec declares ==")
    paths = parameterless_gets()
    # A discovery pass that found nothing would print no failures below and report a clean
    # suite. Assert the denominator.
    check("the spec yields at least one directly callable GET", len(paths) > 0, "found none")
    for path in paths:
        expected = declared_statuses(path, "get")
        try:
            answer = client.request("GET", path)
            check(
                f"GET {path} answers a status the spec declares",
                answer.status in expected,
                f"{answer.status} not in {sorted(expected)}",
            )
            check(
                f"GET {path} answers JSON",
                answer.body is not None and not isinstance(answer.body, str),
                f"body was {type(answer.body).__name__}",
            )
        except ApiError as error:
            check(f"GET {path} answers a status the spec declares", False, str(error))

    print("== the seeded operator is readable ==")
    operators = client.list_operators()
    items = operators.body.get("items") if isinstance(operators.body, dict) else None
    check("the operator list is a paginated envelope", isinstance(items, list), str(operators.body))
    check("the emulator's seeded operator is present", bool(items), "the list was empty")

    print("== a real administrative journey ==")
    # An unexpected refusal here is a FAILURE, not a crash. The first run of this suite died
    # on a traceback out of `create_tenant` and reported nothing about the assertions after
    # it -- so the run that found one defect hid however many more were behind it.
    try:
        created = client.create_tenant("Conformance Tenant", idempotency_key="conformance-key-1")
    except ApiError as error:
        check("creating a tenant answers a status the spec declares", False, str(error))
        return _verdict(paths)
    check(
        "creating a tenant answers a status the spec declares",
        created.status in declared_statuses("/v1/tenants", "post"),
        f"{created.status} not in {sorted(declared_statuses('/v1/tenants', 'post'))}",
    )
    # The spec's `TenantCreated` is `{tenant, environment}`, NOT a bare tenant: creating a
    # tenant creates its first environment with it, and the operation returns both. My first
    # pass at this client assumed the flat shape and read `body["id"]`, which is the exact
    # mistake the from-scratch exercise exists to catch -- the spec says so plainly and I had
    # guessed instead of reading it.
    tenant = created.body.get("tenant") if isinstance(created.body, dict) else None
    environment = created.body.get("environment") if isinstance(created.body, dict) else None
    check(
        "the create returns the spec's tenant-and-environment pair",
        isinstance(tenant, dict) and isinstance(environment, dict),
        str(created.body)[:200],
    )
    tenant_id = tenant.get("id") if isinstance(tenant, dict) else None
    check("the created tenant carries an id", isinstance(tenant_id, str) and bool(tenant_id), str(created.body)[:200])
    check(
        "the first environment is stamped with its tenant",
        isinstance(environment, dict) and environment.get("tenant_id") == tenant_id,
        str(environment)[:200],
    )

    if isinstance(tenant_id, str) and tenant_id:
        fetched = client.get_tenant(tenant_id)
        check("the created tenant reads back", fetched.status == 200, f"status {fetched.status}")
        check(
            "it reads back under the id it was created with",
            isinstance(fetched.body, dict) and fetched.body.get("id") == tenant_id,
            str(fetched.body)[:200],
        )

        # Idempotency. The spec makes Idempotency-Key REQUIRED on this create, which is a
        # promise that replaying one is safe -- and a client that retries a create after a
        # timeout is relying on exactly that.
        replay = client.create_tenant("Conformance Tenant", idempotency_key="conformance-key-1")
        replayed_id = _tenant_id(replay.body)
        check(
            "replaying a create with the same key does not make a second tenant",
            replayed_id == tenant_id,
            f"first {tenant_id!r}, replay {replayed_id!r}",
        )

        # ...and the negative, without which the assertion above passes for a server that
        # ignores the body and returns the same tenant for every create.
        other = client.create_tenant("Another Tenant", idempotency_key="conformance-key-2")
        other_id = _tenant_id(other.body)
        check(
            "a different key makes a different tenant",
            isinstance(other_id, str) and other_id != tenant_id,
            f"first {tenant_id!r}, second {other_id!r}",
        )

    print("== the error envelope on a miss ==")
    try:
        client.get_tenant("ten_definitely-not-a-real-tenant")
        check("an unknown tenant is a documented refusal", False, "it answered 2xx")
    except ApiError as error:
        check(
            "an unknown tenant answers a status the spec declares",
            error.status in declared_statuses("/v1/tenants/{tenant_id}", "get"),
            f"{error.status} not in {sorted(declared_statuses('/v1/tenants/{tenant_id}', 'get'))}",
        )
        check(
            "the refusal carries the documented error envelope",
            error.code is not None,
            f"code={error.code!r}",
        )

    return _verdict(paths)


def _verdict(paths: list[str]) -> int:
    print()
    if _failures:
        print(f"sdk-conformance: FAILED ({len(_failures)} of {_passed + len(_failures)})")
        for failure in _failures:
            print(f"  - {failure}")
        return 1
    print(f"sdk-conformance: clean ({_passed} assertions, {len(paths)} spec-derived GET cases)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--management-url", required=True)
    parser.add_argument("--token", required=True)
    args = parser.parse_args()
    return run(args.management_url, args.token)


if __name__ == "__main__":
    raise SystemExit(main())
