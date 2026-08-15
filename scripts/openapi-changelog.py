#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Enumerate the API-surface diff between two OpenAPI documents (issue #122).

A regenerated SDK release is worthless to a consumer if its changelog says "regenerated
from the latest spec". What a consumer needs is the list of things that changed about the
surface THEY call, and in particular which of those will break them. That list is derivable
from the two spec documents, so it is derived here rather than written by hand: a
hand-written one drifts from the spec the moment somebody is in a hurry, and the entry that
goes missing is the breaking one, because it is the one that needed a paragraph.

BREAKING is decided by direction, not by judgement:

  * removing an operation, or a response a caller could already handle, breaks a caller;
  * removing a property from a RESPONSE breaks a caller that reads it;
  * adding a REQUIRED property to a request body breaks a caller that does not send it;
  * making an optional request property required breaks the same caller.

Adding an operation, an optional request property, or a response property does not.

Usage:
    openapi-changelog.py OLD.json NEW.json      write the changelog to stdout
    openapi-changelog.py --self-test            run the synthetic-diff cases
"""

from __future__ import annotations

import json
import sys

METHODS = ("get", "post", "put", "patch", "delete", "head", "options", "trace")


def operations(spec: dict) -> dict[str, dict]:
    """Every operation, keyed by `METHOD /path`."""
    return {
        f"{method.upper()} {path}": operation
        for path, item in (spec.get("paths") or {}).items()
        for method, operation in (item or {}).items()
        if method in METHODS
    }


def request_properties(operation: dict) -> tuple[set[str], set[str]]:
    """A request body's property names, and the subset that is required."""
    schema = (
        ((operation.get("requestBody") or {}).get("content") or {})
        .get("application/json", {})
        .get("schema")
        or {}
    )
    return set((schema.get("properties") or {}).keys()), set(schema.get("required") or [])


def response_properties(operation: dict) -> dict[str, set[str]]:
    """Each response status's property names."""
    out: dict[str, set[str]] = {}
    for code, response in (operation.get("responses") or {}).items():
        schema = (
            ((response or {}).get("content") or {}).get("application/json", {}).get("schema")
            or {}
        )
        out[code] = set((schema.get("properties") or {}).keys())
    return out


def diff(old: dict, new: dict) -> tuple[list[str], list[str]]:
    """Return (breaking, non_breaking) change lines, each already sorted."""
    breaking: list[str] = []
    additive: list[str] = []

    old_ops, new_ops = operations(old), operations(new)

    for name in sorted(set(old_ops) - set(new_ops)):
        breaking.append(f"removed operation `{name}`")
    for name in sorted(set(new_ops) - set(old_ops)):
        additive.append(f"added operation `{name}`")

    for name in sorted(set(old_ops) & set(new_ops)):
        before, after = old_ops[name], new_ops[name]

        before_props, before_required = request_properties(before)
        after_props, after_required = request_properties(after)

        for prop in sorted(after_props - before_props):
            # A NEW required request property breaks every existing caller; a new optional
            # one breaks nobody. The distinction is the whole reason this is not one list.
            if prop in after_required:
                breaking.append(f"`{name}` requires new request property `{prop}`")
            else:
                additive.append(f"`{name}` accepts new optional request property `{prop}`")
        for prop in sorted(before_props - after_props):
            breaking.append(f"`{name}` no longer accepts request property `{prop}`")
        for prop in sorted((after_required - before_required) & before_props):
            breaking.append(f"`{name}` request property `{prop}` is now required")

        before_responses, after_responses = response_properties(before), response_properties(after)
        for code in sorted(set(before_responses) - set(after_responses)):
            breaking.append(f"`{name}` no longer returns `{code}`")
        for code in sorted(set(after_responses) - set(before_responses)):
            additive.append(f"`{name}` may now return `{code}`")
        for code in sorted(set(before_responses) & set(after_responses)):
            for prop in sorted(before_responses[code] - after_responses[code]):
                breaking.append(f"`{name}` `{code}` no longer returns property `{prop}`")
            for prop in sorted(after_responses[code] - before_responses[code]):
                additive.append(f"`{name}` `{code}` now returns property `{prop}`")

    return breaking, additive


def render(breaking: list[str], additive: list[str]) -> str:
    if not breaking and not additive:
        return "## API surface\n\nNo API-surface changes.\n"
    lines = ["## API surface", ""]
    if breaking:
        lines.append("### Breaking")
        lines.append("")
        lines.extend(f"- **BREAKING** {entry}" for entry in breaking)
        lines.append("")
    if additive:
        lines.append("### Added")
        lines.append("")
        lines.extend(f"- {entry}" for entry in additive)
        lines.append("")
    return "\n".join(lines)


def self_test() -> int:
    """The synthetic-diff cases #122's verification section asks for."""

    def spec(paths):
        return {"openapi": "3.1.0", "paths": paths}

    def op(request=None, required=None, responses=None):
        out: dict = {"operationId": "x", "responses": {}}
        if request is not None:
            out["requestBody"] = {
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {p: {"type": "string"} for p in request},
                            "required": required or [],
                        }
                    }
                }
            }
        for code, props in (responses or {"200": []}).items():
            out["responses"][code] = {
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {p: {"type": "string"} for p in props},
                        }
                    }
                }
            }
        return out

    failures = []

    def case(name, old, new, expect_breaking, expect_additive):
        breaking, additive = diff(old, new)
        if breaking != expect_breaking or additive != expect_additive:
            failures.append(
                f"{name}\n     breaking: {breaking}\n     expected: {expect_breaking}"
                f"\n     added:    {additive}\n     expected: {expect_additive}"
            )

    case(
        "an added operation is additive",
        spec({"/a": {"get": op()}}),
        spec({"/a": {"get": op()}, "/b": {"post": op()}}),
        [],
        ["added operation `POST /b`"],
    )
    case(
        "a removed operation is breaking",
        spec({"/a": {"get": op()}, "/b": {"post": op()}}),
        spec({"/a": {"get": op()}}),
        ["removed operation `POST /b`"],
        [],
    )
    case(
        "a new REQUIRED request property is breaking, a new optional one is not",
        spec({"/a": {"post": op(request=["x"], required=["x"])}}),
        spec({"/a": {"post": op(request=["x", "y", "z"], required=["x", "z"])}}),
        ["`POST /a` requires new request property `z`"],
        ["`POST /a` accepts new optional request property `y`"],
    )
    case(
        "promoting an existing optional property to required is breaking",
        spec({"/a": {"post": op(request=["x", "y"], required=["x"])}}),
        spec({"/a": {"post": op(request=["x", "y"], required=["x", "y"])}}),
        ["`POST /a` request property `y` is now required"],
        [],
    )
    case(
        "dropping a response property is breaking, adding one is not",
        spec({"/a": {"get": op(responses={"200": ["kept", "dropped"]})}}),
        spec({"/a": {"get": op(responses={"200": ["kept", "fresh"]})}}),
        ["`GET /a` `200` no longer returns property `dropped`"],
        ["`GET /a` `200` now returns property `fresh`"],
    )
    case(
        "dropping a whole response status is breaking",
        spec({"/a": {"get": op(responses={"200": [], "409": []})}}),
        spec({"/a": {"get": op(responses={"200": []})}}),
        ["`GET /a` no longer returns `409`"],
        [],
    )
    case(
        "an identical spec produces nothing",
        spec({"/a": {"get": op(request=["x"], required=["x"])}}),
        spec({"/a": {"get": op(request=["x"], required=["x"])}}),
        [],
        [],
    )

    if failures:
        print("openapi-changelog self-test FAILED:\n")
        for failure in failures:
            print(f"  {failure}\n")
        return 1
    print("openapi-changelog: self-test clean (7 synthetic diff cases)")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] == "--self-test":
        return self_test()
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    with open(argv[1]) as old_file, open(argv[2]) as new_file:
        breaking, additive = diff(json.load(old_file), json.load(new_file))
    print(render(breaking, additive), end="")
    # A breaking change is reported, never a failure: deciding whether to ship one is the
    # release's call, and exiting non-zero here would make the changelog a gate it is not.
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
