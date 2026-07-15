#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Adapter: turn the OIDF runner's per-module output into the normalized results
# shape parse_results.py consumes. The OIDF suite reports each test module with a
# `testName`, a `status` (FINISHED / RUNNING / ...), and a `result` (PASSED /
# WARNING / REVIEW / FAILED / SKIPPED); the runner export is a set of such
# module-info objects. This flattens them to:
#
#     {"modules": [{"name": ..., "id": ..., "status": ..., "result": ...}, ...]}
#
# Two inputs are accepted so the wrapper can use whichever the pinned runner
# emits: a DIRECTORY of per-module *.json info objects, or a single JSON file
# that is either a list of info objects or a plan-info object whose `modules`
# each carry (or embed as `instances`) info objects.
#
# The flattening core (normalize_modules) is standard-library only and unit
# tested (test_parse_results.py), so this contract is verified locally even
# though the live runner is not.

import glob
import json
import os
import sys


def _info(module):
    """Pull the reporting fields out of one module-info object."""
    return {
        "name": module.get("testName")
        or module.get("testModule")
        or module.get("name")
        or module.get("id")
        or "<unnamed>",
        "id": module.get("id") or module.get("testId") or "",
        "status": module.get("status"),
        "result": module.get("result"),
    }


def normalize_modules(objects):
    """Flatten runner objects (info dicts and/or plan-info dicts) to modules."""
    modules = []
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        # A plan-info object: expand its module list (each module may itself
        # carry status/result directly or under `instances`).
        if "modules" in obj and isinstance(obj["modules"], list):
            for module in obj["modules"]:
                instances = module.get("instances")
                if isinstance(instances, list) and instances:
                    for inst in instances:
                        merged = {**module, **inst} if isinstance(inst, dict) else module
                        modules.append(_info(merged))
                else:
                    modules.append(_info(module))
        else:
            modules.append(_info(obj))
    return {"modules": modules}


def load(path):
    """Load runner output from a directory of *.json files or a single file."""
    objects = []
    if os.path.isdir(path):
        for name in sorted(glob.glob(os.path.join(path, "*.json"))):
            with open(name, encoding="utf-8") as handle:
                objects.append(json.load(handle))
    else:
        with open(path, encoding="utf-8") as handle:
            doc = json.load(handle)
        objects = doc if isinstance(doc, list) else [doc]
    return objects


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 1:
        sys.stderr.write("usage: normalize_runner_export.py <export-dir-or-file>\n")
        return 2
    print(json.dumps(normalize_modules(load(argv[0])), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
