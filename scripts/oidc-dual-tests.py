#!/usr/bin/env python3
"""Run one checked partition of the unchanged cache-attached OIDC test roster."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
FEATURES = ['testing', 'ironcache']


def target_view(target):
    return {key: target[key] for key in ('name', 'kind', 'test', 'doctest')} | {
        'required_features': target.get('required-features', [])}


def plan(metadata, inventory, shard):
    if inventory.get('schema') != 1 or inventory.get('package') != 'ironauth-oidc' or inventory.get('features') != FEATURES:
        raise ValueError('unexpected roster policy')
    packages = [p for p in metadata['packages'] if p['name'] == 'ironauth-oidc']
    if len(packages) != 1:
        raise ValueError('OIDC package must be unique')
    targets = packages[0]['targets']
    actual = sorted((target_view(t) for t in targets if t['kind'] == ['test']), key=lambda t: t['name'])
    if actual != inventory['integration_targets']:
        raise ValueError('OIDC integration roster changed; update the explicit coverage inventory')
    names = [t['name'] for t in actual]
    if len(names) != len(set(names)) or any(not t['test'] for t in actual):
        raise ValueError('duplicate or disabled test target')
    local_features = packages[0]['features']
    selected = set(['default', *FEATURES])
    while True:
        expanded = selected | {item for name in selected for item in local_features.get(name, []) if item in local_features}
        if expanded == selected:
            break
        selected = expanded
    if sorted(selected) != inventory['selected_local_features']:
        raise ValueError('selected local feature closure changed')
    excluded = [t['name'] for t in actual if set(t['required_features']) - selected]
    if excluded != inventory['feature_gated_exclusions']:
        raise ValueError('feature-gated exclusions changed')
    eligible = [name for name in names if name not in excluded]
    libs = [t for t in targets if t['kind'] == ['lib']]
    examples = sorted(t['name'] for t in targets if t['kind'] == ['example'])
    if len(libs) != 1 or libs[0]['name'] != inventory['lib_target'] or not libs[0]['test'] or not libs[0]['doctest']:
        raise ValueError('library or doctest coverage changed')
    if examples != sorted(inventory['examples_compile_only']) or any(t['test'] or t['doctest'] for t in targets if t['kind'] == ['example']):
        raise ValueError('example test policy changed')
    if any(t['kind'] not in [['lib'], ['test'], ['example']] for t in targets):
        raise ValueError('new target kind is not covered')
    shards = inventory['shards']
    if len(shards) != 4 or [s['index'] for s in shards] != list(range(4)):
        raise ValueError('four explicit shards required')
    assigned = [name for s in shards for name in s['integration_targets']]
    if len(assigned) != len(set(assigned)) or sorted(assigned) != eligible:
        raise ValueError('shards must cover every target exactly once')
    if [s['index'] for s in shards if s['lib']] != [0] or [s['index'] for s in shards if s['doctests']] != [3]:
        raise ValueError('library and doctests must each execute once')
    if not 0 <= shard < 4:
        raise ValueError('unknown shard')
    selected = shards[shard]
    command = ['cargo', 'test', '-p', 'ironauth-oidc', '--features', ','.join(FEATURES), '--no-fail-fast']
    if selected['lib']:
        command.append('--lib')
    for name in selected['integration_targets']:
        command.extend(['--test', name])
    commands = [command]
    if selected['doctests']:
        commands.append(['cargo', 'test', '-p', 'ironauth-oidc', '--features', ','.join(FEATURES), '--doc'])
    return commands


def run_commands(commands):
    result = 0
    for command in commands:
        completed = subprocess.run(command, cwd=ROOT, check=False)
        if completed.returncode and not result:
            result = completed.returncode if completed.returncode > 0 else 1
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shard', type=int, choices=range(4), required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    inventory = json.loads((ROOT / 'scripts/oidc-dual-targets.json').read_text())
    result = subprocess.run(['cargo', 'metadata', '--locked', '--offline', '--no-deps', '--format-version', '1'], cwd=ROOT, check=True, capture_output=True, timeout=60)
    if len(result.stdout) > 8 * 1024 * 1024:
        raise ValueError('metadata exceeds bound')
    commands = plan(json.loads(result.stdout), inventory, args.shard)
    print(json.dumps({'shard': args.shard, 'commands': commands}), flush=True)
    return 0 if args.check else run_commands(commands)


if __name__ == '__main__':
    sys.exit(main())
