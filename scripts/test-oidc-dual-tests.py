#!/usr/bin/env python3
"""Offline regression checks for exact dual-mode target selection, no databases."""
import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('dual', HERE / 'oidc-dual-tests.py')
DUAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DUAL)


class Coverage(unittest.TestCase):
    def setUp(self):
        self.inventory = json.loads((HERE / 'oidc-dual-targets.json').read_text())
        targets = [{k: v for k, v in t.items() if k != 'required_features'} | {'required-features': t['required_features']} for t in self.inventory['integration_targets']]
        targets += [{'name': 'ironauth_oidc', 'kind': ['lib'], 'test': True, 'doctest': True}]
        targets += [{'name': n, 'kind': ['example'], 'test': False, 'doctest': False} for n in self.inventory['examples_compile_only']]
        self.metadata = {'packages': [{'name': 'ironauth-oidc', 'targets': targets, 'features': {'default': [], 'testing': ['ironauth-store/testing', 'ironauth-saml/test-util'], 'ironcache': ['ironauth-hot/ironcache'], 'wasm-hooks': ['dep:ironauth-hooks']}}]}

    def test_actual_commands_cover_all167_enabled_targets_exactly_once(self):
        commands = [c for i in range(4) for c in DUAL.plan(self.metadata, self.inventory, i)]
        selected = [c[n+1] for c in commands for n, a in enumerate(c) if a == '--test']
        self.assertEqual(len(selected), 167)
        self.assertEqual(sorted(selected), [t['name'] for t in self.inventory['integration_targets'] if t['name'] not in self.inventory['feature_gated_exclusions']])
        self.assertEqual(sum('--lib' in c for c in commands), 1)
        self.assertEqual(sum('--doc' in c for c in commands), 1)
        for command in commands:
            self.assertEqual(command[command.index('--features')+1], 'testing,ironcache')
            self.assertNotIn('--ignored', command)
            self.assertNotIn('--skip', command)

    def test_missing_added_disabled_required_feature_and_kind_drift_fail(self):
        for scenario in ['missing', 'added', 'disabled', 'feature', 'kind', 'example', 'doc', 'closure']:
            with self.subTest(scenario=scenario):
                m = copy.deepcopy(self.metadata)
                ts = m['packages'][0]['targets']
                if scenario == 'missing': ts.pop(0)
                if scenario == 'added': ts.append(ts[0] | {'name': 'new_assertions'})
                if scenario == 'disabled': ts[0]['test'] = False
                if scenario == 'feature': ts[0]['required-features'] = ['new-feature']
                if scenario == 'kind': ts.append({'name': 'newbin', 'kind': ['bin'], 'test': True, 'doctest': False})
                if scenario == 'example': ts[-1]['test'] = True
                if scenario == 'doc': ts[-5]['doctest'] = False
                if scenario == 'closure': m['packages'][0]['features']['default'] = ['wasm-hooks']
                with self.assertRaises(ValueError): DUAL.plan(m, self.inventory, 0)

    def test_overlap_gap_and_doctest_omission_fail(self):
        for scenario in ['overlap', 'gap', 'doc']:
            with self.subTest(scenario=scenario):
                inv = copy.deepcopy(self.inventory)
                if scenario == 'overlap': inv['shards'][1]['integration_targets'].append(inv['shards'][0]['integration_targets'][0])
                if scenario == 'gap': inv['shards'][0]['integration_targets'].pop()
                if scenario == 'doc': inv['shards'][3]['doctests'] = False
                with self.assertRaises(ValueError): DUAL.plan(self.metadata, inv, 0)

    def test_failed_target_does_not_suppress_doctests_or_failure(self):
        commands = DUAL.plan(self.metadata, self.inventory, 3)
        with patch.object(DUAL.subprocess, 'run', side_effect=[SimpleNamespace(returncode=17), SimpleNamespace(returncode=0)]) as run:
            self.assertEqual(DUAL.run_commands(commands), 17)
            self.assertEqual([c.args[0] for c in run.call_args_list], commands)


if __name__ == '__main__': unittest.main()
