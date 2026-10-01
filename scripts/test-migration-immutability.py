#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Exercise the migration byte guard against disposable local Git histories."""

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
GUARD = ROOT / "scripts/migration-immutability.sh"
MIGRATION = Path("crates/ironauth-store/migrations/0237_fapi_hardened.sql")
CORRECTED = (ROOT / MIGRATION).read_bytes()
# Retain the exact old fixture without depending on a remote or unshallow history.
OLD = CORRECTED.replace(b"custom_domain, auto_link_posture, fapi_hardened",
                        b"custom_domain, fapi_hardened")


class MigrationImmutability(unittest.TestCase):
    migration_path = MIGRATION
    old = OLD
    corrected = CORRECTED
    old_hash = "02bd786d62041c24c5a6268b8c33bf53cdcdc6610701b42a509c514dbd6f2530"
    corrected_hash = "68cd229209d09ff7045ac02c3a16d60b9ec705b3c633617862f3b75d335dd81b"
    repair_number = "0237"
    def setUp(self):
        self.assertEqual(hashlib.sha256(self.old).hexdigest(),
                         self.old_hash)
        self.assertEqual(hashlib.sha256(self.corrected).hexdigest(),
                         self.corrected_hash)
        temporary = tempfile.TemporaryDirectory(prefix="ironauth-migration-guard-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.migration = self.directory / self.migration_path
        self.migration.parent.mkdir(parents=True)
        self.migration.write_bytes(self.old)
        self.other = self.migration.with_name("0001_other.sql")
        self.other.write_text("SELECT 1;\n", encoding="utf-8")
        self.git("init", "-q")
        self.git("add", ".")
        self.commit()

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.directory,
                              check=True, capture_output=True, text=True)

    def commit(self):
        self.git("-c", "user.name=Migration fixture", "-c",
                 "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
                 "commit", "-qm", "Fixture base")

    def guard(self, allowed):
        env = dict(os.environ, GITHUB_ACTIONS="true")
        result = subprocess.run(["bash", str(GUARD), "HEAD"],
                                cwd=self.directory, env=env,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0 if allowed else 1,
                         result.stdout + result.stderr)
        return result.stdout

    def test_unchanged_and_new_migration_are_allowed(self):
        self.guard(True)
        self.migration.with_name("0241_new.sql").write_text("SELECT 2;\n")
        self.git("add", ".")
        self.guard(True)

    def test_only_exact_repair_is_allowed(self):
        self.migration.write_bytes(self.corrected)
        self.assertIn("admitted exact " + self.repair_number, self.guard(True))
        self.migration.write_bytes(self.corrected + b"\n-- another edit\n")
        self.guard(False)

    def test_same_digest_pair_at_another_path_is_refused(self):
        self.other.write_bytes(self.old)
        self.git("add", ".")
        self.commit()
        self.other.write_bytes(self.corrected)
        self.guard(False)

    def test_unknown_old_digest_is_refused(self):
        self.migration.write_bytes(self.old + b"\n-- unknown old edit\n")
        self.git("add", ".")
        self.commit()
        self.migration.write_bytes(self.corrected)
        self.guard(False)

    def test_corrected_base_does_not_allow_later_edits(self):
        self.migration.write_bytes(self.corrected)
        self.git("add", ".")
        self.commit()
        self.guard(True)
        self.migration.write_bytes(self.old)
        self.guard(False)

    def test_missing_renamed_or_symlinked_file_is_refused(self):
        moved = self.migration.with_name("0241_renamed.sql")
        self.migration.rename(moved)
        self.git("add", "-A")
        self.guard(False)
        moved.write_bytes(self.corrected)
        self.migration.symlink_to(moved.name)
        self.guard(False)

    def test_exact_repair_does_not_hide_other_changes(self):
        self.migration.write_bytes(self.corrected)
        self.other.write_text("SELECT 2;\n")
        self.guard(False)


class FipsMigrationImmutability(MigrationImmutability):
    migration_path = Path("crates/ironauth-store/migrations/0242_fips_profile.sql")
    old = (ROOT / "crates/ironauth-store/tests/fixtures/published_0242_fips_profile.sql").read_bytes()
    corrected = (ROOT / migration_path).read_bytes()
    old_hash = "59fa9390262ccdf8fa57542aa75f93d752a50be7e56bb816f558c371f5ef2121"
    corrected_hash = "f095fd161ff668c0a2e10cfb027507d13580b0b19f0e2553f4db1fd684067aff"
    repair_number = "0242"


if __name__ == "__main__":
    unittest.main()
