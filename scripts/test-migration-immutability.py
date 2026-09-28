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
    def setUp(self):
        self.assertEqual(hashlib.sha256(OLD).hexdigest(),
                         "02bd786d62041c24c5a6268b8c33bf53cdcdc6610701b42a509c514dbd6f2530")
        self.assertEqual(hashlib.sha256(CORRECTED).hexdigest(),
                         "68cd229209d09ff7045ac02c3a16d60b9ec705b3c633617862f3b75d335dd81b")
        temporary = tempfile.TemporaryDirectory(prefix="ironauth-migration-guard-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.migration = self.directory / MIGRATION
        self.migration.parent.mkdir(parents=True)
        self.migration.write_bytes(OLD)
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
        self.migration.write_bytes(CORRECTED)
        self.assertIn("admitted exact 0237", self.guard(True))
        self.migration.write_bytes(CORRECTED + b"\n-- another edit\n")
        self.guard(False)

    def test_same_digest_pair_at_another_path_is_refused(self):
        self.other.write_bytes(OLD)
        self.git("add", ".")
        self.commit()
        self.other.write_bytes(CORRECTED)
        self.guard(False)

    def test_unknown_old_digest_is_refused(self):
        self.migration.write_bytes(OLD + b"\n-- unknown old edit\n")
        self.git("add", ".")
        self.commit()
        self.migration.write_bytes(CORRECTED)
        self.guard(False)

    def test_corrected_base_does_not_allow_later_edits(self):
        self.migration.write_bytes(CORRECTED)
        self.git("add", ".")
        self.commit()
        self.guard(True)
        self.migration.write_bytes(OLD)
        self.guard(False)

    def test_missing_renamed_or_symlinked_file_is_refused(self):
        moved = self.migration.with_name("0241_renamed.sql")
        self.migration.rename(moved)
        self.git("add", "-A")
        self.guard(False)
        moved.write_bytes(CORRECTED)
        self.migration.symlink_to(moved.name)
        self.guard(False)

    def test_exact_repair_does_not_hide_other_changes(self):
        self.migration.write_bytes(CORRECTED)
        self.other.write_text("SELECT 2;\n")
        self.guard(False)


if __name__ == "__main__":
    unittest.main()
