#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# No login path writes a credential to a file (issue #120, criterion 4: "no plaintext token
# files exist after login in default mode").
#
# Why a scan and not a filesystem assertion. A test that logs in and then looks for files
# can only look where it thought to look: it proves nothing about a path it did not imagine,
# and on a machine with no keychain it does not run at all. This proves the property for
# EVERY path in the credential-bearing modules, by making file I/O unreachable from them.
#
# The property rests on two facts, and BOTH are checked, because either alone is a claim
# that quietly stops being true:
#
#   1. the modules that handle a credential never name a file-writing API; and
#   2. the only CredentialStore compiled into the shipped binary is the keychain-backed one,
#      so there is no second implementation for a call site to be pointed at.
#
# Fact 2 is what makes fact 1 worth having. A `FileStore` added "for testing" but not gated
# behind cfg(test) would satisfy fact 1 -- it writes files in its own module, not in these --
# while putting tokens on disk the moment anything constructed it.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# The modules a credential passes through: where it is stored, and where a login obtains one.
CREDENTIAL_PATHS=(
  "crates/ironauth/src/credentials.rs"
  "crates/ironauth/src/login.rs"
  "crates/ironauth/src/loopback_flow.rs"
  "crates/ironauth/src/device_login.rs"
)

# Writing a file, in any of the spellings this workspace would plausibly use.
WRITE_SYMBOLS='fs::write|fs::File|OpenOptions|create_new|File::create|BufWriter|fs::copy|persist\('

fail=0

for path in "${CREDENTIAL_PATHS[@]}"; do
  if [ ! -f "$path" ]; then
    echo "no-plaintext-credentials: $path is gone; this check now guards nothing." >&2
    echo "  Point it at wherever credential handling moved to." >&2
    fail=1
    continue
  fi
  hits="$(grep -nE "$WRITE_SYMBOLS" "$path" || true)"
  if [ -n "$hits" ]; then
    echo "no-plaintext-credentials: $path writes a file:" >&2
    echo "$hits" >&2
    echo "  A credential reaches this module. Criterion 4 requires that no plaintext token" >&2
    echo "  file exists after a login in default mode, and the guarantee is that these" >&2
    echo "  modules cannot write one at all." >&2
    fail=1
  fi
done

# Fact 2: every CredentialStore implementation outside cfg(test) must be the keychain one.
#
# `awk` rather than `grep`, because the question is not whether the line exists but whether a
# `#[cfg(test)]` precedes it in the file. The test doubles (MemoryStore, RefusingStore) live
# under one, and the keychain store does not.
ungated="$(awk '
  /^#\[cfg\(test\)\]/ { gated = 1 }
  /^impl CredentialStore for/ {
    if (!gated) print FILENAME ":" FNR ": " $0
  }
' crates/ironauth/src/credentials.rs)"

actual_count="$(printf '%s\n' "$ungated" | grep -c 'impl CredentialStore' || true)"

if [ "$actual_count" -ne 1 ]; then
  echo "no-plaintext-credentials: expected exactly ONE non-test CredentialStore, found ${actual_count}:" >&2
  printf '%s\n' "$ungated" >&2
  echo "  Every additional one is a place a token could be written somewhere other than" >&2
  echo "  the platform keychain. Gate it behind cfg(test), or state the reason here." >&2
  exit 1
fi

if ! printf '%s\n' "$ungated" | grep -q 'for KeyringStore'; then
  echo "no-plaintext-credentials: the one non-test CredentialStore is not KeyringStore:" >&2
  printf '%s\n' "$ungated" >&2
  echo "  Criterion 4 requires credentials live in the PLATFORM keychain." >&2
  exit 1
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "no-plaintext-credentials: clean (${#CREDENTIAL_PATHS[@]} credential modules write no files; KeyringStore is the only shipped store)"
