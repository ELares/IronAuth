#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Build and run the official Java verifier artifact (issue #118, criterion 4).
#
# Three suites, and they divide the work on purpose:
#
#   Conformance   the SHARED cross-language corpus. This is the only thing that measures
#                 "the verifiers agree"; it is also the first run to verify EVERY accepted
#                 vector, since the JDK does Ed25519, P-256 and RSA and the Rust verifier
#                 has no P-256 key type.
#   SelfTest      the properties a fixed corpus CANNOT express, because they need a token
#                 signed by a key the corpus does not carry a private half of. Each one was
#                 chosen by mutating the verifier and finding the corpus blind to it.
#   SampleHarness the SAMPLE, run end to end against a loopback issuer. Criterion 4 asks for
#                 a sample; a sample nobody executes compiles, reads correctly, and is wrong.
#
# NO BUILD TOOL AND NO DEPENDENCIES. Not Maven, not Gradle, not Nimbus, not Tink. `javac`
# compiles four hundred lines and `java` runs them, which is the strongest possible form of
# the criterion's "no extra user dependencies": there is nothing to resolve, so there is
# nothing that can drift, break, or need a lockfile.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

JAVAC="javac"
JAVA="java"
if [ -n "${JAVA_HOME:-}" ]; then
    JAVAC="${JAVA_HOME}/bin/javac"
    JAVA="${JAVA_HOME}/bin/java"
fi

if ! command -v "${JAVAC}" >/dev/null 2>&1; then
    # A HARD failure, not a skip. A gate that prints "no JDK, skipping" is a gate that is
    # green on every machine that cannot run it, which is every machine where it matters.
    echo "java-verify: no javac found (set JAVA_HOME or install a JDK 17+)" >&2
    exit 1
fi

# Ed25519 in the platform arrived in Java 15 (JEP 339), and records and switch expressions
# used here need 17. Checked rather than assumed: on an older JDK the failure would otherwise
# be a wall of syntax errors that says nothing about the actual cause.
VERSION="$("${JAVA}" -version 2>&1 | head -1)"
MAJOR="$("${JAVA}" -XshowSettings:properties -version 2>&1 | sed -n 's/.*java\.specification\.version = //p' | head -1)"
if [ -z "${MAJOR}" ] || [ "${MAJOR}" -lt 17 ]; then
    echo "java-verify: need JDK 17 or newer for in-box Ed25519 and records, found: ${VERSION}" >&2
    exit 1
fi
echo "java-verify: ${VERSION}"

OUT="sdks/java/out"
rm -rf "${OUT}"
mkdir -p "${OUT}"

# -Werror, because the one warning that matters here (an unused variable holding an event, a
# raw type swallowing a cast) is exactly the shape of the defects this artifact must not have.
find sdks/java/src -name '*.java' -print0 | xargs -0 "${JAVAC}" -Xlint:all -Werror -d "${OUT}"
echo "java-verify: compiled with -Xlint:all -Werror"

"${JAVA}" -cp "${OUT}" dev.ironauth.verify.Conformance packages/ironauth-sdk/vectors/verify-vectors.json
"${JAVA}" -cp "${OUT}" dev.ironauth.verify.SelfTest
"${JAVA}" -cp "${OUT}" dev.ironauth.verify.SampleHarness

rm -rf "${OUT}"
echo "java-verify: OK"
