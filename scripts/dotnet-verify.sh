#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Build and run the official .NET verifier artifact (issue #118, criterion 5).
#
# Three suites, dividing the work the same way the Java artifact's do:
#
#   conformance   the SHARED cross-language corpus, the only thing that measures whether the
#                 verifiers AGREE rather than whether each is self-consistent. Like the Java
#                 artifact and unlike the others, this verifies every accepted vector: RSA and
#                 P-256 come from the platform and Ed25519 from BouncyCastle.
#   selftest      the properties a fixed corpus CANNOT express, because they need a token signed
#                 by a key the corpus carries no private half of.
#   sample        the SAMPLE, run end to end against a loopback issuer. Criterion 5 asks for a
#                 sample; one nobody executes compiles, reads correctly, and is wrong.
#
# ONE DEPENDENCY, and the criterion named it: BouncyCastle, for Ed25519 alone. .NET has no in-box
# Ed25519 as of .NET 10 -- verified by reflecting over System.Security.Cryptography and finding no
# Ed-anything public type, not assumed from the docs.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

if ! command -v dotnet >/dev/null 2>&1; then
    # A HARD failure, not a skip. A gate that prints "no SDK, skipping" is green on every machine
    # that cannot run it, which is every machine where it matters.
    echo "dotnet-verify: no dotnet on PATH (install the .NET SDK)" >&2
    exit 1
fi

export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_NOLOGO=1

CHECKS="sdks/dotnet/IronAuth.Verify.Checks/IronAuth.Verify.Checks.csproj"

echo "dotnet-verify: $(dotnet --version)"

# The library builds with AnalysisMode=All and TreatWarningsAsErrors, so this is also the lint.
dotnet build "${CHECKS}" --nologo -v quiet
echo "dotnet-verify: built (analyzers at AnalysisMode=All, warnings as errors)"

dotnet run --project "${CHECKS}" --no-build -- conformance packages/ironauth-sdk/vectors/verify-vectors.json
dotnet run --project "${CHECKS}" --no-build -- selftest
dotnet run --project "${CHECKS}" --no-build -- sample

echo "dotnet-verify: OK"
