#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Verify a published IronAuth container image signature (issue #151 criterion 3).
#
# ONE SCRIPT, TWO CALLERS, so "documented" and "tested in CI" cannot drift. The
# release workflow runs this against the image it has just signed, and
# docs/RELEASING.md tells a consumer to run the same file. A verify command that
# lives only in prose is a command nobody has ever run.
#
# The images are signed KEYLESS, so there is no public key to distribute. What
# stands in for one is the signing IDENTITY: the release workflow of this
# repository, as attested by GitHub's OIDC issuer. Both halves are required.
# Checking the issuer alone would accept any workflow in any repository on
# GitHub; checking the identity alone would accept a certificate from an issuer
# an attacker controls.
set -euo pipefail

# SELFCHECK: the docs quote the raw cosign invocation for consumers who are
# verifying from somewhere this repository is not checked out, so the identity
# pattern exists in two files. That is the shape that rots: the script changes,
# the prose does not, and the published instructions quietly stop matching what
# CI proved. This asserts the two agree, and CI runs it.
if [ "${1:-}" = "--selfcheck" ]; then
    doc="$(dirname "$0")/../docs/RELEASING.md"
    if [ ! -f "$doc" ]; then
        echo "verify-image: selfcheck cannot find $doc" >&2
        exit 1
    fi
    # The literal the script builds its regexp from, as it appears in prose
    # (the doc escapes it for the shell the reader will paste into).
    if ! grep -q "certificate-oidc-issuer https://token.actions.githubusercontent.com" "$doc"; then
        echo "verify-image: docs/RELEASING.md no longer documents the OIDC issuer this script uses" >&2
        exit 1
    fi
    if ! grep -q "refs/tags/ironauth-v" "$doc"; then
        echo "verify-image: docs/RELEASING.md no longer documents the signing identity pattern" >&2
        exit 1
    fi
    if ! grep -q "by digest" "$doc"; then
        echo "verify-image: docs/RELEASING.md no longer tells the reader to use a digest" >&2
        exit 1
    fi
    echo "verify-image: selfcheck ok (docs and script agree on issuer, identity and digest rule)"
    exit 0
fi

image="${1:-}"
tag="${2:-}"

if [ -z "$image" ]; then
    echo "usage: $0 <image>@<digest> [tag]" >&2
    echo "  e.g. $0 ghcr.io/elares/ironauth@sha256:abc... ironauth-v1.2.3" >&2
    exit 2
fi

# A DIGEST, NOT A TAG. Verifying `ironauth:latest` verifies whatever `latest`
# points at during this call, and a registry can move it afterwards. The digest
# is the only reference that names the bytes the signature covers.
case "$image" in
    *@sha256:*) ;;
    *)
        echo "verify-image: refusing to verify '$image': reference it by digest" >&2
        echo "verify-image: a tag can be moved after verification; a digest cannot" >&2
        exit 2
        ;;
esac

repo="${IRONAUTH_REPO:-ELares/IronAuth}"
issuer="${IRONAUTH_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
workflow=".github/workflows/release.yml"

if [ -n "$tag" ]; then
    # The exact release that is supposed to have produced this image.
    identity=(--certificate-identity "https://github.com/${repo}/${workflow}@refs/tags/${tag}")
else
    # Any tagged release of this repository, anchored at both ends so a
    # lookalike repository whose name merely CONTAINS ours cannot match.
    identity=(--certificate-identity-regexp \
        "^https://github\\.com/${repo}/${workflow}@refs/tags/ironauth-v[0-9]+\\.[0-9]+\\.[0-9]+\$")
fi

echo "verify-image: verifying ${image}"
echo "verify-image: issuer ${issuer}"

cosign verify \
    "${identity[@]}" \
    --certificate-oidc-issuer "$issuer" \
    "$image"

echo "verify-image: OK"
