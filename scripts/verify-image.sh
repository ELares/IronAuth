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

repo="${IRONAUTH_REPO:-ELares/IronAuth}"
issuer="${IRONAUTH_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
# The literal path, for the exact-identity branch.
workflow=".github/workflows/release.yml"
# The same path with its dots escaped, for the regexp branch. Interpolating the
# literal left `.github` and `release.yml` as wildcards, so the pattern the
# script ran was strictly looser than the one the docs published: it also
# accepted `/xgithub/workflows/release.yml` and `/release-yml`. No live bypass
# came of it, because GitHub always writes that path segment literally, but a
# supply-chain pattern that differs from its published form is worth nothing as
# a published form.
workflow_pattern='\.github/workflows/release\.yml'
identity_regexp="^https://github\.com/${repo}/${workflow_pattern}@refs/tags/ironauth-v[0-9]+\.[0-9]+\.[0-9]+\$"

# SELFCHECK: the docs quote the raw cosign invocation for consumers verifying
# from somewhere this repository is not checked out, so the identity pattern
# exists in two places.
#
# THE FIRST VERSION OF THIS GATE CHECKED THE WRONG SIDE. It grepped the doc for
# three hard-coded literals and never opened the script, so the rot direction it
# names -- "the script changes, the prose does not" -- was the one direction it
# structurally could not see. A review showed four mutations surviving it: the
# documented regexp repointed at another GitHub org, the script's own repo
# default changed, its issuer default changed, and the digest guard deleted
# outright. Each printed "selfcheck ok".
#
# It now asserts the doc contains the exact strings the script BUILDS, and
# exercises the digest guard instead of trusting it to be there.
if [ "${1:-}" = "--selfcheck" ]; then
    doc="$(dirname "$0")/../docs/RELEASING.md"
    fail() {
        echo "verify-image: selfcheck: $1" >&2
        exit 1
    }
    [ -f "$doc" ] || fail "cannot find $doc"

    grep -qF -- "$issuer" "$doc" ||
        fail "docs/RELEASING.md does not document the issuer this script uses ($issuer)"
    grep -qF -- "$identity_regexp" "$doc" ||
        fail "docs/RELEASING.md does not publish the identity pattern this script builds"
    grep -q "by digest" "$doc" ||
        fail "docs/RELEASING.md no longer tells the reader to use a digest"

    # EXERCISED, NOT GREPPED. A grep for the guard's source text passes on a
    # guard that has been commented out or made unreachable. Exit 2 is the
    # guard's own code: if it were removed the script would fall through to
    # cosign and exit 1 or 127, which this catches.
    set +e
    "$0" "ghcr.io/example/image:latest" >/dev/null 2>&1
    guard_rc=$?
    set -e
    [ "$guard_rc" -eq 2 ] ||
        fail "the digest guard no longer refuses a tag reference (exit $guard_rc, expected 2)"

    echo "verify-image: selfcheck ok (docs publish the issuer and pattern this script builds,"
    echo "verify-image: and the digest guard refuses a tag reference)"
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

if [ -n "$tag" ]; then
    # The exact release that is supposed to have produced this image.
    identity=(--certificate-identity "https://github.com/${repo}/${workflow}@refs/tags/${tag}")
else
    # Any tagged release of this repository, anchored at both ends so a
    # lookalike repository whose name merely CONTAINS ours cannot match.
    identity=(--certificate-identity-regexp "$identity_regexp")
fi

echo "verify-image: verifying ${image}"
echo "verify-image: issuer ${issuer}"

cosign verify \
    "${identity[@]}" \
    --certificate-oidc-issuer "$issuer" \
    "$image"

echo "verify-image: OK"
