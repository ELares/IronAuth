#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# One AppAuth-SHAPED authorization-code exchange, printing the token endpoint's status.
#
#   scripts/lib/mobile-flow.sh <issuer> <client_id> <work dir>
#
# Deliberately sends NO DPoP PROOF, because that is what AppAuth sends. Everything else is
# what RFC 8252 asks of a native app: a public client, PKCE, and a loopback redirect. The
# browser hops are walked with curl so CI can prove the exchange completes rather than that
# the pages render.
#
# Writes the token response to <work dir>/token.json and prints the HTTP status, so a caller
# can distinguish "refused for the right reason" from "refused for another one".
set -euo pipefail

ISSUER="$1"
CLIENT_ID="$2"
WORK="$3"
REDIRECT="http://127.0.0.1:4571/callback"
BASE=$(printf '%s' "${ISSUER}" | sed -E 's#(https?://[^/]+).*#\1#')
TOKEN_ENDPOINT=$(curl -s "${ISSUER}/.well-known/openid-configuration" \
    | python3 -c 'import json,sys;print(json.load(sys.stdin)["token_endpoint"])')

VERIFIER=$(openssl rand -hex 32)
CHALLENGE=$(printf '%s' "${VERIFIER}" | openssl dgst -binary -sha256 | openssl base64 | tr '+/' '-_' | tr -d '=')
JAR="${WORK}/jar.txt"
rm -f "${JAR}"
encode() { python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$1"; }

NEXT="${ISSUER}/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=$(encode "${REDIRECT}")&scope=openid&state=m1&code_challenge=${CHALLENGE}&code_challenge_method=S256"
for _ in 1 2 3 4 5 6 7 8; do
    case "${NEXT}" in "${REDIRECT}"*) break;; esac
    CODE=$(curl -s -c "${JAR}" -b "${JAR}" -o "${WORK}/page.html" -w '%{http_code}' "${NEXT}")
    if [ "${CODE}" = "303" ] || [ "${CODE}" = "302" ]; then
        NEXT=$(curl -s -c "${JAR}" -b "${JAR}" -o /dev/null -w '%{redirect_url}' "${NEXT}")
        continue
    fi
    ACTION=$(grep -oE '<form[^>]*action="[^"]*"' "${WORK}/page.html" | head -1 | sed 's/.*action="//;s/"//')
    RETURN_TO=$(python3 -c "import html,re,sys;print(html.unescape(re.search(r'name=\"return_to\" value=\"([^\"]*)\"',open(sys.argv[1],encoding='utf-8').read()).group(1)))" "${WORK}/page.html")
    if grep -q 'name="password"' "${WORK}/page.html"; then
        NEXT=$(curl -s -c "${JAR}" -b "${JAR}" -o /dev/null -w '%{redirect_url}' -X POST "${BASE}${ACTION}" \
            --data-urlencode "return_to=${RETURN_TO}" \
            --data-urlencode 'identifier=dev@example.test' \
            --data-urlencode 'password=dev-password-not-for-production')
    else
        NEXT=$(curl -s -c "${JAR}" -b "${JAR}" -o /dev/null -w '%{redirect_url}' -X POST "${BASE}${ACTION}" \
            --data-urlencode "return_to=${RETURN_TO}" -d 'decision=allow')
    fi
done

AUTH_CODE=$(printf '%s' "${NEXT}" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
if [ -z "${AUTH_CODE}" ]; then
    echo "mobile-flow: the browser never reached the redirect with a code: ${NEXT}" >&2
    exit 1
fi

# NO `DPoP:` HEADER. This single omission is the whole question the caller is asking.
curl -s -X POST "${TOKEN_ENDPOINT}" \
    -d grant_type=authorization_code \
    -d "code=${AUTH_CODE}" \
    -d "client_id=${CLIENT_ID}" \
    --data-urlencode "redirect_uri=${REDIRECT}" \
    -d "code_verifier=${VERIFIER}" \
    -o "${WORK}/token.json" -w '%{http_code}'
