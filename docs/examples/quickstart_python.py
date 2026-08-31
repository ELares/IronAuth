#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Sign a user in from Python with the device flow, and VERIFY the token (issue #116).

Read alongside `docs/quickstart-python.md`. One dependency, `cryptography`, and only for the
Ed25519 signature check -- everything else is standard library, so the verification below is
visible rather than hidden behind a library call.

That one dependency is not negotiable and the code treats it that way: an earlier version printed
"skipping that check" when it was missing and carried on, which is worse than not verifying at
all. It prints a reassuring line, returns claims, and teaches a reader that the signature is
optional.

That verification is the part worth reading. A token that arrived over TLS from the right host is
not a verified token: TLS says who sent it, and the signature says who MINTED it, which is a
different question the moment anything sits between you and the issuer.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ISSUER = os.environ["ISSUER"]
CLIENT_ID = os.environ["CLIENT_ID"]
# The protocol endpoints live at the DEPLOYMENT ROOT while the issuer is per environment.
ROOT = ISSUER.split("/t/")[0]

USER = os.environ.get("DEV_USER", "dev@example.test")
PASSWORD = os.environ.get("DEV_PASSWORD", "dev-password-not-for-production")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Do not follow redirects.

    urllib follows them by default, and here that is actively wrong: the login POST answers 303
    to `/authorize`, which answers 303 to the client's registered `redirect_uri` -- and that is
    `http://127.0.0.1/callback`, port 80, where nothing is listening.

    Following the chain turns a working login into `ConnectionRefusedError` from a host the
    quickstart never meant to contact. What this code wants from `/login` is the SESSION COOKIE
    it sets, which arrives on the 303 itself.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def post(url: str, form: dict[str, str], jar: dict[str, str] | None = None) -> tuple[int, bytes, dict[str, str]]:
    body = urllib.parse.urlencode(form).encode()
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("content-type", "application/x-www-form-urlencoded")
    if jar:
        request.add_header("cookie", "; ".join(f"{k}={v}" for k, v in jar.items()))

    def cookies_of(headers) -> dict[str, str]:
        found = {}
        for header in headers.get_all("set-cookie") or []:
            name, _, rest = header.partition("=")
            found[name] = rest.split(";")[0]
        return found

    try:
        with _OPENER.open(request) as response:
            return response.status, response.read(), cookies_of(response.headers)
    except urllib.error.HTTPError as error:
        # A 3xx arrives here because redirects are not followed, and its cookies are the point.
        return error.code, error.read(), cookies_of(error.headers)


def b64url(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def verify(id_token: str, audience: str) -> dict:
    """Verify an EdDSA ID token against the environment's published JWKS.

    Every check here is one a real verifier must do, and the ORDER matters: the algorithm comes
    from what the issuer publishes, the key from the published set, and the token's own header is
    only ever matched against them. A verifier that took `alg` from the header can be talked into
    `none`, which is the oldest JOSE bug there is.
    """
    header_b64, payload_b64, signature_b64 = id_token.split(".")
    header = json.loads(b64url(header_b64))
    payload = json.loads(b64url(payload_b64))

    with urllib.request.urlopen(f"{ISSUER}/jwks.json") as response:
        jwks = json.load(response)

    published = {key.get("kid"): key for key in jwks["keys"]}
    if header.get("alg") != "EdDSA":
        raise SystemExit(f"quickstart: this environment publishes EdDSA, token says {header.get('alg')}")
    key = published.get(header.get("kid"))
    if key is None:
        raise SystemExit(f"quickstart: no published key for kid {header.get('kid')}")

    # THE SIGNATURE, and a missing library is a HARD FAILURE rather than a skipped check.
    #
    # The first version of this printed "skipping that check" and carried on, which is worse than
    # not verifying at all: it prints a reassuring line, returns claims, and teaches a reader that
    # the signature is optional. A quickstart is where someone learns the shape of the thing, and
    # the shape must not have a hole in it where the most important check goes.
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        raise SystemExit(
            "quickstart: `cryptography` is required to verify the signature. "
            "Run: python3 -m pip install cryptography"
        ) from None
    public = Ed25519PublicKey.from_public_bytes(b64url(key["x"]))
    # Raises on a bad signature, which is what we want: there is no sensible way to continue.
    public.verify(b64url(signature_b64), f"{header_b64}.{payload_b64}".encode())

    if payload.get("iss") != ISSUER:
        raise SystemExit(f"quickstart: wrong issuer {payload.get('iss')}")
    audiences = payload.get("aud")
    audiences = audiences if isinstance(audiences, list) else [audiences]
    if audience not in audiences:
        raise SystemExit(f"quickstart: wrong audience {audiences}")
    if payload.get("exp", 0) <= time.time():
        raise SystemExit("quickstart: the token has expired")
    return payload


def main() -> int:
    # 1. Start the device grant. A public client, so no secret travels.
    status, body, _ = post(
        f"{ROOT}/device_authorization",
        {"client_id": CLIENT_ID, "scope": "openid"},
    )
    if status != 200:
        raise SystemExit(f"quickstart: the grant did not start ({status}): {body!r}")
    grant = json.loads(body)
    device_code, user_code = grant["device_code"], grant["user_code"]
    interval = grant.get("interval", 5)
    print(f"quickstart: visit {grant.get('verification_uri')} and enter {user_code}")

    # 2. Approve it, as the user's second device would. In a real quickstart a person does this;
    #    here it is scripted so CI can run the whole thing unattended.
    resume = f"/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri=http://127.0.0.1/callback&scope=openid"
    _, _, jar = post(
        f"{ROOT}/login",
        {"identifier": USER, "password": PASSWORD, "return_to": resume},
    )
    _, page, more = post(f"{ISSUER}/device", {"user_code": user_code}, jar)
    jar.update(more)
    import re

    flow = re.search(rb'name="device_code_id"[^>]*value="([^"]+)"', page)
    if not flow:
        raise SystemExit("quickstart: the approval page carried no flow handle")
    post(
        f"{ISSUER}/device",
        {"decision": "allow", "device_code_id": flow.group(1).decode(), "user_code": user_code},
        jar,
    )

    # 3. Poll, honouring the advertised interval. A client that polled faster would be told to
    #    slow down, and one that ignored THAT would be refused.
    deadline = time.time() + 60
    while time.time() < deadline:
        time.sleep(interval)
        status, body, _ = post(
            f"{ROOT}/token",
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
                "client_id": CLIENT_ID,
            },
        )
        payload = json.loads(body)
        if status == 200:
            claims = verify(payload["id_token"], CLIENT_ID)
            print(f"quickstart: signed in as {claims['sub']}")
            return 0
        if payload.get("error") not in ("authorization_pending", "slow_down"):
            raise SystemExit(f"quickstart: the grant failed: {payload}")
    raise SystemExit("quickstart: timed out waiting for approval")


if __name__ == "__main__":
    sys.exit(main())
