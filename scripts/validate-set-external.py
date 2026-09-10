#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Validate IronAuth's Security Event Tokens with an INDEPENDENT library (issue #143).

#143's criterion is that emitted SETs "validate with an external, independent JWT/SET library
against the environment JWKS". `ironauth-oidc`'s own test suite already verifies a minted SET,
but it verifies through `ironauth-jose`, which is the code that signed it. One implementation
checked against itself agrees with itself: a shared misreading of RFC 8417 or RFC 7515 passes in
both directions, and a receiver built on any other library is the first to discover it.

So this reads the corpus `tests/ssf_set_corpus.rs` wrote and judges it with PyJWT, which shares
no line of code with this repository. Everything it asserts against comes from `expect.json`,
written by the minting side in the same run: a validator holding its own copy of the expected
issuer would keep passing after the issuer stopped matching.

NEGATIVE CONTROLS ARE THE OTHER HALF, and the reason is that a validator misconfigured into
accepting anything reports the same "all valid" a working one does. Every mutation below is
applied to every token and every one MUST be rejected; a corpus that passes the positive check
while any control is ACCEPTED is a failure, not a pass. The count is derived from CONTROLS rather
than written out, because two files stating a number the code computes is how one of them goes
stale.

THE WRONG-KEY CONTROL USES A DECOY OF THE SAME ALGORITHM, which is the difference between a
control and a formality. Offering an EdDSA token an ES256 key is refused by PyJWT's key-type
check before any signature math runs, so those cross-case controls -- kept, because they do catch
a validator with verification switched off -- cannot tell you the signature is checked. The decoy
can, and its rejection must be an InvalidSignatureError specifically rather than any exception.
"""

import base64
import json
import pathlib
import sys

try:
    import jwt
    from jwt import PyJWKSet
except ImportError:  # pragma: no cover - the gate provisions this
    sys.exit(
        "validate-set-external: PyJWT is not installed. This check is deliberately NOT\n"
        "stdlib-only: the whole point is a second implementation. Install it with\n"
        "    python3 -m pip install --require-hashes -r deploy/conformance/requirements-set.txt"
    )

# The corpus covers the algorithms `DayOneSigningKeys` provisions, and each directory is bound to
# the algorithm it is named for.
#
# A BARE SET OF NAMES WAS NOT ENOUGH. It matched on directory names alone, so a corpus of three
# EdDSA tokens in directories named eddsa, es256 and rs256 passed the whole lane while the summary
# printed "3 algorithms validated" -- measured by a reviewer, not hypothesised. The value is the
# `alg` the token in that directory must declare, so the matrix cannot degrade into one algorithm
# repeated three times.
EXPECTED_CASES = {"eddsa": "EdDSA", "es256": "ES256", "rs256": "RS256"}

# The controls every token gets regardless of how many cases there are: a flipped signature bit,
# a declared algorithm it was not signed with, a wrong audience, a wrong issuer, and a decoy key
# of its own algorithm. The cross-case key controls are counted separately, since there is one
# per OTHER case.
CONTROLS_PER_TOKEN = 5


def b64url_decode(segment: str) -> bytes:
    """Decode one JWS segment, restoring the padding RFC 7515 strips."""
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def key_for(jwks_text: str, kid: str):
    """The JWKS member whose `kid` matches, as a key object PyJWT can verify with."""
    keyset = PyJWKSet.from_json(jwks_text)
    for key in keyset.keys:
        if key.key_id == kid:
            return key.key
    raise AssertionError(f"the JWKS carries no key with kid {kid!r}")


def decode(token: str, key, alg: str, audience: str, issuer: str) -> dict:
    """Verify and decode, with the SET-specific relaxations and nothing else.

    `verify_exp` is off because SSF 1.0 section 4.1.7 says a SET MUST NOT carry `exp`; every
    other check PyJWT performs stays on, including the signature, the algorithm allowlist, the
    audience and the issuer.
    """
    return jwt.decode(
        token,
        key=key,
        algorithms=[alg],
        audience=audience,
        issuer=issuer,
        options={"verify_exp": False, "require": ["iss", "iat", "jti"]},
    )


def rejects(label: str, control: str, thunk, expect=Exception) -> list[str]:
    """Run a negative control. It must raise `expect`; anything else is a failure.

    THE EXCEPTION TYPE IS PART OF THE CONTROL where it can be. A helper that accepted any
    exception would count a TypeError raised before verification began as proof that verification
    rejects the mutation, which is the difference between a control and a formality. `expect`
    stays broad for the mutations that legitimately fail several ways and is narrowed to
    InvalidSignatureError for the decoy, where the whole point is WHICH check fired.
    """
    try:
        thunk()
    except expect:
        return []
    except Exception as error:  # noqa: BLE001 - rejected, but not for the reason claimed
        return [
            f"{label}: the {control} control was rejected by {type(error).__name__}, "
            f"not {expect.__name__}; it does not test what it claims to"
        ]
    return [f"{label}: the {control} control was ACCEPTED; this validator proves nothing"]


def check_case(case: pathlib.Path, others: dict) -> list[str]:
    """Validate one algorithm's SET, positively and then adversarially."""
    label = case.name
    failures: list[str] = []
    token = (case / "set.jwt").read_text().strip()
    jwks_text = (case / "jwks.json").read_text()
    expect = json.loads((case / "expect.json").read_text())

    # THE DIRECTORY NAME IS A CLAIM ABOUT THE ALGORITHM, and this is where it is checked. Without
    # it `expect.json` and the token agree with each other while both disagree with the matrix the
    # lane reports.
    if expect["alg"] != EXPECTED_CASES[label]:
        failures.append(
            f"{label}: the corpus case declares alg {expect['alg']!r}, but a case in this "
            f"directory must be {EXPECTED_CASES[label]!r}"
        )

    header = json.loads(b64url_decode(token.split(".")[0]))
    if header.get("typ") != expect["typ"]:
        failures.append(
            f"{label}: header typ is {header.get('typ')!r}, expected {expect['typ']!r}"
        )
    if header.get("alg") != expect["alg"]:
        failures.append(
            f"{label}: header alg is {header.get('alg')!r}, expected {expect['alg']!r}"
        )
    kid = header.get("kid")
    if not kid:
        failures.append(f"{label}: the header carries no kid, so a receiver cannot select a key")
        return failures

    try:
        key = key_for(jwks_text, kid)
    except AssertionError as error:
        return failures + [f"{label}: {error}"]

    try:
        claims = decode(token, key, expect["alg"], expect["aud"], expect["iss"])
    except Exception as error:  # noqa: BLE001 - report, do not raise
        return failures + [f"{label}: an independent library REJECTED the SET: {error!r}"]

    if claims.get("jti") != expect["jti"]:
        failures.append(f"{label}: jti is {claims.get('jti')!r}, expected {expect['jti']!r}")
    # SSF 1.0 section 3.1 makes the top-level `sub_id` a MUST, and RFC 8417 leaves `sub`
    # discouraged for a SET: a receiver resolving `sub` would resolve the wrong thing.
    sub_id = claims.get("sub_id")
    if not isinstance(sub_id, dict):
        failures.append(f"{label}: there is no top-level sub_id object")
    else:
        if sub_id.get("format") != expect["subject_format"]:
            failures.append(
                f"{label}: sub_id format is {sub_id.get('format')!r}, "
                f"expected {expect['subject_format']!r}"
            )
        if sub_id.get("sub") != expect["subject_sub"]:
            failures.append(
                f"{label}: sub_id sub is {sub_id.get('sub')!r}, "
                f"expected {expect['subject_sub']!r}"
            )
    if "sub" in claims:
        failures.append(f"{label}: a top-level sub is present: {claims['sub']!r}")
    if "exp" in claims:
        failures.append(f"{label}: SSF 1.0 section 4.1.7 forbids exp, and one is present")
    events = claims.get("events")
    if not isinstance(events, dict) or expect["event_type"] not in events:
        failures.append(
            f"{label}: events is not an object keyed by {expect['event_type']!r}: {events!r}"
        )

    # The negative controls. Each varies EXACTLY ONE thing from the call that just succeeded, so a
    # rejection names the mutation that caused it.
    head, payload, signature = token.split(".")
    # A DECODED BYTE, not a base64url character, and the reason is worth stating correctly
    # because the first attempt to state it was misleading.
    #
    # Substituting the LAST CHARACTER was the first version, and it was accepted for RS256 on the
    # run that caught it. The note then blamed the 256-byte RSA signature, which is wrong: every
    # signature here is 1 mod 3 bytes long (EdDSA and ES256 are 64, RSA is 256), so all three end
    # in a one-byte group whose final character carries four bits the decoder discards. Which
    # algorithm trips is a COIN FLIP, about one run in four per algorithm: the substitution is a
    # no-op exactly when the original last character and its replacement agree in their top two
    # bits, and the signature changes every run because `iat` does. On the run in question the
    # RSA signature happened to end in 'A' and the replacement was 'B' -- 0 and 1, both with top
    # two bits 00 -- while EdDSA and ES256 happened to end in 'g' and 'w' and escaped.
    #
    # Flipping a bit of the first signature byte and re-encoding changes the signature every
    # time, for every algorithm and every length.
    raw = bytearray(b64url_decode(signature))
    raw[0] ^= 0x01
    tampered = base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("ascii")
    assert tampered != signature, "the signature mutation did not change the signature"
    failures += rejects(
        label,
        "flipped-signature",
        lambda: decode(
            f"{head}.{payload}.{tampered}",
            key,
            expect["alg"],
            expect["aud"],
            expect["iss"],
        ),
    )
    for other_label, other_key in others.items():
        if other_label == label:
            continue
        failures += rejects(
            label,
            f"key-from-{other_label}",
            lambda k=other_key: decode(
                token, k, expect["alg"], expect["aud"], expect["iss"]
            ),
        )
    wrong_alg = "RS256" if expect["alg"] != "RS256" else "ES256"
    failures += rejects(
        label,
        f"declared-{wrong_alg}",
        lambda: decode(token, key, wrong_alg, expect["aud"], expect["iss"]),
    )
    failures += rejects(
        label,
        "wrong-audience",
        lambda: decode(
            token, key, expect["alg"], "https://receiver.example/somebody-else", expect["iss"]
        ),
        expect=jwt.InvalidAudienceError,
    )
    # THE ISSUER, which had no control at all. Every other control handed the decoder the correct
    # `iss`, so deleting `issuer=` from the decode call left the lane printing "clean" -- and the
    # issuer is what ties a SET to the environment whose keys signed it.
    failures += rejects(
        label,
        "wrong-issuer",
        lambda: decode(
            token, key, expect["alg"], expect["aud"], "https://issuer.example/t/nobody/e/nowhere"
        ),
        expect=jwt.InvalidIssuerError,
    )
    # THE DECOY: a key of the SAME algorithm that signed nothing, so PyJWT reaches the signature
    # and fails THERE. The cross-case controls above cannot get that far.
    decoy_text = (case / "decoy_jwks.json").read_text()
    decoy_kid = json.loads(decoy_text)["keys"][0]["kid"]
    try:
        decoy = key_for(decoy_text, decoy_kid)
    except AssertionError as error:
        return failures + [f"{label}: the decoy key set is unusable: {error}"]
    failures += rejects(
        label,
        "same-algorithm-decoy-key",
        lambda: decode(token, decoy, expect["alg"], expect["aud"], expect["iss"]),
        expect=jwt.InvalidSignatureError,
    )
    return failures


def main() -> int:
    if len(sys.argv) != 2:
        sys.exit("usage: validate-set-external.py <corpus-directory>")
    root = pathlib.Path(sys.argv[1])
    if not root.is_dir():
        sys.exit(f"validate-set-external: {root} is not a directory")

    cases = sorted(p for p in root.iterdir() if p.is_dir())
    found = {p.name for p in cases}
    if found != set(EXPECTED_CASES):
        missing = sorted(set(EXPECTED_CASES) - found)
        extra = sorted(found - set(EXPECTED_CASES))
        print(
            f"validate-set-external: the corpus covers {sorted(found)}, expected "
            f"{sorted(EXPECTED_CASES)} (missing {missing}, unexpected {extra}).\n"
            "An algorithm added to DayOneSigningKeys belongs in the corpus and in "
            "EXPECTED_CASES here, deliberately rather than by discovery.",
            file=sys.stderr,
        )
        return 1

    # Every case's key, so each token can be offered a KEY THAT IS NOT ITS OWN. Collected up
    # front because the control needs the other cases, not just this one.
    keys = {}
    for case in cases:
        token = (case / "set.jwt").read_text().strip()
        header = json.loads(b64url_decode(token.split(".")[0]))
        if header.get("kid"):
            keys[case.name] = key_for((case / "jwks.json").read_text(), header["kid"])

    failures: list[str] = []
    for case in cases:
        failures += check_case(case, keys)

    if failures:
        print("validate-set-external: FAILED", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    # COUNTED FROM THE CORPUS, not from the directory count. `len(cases)` is unconditionally
    # three by the time this line runs -- the name check above returns 1 on any other value -- so
    # printing it as an algorithm count was a constant wearing the grammar of a measurement.
    algorithms = sorted({json.loads((case / "expect.json").read_text())["alg"] for case in cases})
    print(
        f"validate-set-external: clean ({len(algorithms)} algorithms validated by PyJWT "
        f"{jwt.__version__} against the published JWKS: {', '.join(algorithms)}; "
        f"{CONTROLS_PER_TOKEN + len(cases) - 1} negative controls rejected per token)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
