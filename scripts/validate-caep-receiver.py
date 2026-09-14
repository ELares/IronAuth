#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Judge IronAuth's CAEP events as an INDEPENDENT RECEIVER would (issue #144 criterion 1).

Criterion 1 asks that a public receiver accepts and validates the CAEP events this build emits,
with the evidence captured. `validate-set-external.py` beside this already hands an independent
library one SET per signing algorithm, and what that library judges is the ENVELOPE: a well
formed, correctly signed JWS whose claims verify against the published JWKS.

A RECEIVER JUDGES SOMETHING ELSE. It reads the `events` map, finds a CAEP type it recognises, and
acts on what that event's own members say. An envelope can be flawless while the event inside it
is one no receiver can use: two members under `events`, a subject in a format the stream did not
negotiate, an `event_timestamp` in milliseconds, a body that is not an object. Those are the
divergences the CAEP Interoperability Profile exists to remove, and not one of them is a
signature problem.

So this reads the corpus `tests/caep_receiver_corpus.rs` wrote and applies rules written from the
profile and RFC 8417, in a second implementation. PyJWT does the signature; everything about the
EVENT is checked here, by code that shares no line with the emitter.

WHAT THIS IS NOT is a conformance certificate, and no script can issue one. It is this deployment
asserting, against an outside judgement, that the events it emits are the shape a receiver can
act on.

NEGATIVE CONTROLS ARE THE OTHER HALF, for the reason the sibling validator gives: a checker
misconfigured into accepting anything reports the same "all valid" a working one does. Every
mutation below is applied to every event and every one MUST be rejected. The count is derived
from CONTROLS rather than written out, because two places stating a number the code computes is
how one of them goes stale.
"""

import base64
import copy
import json
import pathlib
import sys

try:
    import jwt
    from jwt import PyJWKSet
except ImportError:  # pragma: no cover - the gate provisions this
    sys.exit(
        "validate-caep-receiver: PyJWT is not installed. This check is deliberately NOT\n"
        "stdlib-only: a second JOSE implementation written here would be this repository\n"
        "checking itself. Install deploy/conformance/requirements-set.txt."
    )

# The CAEP event types a receiver may be handed by this build. Written HERE rather than read from
# the corpus, because a validator that learned which types to expect from the thing under test
# would accept a build that emitted none of them.
CAEP_PREFIX = "https://schemas.openid.net/secevent/caep/event-type/"
KNOWN_CAEP_TYPES = {
    CAEP_PREFIX + "session-revoked",
    CAEP_PREFIX + "credential-change",
    CAEP_PREFIX + "token-claims-change",
    CAEP_PREFIX + "assurance-level-change",
}

# The members CAEP 1.0 makes REQUIRED for each event, which a receiver acts on and without which
# the event says nothing it is for.
#
# THIS IS THE RULE THE FIRST VERSION DID NOT HAVE, and its absence was not academic: the build
# under test emitted a `token-claims-change` carrying only `event_timestamp`, CAEP 1.0 section
# 3.2.1 makes `claims` REQUIRED ("one or more claims with their new value(s)"), and this
# validator ACCEPTED it. A receiver checking the schema would not have, which is the entire
# reason to have an outside judgement rather than our own tests.
#
# `event_timestamp` IS NOT LISTED per type because every CAEP event carries it and it is checked
# for every event below; these are the per-type members on top of it.
REQUIRED_EVENT_MEMBERS = {
    CAEP_PREFIX + "session-revoked": (),
    # Section 3.2.1. A transmitter that cannot say WHICH claims changed and to what cannot emit
    # this event conformantly, which is a fact about the transmitter and not about the receiver.
    CAEP_PREFIX + "token-claims-change": ("claims",),
    # Section 3.3.1: `credential_type` and `change_type`.
    CAEP_PREFIX + "credential-change": ("credential_type", "change_type"),
    # Section 3.4.1: the level it moved to, and which direction.
    CAEP_PREFIX + "assurance-level-change": ("current_level", "change_direction"),
}

# RFC 9493 subject identifier formats a receiver can resolve. `iss_sub` is the one the corpus
# negotiates; the others are listed so a corpus that changed format is REPORTED rather than
# silently accepted by a check that only knew one.
SUBJECT_FORMATS = {
    "iss_sub": ("iss", "sub"),
    "opaque": ("id",),
    "email": ("email",),
}


class Rejected(Exception):
    """A judgement that this event is not one a receiver can act on."""


def _b64url(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def decode_header(token: str) -> dict:
    return json.loads(_b64url(token.split(".")[0]))


def verify_envelope(token: str, jwks: dict, expect: dict) -> dict:
    """The JWS half, through PyJWT, with the profile's own envelope requirements.

    `typ` IS CHECKED and it is not incidental: RFC 8417 section 2.2 requires `secevent+jwt`, and
    the profile relies on it so a receiver can tell a SET from any other token minted by the same
    issuer with the same key. A receiver that skipped it would accept an ID token as a signal.
    """
    header = decode_header(token)
    if header.get("typ") != expect["typ"]:
        raise Rejected(f"typ is {header.get('typ')!r}, expected {expect['typ']!r}")
    key = PyJWKSet.from_dict(jwks).keys[0]
    claims = jwt.decode(
        token,
        key=key.key,
        algorithms=[header["alg"]],
        audience=expect["aud"],
        issuer=expect["iss"],
        # A SET CARRIES NO `exp`. RFC 8417 section 4.1.4 says so explicitly: the event happened,
        # and an expiry would mean a receiver could be handed a signal it must ignore.
        options={"verify_exp": False, "require": ["iss", "aud", "iat", "jti"]},
    )
    return claims


def judge_receiver_rules(claims: dict) -> str:
    """Everything a RECEIVER checks, from the profile. Returns the event type it found.

    NOTHING HERE COMES FROM THE EMITTER. That is the split the first version did not make, and
    two of its six negative controls were the cost: mutating the event type or the subject format
    was caught by an equality against `expect.json` -- the file the minting side writes -- and
    never reached the rule the control was named for. Both would have gone on passing against a
    validator that had no such rule at all, which is precisely the mistake the sibling validator's
    own comments warn about.
    """
    events = claims.get("events")
    if not isinstance(events, dict):
        raise Rejected("`events` is not an object")
    # EXACTLY ONE. RFC 8417 allows more, and the interop profile pins one so a receiver need not
    # decide what it means to act on half of a SET it partly understands. A transmitter putting
    # two in is the divergence that reaches a receiver as a silently dropped event.
    if len(events) != 1:
        raise Rejected(f"`events` carries {len(events)} members, expected exactly 1")
    (event_type, body), = events.items()
    if event_type not in KNOWN_CAEP_TYPES:
        raise Rejected(f"{event_type!r} is not a CAEP event type this receiver knows")
    if not isinstance(body, dict):
        raise Rejected(f"the body of {event_type} is {type(body).__name__}, expected an object")

    # `event_timestamp` IS SECONDS. CAEP says so, and a transmitter sending milliseconds produces
    # an event a receiver dates to the year 55000 -- which no signature check can catch and which
    # reorders every event it holds for that subject.
    stamp = body.get("event_timestamp")
    if not isinstance(stamp, int) or isinstance(stamp, bool):
        raise Rejected(f"`event_timestamp` is {stamp!r}, expected an integer")
    if abs(stamp) > 4_102_444_800:  # 2100-01-01, generous for any real event
        raise Rejected(f"`event_timestamp` {stamp} is not a second count")

    # THE PER-TYPE REQUIRED MEMBERS, which is the check whose absence let a non-conformant event
    # through. A receiver acts on these; an event without them is one it can only log.
    for member in REQUIRED_EVENT_MEMBERS[event_type]:
        if member not in body:
            raise Rejected(f"{event_type} is missing the REQUIRED member {member!r}")

    subject = claims.get("sub_id")
    if not isinstance(subject, dict):
        raise Rejected("`sub_id` is not an object")
    fmt = subject.get("format")
    required = SUBJECT_FORMATS.get(fmt)
    if required is None:
        raise Rejected(f"{fmt!r} is not an RFC 9493 format this receiver resolves")
    for member in required:
        if not isinstance(subject.get(member), str) or not subject[member]:
            raise Rejected(f"subject format {fmt} is missing {member!r}")
    return event_type


def judge_corpus_correspondence(claims: dict, expect: dict, event_type: str) -> None:
    """The equalities against what the MINTING side wrote, which are not receiver rules.

    They are here because a corpus that minted the wrong event, for the wrong subject, would
    otherwise pass every rule above -- but they are NOT evidence of interoperability, and keeping
    them apart is what makes that legible. A reader can see exactly which of this file's
    judgements are independent and which take the emitter's word.
    """
    if event_type != expect["event_type"]:
        raise Rejected(f"event type is {event_type!r}, expected {expect['event_type']!r}")
    subject = claims["sub_id"]
    if subject.get("format") != expect["subject_format"]:
        raise Rejected(
            f"subject format is {subject.get('format')!r}, expected {expect['subject_format']!r}"
        )
    if subject.get("format") == "iss_sub" and subject["sub"] != expect["subject_sub"]:
        raise Rejected(f"subject is {subject['sub']!r}, expected {expect['subject_sub']!r}")
    if claims.get("jti") != expect["jti"]:
        raise Rejected(f"jti is {claims.get('jti')!r}, expected {expect['jti']!r}")


# Every mutation a receiver must refuse, applied to the CLAIMS of every case. Each is a real
# divergence somebody has shipped, not a synthetic one.
CONTROLS = [
    ("two events in one SET", lambda c: _two_events(c)),
    ("an event type no receiver knows", lambda c: _retype(c, CAEP_PREFIX + "invented")),
    ("a millisecond event_timestamp", lambda c: _scale_stamp(c, 1000)),
    ("a scalar event body", lambda c: _scalar_body(c)),
    ("a subject with no sub", lambda c: _drop_subject_member(c, "sub")),
    ("a subject format no receiver resolves", lambda c: _reformat_subject(c, "invented")),
    # THE CONTROL FOR THE RULE THAT WAS MISSING. A body stripped to its timestamp is exactly
    # what this build emitted for `token-claims-change` and what this validator accepted, so
    # the control exists to keep the required-member rule from being deleted quietly. It is a
    # no-op for a type with no required members, which is why the runner SKIPS it there rather
    # than counting a control that cannot fail.
    ("a body missing its required members", lambda c: _strip_required(c)),
]


def _two_events(claims: dict) -> dict:
    out = copy.deepcopy(claims)
    (_, body), = list(out["events"].items())[:1]
    out["events"][CAEP_PREFIX + "credential-change"] = copy.deepcopy(body)
    return out


def _retype(claims: dict, event_type: str) -> dict:
    out = copy.deepcopy(claims)
    (_, body), = out["events"].items()
    out["events"] = {event_type: body}
    return out


def _scale_stamp(claims: dict, factor: int) -> dict:
    out = copy.deepcopy(claims)
    for body in out["events"].values():
        body["event_timestamp"] *= factor
    return out


def _scalar_body(claims: dict) -> dict:
    out = copy.deepcopy(claims)
    out["events"] = {next(iter(out["events"])): "revoked"}
    return out


def _drop_subject_member(claims: dict, member: str) -> dict:
    out = copy.deepcopy(claims)
    out["sub_id"].pop(member, None)
    return out


def _reformat_subject(claims: dict, fmt: str) -> dict:
    out = copy.deepcopy(claims)
    out["sub_id"]["format"] = fmt
    return out


def _strip_required(claims: dict) -> dict:
    out = copy.deepcopy(claims)
    for event_type, body in out["events"].items():
        for member in REQUIRED_EVENT_MEMBERS.get(event_type, ()):  # pragma: no branch
            body.pop(member, None)
    return out


def _applicable(name: str, event_type: str) -> bool:
    """Whether a control can actually fail for this event type.

    A CONTROL THAT CANNOT FAIL IS NOT A CONTROL, and counting one would inflate the evidence
    this gate prints. `session-revoked` has no required members beyond the timestamp every event
    carries, so stripping them changes nothing and the runner says so rather than scoring it.
    """
    if name == "a body missing its required members":
        return bool(REQUIRED_EVENT_MEMBERS.get(event_type, ()))
    return True


def self_test() -> list[str]:
    """Prove the rules REJECT what they are for, on events this build does not emit.

    # Why a validator needs its own negatives

    Every control in `CONTROLS` runs against an event the corpus produced, so a rule that only
    fires for a type this build does not emit is exercised by nothing -- it would sit here
    looking like coverage and catch nothing, which is the shape the first version of this file
    actually had.

    THE FIRST CASE IS NOT HYPOTHETICAL. This repository emitted a `token-claims-change` carrying
    only `event_timestamp`, CAEP 1.0 section 3.2.1 makes `claims` REQUIRED, and this validator
    ACCEPTED it -- the whole reason for an outside judgement, failing at the one thing it was
    for. The emitter was withdrawn; this is what keeps the rule that would have caught it.
    """
    failures = []
    subject = {"format": "iss_sub", "iss": "https://issuer.example", "sub": "usr_selftest"}
    for event_type, body, expected in [
        # THE EVENT THAT WAS ALMOST SHIPPED.
        (
            CAEP_PREFIX + "token-claims-change",
            {"event_timestamp": 1_700_000_000},
            "rejected",
        ),
        # AND THE SAME EVENT MADE CONFORMANT, so the rule is measuring the missing member
        # rather than refusing the type.
        (
            CAEP_PREFIX + "token-claims-change",
            {"event_timestamp": 1_700_000_000, "claims": {"role": "admin"}},
            "accepted",
        ),
        (
            CAEP_PREFIX + "credential-change",
            {"event_timestamp": 1_700_000_000, "credential_type": "password"},
            "rejected",
        ),
        (
            CAEP_PREFIX + "credential-change",
            {
                "event_timestamp": 1_700_000_000,
                "credential_type": "password",
                "change_type": "update",
            },
            "accepted",
        ),
    ]:
        claims = {"events": {event_type: body}, "sub_id": subject, "jti": "evt_selftest"}
        try:
            judge_receiver_rules(claims)
            actual = "accepted"
        except Rejected:
            actual = "rejected"
        if actual != expected:
            failures.append(
                f"self-test: {event_type} with body {sorted(body)} was {actual}, "
                f"expected {expected}"
            )
    return failures


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: validate-caep-receiver.py <corpus-dir>", file=sys.stderr)
        return 2
    root = pathlib.Path(argv[1])
    cases = sorted(p for p in root.iterdir() if p.is_dir())
    if not cases:
        print(f"validate-caep-receiver: no cases under {root}", file=sys.stderr)
        return 1

    # THE VALIDATOR'S OWN NEGATIVES FIRST. A rule that fires only for a type this build does
    # not emit is exercised by no corpus case, and the required-member rule is exactly that today.
    failures: list[str] = self_test()
    report = {"cases": [], "controls_defined": len(CONTROLS), "self_test_cases": 4}
    for case in cases:
        label = case.name
        token = (case / "set.jwt").read_text().strip()
        jwks = json.loads((case / "jwks.json").read_text())
        expect = json.loads((case / "expect.json").read_text())
        try:
            claims = verify_envelope(token, jwks, expect)
            event_type = judge_receiver_rules(claims)
            judge_corpus_correspondence(claims, expect, event_type)
        except (Rejected, jwt.PyJWTError) as error:
            failures.append(f"{label}: a valid event was REJECTED: {error}")
            continue

        # THE CONTROLS RUN AGAINST THE RECEIVER RULES ONLY, never the corpus correspondence.
        # A mutation caught by an equality against `expect.json` proves nothing about
        # interoperability: the emitter wrote that file, so the comparison is this repository
        # agreeing with itself, and a control that tripped on it would pass against a validator
        # with no receiver rule at all.
        #
        # ON CLAIMS THIS VALIDATOR HAS ALREADY ACCEPTED, so a rejection is attributable to the
        # mutation and to nothing else.
        applicable = [(name, m) for name, m in CONTROLS if _applicable(name, event_type)]
        accepted_controls = []
        for name, mutate in applicable:
            try:
                judge_receiver_rules(mutate(claims))
            except Rejected:
                continue
            accepted_controls.append(name)
        if accepted_controls:
            failures.append(f"{label}: controls ACCEPTED: {accepted_controls}")
        skipped = [name for name, _ in CONTROLS if not _applicable(name, event_type)]
        report["cases"].append(
            {
                "case": label,
                "event_type": expect["event_type"],
                "alg": decode_header(token)["alg"],
                "accepted": True,
                "controls_rejected": len(applicable) - len(accepted_controls),
                # NAMED, not just subtracted. A gate whose evidence said "5 of 6" without saying
                # which one it dropped would read as a partial failure.
                "controls_not_applicable": skipped,
            }
        )

    (root / "validation-report.json").write_text(json.dumps(report, indent=2) + "\n")
    for line in failures:
        print(f"validate-caep-receiver: {line}", file=sys.stderr)
    if failures:
        return 1
    print(
        f"validate-caep-receiver: {len(report['cases'])} CAEP event(s) accepted by an "
        f"independent receiver"
    )
    for entry in report["cases"]:
        line = (
            f"  {entry['case']}: {entry['event_type']} ({entry['alg']}), "
            f"{entry['controls_rejected']} controls rejected"
        )
        if entry["controls_not_applicable"]:
            line += f", not applicable: {entry['controls_not_applicable']}"
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
