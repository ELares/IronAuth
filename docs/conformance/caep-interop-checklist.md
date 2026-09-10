# CAEP Interoperability Profile conformance checklist

The [CAEP Interoperability Profile 1.0](https://openid.net/specs/openid-caep-interoperability-profile-1_0-01.html)
is what the Shared Signals interop events actually measure. SSF 1.0, CAEP 1.0 and RISC 1.0
say what a transmitter MAY do; the profile says what it must do to work with somebody
else's receiver. Implementations pass the base specs and still fail to talk to each other,
because each made a different legal choice, which is why the Gartner events test against
the profile rather than the specs.

This document maps each normative transmitter requirement to the executable test that
covers it. It is checked on every PR by `scripts/caep-interop-scan.sh`, which fails when a
row names a test that does not exist and when a test in the suite is not named by a row.
The map cannot silently rot in either direction: a deleted test breaks the build, and a new
test with no requirement is a prompt to write the requirement down.

Every test lives in `crates/ironauth-oidc/tests/caep_interop_profile.rs`.

## What this is not

Passing is not a conformance certificate, and no CI job can issue one. It is this
deployment asserting, on every change, that it still does what it told the profile it does.
Two requirements are deployment properties rather than code properties and are recorded as
such below; a test that pretended to settle them would be the more dangerous outcome,
because the row would read as covered.

## Transmitter requirements

| Profile section | Requirement | Covered by |
| --- | --- | --- |
| 2.3.1 | `spec_version` present, value `1_0` or greater | `section_2_3_1_the_spec_version_is_1_0_or_greater` |
| 2.3.2 | `delivery_methods_supported` present | `section_2_3_the_metadata_carries_every_field_the_profile_requires` |
| 2.3.3 | `jwks_uri` present and resolving to the current signing keys | `section_2_3_the_advertised_endpoints_are_absolute_and_under_this_issuer` |
| 2.3.4 | `configuration_endpoint` present | `section_2_3_the_metadata_carries_every_field_the_profile_requires` |
| 2.3.5 | `status_endpoint` present | `section_2_3_the_metadata_carries_every_field_the_profile_requires` |
| 2.3.6 | `verification_endpoint` present | `section_2_3_the_metadata_carries_every_field_the_profile_requires` |
| 2.3.7 | `authorization_schemes` present and including `urn:ietf:rfc:6749` | `section_2_3_7_the_authorization_scheme_names_rfc_6749` |
| 2.3.8.1 | Create Stream processed for push (RFC 8935) and poll (RFC 8936) | `section_2_3_2_both_profile_delivery_methods_are_advertised` |
| 2.5 | At least one of the `email`, `iss_sub`, `opaque` subject formats | `section_2_5_a_required_subject_identifier_format_is_supported` |
| 2.8.1 | The `events` claim carries exactly one event | `section_2_8_1_a_set_carries_exactly_one_event` |

## Requirements that are deployment properties, not code properties

These are real obligations and they are not covered by a test, because the thing they
constrain is chosen by the operator rather than by this repository. Writing them here with
no test named is the honest form: a row pointing at a test that could not fail would read
as covered and be worse than an empty cell.

| Profile section | Requirement | Why no test, and what an operator must do |
| --- | --- | --- |
| 2.1 | TLS 1.2 or later on every endpoint, following RFC 9325 | Termination is the deployment's, not this process's: IronAuth is normally run behind a terminating proxy, so a test here would assert the harness's transport rather than production's. The operator's obligation is the proxy configuration. |
| 2.6 | Events signed with `RS256`, minimum 2048-bit keys | The signing algorithm is per-environment configuration, and this build also supports EdDSA and ES256, which are valid under SSF 1.0 and NOT under this profile. An environment that intends to interoperate must register an RS256 key of at least 2048 bits. `ssf_set`'s minting path signs with whatever the environment registered; it does not and should not override the operator's choice. |

## Receiver requirements

The profile's receiver requirements are not mapped here. This repository's receiver is the
Google Cross-Account Protection consumer (issue #144 criteria 4 and 5), which #144 scopes
to one transmitter rather than to the profile: `crates/ironauth-oidc/tests/risc_receiver.rs`
tests it against Google's documented wire format, which differs from the profile's in
`aud`, in where the subject sits, and in the event vocabulary. Mapping it against the
profile would claim a generality it does not have.
