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
| 2.3.3 | `jwks_uri` present, absolute, and under this issuer | `section_2_3_the_advertised_endpoints_are_absolute_and_under_this_issuer` |
| 2.3.4 | `configuration_endpoint` present | `section_2_3_the_metadata_carries_every_field_the_profile_requires` |
| 2.3.5 | `status_endpoint` present | `section_2_3_the_metadata_carries_every_field_the_profile_requires` |
| 2.3.6 | `verification_endpoint` present | `section_2_3_the_metadata_carries_every_field_the_profile_requires` |
| 2.3.7 | `authorization_schemes` present and including `urn:ietf:rfc:6749` | `section_2_3_7_the_authorization_scheme_names_rfc_6749` |
| 2.3.2 | Both profile delivery methods advertised as supported | `section_2_3_2_both_profile_delivery_methods_are_advertised` |
| 2.5 | At least one of the `email`, `iss_sub`, `opaque` subject formats, rendered | `section_2_5_a_required_subject_identifier_format_is_actually_rendered` |
| 3.1 | Session Revocation supported, with a NON-EMPTY `reason_admin` | `section_3_1_a_session_revoked_event_carries_a_non_empty_reason_admin` |
| 2.8.1 | The `events` claim carries exactly one event | `section_2_8_1_a_set_carries_exactly_one_event` |

## Requirements this build does NOT satisfy

Recording these is the point of the document. A conformance checklist that lists only the
rows it passes is a marketing page, and the reader it misleads is the operator deciding
whether to enter an interop matrix.

Each row here names a test that pins the CURRENT behaviour, so closing the gap fails that
test and forces the row to be updated in the same change. A not-satisfied row with no test
decays: somebody adds the missing support and the document still says it is missing.

| Profile section | Requirement | Status | Pinned by |
| --- | --- | --- | --- |
| 2.7.2 | Accept OAuth 2.0 Bearer access tokens in the HTTP `Authorization` header; do not accept them via query parameter; verify validity, integrity, expiration and revocation; return errors per RFC 6750 section 3.1 | **NOT SATISFIED.** The stream-management endpoints authenticate the RECEIVER as an OAuth CLIENT, through `client_secret_basic`, rather than accepting an access token issued to it. Nothing accepts a token via query parameter, so that half holds trivially, but the positive requirement does not: a conformant receiver arriving with a Bearer access token is refused. The discovery document is honest about it -- `authorization_schemes` advertises `token_endpoint_auth_methods_supported: ["client_secret_basic"]` -- so a receiver reading the metadata learns this before it fails, but advertising a narrower scheme is not the same as satisfying 2.7.2. The error format is wrong for the same reason: the 401 carries `WWW-Authenticate: Basic realm="ironauth"` and `invalid_client`, where 2.7.2 wants a `Bearer` challenge. Closing it means accepting and validating a Bearer access token at the five stream endpoints, which is its own change. | `section_2_7_2_a_bearer_access_token_is_refused_today` |
| 2.7.3 | The authorization server issuing tokens to receivers supports the `ssf.manage` and `ssf.read` scopes | **NOT SATISFIED**, and it cannot be until 2.7.2 is: neither scope name appears anywhere in this repository, because nothing consumes an access token at these endpoints for a scope to gate. It is listed separately rather than folded into the row above so that closing 2.7.2 without defining the scopes does not silently look complete. | Not pinned: there is nothing to assert about a scope no code reads. Closing 2.7.2 makes this testable. |

## Requirements the profile states and this table does not yet cover

The profile has more normative text than the rows above. Sections not represented here are
not silently claimed: this table maps what is covered and what is known not to be, and a
section absent from both lists has not been assessed. Naming that explicitly is the
difference between a map with edges and a map that pretends to be complete.

Assessed and covered: 2.3.1 through 2.3.7, 2.5, 2.8.1, 3.1. Assessed and not satisfied:
2.7.2 and 2.7.3 -- which matters because issue #144's criterion 6 names "discovery, auth,
mandatory events", and 2.7 IS the auth third. Assessed and untestable here: 2.1, 2.6 (below). Everything else in the profile,
including the stream-control operations of 2.3.8.2 and the use cases of 3.2 and 3.3, is
UNASSESSED.

## Requirements that are deployment properties, not code properties

These are real obligations and they are not covered by a test, because the thing they
constrain is chosen by the operator rather than by this repository. Writing them here with
no test named is the honest form: a row pointing at a test that could not fail would read
as covered and be worse than an empty cell.

| Profile section | Requirement | Why no test, and what an operator must do |
| --- | --- | --- |
| 2.1 | TLS 1.2 or later on every endpoint, following RFC 9325 | Termination is the deployment's, not this process's: IronAuth is normally run behind a terminating proxy, so a test here would assert the harness's transport rather than production's. The operator's obligation is the proxy configuration. |
| 2.6 | Events signed with `RS256`, minimum 2048-bit keys | The SET is signed under the ENVIRONMENT's registered signing policy, which this repository does not choose: `mint_set` uses the issuer entry's policy rather than pinning an algorithm, and the build supports Ed25519, ECDSA and RSA key material. EdDSA and ES256 are legal under SSF 1.0 and NOT under this profile, so an environment intending to interoperate must be configured with RSA key material and its effective `alg` confirmed against a minted token. This row states the obligation; it does not assert that any given environment meets it, and no test here can. |

## Receiver requirements

The profile's receiver requirements are not mapped here. This repository's receiver is the
Google Cross-Account Protection consumer (issue #144 criteria 4 and 5), which #144 scopes
to one transmitter rather than to the profile: `crates/ironauth-oidc/tests/risc_receiver.rs`
tests it against Google's documented wire format, which differs from the profile's in
`aud`, in where the subject sits, and in the event vocabulary. Mapping it against the
profile would claim a generality it does not have.
