# IDA schema readiness (DESIGN NOTE + SHIPPED SEAM)

**Status:** the schema seam ships (verified_claims carrier + subset semantics); the full IDA surface does not.
**Pinned revision:** the IDA verified_claims shape as it stands (trust framework, evidence, assurance).
**Feature flag:** none (the carrier is inert until a claim document stores an envelope and a request names it).
**Trigger condition for the full surface:** a regulated customer demanding IDA verified_claims request syntax and response assembly (4-8 weeks as an additive feature, by design).
**Graduation criteria for the seam:** the acceptance criterion's end-to-end demonstration - a claim carrying verification metadata stored, requested, and emitted - in the test suite (landed).

## The shipped seam

The claims pipeline now carries per-claim verification metadata end to end:

- **Stored:** the user's claim document (migration 0009, verbatim JSON) carries the `verified_claims` envelope.
- **Requested:** the `claims` parameter names `verified_claims`, optionally pinning the verification subset (trust frameworks, assurance levels).
- **Emitted:** the ONE shared assembler (`scope_claims::assemble_claims`) releases the filtered envelope; an envelope outside the pinned subset is omitted entirely - never partially released, because the claims half without the assurance context would present unverifiable identity data as verified.

## The additive surface

When the trigger fires: verified_claims request syntax and response assembly land ON TOP of the seam - the envelope model, the subset release, and the assembler wiring are already there. The seam deliberately does not verify anything about the metadata's truth; trust-framework believability is the framework's own question.
