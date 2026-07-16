# ironauth-screening changelog

All notable changes to the `ironauth-screening` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- Password-quality scoring (issue #66 PR C): `PasswordPolicy` gains a `min_zxcvbn_score`
  (0-4, default 0 = off) and `evaluate_strength`, a separate step scored AFTER the
  length/composition policy and BEFORE the breach screen, with a new non-enumerating
  `PolicyRejection::TooWeak`. zxcvbn GATE DECISION: the `zxcvbn` crate (v3, MIT) was
  proposed but FAILS the supply-chain gate under this repo's MSRV 1.85 floor. It
  transitively pulls `time`, and there is NO `time` version that satisfies both the
  advisories-as-errors gate (RUSTSEC-2026-0009 is fixed only in `time >= 0.3.47`) and MSRV
  1.85 (every `time >= 0.3.47` requires rustc 1.88). Per the gate protocol the crate is
  NOT forced; the documented in-tree fallback ships instead: a reduced-strength estimator
  (`strength.rs`, Shannon-entropy-over-charset-and-length plus a compiled-in
  common-password / keyboard / sequence pattern floor) exposing the SAME 0-4 score
  contract behind `evaluate_strength`, so zxcvbn can be swapped back in later behind one
  function the day its tree passes the gate. Pure and deterministic (no clock, no RNG), so
  no env seam.
- Documented the `FactorContext::MfaFactor` residual (issue #63 review): the 8-code-point
  MFA floor is currently INERT because every shipped credential-set path evaluates as
  `SoleFactor` (15, always 63B-4-compliant); it is wired as a policy input and activates when
  the MFA-enrollment context drives an `MfaFactor` evaluation. Documentation only.
- Initial breached-password screening and NIST SP 800-63B-4 password policy (issue #63).
  - K-anonymity screening core: `digest_password` computes the password's SHA-1 LOCALLY
    and splits it into a 5-character `Sha1Prefix` (the only part ever put on the wire) and
    a 35-character `Sha1Suffix` (compared only in-process, in constant time via
    `Sha1Suffix::ct_eq`). The full password and full hash never leave the process.
  - `BreachRangeProvider` trait: the pluggable provider interface, handed only a
    `Sha1Prefix` and returning the matching `BreachRange` of suffixes. `BreachRange::contains`
    matches the candidate suffix in constant time (no early exit).
  - `HibpRangeProvider`: the online HIBP range API provider. `GET {base}/range/{PREFIX}`
    over the SSRF-hardened `ironauth-fetch` (never a direct HTTP client), with
    `Add-Padding: true` to request padded responses, stripping `:0` padding decoys. The
    `BreachScreening` fetch purpose is added to `ironauth-fetch`.
  - `OfflineCorpusProvider`: the offline / self-hosted provider. Indexes an
    operator-supplied dataset of SHA-1 hashes (the HIBP downloadable format, or a plain
    list) in memory by prefix and screens entirely offline, with no outbound access.
  - `Screener` + `FailurePolicy`: applies fail-open (allow + flag for audit) or
    fail-closed (refuse) when a provider cannot answer, consistent with the platform's
    documented fail-open/closed conventions. `ScreenOutcome` distinguishes not-breached,
    breached, and the two provider-failure dispositions.
  - `PasswordPolicy`: the 800-63B-4 memorized-secret verifier policy. Shipped defaults are
    15 code points minimum for a sole-factor password and 8 for one factor of MFA, a
    64-code-point maximum, no composition rules, no forced rotation, and mandatory
    screening. `normalize_nfkc` applies NFKC once before length counting, screening, and
    hashing; length is counted in code points. Legacy overrides (composition, rotation,
    different lengths) are settings, each reported by `PasswordPolicy::nist_deviations` as
    a documented deviation for an admin surface to render.
  - No wall-clock, monotonic, or randomness use, so nothing routes through the
    `ironauth-env` seam; the only outbound path is `ironauth-fetch`.
