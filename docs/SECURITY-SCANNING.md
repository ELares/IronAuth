# Security scanning

IronAuth checks source code, dependencies, and repository practices separately.
A green scan is evidence for its configured checks, not a promise that every
vulnerability or operating risk has been eliminated. Report suspected new
vulnerabilities through the [private reporting channel](../SECURITY.md).

## Automated checks

| Check | Coverage and trigger | Limits |
| --- | --- | --- |
| CodeQL | JavaScript/TypeScript, Python, Go, Rust, and GitHub Actions; every PR, every main push, a weekly schedule, and manual runs. The workflow uses `security-extended` queries and uploads a separate result category per language. | Only completed extraction and analysis runs provide results. CodeQL does not cover every language or prove application behavior. |
| Dependency Review | Every PR; fails on newly introduced moderate or higher vulnerabilities in runtime, development, and unknown scopes. | Uses GitHub's dependency graph and advisory coverage. It compares changes rather than auditing every pre-existing dependency. |
| OpenSSF Scorecard | Main pushes and scheduled runs; uploads repository-practice findings to code scanning. | Some checks measure historical reviews, CI, age, or external enrollment rather than current source defects. |
| Cargo deny | The local gate and CI check Rust advisories, licenses, bans, and approved sources using `deny.toml`. | Three narrowly documented advisory exceptions remain below. |
| Fuzzing and behavioral tests | CI compiles registered fuzz targets; the local gate exercises parser, isolation, authentication, and invariant tests. | Each target and suite has a defined input surface. A passing run is not exhaustive. |

The workflow files in [.github/workflows](../.github/workflows/) are authoritative
for triggers, permissions, and query settings. CodeQL scans documentation-only
changes too, so its coverage does not depend on a path filter. Main analyses
retain separate runs rather than cancelling a prior commit's scan.

Repository settings must enable the dependency graph and Dependabot alerts for
dependency review to use the comparison API. Dependabot security updates propose
patches; they still need validation against the repository's compatibility and
license promises. Private vulnerability reporting is a separate setting and
must remain enabled for the link in `SECURITY.md` to work.

## Reproducible inputs

Workflow actions use full commit hashes with readable version comments. Verify
the upstream commit and action inputs when updating a pin; changing a comment
does not update the action. Dependabot tracks action updates. The Rust 1.85
action pin installs 1.85.1, preserving the published compatibility floor.

Node projects use committed lockfiles and `npm ci`. The TypeScript hook sample
and integration fixture are built from the same checked-in source; no generated
WASM component is committed. The full gate and CI build it before testing. For
a direct integration run:

```sh
scripts/build-ts-hook-fixture.sh
cargo test --locked -p ironauth-hooks --test typescript_hook --release
```

This preparation needs Node and npm. Ordinary Rust builds do not invoke Node,
fetch npm packages, or require the generated test component. The
[sample guide](../crates/ironauth-hooks/guests-ts/README.md) describes the locked
builder, sandbox assertions, and size bounds. `scripts/ts-hook-freshness.sh`
builds a temporary component and tests the actual loader override and behavior.

Discovery, token, and capture JSON in the development scripts is downloaded to
temporary files and parsed by fixed local Python code. Remote responses are
data, not downloaded executable programs. Keep that distinction when modifying
these scripts.

## Reviewed Rust dependency exceptions

The following entries already existed in `deny.toml`. The security remediation
updates their explanations rather than adding a broad ignore. They are not
patched dependencies. Re-check consumer source and the complete dependency
graph whenever a relevant dependency or feature changes.

| Advisory | Dependency and actual use | Remaining constraint and next action |
| --- | --- | --- |
| [RUSTSEC-2024-0436](https://rustsec.org/advisories/RUSTSEC-2024-0436.html) | `paste` is an unmaintained compile-time macro reached through `cel` 0.11.6; it contributes no runtime code. | CEL versions that remove it require Rust 1.86 in practice or by declaration. Upgrade CEL and remove the exception when the default MSRV is raised to at least 1.86. |
| [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html) | `rsa` generates and exports a key in `ironauth-jose`, and verifies public-key signatures in the Fastly snippet. Neither consumer performs private-key decryption or signs with this crate; the Marvin decryption path is unreachable. | No fixed upstream release is available. Any new private-key decryption or signing use invalidates the justification and requires a fresh review before shipping. |
| [RUSTSEC-2026-0009](https://rustsec.org/advisories/RUSTSEC-2026-0009.html) | `time` 0.3.41 ships through LDAP X.509 parsing and also reaches test code through `rcgen`. Its parsing feature is compiled, but consumers construct ASN.1 dates or format RFC 2822 output; none calls the vulnerable RFC 2822 input parser. | The fix in 0.3.47 requires Rust 1.88, above the default Rust 1.85 promise. Upgrade and remove the exception when that promise changes; any new RFC 2822 parsing invalidates the current justification. |

Do not describe `time` as test-only, absent from the binary, or fixed. Its
exception relies on current call paths. Likewise, the `rsa` exception must
account for the Fastly verifier, not just server key generation.

Useful review commands include:

```sh
cargo tree -i time --all-features
cargo tree -i rsa --all-features
cargo tree -i paste --all-features
cargo deny check
```

Follow these with a source review of every consumer. A dependency tree alone
cannot establish whether an affected function is called. An independent OSV
scan can still report these entries even when Cargo deny accepts the reviewed
exceptions; preserve that visibility rather than suppressing future findings.

## Investigating Scorecard findings

Read the rule's evidence and scan commit before editing or dismissing an alert.
The [Scorecard check definitions](https://github.com/ossf/scorecard/blob/main/docs/checks.md)
explain the measurements. A fresh main scan is required to verify a remediation
landed; a PR scan alone does not update main's findings.

- **Pinned dependencies, binary artifacts, security policy:** fix the current
  source or policy and re-scan. Keep generated test artifacts out of Git.
- **Vulnerabilities:** independently audit all relevant lockfiles and review
  every residual advisory. An aggregate finding can contain aliases for the
  same defect. Do not treat a raw identifier count as a count of distinct bugs.
- **SAST and CI tests:** verify actual completed analyses and test checks on
  merged commits. Historical windows can remain below their maximum immediately
  after enabling a workflow; do not rewrite history to manufacture coverage.
- **Code review:** human-authored changes require independent review. A self
  review or an admin override does not constitute independent approval, and
  existing branch protection cannot repair historical review records.
- **Maintained:** Scorecard also considers repository age. This repository was
  created on July 12, 2026 and reaches 90 days on October 10, 2026. Keep actual
  maintenance evidence and reassess after the age threshold; do not fabricate it.
- **OpenSSF Best Practices:** a badge requires genuine enrollment and a truthful
  assessment at [bestpractices.dev](https://www.bestpractices.dev/). Adding a badge
  image or declaring an invented project ID does not satisfy the check.

Dismiss only a finding that has a defensible recorded disposition. Include the
actual reason, evidence, scan commit, and follow-up condition. Accepted risk is
different from a false positive or a patched issue. Do not disable a scanner or
weaken its query set just to clear the dashboard.
