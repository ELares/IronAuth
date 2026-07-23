// SPDX-License-Identifier: MIT OR Apache-2.0

//! The token-signing compatibility interop table and its recommendation engine
//! (issue #93, Bet 2).
//!
//! The compatibility wizard recommends a per-client ID-token signing algorithm
//! based on what will VERIFY the tokens downstream (an API gateway, a serverless
//! runtime, a framework's JWT stack). Some widely deployed verifiers cannot verify
//! `EdDSA` (IronAuth's default), so pinning it there would silently break token
//! verification; the wizard steers those clients to the widely supported `RS256` or
//! `ES256` instead.
//!
//! This module is the SINGLE, unit-tested source of truth for that table. Every
//! `recommended` and every `supported` entry stays within the three algorithms every
//! IronAuth environment provisions in its JWKS (`EdDSA`, `ES256`, `RS256`), so a
//! recommendation is always one the environment can actually sign with. It is PURE:
//! a total lookup over the [`Verifier`] enum, no I/O. Each row carries a `// citation:`
//! comment naming the interop source it is drawn from.

use ironauth_jose::JwsAlgorithm;

/// A downstream token verifier the compatibility wizard knows the interop posture of.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verifier {
    /// AWS API Gateway JWT authorizers (HTTP API).
    AwsApiGateway,
    /// Cloudflare Workers verifying a JWT with the `WebCrypto` `SubtleCrypto` API.
    CloudflareWorkers,
    /// Azure API Management's `validate-jwt` policy.
    AzureApim,
    /// The .NET `Microsoft.IdentityModel` JWT stack.
    DotNet,
    /// Spring Security's resource server, backed by Nimbus JOSE + JWT.
    SpringSecurity,
    /// The Envoy proxy `jwt_authn` HTTP filter.
    Envoy,
    /// A modern, fully specified JOSE library (for example panva `jose`, `jose4j`).
    ModernJose,
}

impl Verifier {
    /// Every verifier, in the table's presentation order. Used to iterate the matrix
    /// and to prove the recommendation function is total over the enum.
    pub const ALL: [Verifier; 7] = [
        Verifier::AwsApiGateway,
        Verifier::CloudflareWorkers,
        Verifier::AzureApim,
        Verifier::DotNet,
        Verifier::SpringSecurity,
        Verifier::Envoy,
        Verifier::ModernJose,
    ];

    /// The stable, machine-readable wire identifier for this verifier (the value the
    /// management API and the SPA key on).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Verifier::AwsApiGateway => "aws_api_gateway",
            Verifier::CloudflareWorkers => "cloudflare_workers",
            Verifier::AzureApim => "azure_apim",
            Verifier::DotNet => "dotnet",
            Verifier::SpringSecurity => "spring_security",
            Verifier::Envoy => "envoy",
            Verifier::ModernJose => "modern_jose",
        }
    }
}

/// One row of the interop table: the verifier, its human label, the algorithms it can
/// verify (always a subset of `{EdDSA, ES256, RS256}`), the recommended choice, the
/// supported minus recommended alternatives, and the one-line reason shown to the
/// operator.
pub struct InteropCell {
    verifier: Verifier,
    label: &'static str,
    supported: &'static [JwsAlgorithm],
    recommended: JwsAlgorithm,
    alternatives: &'static [JwsAlgorithm],
    reason: &'static str,
}

impl InteropCell {
    /// The human-readable label.
    #[must_use]
    pub fn label(&self) -> &'static str {
        self.label
    }

    /// The algorithms this verifier can verify (a subset of `{EdDSA, ES256, RS256}`).
    #[must_use]
    pub fn supported(&self) -> &'static [JwsAlgorithm] {
        self.supported
    }
}

/// The interop table: one exhaustive row per [`Verifier`]. The single source of truth
/// the management API surfaces and the recommendation engine reads.
const MATRIX: &[InteropCell] = &[
    // citation: AWS API Gateway HTTP API JWT authorizer documentation (a JWT authorizer
    // validates against the issuer JWKS; RS256 is the interoperable default and EdDSA is
    // not among the accepted signature algorithms).
    InteropCell {
        verifier: Verifier::AwsApiGateway,
        label: "AWS API Gateway JWT authorizers",
        supported: &[JwsAlgorithm::Rs256],
        recommended: JwsAlgorithm::Rs256,
        alternatives: &[],
        reason: "AWS API Gateway JWT authorizers verify RS256, not EdDSA",
    },
    // citation: Cloudflare Workers Web Crypto (SubtleCrypto) documentation: recent Workers
    // runtimes verify Ed25519 in addition to RSASSA PKCS1 v1_5, RSA PSS, and ECDSA. RS256
    // stays the conservative default because it is the most broadly compatible across
    // runtime versions and downstream tooling.
    InteropCell {
        verifier: Verifier::CloudflareWorkers,
        label: "Cloudflare Workers WebCrypto",
        supported: &[
            JwsAlgorithm::EdDsa,
            JwsAlgorithm::Es256,
            JwsAlgorithm::Rs256,
        ],
        recommended: JwsAlgorithm::Rs256,
        alternatives: &[JwsAlgorithm::EdDsa, JwsAlgorithm::Es256],
        reason: "Cloudflare Workers WebCrypto verifies Ed25519 on recent runtimes as well as \
                 RSA and ECDSA; RS256 stays the broadly compatible default",
    },
    // citation: Azure API Management validate jwt policy, backed by Microsoft.IdentityModel:
    // it validates RSA and ECDSA signed tokens; EdDSA (Ed25519) is not a supported signature
    // algorithm.
    InteropCell {
        verifier: Verifier::AzureApim,
        label: "Azure API Management validate jwt",
        supported: &[JwsAlgorithm::Rs256, JwsAlgorithm::Es256],
        recommended: JwsAlgorithm::Rs256,
        alternatives: &[JwsAlgorithm::Es256],
        reason: "Azure API Management validate jwt verifies RSA and ECDSA, not EdDSA",
    },
    // citation: Microsoft.IdentityModel.Tokens (System.IdentityModel.Tokens.Jwt): the .NET
    // JWT stack verifies RSA and ECDSA; there is no built in Ed25519 JWS verifier.
    InteropCell {
        verifier: Verifier::DotNet,
        label: ".NET Microsoft IdentityModel JWT",
        supported: &[JwsAlgorithm::Rs256, JwsAlgorithm::Es256],
        recommended: JwsAlgorithm::Rs256,
        alternatives: &[JwsAlgorithm::Es256],
        reason: "the .NET Microsoft IdentityModel JWT stack verifies RSA and ECDSA, not EdDSA",
    },
    // citation: Nimbus JOSE + JWT (com.nimbusds), the JWT engine under Spring Security: it
    // has long verified ES256 and RS256; Ed25519 (via Tink) arrived only in recent versions,
    // so ES256 is the safe modern default and RS256 the universal fallback.
    InteropCell {
        verifier: Verifier::SpringSecurity,
        label: "Spring Security with Nimbus JOSE",
        supported: &[JwsAlgorithm::Es256, JwsAlgorithm::Rs256],
        recommended: JwsAlgorithm::Es256,
        alternatives: &[JwsAlgorithm::Rs256],
        reason: "Spring Security with Nimbus JOSE verifies ES256 and RS256; Ed25519 arrived \
                 only in recent versions",
    },
    // citation: Envoy jwt_authn HTTP filter documentation: the supported algorithms are
    // RS256/384/512, ES256/384/512, PS256/384/512, and HS256/384/512; EdDSA is not supported.
    InteropCell {
        verifier: Verifier::Envoy,
        label: "Envoy jwt_authn filter",
        supported: &[JwsAlgorithm::Rs256, JwsAlgorithm::Es256],
        recommended: JwsAlgorithm::Rs256,
        alternatives: &[JwsAlgorithm::Es256],
        reason: "the Envoy jwt_authn filter verifies RSA and ECDSA, not EdDSA",
    },
    // citation: RFC 8037 (CFRG EdDSA in JOSE) and modern fully specified JOSE libraries
    // (panva jose, jose4j): they verify Ed25519, whose signatures and keys are far smaller
    // and faster to verify than RSA.
    InteropCell {
        verifier: Verifier::ModernJose,
        label: "modern JOSE libraries",
        supported: &[
            JwsAlgorithm::EdDsa,
            JwsAlgorithm::Es256,
            JwsAlgorithm::Rs256,
        ],
        recommended: JwsAlgorithm::EdDsa,
        alternatives: &[JwsAlgorithm::Es256, JwsAlgorithm::Rs256],
        reason: "modern JOSE libraries verify Ed25519; smaller and faster than RSA",
    },
];

/// The interop-table row for `verifier` (its label and supported set). Pairs with
/// [`recommend`] to build the management API's per-verifier view.
///
/// A pure, total lookup into [`MATRIX`]: every [`Verifier`] has exactly one row, so this
/// never fails.
#[must_use]
pub fn cell(verifier: Verifier) -> &'static InteropCell {
    MATRIX
        .iter()
        .find(|cell| cell.verifier == verifier)
        .expect("MATRIX has one row per Verifier")
}

/// A signing-algorithm recommendation for one verifier: the recommended algorithm, the
/// one-line reason, and the supported minus recommended alternatives.
pub struct SigningRecommendation {
    /// The recommended algorithm.
    pub recommended: JwsAlgorithm,
    /// The one-line, operator-facing reason.
    pub reason: &'static str,
    /// The supported minus recommended alternatives (a subset of the wizard set).
    pub alternatives: &'static [JwsAlgorithm],
}

/// The signing-algorithm recommendation for `verifier`.
///
/// A pure, total lookup into [`MATRIX`]: every [`Verifier`] has exactly one row, so this
/// never fails. The returned `recommended` is always within `{EdDSA, ES256, RS256}`, so
/// the wizard only ever proposes an algorithm the environment provisions.
#[must_use]
pub fn recommend(verifier: Verifier) -> SigningRecommendation {
    // Total by construction: MATRIX has one row per Verifier (proven by
    // `matrix_is_exhaustive_and_within_the_wizard_set`), so the lookup always resolves.
    let cell = MATRIX
        .iter()
        .find(|cell| cell.verifier == verifier)
        .expect("MATRIX has one row per Verifier");
    SigningRecommendation {
        recommended: cell.recommended,
        reason: cell.reason,
        alternatives: cell.alternatives,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_api_gateway_recommends_rs256_with_the_pinned_reason() {
        // Pinned acceptance criterion: AWS API Gateway JWT authorizers cannot verify
        // EdDSA, so the wizard steers to RS256 with this exact reason.
        let rec = recommend(Verifier::AwsApiGateway);
        assert_eq!(rec.recommended, JwsAlgorithm::Rs256);
        assert_eq!(
            rec.reason,
            "AWS API Gateway JWT authorizers verify RS256, not EdDSA"
        );
    }

    #[test]
    fn modern_jose_recommends_eddsa_with_the_pinned_reason() {
        // Pinned acceptance criterion: a modern JOSE library verifies Ed25519, so the
        // wizard recommends EdDSA with this exact reason.
        let rec = recommend(Verifier::ModernJose);
        assert_eq!(rec.recommended, JwsAlgorithm::EdDsa);
        assert_eq!(
            rec.reason,
            "modern JOSE libraries verify Ed25519; smaller and faster than RSA"
        );
    }

    #[test]
    fn matrix_is_exhaustive_and_within_the_wizard_set() {
        // The three algorithms every environment provisions in its JWKS; every cell must
        // stay within this set so a recommendation is always signable.
        const WIZARD_ALGS: [JwsAlgorithm; 3] = [
            JwsAlgorithm::EdDsa,
            JwsAlgorithm::Es256,
            JwsAlgorithm::Rs256,
        ];
        // One row per verifier, no duplicates: the recommendation lookup is total.
        assert_eq!(
            MATRIX.len(),
            Verifier::ALL.len(),
            "one MATRIX row per Verifier"
        );
        for verifier in Verifier::ALL {
            let rows = MATRIX.iter().filter(|c| c.verifier == verifier).count();
            assert_eq!(rows, 1, "exactly one row for {verifier:?}");
        }

        for cell in MATRIX {
            // Every supported entry is within the three provisioned algorithms.
            for alg in cell.supported {
                assert!(
                    WIZARD_ALGS.contains(alg),
                    "{:?}: supported {alg:?} is outside the wizard set",
                    cell.verifier
                );
            }
            // The recommendation is itself one of the supported algorithms.
            assert!(
                cell.supported.contains(&cell.recommended),
                "{:?}: recommended {:?} is not in supported",
                cell.verifier,
                cell.recommended
            );
            // The recommendation is within the wizard set (so it is always signable).
            assert!(
                WIZARD_ALGS.contains(&cell.recommended),
                "{:?}: recommended {:?} is outside the wizard set",
                cell.verifier,
                cell.recommended
            );
            // alternatives == supported minus recommended (order preserved).
            let expected: Vec<JwsAlgorithm> = cell
                .supported
                .iter()
                .copied()
                .filter(|alg| *alg != cell.recommended)
                .collect();
            assert_eq!(
                cell.alternatives,
                expected.as_slice(),
                "{:?}: alternatives must equal supported minus recommended",
                cell.verifier
            );
            // `recommend` returns exactly the cell's own recommendation and alternatives.
            let rec = recommend(cell.verifier);
            assert_eq!(rec.recommended, cell.recommended);
            assert_eq!(rec.alternatives, cell.alternatives);
            assert_eq!(rec.reason, cell.reason);
        }
    }

    #[test]
    fn verifier_wire_ids_are_stable_and_distinct() {
        let mut ids: Vec<&str> = Verifier::ALL.iter().map(|v| v.as_str()).collect();
        ids.sort_unstable();
        let count = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), count, "verifier wire ids must be distinct");
    }
}
