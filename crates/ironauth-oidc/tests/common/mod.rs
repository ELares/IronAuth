// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared harness for the OIDC provider integration tests.
//!
//! Brings up a real database (via the ironauth-store test harness), seeds a
//! `(tenant, environment)` scope with one OAuth client, provisions an Ed25519
//! signing key for the environment, builds the OIDC router over a data-plane
//! store, and drives requests through it. Not every helper is used by every test
//! binary, so dead code is allowed here.
#![allow(dead_code)]

use std::sync::Arc;
use std::time::SystemTime;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use http_body_util::BodyExt;
use ironauth_config::{OidcConfig, QuotaConfig};
use ironauth_env::{Env, ManualClock};
use ironauth_jose::{
    EmissionOptions, JwsAlgorithm, KeySet, SigningKey, SigningPolicy, TrustedKey,
    VerificationPolicy, sign_jws_with_policy,
};
use ironauth_oidc::{
    ClientAuthMethod, ClientKeyResolver, DiscoveryCapabilities, DiscoveryState, IssuerEntry,
    IssuerRegistry, IssuerState, JwksCacheWindow, OidcState, PairwiseSalt, SESSION_COOKIE,
    discovery_router, issuer_router, oidc_router,
};
use ironauth_quota::QuotaEnforcer;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    AssertionMappingId, ClientId, CorrelationId, ExternalIssuerId, InitialAccessTokenId,
    NewAssertionSubjectMapping, NewExternalAssertionIssuer, NewInitialAccessToken,
    NewJwtAuthClient, NewSigningKey, Scope, SessionId, SigningKeyId, SigningKeyMaterialKind, Store,
};
use tower::ServiceExt;

/// The RFC 7636 Appendix B PKCE verifier and its S256 challenge.
pub const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// The S256 challenge for [`PKCE_VERIFIER`].
pub const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
/// A syntactically valid redirect URI the tests bind codes to.
pub const REDIRECT_URI: &str = "https://client.test/cb";
/// The issuer base the harness configures.
pub const ISSUER_BASE: &str = "https://issuer.test";
/// A far-future expiry (year 2100) in epoch microseconds, so a seeded session
/// survives the clock advances the expiry and reuse tests perform.
pub const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;
/// The password the seeded harness users are created with.
pub const SEED_PASSWORD: &str = "correct horse battery staple";
/// The broad standard-OIDC scope the generic [`Harness::grant_consent`] shortcut
/// records the consent against. Scope-aware consent (issue #196) only issues a code
/// when the REQUESTED scope is a subset of the recorded granted scope, so the
/// shortcut grants every standard scope a test might request; the mint still binds
/// the REQUESTED scope, so a broad recorded consent is invisible to the claim and
/// `UserInfo` assertions.
pub const CONSENTED_SCOPE: &str = "openid profile email address phone";

/// A committed throwaway ECDSA P-256 PKCS#8 key, for provisioning an ES256-only
/// environment (AC #3). Generated offline by ring's `generate_pkcs8`, exactly like
/// the ironauth-jose signing fixtures; secret only in the technical sense.
const ES256_PKCS8: &[u8] = &[
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02,
    0x01, 0x01, 0x04, 0x20, 0xfc, 0x76, 0xdf, 0x7c, 0x3d, 0x9f, 0xef, 0x33, 0x39, 0x20, 0x6f, 0x02,
    0xe9, 0xec, 0xb3, 0x30, 0x0b, 0xcd, 0x3b, 0x01, 0xf4, 0x09, 0x91, 0x10, 0x23, 0x75, 0x80, 0xd2,
    0xda, 0x1b, 0x3e, 0xf9, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x85, 0xd1, 0x32, 0xad, 0x68, 0xc7,
    0x5b, 0x7e, 0xd4, 0x5c, 0x7e, 0xef, 0x46, 0x5e, 0x98, 0xa3, 0x30, 0xb6, 0x71, 0x4b, 0x9a, 0xfb,
    0x29, 0xc9, 0xbd, 0xdf, 0xaa, 0x2a, 0xe6, 0xf8, 0xdf, 0x63, 0xc4, 0x97, 0x49, 0x4b, 0x76, 0xcc,
    0x05, 0xbe, 0xdc, 0x5f, 0xb9, 0xb8, 0xe7, 0x1c, 0x9c, 0x86, 0x4e, 0x47, 0xde, 0x6f, 0xf4, 0x08,
    0xf2, 0x34, 0x12, 0x9d, 0xb0, 0x02, 0x94, 0xe0, 0xc7, 0x4d,
];

/// A committed throwaway RSA-2048 PKCS#1 private key (DER), for provisioning an
/// environment that can sign RS256 alongside `EdDSA` (issue #30 negotiation and
/// honor-at-mint). Generated offline exactly like the other committed fixtures;
/// secret only in the technical sense.
const RSA_PKCS1: &[u8] = &[
    0x30, 0x82, 0x04, 0xa4, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xb8, 0x89, 0x93, 0x9f,
    0x7b, 0x50, 0x6b, 0xa9, 0x8b, 0x12, 0x85, 0xf4, 0xf8, 0x14, 0xc5, 0x14, 0xef, 0x86, 0xf0, 0x05,
    0x7f, 0x2e, 0x63, 0x3c, 0xe6, 0x9e, 0x55, 0xc1, 0x00, 0x90, 0xd5, 0xe9, 0xbf, 0x71, 0x9e, 0x23,
    0xda, 0xda, 0xfe, 0x42, 0x65, 0x8d, 0x81, 0x5f, 0xce, 0xb8, 0x8e, 0xcd, 0x94, 0x11, 0x35, 0xd8,
    0x36, 0x4b, 0xd0, 0x8f, 0x83, 0x71, 0xf3, 0x47, 0xfb, 0xd2, 0xd4, 0x73, 0x44, 0x9d, 0xc6, 0x84,
    0xc9, 0x7e, 0xa4, 0xab, 0xb5, 0x15, 0xc0, 0xa1, 0xaa, 0x1a, 0xa7, 0xc8, 0xd8, 0xe8, 0x3d, 0x11,
    0xae, 0x9d, 0x5a, 0x04, 0xd1, 0x3d, 0x35, 0x91, 0x93, 0x53, 0xbd, 0x69, 0x71, 0x07, 0x32, 0xc6,
    0x8f, 0xf6, 0x50, 0xa2, 0x70, 0x28, 0xbd, 0xcd, 0xc2, 0x3e, 0xd0, 0x94, 0x70, 0x59, 0x1c, 0x22,
    0xec, 0x21, 0x9d, 0x41, 0x99, 0x28, 0xc5, 0x3b, 0xcb, 0xa9, 0xfb, 0xef, 0x90, 0xa0, 0x42, 0x07,
    0x2d, 0x02, 0x77, 0x90, 0xba, 0x16, 0xc5, 0xdc, 0xf1, 0xa7, 0x94, 0xe3, 0xa5, 0xcb, 0x7d, 0x2d,
    0x3f, 0x54, 0x02, 0x93, 0xa9, 0x81, 0xd1, 0x20, 0xd1, 0xd5, 0x72, 0x83, 0x8f, 0x43, 0x47, 0xe4,
    0x18, 0x29, 0xab, 0x01, 0x66, 0x2f, 0x98, 0xf9, 0x90, 0x91, 0x60, 0xf5, 0x35, 0x7b, 0xbc, 0x3c,
    0xd4, 0x4b, 0x35, 0xe9, 0x27, 0x36, 0x40, 0x8b, 0xec, 0xc5, 0x41, 0xb5, 0xf0, 0x8c, 0x54, 0x47,
    0x48, 0xa0, 0xb2, 0x36, 0xd3, 0xc1, 0xa9, 0xbc, 0xf0, 0xf3, 0x71, 0x9f, 0x42, 0x2a, 0x3f, 0x48,
    0x2a, 0xc5, 0xde, 0x03, 0x17, 0x0c, 0xb5, 0xd2, 0xd2, 0x2e, 0x77, 0xad, 0x1f, 0xc6, 0x29, 0x3c,
    0x55, 0x81, 0x26, 0xa0, 0x8c, 0x98, 0xcd, 0x40, 0xaa, 0xe6, 0x62, 0x2c, 0x1e, 0x94, 0xb0, 0x99,
    0x74, 0x78, 0x77, 0xdc, 0x56, 0xde, 0xe0, 0xcf, 0xa2, 0xd0, 0xf5, 0x8d, 0x02, 0x03, 0x01, 0x00,
    0x01, 0x02, 0x82, 0x01, 0x00, 0x33, 0x20, 0x42, 0x9b, 0x03, 0xc2, 0x23, 0x21, 0xe4, 0xda, 0xeb,
    0xec, 0x13, 0xb3, 0x45, 0x6a, 0xe8, 0x75, 0xbd, 0x17, 0xf8, 0xc5, 0x74, 0x4f, 0x12, 0x21, 0xb9,
    0xe6, 0x6f, 0xee, 0xb0, 0xa5, 0x43, 0x1a, 0x0a, 0x53, 0x2a, 0xb6, 0x53, 0x8d, 0x37, 0xaf, 0x7d,
    0xb1, 0x7a, 0x87, 0x5d, 0x61, 0x0d, 0x6d, 0xbb, 0x3a, 0x3c, 0xc8, 0xc2, 0x6e, 0x90, 0x5f, 0x48,
    0xa4, 0x9f, 0xdb, 0x28, 0x6b, 0x0b, 0x0e, 0x9f, 0x4a, 0x78, 0xbc, 0xb2, 0x88, 0xb3, 0xf1, 0xe3,
    0xdd, 0xa6, 0x50, 0x1e, 0x3e, 0x22, 0x02, 0x2d, 0xb1, 0x31, 0x6c, 0x7c, 0xdd, 0x2a, 0xcf, 0x47,
    0x81, 0x1e, 0x8d, 0x2b, 0xc4, 0x03, 0xc1, 0x97, 0xca, 0xb5, 0x65, 0xeb, 0xaf, 0x25, 0x5d, 0xd4,
    0x40, 0x26, 0x59, 0xda, 0xd5, 0xd5, 0x4e, 0x8a, 0xe2, 0x0e, 0x03, 0xbe, 0x1a, 0xc7, 0x81, 0x29,
    0x2b, 0xc8, 0xe0, 0x3e, 0x61, 0x06, 0xac, 0x41, 0x3b, 0x5b, 0x72, 0x74, 0xca, 0xb2, 0x1b, 0xdb,
    0x6e, 0x98, 0x2e, 0xfd, 0x5d, 0x77, 0x0e, 0x8e, 0x49, 0x1b, 0x7a, 0xde, 0xb8, 0xfa, 0xd1, 0x1f,
    0x6f, 0xe1, 0x29, 0x29, 0x70, 0x1d, 0xde, 0x89, 0x86, 0x9d, 0x78, 0xee, 0x1e, 0x14, 0xed, 0xf3,
    0x2b, 0x40, 0x02, 0x29, 0xc2, 0x02, 0xd5, 0xc4, 0xc9, 0x53, 0xf2, 0x85, 0x12, 0x96, 0x26, 0xca,
    0xb6, 0xb8, 0xe7, 0x6a, 0x37, 0xbe, 0x41, 0xf1, 0x73, 0xe6, 0x2e, 0x51, 0x0b, 0x78, 0x64, 0x3b,
    0x7a, 0x29, 0x2a, 0x60, 0x9a, 0xd4, 0xfa, 0x05, 0x3d, 0x12, 0xc1, 0x70, 0x93, 0x36, 0x7e, 0x69,
    0x39, 0xea, 0xf5, 0x1f, 0x6d, 0x54, 0x97, 0x80, 0x05, 0xfa, 0xf8, 0x30, 0x16, 0xa1, 0x9e, 0xab,
    0x9f, 0x50, 0xcc, 0x0e, 0x17, 0x10, 0xac, 0x85, 0x9d, 0xe9, 0xaa, 0xfd, 0xe9, 0x77, 0xab, 0xe0,
    0xbd, 0xcf, 0x9c, 0x74, 0xc1, 0x02, 0x81, 0x81, 0x00, 0xf4, 0xa2, 0x71, 0x60, 0xfa, 0x9e, 0xce,
    0x3c, 0x97, 0x66, 0x01, 0xbd, 0x31, 0xf4, 0x36, 0xe3, 0x22, 0x16, 0x7b, 0xc5, 0x0b, 0x5e, 0x83,
    0x40, 0xdc, 0x77, 0xb3, 0x57, 0x5d, 0x15, 0x5a, 0x79, 0x25, 0x1b, 0x6d, 0x6e, 0xb2, 0xe3, 0x33,
    0xb1, 0xad, 0xa0, 0xfa, 0xde, 0x21, 0xa6, 0x20, 0x3c, 0x05, 0x4c, 0x2b, 0x68, 0xec, 0xe9, 0xd0,
    0x22, 0x08, 0x8a, 0x46, 0x62, 0x54, 0x7a, 0x85, 0x42, 0x5e, 0x3b, 0x44, 0x99, 0xab, 0xe7, 0xea,
    0xfe, 0x1b, 0xa7, 0x6f, 0xc7, 0xb7, 0x0d, 0xa0, 0xf8, 0xb1, 0x15, 0x77, 0xa3, 0xbe, 0x21, 0x06,
    0xf8, 0xb2, 0xb8, 0xe8, 0x85, 0x28, 0x57, 0x04, 0x0a, 0x0d, 0x63, 0xe5, 0xbd, 0x49, 0xcb, 0x9f,
    0x1e, 0xa1, 0x00, 0x28, 0x8f, 0x18, 0x32, 0x05, 0x78, 0x91, 0xad, 0x80, 0x3a, 0x1e, 0x2b, 0xff,
    0x6e, 0x25, 0xb0, 0x6a, 0x97, 0x81, 0xdd, 0xd6, 0xbd, 0x02, 0x81, 0x81, 0x00, 0xc1, 0x1c, 0x5e,
    0x93, 0xe2, 0xed, 0xb7, 0xc7, 0x3a, 0xa3, 0x27, 0x18, 0x27, 0x9e, 0x32, 0x4d, 0x52, 0x3b, 0x85,
    0x85, 0x8f, 0x97, 0x1d, 0x39, 0x17, 0x24, 0xc9, 0xde, 0x42, 0x13, 0xbc, 0x7d, 0x87, 0xda, 0x83,
    0x6f, 0x96, 0x34, 0xbf, 0xc4, 0x6b, 0x72, 0xa8, 0x4c, 0x50, 0x17, 0x99, 0x26, 0xc2, 0x5b, 0x14,
    0xd2, 0xd2, 0x6a, 0xc2, 0x5a, 0x19, 0xed, 0xd9, 0xcc, 0x26, 0x85, 0xef, 0xe9, 0x55, 0xf9, 0xee,
    0x96, 0xe7, 0x4a, 0x27, 0x00, 0x30, 0x6a, 0x5e, 0x4c, 0xdb, 0xa6, 0x98, 0xe6, 0x37, 0x74, 0x50,
    0x34, 0xcc, 0xfd, 0xac, 0xb8, 0x34, 0xd8, 0xad, 0x5d, 0x2b, 0x86, 0xa1, 0x20, 0xfd, 0xed, 0xa0,
    0x43, 0x35, 0x69, 0x8c, 0x34, 0x81, 0x65, 0x80, 0x80, 0x46, 0xb4, 0x52, 0x47, 0xc3, 0xd6, 0xed,
    0xad, 0x46, 0x12, 0x63, 0x30, 0xc4, 0x7f, 0xe8, 0x45, 0xbe, 0x5d, 0x2f, 0x11, 0x02, 0x81, 0x81,
    0x00, 0xd0, 0x10, 0x89, 0x55, 0xee, 0x52, 0xbb, 0x1e, 0x15, 0xb6, 0x90, 0xac, 0x15, 0x9c, 0x9c,
    0x42, 0x3a, 0x6f, 0xdc, 0xfd, 0x0e, 0x5a, 0x68, 0x4f, 0xf6, 0x33, 0x68, 0xb9, 0x59, 0x56, 0x1c,
    0x09, 0x05, 0x62, 0x7a, 0x84, 0xb8, 0x69, 0x3d, 0x42, 0x55, 0x66, 0xa1, 0x77, 0xe4, 0x2e, 0xa3,
    0x23, 0xe9, 0x6d, 0x8b, 0x4e, 0x46, 0x91, 0xe6, 0x8f, 0xcb, 0xab, 0xaf, 0x89, 0x5a, 0x48, 0x8a,
    0xa6, 0x93, 0xf6, 0xdc, 0xb5, 0xc6, 0xdc, 0x0d, 0xa5, 0xea, 0x67, 0x52, 0x4f, 0x0e, 0x85, 0xec,
    0xef, 0x17, 0xce, 0x26, 0x5f, 0x82, 0x0a, 0x1d, 0x1f, 0xd1, 0x02, 0x2b, 0xe1, 0x75, 0x19, 0xed,
    0x39, 0x8f, 0x81, 0xf3, 0x98, 0x36, 0xf7, 0x94, 0x72, 0x3c, 0x85, 0x21, 0xf9, 0xf2, 0x9e, 0x38,
    0xc0, 0xff, 0x46, 0x0d, 0xd5, 0x60, 0x6c, 0x13, 0x67, 0xdf, 0x6e, 0x58, 0x7a, 0x5b, 0xde, 0x0e,
    0x11, 0x02, 0x81, 0x80, 0x54, 0xbe, 0x76, 0x62, 0xbf, 0xbb, 0x42, 0x63, 0x13, 0xc0, 0x75, 0x6f,
    0x8c, 0x33, 0x48, 0x2f, 0xd6, 0x5e, 0x78, 0x81, 0xdc, 0x39, 0x9c, 0x81, 0x69, 0x3e, 0xa3, 0xb7,
    0xfd, 0x97, 0x5b, 0xa8, 0x5a, 0xed, 0xf1, 0xb0, 0x0e, 0x62, 0xa7, 0xa5, 0x32, 0xe1, 0xe6, 0x29,
    0x57, 0x1c, 0x84, 0x01, 0x16, 0x59, 0x92, 0x11, 0xd2, 0x75, 0x37, 0x45, 0x03, 0x0b, 0xf6, 0x00,
    0x39, 0x07, 0x9d, 0xf8, 0xef, 0xd9, 0xf6, 0x72, 0x12, 0x9d, 0xdf, 0xef, 0x9d, 0x4f, 0x90, 0x82,
    0x7a, 0x01, 0xea, 0x27, 0x5d, 0x3e, 0x95, 0xd4, 0x16, 0x01, 0x5c, 0xc2, 0x99, 0xae, 0x5c, 0xa5,
    0xfe, 0x6b, 0xde, 0x59, 0xf4, 0x15, 0x4b, 0xb7, 0x32, 0xc1, 0x56, 0xdd, 0xd3, 0xcb, 0x0f, 0x51,
    0x3b, 0xb5, 0xf6, 0x45, 0xb8, 0x13, 0xa1, 0xc9, 0xe0, 0x6e, 0x41, 0x49, 0x2d, 0x72, 0x54, 0x24,
    0x07, 0x1e, 0x2d, 0x81, 0x02, 0x81, 0x81, 0x00, 0x8c, 0x0e, 0xa8, 0x6b, 0x01, 0x02, 0xf0, 0x24,
    0xd6, 0x92, 0xbd, 0xce, 0x4a, 0x87, 0x55, 0xe0, 0xaf, 0xfe, 0x3c, 0x5e, 0xca, 0xf5, 0x9e, 0xe4,
    0x0c, 0x4e, 0x78, 0x80, 0xe4, 0x68, 0x62, 0xea, 0x52, 0xe9, 0xd9, 0xdb, 0x56, 0x75, 0x12, 0x37,
    0x18, 0x76, 0x32, 0x46, 0x6d, 0xd2, 0xc1, 0xa1, 0xc3, 0x94, 0x23, 0x5b, 0x4f, 0x3d, 0x8e, 0x67,
    0x41, 0x7d, 0xa3, 0xba, 0xfb, 0xb9, 0xe0, 0x73, 0xf4, 0x94, 0x00, 0xde, 0xf9, 0x68, 0x91, 0xdc,
    0x27, 0x35, 0x43, 0xa1, 0xbf, 0xd7, 0x21, 0xf3, 0x97, 0xe7, 0x3a, 0xe1, 0xf6, 0x4b, 0xeb, 0xbf,
    0x18, 0x49, 0x9d, 0x31, 0xce, 0xa8, 0x16, 0xe6, 0x88, 0x7a, 0x3b, 0x4d, 0x71, 0x59, 0x73, 0xf5,
    0x74, 0x2c, 0xb7, 0xc1, 0xb2, 0x97, 0xa3, 0xac, 0x2b, 0x35, 0x1b, 0xe0, 0x12, 0x11, 0x1c, 0x5d,
    0x5b, 0x41, 0xa1, 0x61, 0x7d, 0x94, 0x7f, 0xad,
];

/// The signing-key algorithm a store-backed harness provisions its environment
/// with.
enum HarnessKey {
    Ed25519,
    Es256,
}

/// The provisioned key material plus the public verifying key derived from it.
struct ProvisionedKey {
    algorithm: &'static str,
    material_kind: SigningKeyMaterialKind,
    material: Vec<u8>,
    verifying_key: TrustedKey,
}

impl HarnessKey {
    /// Build the signing key for `key_id` and return the material to persist and the
    /// public verifying key derived from the SAME material.
    fn provision(&self, env: &Env, key_id: &SigningKeyId) -> ProvisionedKey {
        let kid = Some(key_id.to_string());
        match self {
            HarnessKey::Ed25519 => {
                let mut seed = [0_u8; 32];
                env.entropy().fill_bytes(&mut seed);
                let signing_key = SigningKey::ed25519_from_seed(kid, &seed).expect("ed25519 key");
                ProvisionedKey {
                    algorithm: "EdDSA",
                    material_kind: SigningKeyMaterialKind::Ed25519Seed,
                    material: seed.to_vec(),
                    verifying_key: signing_key.verifying_key().expect("verifying key"),
                }
            }
            HarnessKey::Es256 => {
                let signing_key =
                    SigningKey::ecdsa_p256_from_pkcs8(kid, ES256_PKCS8).expect("es256 key");
                ProvisionedKey {
                    algorithm: "ES256",
                    material_kind: SigningKeyMaterialKind::EcdsaPkcs8,
                    material: ES256_PKCS8.to_vec(),
                    verifying_key: signing_key.verifying_key().expect("verifying key"),
                }
            }
        }
    }
}

/// A running OIDC provider over a fresh database.
pub struct Harness {
    // Held so the database and its pools outlive the router.
    db: TestDatabase,
    env: Env,
    clock: Arc<ManualClock>,
    scope: Scope,
    client_id: ClientId,
    verifying_key: TrustedKey,
    issuer: String,
    // The issuer registry the state was built over, so a test can reach the live
    // environment signer to mint a token shape the mint does not produce today (a
    // JSON-array `aud`, issue #22 introspection hardening / #28).
    registry: Arc<IssuerRegistry>,
    // A clone of the OidcState the router was built from, so a test can call the
    // state directly (for example the access-token target resolution, issue #29).
    state: OidcState,
    // The quota engine installed on the state, retained so a test can inspect the
    // live bucket count and drive the idle-bucket reaper (issue #50).
    quota: Option<Arc<QuotaEnforcer>>,
    router: Router,
}

impl Harness {
    /// Start a fresh database, seed a scope and a client, provision a signing
    /// key, and build the OIDC router. Uses a deterministic clock frozen at the
    /// Unix epoch so token lifetimes and code expiry are driven explicitly.
    ///
    /// The default harness relaxes the confidential-client PKCE policy
    /// (`require_pkce_for_confidential_clients = false`, issue #13) so the
    /// client-authentication and interop tests can drive a confidential client
    /// through the token exchange WITHOUT PKCE (they exercise client auth, not
    /// PKCE). A PUBLIC client still always requires PKCE, so the public-client
    /// flows include a `code_challenge`. Tests that want the production default
    /// (PKCE required for confidential clients too) build the config explicitly and
    /// call [`Harness::start_with`].
    pub async fn start() -> Self {
        Self::start_with(OidcConfig {
            require_pkce_for_confidential_clients: false,
            ..OidcConfig::default()
        })
        .await
    }

    /// Like [`Harness::start`] but with explicit OIDC settings (for the expiry
    /// test, which wants a short code lifetime).
    pub async fn start_with(config: OidcConfig) -> Self {
        Self::start_inner(config, None, None).await
    }

    /// Like [`Harness::start_with`] but wiring a `private_key_jwt` client-key
    /// resolver (issue #25), so a `jwks_uri` client's keys resolve through the
    /// fetcher. Confidential PKCE is relaxed via the passed config.
    pub async fn start_with_resolver(config: OidcConfig, resolver: Arc<ClientKeyResolver>) -> Self {
        Self::start_inner(config, Some(resolver), None).await
    }

    /// Like [`Harness::start_with`] but with the tenant/environment quota engine
    /// (issue #50) installed on the data plane, built from `quota_config` and the
    /// harness's deterministic clock. Used to drive the real `/authorize` request
    /// path into a 429 and to prove tenant fairness end to end.
    pub async fn start_with_quota(config: OidcConfig, quota_config: QuotaConfig) -> Self {
        Self::start_inner(config, None, Some(quota_config)).await
    }

    async fn start_inner(
        config: OidcConfig,
        resolver: Option<Arc<ClientKeyResolver>>,
        quota_config: Option<QuotaConfig>,
    ) -> Self {
        let (db, env, clock, scope, client_id) = Self::seed_common().await;

        // One Ed25519 signing key for the environment, held in a PRE-POPULATED
        // registry: the database-free key path the non-#194 tests rely on. The
        // registry is the single key holder (issue #194); OidcState no longer holds
        // a separate key store.
        let signing_key =
            SigningKey::generate_ed25519(Some("k1".to_owned()), env.entropy()).expect("gen key");
        let verifying_key = signing_key.verifying_key().expect("verifying key");
        let registry = IssuerRegistry::new(
            ISSUER_BASE,
            JwksCacheWindow::clamped(config.jwks_cache_max_age_secs),
        );
        registry.insert(
            scope,
            IssuerEntry::new(
                KeySet::bootstrap(signing_key, SystemTime::UNIX_EPOCH),
                SigningPolicy::eddsa_default(),
                PairwiseSalt::new(Vec::new()),
            ),
        );
        let registry = Arc::new(registry);

        let state = match resolver {
            Some(resolver) => OidcState::with_client_key_resolver(
                db.store().clone(),
                env.clone(),
                Arc::clone(&registry),
                &config,
                ISSUER_BASE,
                resolver,
            ),
            None => OidcState::new(
                db.store().clone(),
                env.clone(),
                Arc::clone(&registry),
                &config,
                ISSUER_BASE,
            ),
        };
        // Install the tenant/environment quota engine over the SAME deterministic
        // clock when the test asked for it (issue #50), so an over-quota scope on the
        // real request path short-circuits with a 429 and refill is clock-driven.
        let (state, quota) = match quota_config {
            Some(quota_config) => {
                let enforcer = Arc::new(QuotaEnforcer::from_config(&quota_config, env.clock_arc()));
                (
                    state.with_quota_enforcer(Arc::clone(&enforcer)),
                    Some(enforcer),
                )
            }
            None => (state, None),
        };
        let issuer = state.issuer_for(&scope);
        let router = oidc_router(state.clone());

        Self {
            db,
            env,
            clock,
            scope,
            client_id,
            verifying_key,
            issuer,
            registry,
            state,
            quota,
            router,
        }
    }

    /// Like [`Harness::start_with`] but the pre-populated environment carries BOTH
    /// an `EdDSA` (default/preferred) and an RS256 signing key, under a policy that
    /// permits both. Used to exercise the DCR algorithm negotiation and the
    /// honor-at-mint path (issue #30): the environment can truthfully sign an ID
    /// token under EITHER algorithm, so a client may negotiate RS256 and the token
    /// endpoint signs THAT client's ID token under RS256 while the environment
    /// default stays `EdDSA`. [`Harness::verifying_key`] is the `EdDSA` key (the
    /// default).
    pub async fn start_dual_signing(config: OidcConfig) -> Self {
        let (db, env, clock, scope, client_id) = Self::seed_common().await;

        let ed = SigningKey::generate_ed25519(Some("k-ed".to_owned()), env.entropy())
            .expect("gen ed25519 key");
        let verifying_key = ed.verifying_key().expect("verifying key");
        let rsa = SigningKey::rsa_from_pkcs1_der(
            Some("k-rsa".to_owned()),
            JwsAlgorithm::Rs256,
            RSA_PKCS1,
        )
        .expect("rsa key");
        // Both keys are day-one (published and active from the epoch), so either can
        // sign at once; EdDSA is the policy's FIRST (preferred) algorithm.
        let mut keyset = KeySet::bootstrap(ed, SystemTime::UNIX_EPOCH);
        keyset.add(rsa, SystemTime::UNIX_EPOCH);
        let policy = SigningPolicy::new(vec![JwsAlgorithm::EdDsa, JwsAlgorithm::Rs256])
            .expect("dual policy");

        let registry = IssuerRegistry::new(
            ISSUER_BASE,
            JwksCacheWindow::clamped(config.jwks_cache_max_age_secs),
        );
        registry.insert(
            scope,
            IssuerEntry::new(keyset, policy, PairwiseSalt::new(Vec::new())),
        );
        let registry = Arc::new(registry);

        let state = OidcState::new(
            db.store().clone(),
            env.clone(),
            Arc::clone(&registry),
            &config,
            ISSUER_BASE,
        );
        let issuer = state.issuer_for(&scope);
        let router = oidc_router(state.clone());

        Self {
            db,
            env,
            clock,
            scope,
            client_id,
            verifying_key,
            issuer,
            registry,
            state,
            quota: None,
            router,
        }
    }

    /// Like [`Harness::start`] but the registry is STORE-BACKED (issue #194): the
    /// environment's Ed25519 signing key is PROVISIONED into the database, and the
    /// live registry loads it lazily through the RLS-forced scoped store on first
    /// use. The per-environment JWKS surface is mounted alongside the protocol
    /// router, so a test can fetch the published key set the mint actually signs
    /// with. Confidential PKCE is relaxed, exactly like [`Harness::start`].
    pub async fn start_store_backed() -> Self {
        Self::start_store_backed_with(OidcConfig {
            require_pkce_for_confidential_clients: false,
            ..OidcConfig::default()
        })
        .await
    }

    /// Like [`Harness::start_store_backed`] but with explicit OIDC settings (for
    /// example a non-default `jwks_cache_max_age_secs`, so the served JWKS
    /// `Cache-Control` can be asserted against the configured window). Provisions an
    /// Ed25519 environment key.
    pub async fn start_store_backed_with(config: OidcConfig) -> Self {
        Self::build_store_backed(config, HarnessKey::Ed25519).await
    }

    /// Like [`Harness::start_store_backed`] but the environment is provisioned with
    /// an ES256-ONLY signing key. Because the live registry derives the algorithm
    /// policy from exactly the keys it loads (issue #194), this environment's policy
    /// is `{ES256}`, so it can emit nothing but ES256 tokens: proving that an
    /// ES256-only environment never emits a non-ES256 token on the live mint path
    /// (AC #3). Confidential PKCE is relaxed, exactly like [`Harness::start`].
    pub async fn start_store_backed_es256() -> Self {
        Self::build_store_backed(
            OidcConfig {
                require_pkce_for_confidential_clients: false,
                ..OidcConfig::default()
            },
            HarnessKey::Es256,
        )
        .await
    }

    /// Build a store-backed harness whose environment is provisioned with `key`,
    /// mounting the protocol, per-environment JWKS, and discovery routers over the
    /// one lazy registry (exactly as `main.rs` mounts all three), so a test can
    /// fetch the LIVE discovery document whose per-environment policy is derived from
    /// the loaded key set.
    async fn build_store_backed(config: OidcConfig, key: HarnessKey) -> Self {
        let (db, env, clock, scope, client_id) = Self::seed_common().await;

        // Build the key with its `sik_` id as the kid and PROVISION the SAME
        // material into the store, so the lazily loaded key rebuilds identically and
        // a minted token's kid matches the provisioned (and published) key.
        let key_id = SigningKeyId::generate(&env, &scope);
        let provisioned = key.provision(&env, &key_id);
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .signing_keys()
            .provision(
                &env,
                NewSigningKey {
                    id: &key_id,
                    algorithm: provisioned.algorithm,
                    material_kind: provisioned.material_kind,
                    material: &provisioned.material,
                    // A day-one key is published and active from the epoch (the
                    // harness clock), so it signs and appears in the JWKS at once.
                    publish_at_micros: 0,
                    activate_at_micros: 0,
                    retire_at_micros: None,
                    expire_at_micros: None,
                },
            )
            .await
            .expect("provision signing key");

        let registry = Arc::new(IssuerRegistry::store_backed(
            ISSUER_BASE,
            JwksCacheWindow::clamped(config.jwks_cache_max_age_secs),
            db.store().clone(),
        ));
        let issuer_state = IssuerState::new(Arc::clone(&registry), env.clone());
        // Discovery over the SAME store-backed registry (issue #194), so the served
        // discovery document derives its per-environment policy from the loaded keys.
        let discovery_state = DiscoveryState::new(
            ISSUER_BASE,
            JwksCacheWindow::clamped(config.jwks_cache_max_age_secs),
            DiscoveryCapabilities::from_config(&config),
            Arc::clone(&registry),
        );
        let state = OidcState::new(
            db.store().clone(),
            env.clone(),
            Arc::clone(&registry),
            &config,
            ISSUER_BASE,
        );
        let issuer = state.issuer_for(&scope);
        let router = oidc_router(state.clone())
            .merge(issuer_router(issuer_state))
            .merge(discovery_router(discovery_state));

        Self {
            db,
            env,
            clock,
            scope,
            client_id,
            verifying_key: provisioned.verifying_key,
            issuer,
            registry,
            state,
            quota: None,
            router,
        }
    }

    /// Simulate a NODE RESTART: rebuild every scrap of process-level state from
    /// scratch against the SAME Postgres (issue #32, acceptance criterion 1).
    ///
    /// A brand-new connection pool, a brand-new `Store`, a brand-new (cold, empty)
    /// `IssuerRegistry`, a brand-new `OidcState`, and a brand-new router. Nothing
    /// in-process is carried over, so anything the restarted node can still do it does
    /// PURELY from what Postgres holds. If any authoritative session state lived only
    /// in memory, it is gone now and the caller's next request fails.
    ///
    /// The clock and the `(tenant, environment)` scope are kept: this is a restart of
    /// the same node against the same database, not a new deployment.
    #[must_use]
    pub async fn restart(&self, config: &OidcConfig) -> Self {
        let store = self.db.restart_app_store().await;
        let registry = Arc::new(IssuerRegistry::store_backed(
            ISSUER_BASE,
            JwksCacheWindow::clamped(config.jwks_cache_max_age_secs),
            store.clone(),
        ));
        let issuer_state = IssuerState::new(Arc::clone(&registry), self.env.clone());
        let discovery_state = DiscoveryState::new(
            ISSUER_BASE,
            JwksCacheWindow::clamped(config.jwks_cache_max_age_secs),
            DiscoveryCapabilities::from_config(config),
            Arc::clone(&registry),
        );
        let state = OidcState::new(
            store,
            self.env.clone(),
            Arc::clone(&registry),
            config,
            ISSUER_BASE,
        );
        let router = oidc_router(state.clone())
            .merge(issuer_router(issuer_state))
            .merge(discovery_router(discovery_state));
        Self {
            db: self.db.clone(),
            env: self.env.clone(),
            clock: Arc::clone(&self.clock),
            scope: self.scope,
            client_id: self.client_id,
            verifying_key: self.verifying_key.clone(),
            issuer: self.issuer.clone(),
            registry,
            state,
            quota: None,
            router,
        }
    }

    /// Seed the shared fixtures both constructors build on: a fresh database, a
    /// deterministic clock frozen at the Unix epoch, a `(tenant, environment)`
    /// scope, and one OAuth client with the harness redirect URI registered (so the
    /// exact-string redirect match, issue #13, accepts it).
    async fn seed_common() -> (TestDatabase, Env, Arc<ManualClock>, Scope, ClientId) {
        let db = TestDatabase::start().await;
        let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0D1C_5EED);
        let scope = db.seed_scope(&env).await;

        let client_id = db
            .store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .clients()
            .create(&env, "oidc test client")
            .await
            .expect("create client");
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .clients()
            .register_redirect_uris(&env, &client_id, &[REDIRECT_URI])
            .await
            .expect("register redirect uri");

        (db, env, clock, scope, client_id)
    }

    /// The data-plane store behind the router, for verifying audit rows and token
    /// status.
    #[must_use]
    pub fn store(&self) -> &Store {
        self.db.store()
    }

    /// The OIDC state the router was built from, for tests that call the state
    /// directly (for example `resolve_access_token_target`, issue #29).
    #[must_use]
    pub fn state(&self) -> &OidcState {
        &self.state
    }

    /// The quota engine installed on the state (issue #50), for tests that assert
    /// the live bucket count stays bounded or drive the idle-bucket reaper.
    #[must_use]
    pub fn quota_enforcer(&self) -> &Arc<QuotaEnforcer> {
        self.quota
            .as_ref()
            .expect("harness was started with a quota engine")
    }

    /// The seeded scope.
    #[must_use]
    pub fn scope(&self) -> Scope {
        self.scope
    }

    /// The seeded client identifier (its string is the `client_id`).
    #[must_use]
    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    /// The environment seam (for minting cross-scope test data).
    #[must_use]
    pub fn env(&self) -> &Env {
        &self.env
    }

    /// Seed a second environment of the SAME tenant and return a scope over it,
    /// for cross-environment isolation tests.
    pub async fn second_scope(&self) -> Scope {
        let environment = self
            .db
            .seed_environment(&self.env, self.scope.tenant())
            .await;
        Scope::new(self.scope.tenant(), environment)
    }

    /// Seed a SEPARATE tenant and environment (a foreign scope, owned by a
    /// DIFFERENT tenant) and provision its own Ed25519 signing key. Returns the
    /// foreign scope.
    ///
    /// Used to prove env-to-tenant binding (issue #194 AC #5): this environment
    /// resolves 200 under its OWN tenant, but a request that names it under the
    /// harness's different tenant must fail closed (RLS finds no rows), never
    /// serving this scope's key set as a self-consistent bogus 200.
    pub async fn provision_foreign_scope(&self) -> Scope {
        let scope = self.db.seed_scope(&self.env).await;
        let key_id = SigningKeyId::generate(&self.env, &scope);
        let mut seed = [0_u8; 32];
        self.env.entropy().fill_bytes(&mut seed);
        let (actor, corr) = self.seeding_actor();
        self.store()
            .scoped(scope)
            .acting(actor, corr)
            .signing_keys()
            .provision(
                &self.env,
                NewSigningKey {
                    id: &key_id,
                    algorithm: "EdDSA",
                    material_kind: SigningKeyMaterialKind::Ed25519Seed,
                    material: &seed,
                    publish_at_micros: 0,
                    activate_at_micros: 0,
                    retire_at_micros: None,
                    expire_at_micros: None,
                },
            )
            .await
            .expect("provision foreign signing key");
        scope
    }

    /// The manual clock handle, for advancing time in the expiry test.
    #[must_use]
    pub fn clock(&self) -> &Arc<ManualClock> {
        &self.clock
    }

    /// Sign a synthetic `at+jwt` access token over `claims` with the environment's
    /// LIVE signing key and policy (the same key/policy the mint signs with, resolved
    /// through the issuer registry), for a test that needs a token shape the mint does
    /// not produce today. Used by the issue #22 introspection guard test to forge a
    /// JSON-array `aud` (RFC 7519 / #28), reusing a real token's `jti` so its store row
    /// still resolves.
    pub async fn sign_at_jwt(&self, claims: &serde_json::Value) -> String {
        let entry = self
            .registry
            .entry_for(&self.scope)
            .await
            .expect("issuer entry for scope");
        let signer = entry
            .signer(self.state.now())
            .expect("an active signer at now");
        let bytes = serde_json::to_vec(claims).expect("claims serialize");
        sign_jws_with_policy(
            entry.policy(),
            signer,
            &bytes,
            &EmissionOptions::new().with_typ("at+jwt"),
        )
        .expect("sign at+jwt")
    }

    /// The per-environment issuer the tokens carry.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// A clone of the router (concurrent race test clones it per task).
    pub fn router(&self) -> Router {
        self.router.clone()
    }

    /// The environment's public verifying key, for building a verification policy
    /// under a non-EdDSA algorithm (for example the ES256 environment, issue #29).
    #[must_use]
    pub fn verifying_key(&self) -> TrustedKey {
        self.verifying_key.clone()
    }

    /// A verification policy that trusts the environment's public key and expects
    /// the harness issuer and the given audience.
    #[must_use]
    pub fn policy(&self, audience: &str) -> VerificationPolicy {
        VerificationPolicy::new(
            vec![JwsAlgorithm::EdDsa],
            vec![self.verifying_key.clone()],
            self.issuer.clone(),
            audience.to_owned(),
        )
        .expect("policy builds")
    }

    /// Drive one request through the router.
    pub async fn send(&self, request: Request<Body>) -> (StatusCode, HeaderMap, String) {
        send_through(self.router.clone(), request).await
    }

    /// `GET /authorize` with a pre-built query string (already encoded).
    pub async fn authorize(&self, query: &str) -> (StatusCode, HeaderMap, String) {
        let request = Request::builder()
            .method("GET")
            .uri(format!("/authorize?{query}"))
            .body(Body::empty())
            .expect("request builds");
        self.send(request).await
    }

    /// `POST /token` with a pre-built form body (already encoded).
    pub async fn token(&self, form: &str) -> (StatusCode, HeaderMap, String) {
        self.token_with_auth(form, None).await
    }

    /// `POST /token` with an optional `Authorization` header (for
    /// `client_secret_basic`).
    pub async fn token_with_auth(
        &self,
        form: &str,
        authorization: Option<&str>,
    ) -> (StatusCode, HeaderMap, String) {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(value) = authorization {
            builder = builder.header(header::AUTHORIZATION, value);
        }
        let request = builder
            .body(Body::from(form.to_owned()))
            .expect("request builds");
        self.send(request).await
    }

    /// `POST /par` (RFC 9126, issue #27) with a pre-built form body (already encoded)
    /// and an optional `Authorization` header (for a `client_secret_basic` client).
    pub async fn par(
        &self,
        form: &str,
        authorization: Option<&str>,
    ) -> (StatusCode, HeaderMap, String) {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/par")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(value) = authorization {
            builder = builder.header(header::AUTHORIZATION, value);
        }
        let request = builder
            .body(Body::from(form.to_owned()))
            .expect("request builds");
        self.send(request).await
    }

    /// Enable the RFC 8628 device grant on `client_id` and register a display logo
    /// (issue #24), so the client may start a device-authorization flow. `grant_types`
    /// is the space-separated allowlist (it must contain the `device_code` URN for the
    /// device endpoint to admit the client).
    pub async fn enable_device_grant(
        &self,
        client_id: &ClientId,
        grant_types: &str,
        logo_uri: Option<&str>,
    ) {
        let (actor, corr) = self.seeding_actor();
        self.store()
            .scoped(self.scope)
            .acting(actor, corr)
            .clients()
            .set_device_grant(&self.env, client_id, grant_types, logo_uri)
            .await
            .expect("enable device grant");
    }

    /// Set the per-client `require_pushed_authorization_requests` flag (issue #27) for
    /// `client_id`, so a plain (non-PAR) authorization request from it is rejected.
    pub async fn require_par_for_client(&self, client_id: &ClientId) {
        let (actor, corr) = self.seeding_actor();
        self.store()
            .scoped(self.scope)
            .acting(actor, corr)
            .clients()
            .set_require_pushed_authorization_requests(&self.env, client_id, true)
            .await
            .expect("set require PAR");
    }

    /// `GET /authorize` with a session cookie, so a request from an authenticated,
    /// consenting subject proceeds straight to issuing the code.
    pub async fn authorize_with_cookie(
        &self,
        query: &str,
        cookie: &str,
    ) -> (StatusCode, HeaderMap, String) {
        let request = Request::builder()
            .method("GET")
            .uri(format!("/authorize?{query}"))
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .expect("request builds");
        self.send(request).await
    }

    /// `GET` any path with a session cookie (used to follow the interaction
    /// redirects in the end-to-end test).
    pub async fn get_with_cookie(
        &self,
        path: &str,
        cookie: Option<&str>,
    ) -> (StatusCode, HeaderMap, String) {
        let mut builder = Request::builder().method("GET").uri(path);
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        self.send(builder.body(Body::empty()).expect("request builds"))
            .await
    }

    /// `POST` a form to `path` with an optional session cookie (used to submit the
    /// login, registration, and consent forms in the end-to-end test).
    pub async fn post_form(
        &self,
        path: &str,
        form: &str,
        cookie: Option<&str>,
    ) -> (StatusCode, HeaderMap, String) {
        let mut builder = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        self.send(
            builder
                .body(Body::from(form.to_owned()))
                .expect("request builds"),
        )
        .await
    }

    /// A throwaway acting context for direct store seeding.
    fn seeding_actor(&self) -> (ironauth_store::ActorRef, CorrelationId) {
        (
            self.db.test_actor(&self.env),
            CorrelationId::generate(&self.env),
        )
    }

    /// Register a bootstrap user in the harness scope and return its subject (the
    /// `usr_` id string).
    pub async fn seed_user(&self, identifier: &str, password: &str) -> String {
        let hash = ironauth_oidc::hash_password(&self.env, password).expect("hash password");
        let (actor, corr) = self.seeding_actor();
        self.store()
            .scoped(self.scope)
            .acting(actor, corr)
            .users()
            .register(&self.env, identifier, &hash)
            .await
            .expect("register user")
            .to_string()
    }

    /// Register a bootstrap user with a standard-claim document (issue #15) and
    /// return its subject. `claims_json` is the OIDC standard-claim object as JSON
    /// text (for example `{"email":"a@b.test","email_verified":true}`), which
    /// `UserInfo` releases selectively per the granted scope and claims request.
    pub async fn seed_user_with_claims(
        &self,
        identifier: &str,
        password: &str,
        claims_json: &str,
    ) -> String {
        let hash = ironauth_oidc::hash_password(&self.env, password).expect("hash password");
        let (actor, corr) = self.seeding_actor();
        self.store()
            .scoped(self.scope)
            .acting(actor, corr)
            .users()
            .register_with_claims(&self.env, identifier, &hash, claims_json)
            .await
            .expect("register user with claims")
            .to_string()
    }

    /// Seed a fresh user with a unique identifier (drawn from the deterministic
    /// entropy stream, which advances per call) and return its subject.
    pub async fn seed_unique_user(&self) -> String {
        use std::fmt::Write as _;
        let mut suffix = [0_u8; 8];
        self.env.entropy().fill_bytes(&mut suffix);
        let id = suffix.iter().fold(String::new(), |mut acc, byte| {
            let _ = write!(acc, "{byte:02x}");
            acc
        });
        self.seed_user(&format!("user-{id}@example.test"), SEED_PASSWORD)
            .await
    }

    /// Record `subject`'s consent to `client_id` in the harness scope for the broad
    /// [`CONSENTED_SCOPE`], so the shortcut covers any standard-scope request under
    /// the scope-aware consent check (issue #196).
    pub async fn grant_consent(&self, subject: &str, client_id: &str) {
        self.grant_consent_scoped(subject, client_id, Some(CONSENTED_SCOPE))
            .await;
    }

    /// Record `subject`'s consent to `client_id` against an EXPLICIT `scope` (issue
    /// #196), for tests that pin the scope a consent was granted against (for example
    /// a NARROW prior consent that must re-prompt on a broader request).
    pub async fn grant_consent_scoped(&self, subject: &str, client_id: &str, scope: Option<&str>) {
        let (actor, corr) = self.seeding_actor();
        self.store()
            .scoped(self.scope)
            .acting(actor, corr)
            .consents()
            .grant(&self.env, subject, client_id, scope)
            .await
            .expect("grant consent");
    }

    /// Record `subject`'s consent to `client_id` against `scope` with an explicit
    /// `expires_at_unix_micros` (issue #21), for the remembered-consent TTL tests: a
    /// consent recorded with a finite expiry is honored until the clock passes it,
    /// then re-prompts.
    pub async fn grant_consent_with_expiry(
        &self,
        subject: &str,
        client_id: &str,
        scope: Option<&str>,
        expires_at_unix_micros: Option<i64>,
    ) {
        let (actor, corr) = self.seeding_actor();
        self.store()
            .scoped(self.scope)
            .acting(actor, corr)
            .consents()
            .grant_with_expiry(&self.env, subject, client_id, scope, expires_at_unix_micros)
            .await
            .expect("grant consent with expiry");
    }

    /// Configure a client's consent mode and refresh-rotation policy (issue #21):
    /// the consent mode (`explicit`/`implicit`/`remembered`), the skip and no-store
    /// consent knobs, and the optional rotation override (`always`/`threshold`).
    pub async fn configure_client_policy(
        &self,
        client_id: &ClientId,
        consent_mode: &str,
        skip_consent: bool,
        store_skipped_consent: bool,
        refresh_rotation: Option<&str>,
    ) {
        let (actor, corr) = self.seeding_actor();
        self.store()
            .scoped(self.scope)
            .acting(actor, corr)
            .clients()
            .configure_policy(
                &self.env,
                client_id,
                consent_mode,
                skip_consent,
                store_skipped_consent,
                refresh_rotation,
            )
            .await
            .expect("configure client policy");
    }

    /// Count the audit rows in the harness scope whose action equals `action` (issue
    /// #21): used to prove the typed reuse event is emitted EXACTLY once per incident.
    pub async fn count_audit_action(&self, action: &str) -> usize {
        self.store()
            .scoped(self.scope)
            .audit()
            .list()
            .await
            .expect("list audit")
            .into_iter()
            .filter(|row| row.action == action)
            .count()
    }

    /// Resolve a presented refresh token's live state in the harness scope (issue
    /// #21), for asserting rotation, supersession, and family revocation.
    pub async fn resolve_refresh(
        &self,
        token: &str,
    ) -> Option<ironauth_store::RefreshTokenResolution> {
        self.store()
            .scoped(self.scope)
            .refresh()
            .load(token)
            .await
            .expect("load refresh token")
    }

    /// Count `family`'s LIVE leaves: unrotated refresh-token rows in an unrevoked
    /// family (issue #21). The rotation invariant is that this is ALWAYS at most one,
    /// even under concurrent within-grace refreshes: a family must never fork into two
    /// sibling live leaves.
    pub async fn count_live_refresh_leaves(&self, family: &ironauth_store::RefreshFamilyId) -> i64 {
        self.store()
            .scoped(self.scope)
            .refresh()
            .live_leaf_count(family)
            .await
            .expect("count live leaves")
    }

    /// The `(refresh_families, refresh_tokens)` row counts in the harness scope (issue
    /// #23), for the client-credentials DB-negative: a machine-token issuance must open
    /// NO refresh family and mint NO refresh token (RFC 6749 4.4.3), proven at the
    /// database rather than only in the token-response body.
    pub async fn count_refresh_rows(&self) -> (i64, i64) {
        self.store()
            .scoped(self.scope)
            .refresh()
            .count_in_scope()
            .await
            .expect("count refresh rows")
    }

    /// Count the `client_sessions` rows in the harness scope (issue #32), so a test can
    /// prove the code-exchange path minted NO new per-client session (hence no fresh
    /// `sid`) when it refused a dead session.
    pub async fn count_client_sessions(&self) -> i64 {
        self.store()
            .scoped(self.scope)
            .client_sessions()
            .count_in_scope()
            .await
            .expect("count client sessions")
    }

    /// Create a session for `subject` (a bootstrap `pwd` authentication event at
    /// the epoch) and return the `Cookie` header value. The session is far-future
    /// so it survives the clock advances in the expiry and reuse tests.
    pub async fn session_cookie(&self, subject: &str) -> String {
        self.session_cookie_at(subject, "pwd", 0).await
    }

    /// Like [`Harness::session_cookie`] but with an explicit `auth_methods` and
    /// recorded `auth_time` (epoch microseconds), so the ID-token claim tests can
    /// pin the authentication event a token derives its `auth_time`/`amr`/`acr`
    /// from.
    pub async fn session_cookie_at(
        &self,
        subject: &str,
        auth_methods: &str,
        auth_time_micros: i64,
    ) -> String {
        let (_id, cookie) = self
            .session_with_id(subject, auth_methods, auth_time_micros)
            .await;
        cookie
    }

    /// Seed a session exactly as [`Harness::session_cookie_at`] does, and return its
    /// identifier alongside the `Cookie` value (issue #32), so a test can revoke or
    /// inspect the very session a request presents.
    pub async fn session_with_id(
        &self,
        subject: &str,
        auth_methods: &str,
        auth_time_micros: i64,
    ) -> (SessionId, String) {
        let session_id = SessionId::generate(&self.env, &self.scope);
        let (actor, corr) = self.seeding_actor();
        self.store()
            .scoped(self.scope)
            .acting(actor, corr)
            .sessions()
            // The authoritative create path (issue #32) is a rotation with no prior
            // session: a fresh id, both lifetimes, and no binding metadata (the two
            // binding knobs are off by default).
            .rotate(
                &self.env,
                &session_id,
                None,
                ironauth_store::NewSession {
                    subject,
                    auth_methods,
                    auth_time_micros,
                    idle_expires_micros: FAR_FUTURE_MICROS,
                    absolute_expires_micros: FAR_FUTURE_MICROS,
                    user_agent: None,
                    peer_ip: None,
                },
            )
            .await
            .expect("create session");
        let cookie = format!("{SESSION_COOKIE}={session_id}");
        (session_id, cookie)
    }

    /// A ready authenticated `Cookie` value for the harness client: seeds a fresh
    /// user, records consent to the harness client, and returns the cookie. Each
    /// call is independent (a distinct user), so it can be used per code issuance.
    pub async fn authenticated_cookie(&self) -> String {
        self.authenticated_cookie_for(&self.client_id.to_string())
            .await
    }

    /// A ready authenticated `Cookie` value for an arbitrary `client_id`: seeds a
    /// fresh user, records consent to that client, and returns the cookie. Used by
    /// the ID-token claim tests that drive a purpose-built client (for example one
    /// that registered `require_auth_time`).
    pub async fn authenticated_cookie_for(&self, client_id: &str) -> String {
        let subject = self.seed_unique_user().await;
        self.grant_consent(&subject, client_id).await;
        self.session_cookie(&subject).await
    }

    /// Create a PUBLIC client that registered `require_auth_time` (issue #14), so
    /// its ID tokens carry `auth_time` even without a `max_age` request. Returns
    /// its id.
    pub async fn create_client_requiring_auth_time(&self) -> ClientId {
        let (actor, corr) = self.seeding_actor();
        let id = self
            .store()
            .scoped(self.scope)
            .acting(actor, corr)
            .clients()
            .create_requiring_auth_time(&self.env, "require-auth-time client")
            .await
            .expect("create require_auth_time client");
        self.register_default_redirect(&id).await;
        id
    }

    /// Create a PUBLIC client (`token_endpoint_auth_method` = none) and register
    /// `redirect_uris` for it, returning its id. Used by the redirect-matching and
    /// native-app tests to register loopback and private-use-scheme redirects.
    pub async fn create_public_client_with_redirects(
        &self,
        display_name: &str,
        redirect_uris: &[&str],
    ) -> ClientId {
        let (actor, corr) = self.seeding_actor();
        let id = self
            .store()
            .scoped(self.scope)
            .acting(actor, corr)
            .clients()
            .create(&self.env, display_name)
            .await
            .expect("create public client");
        let (actor, corr) = self.seeding_actor();
        self.store()
            .scoped(self.scope)
            .acting(actor, corr)
            .clients()
            .register_redirect_uris(&self.env, &id, redirect_uris)
            .await
            .expect("register redirect uris");
        id
    }

    /// Register the client's POST-LOGOUT redirect URIs (issue #33), so the
    /// RP-Initiated Logout `end_session` endpoint's exact-string match honors one.
    pub async fn register_post_logout_redirects(&self, client_id: &ClientId, uris: &[&str]) {
        let (actor, corr) = self.seeding_actor();
        self.store()
            .scoped(self.scope)
            .acting(actor, corr)
            .clients()
            .register_post_logout_redirect_uris(&self.env, client_id, uris)
            .await
            .expect("register post-logout redirect uris");
    }

    /// Register a client's OIDC Front-Channel Logout 1.0 opt-in (issue #39): its
    /// `frontchannel_logout_uri` and whether `iss`/`sid` must be appended.
    pub async fn register_frontchannel_logout(
        &self,
        client_id: &ClientId,
        uri: Option<&str>,
        session_required: bool,
    ) {
        let (actor, corr) = self.seeding_actor();
        self.store()
            .scoped(self.scope)
            .acting(actor, corr)
            .clients()
            .register_frontchannel_logout(&self.env, client_id, uri, session_required)
            .await
            .expect("register frontchannel logout");
    }

    /// Register the harness redirect URI for `client_id`, so the authorization
    /// endpoint's exact-string redirect match (issue #13) accepts it.
    pub async fn register_default_redirect(&self, client_id: &ClientId) {
        let (actor, corr) = self.seeding_actor();
        self.store()
            .scoped(self.scope)
            .acting(actor, corr)
            .clients()
            .register_redirect_uris(&self.env, client_id, &[REDIRECT_URI])
            .await
            .expect("register redirect uri");
    }

    /// Issue an `authorization_code` bound to `client_id` for a fresh consenting
    /// subject (no PKCE, so the exchange only has to satisfy client
    /// authentication and the `redirect_uri` binding), returning the raw code.
    /// Used by the interop test to drive a mainstream OAuth client through the
    /// token exchange.
    pub async fn issue_authenticated_code(&self, client_id: &str) -> String {
        let subject = self.seed_unique_user().await;
        self.grant_consent(&subject, client_id).await;
        let cookie = self.session_cookie(&subject).await;
        let query = format!(
            "response_type=code&client_id={client_id}&redirect_uri={}",
            enc(REDIRECT_URI)
        );
        let (status, headers, body) = self.authorize_with_cookie(&query, &cookie).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {body}");
        location_param(&headers, "code").expect("code in redirect")
    }

    /// Create a CONFIDENTIAL client registered for `method`, returning its id and
    /// the plaintext secret (shown once).
    pub async fn create_confidential_client(&self, method: ClientAuthMethod) -> (ClientId, String) {
        self.create_confidential_client_named(method, "confidential client")
            .await
    }

    /// Like [`Harness::create_confidential_client`] but with an explicit display
    /// name (used to prove the consent screen escapes a hostile client name).
    pub async fn create_confidential_client_named(
        &self,
        method: ClientAuthMethod,
        display_name: &str,
    ) -> (ClientId, String) {
        let secret = ironauth_oidc::generate_secret(&self.env);
        let secret_hash = ironauth_oidc::hash_secret(&secret);
        let (actor, corr) = self.seeding_actor();
        let id = self
            .store()
            .scoped(self.scope)
            .acting(actor, corr)
            .clients()
            .create_confidential(&self.env, display_name, method.as_str(), &secret_hash)
            .await
            .expect("create confidential client");
        self.register_default_redirect(&id).await;
        (id, secret)
    }

    /// Create a CONFIDENTIAL client registered for `method` in an ARBITRARY `scope`
    /// (not necessarily the harness scope), returning its id and plaintext secret.
    /// Used by the cross-tenant isolation tests (issue #22) to stand up a client in a
    /// foreign scope that then attempts to revoke/introspect a token from another
    /// scope.
    pub async fn create_confidential_client_in(
        &self,
        scope: Scope,
        method: ClientAuthMethod,
        display_name: &str,
    ) -> (ClientId, String) {
        let secret = ironauth_oidc::generate_secret(&self.env);
        let secret_hash = ironauth_oidc::hash_secret(&secret);
        let (actor, corr) = self.seeding_actor();
        let id = self
            .store()
            .scoped(scope)
            .acting(actor, corr)
            .clients()
            .create_confidential(&self.env, display_name, method.as_str(), &secret_hash)
            .await
            .expect("create confidential client in scope");
        (id, secret)
    }

    /// Create a client that authenticates with a JWT assertion (issue #25):
    /// `private_key_jwt` (inline `jwks` or a `jwks_uri`) or `client_secret_jwt`,
    /// with an optional pinned `token_endpoint_auth_signing_alg`. Registers the
    /// harness redirect URI and returns the id. Panics on a registration error; use
    /// [`Harness::try_create_jwt_auth_client`] to assert a rejection.
    pub async fn create_jwt_auth_client(
        &self,
        auth_method: ClientAuthMethod,
        jwks: Option<&str>,
        jwks_uri: Option<&str>,
        signing_alg: Option<&str>,
    ) -> ClientId {
        self.try_create_jwt_auth_client(auth_method, jwks, jwks_uri, signing_alg)
            .await
            .expect("create jwt-auth client")
    }

    /// Like [`Harness::create_jwt_auth_client`] but RETURNS the store result, so a
    /// test can assert a registration is rejected (a keyless or dual-source
    /// `private_key_jwt`, or the inert `client_secret_jwt`). The redirect URI is
    /// registered only on success.
    pub async fn try_create_jwt_auth_client(
        &self,
        auth_method: ClientAuthMethod,
        jwks: Option<&str>,
        jwks_uri: Option<&str>,
        signing_alg: Option<&str>,
    ) -> Result<ClientId, ironauth_store::StoreError> {
        let (actor, corr) = self.seeding_actor();
        let id = self
            .store()
            .scoped(self.scope)
            .acting(actor, corr)
            .clients()
            .create_jwt_auth(
                &self.env,
                NewJwtAuthClient {
                    display_name: "jwt-auth client",
                    auth_method: auth_method.as_str(),
                    jwks,
                    jwks_uri,
                    signing_alg,
                },
            )
            .await?;
        self.register_default_redirect(&id).await;
        Ok(id)
    }

    /// Read the recorded out-of-band client-authentication diagnostics for
    /// `client_id` in the harness scope (issue #25). The JWT bearer assertion grant
    /// (#26) records its failures in the SAME sink under the presenting client's id,
    /// so this reads those too.
    pub async fn client_auth_diagnostics(
        &self,
        client_id: &str,
    ) -> Vec<ironauth_store::ClientAuthDiagnosticRecord> {
        self.store()
            .scoped(self.scope)
            .client_auth_diagnostics()
            .for_client(client_id)
            .await
            .expect("read client-auth diagnostics")
    }

    /// Register an external assertion issuer as a trust anchor for the JWT bearer
    /// assertion grant (issue #26), returning its `xai_` identifier so a test can later
    /// toggle its enable switch. Exactly one of `jwks`/`jwks_uri` must be set.
    /// `enabled` registers the enable switch, so a test can register a disabled issuer
    /// to prove disabled issuers are rejected.
    pub async fn register_external_issuer(
        &self,
        issuer: &str,
        jwks: Option<&str>,
        jwks_uri: Option<&str>,
        signing_alg_allow: Option<&str>,
        enabled: bool,
    ) -> ExternalIssuerId {
        let id = ExternalIssuerId::generate(&self.env, &self.scope);
        let (actor, corr) = self.seeding_actor();
        self.store()
            .scoped(self.scope)
            .acting(actor, corr)
            .external_assertion_issuers()
            .register(
                &self.env,
                NewExternalAssertionIssuer {
                    id: &id,
                    issuer,
                    jwks,
                    jwks_uri,
                    signing_alg_allow,
                    enabled,
                },
            )
            .await
            .expect("register external assertion issuer");
        id
    }

    /// Toggle a registered external issuer's enable switch (issue #26) through the
    /// column-scoped data-plane grant, exactly as the (M13) management surface will.
    /// Proves the revocability capability end to end: disabling a live issuer makes
    /// the grant reject its assertions.
    pub async fn set_external_issuer_enabled(&self, id: &ExternalIssuerId, enabled: bool) {
        let (actor, corr) = self.seeding_actor();
        self.store()
            .scoped(self.scope)
            .acting(actor, corr)
            .external_assertion_issuers()
            .set_enabled(&self.env, id, enabled)
            .await
            .expect("set external issuer enabled");
    }

    /// Like [`Harness::register_external_issuer`] but RETURNS the store result, so a
    /// test can assert a rejected registration (a keyless or dual-source issuer).
    pub async fn try_register_external_issuer(
        &self,
        issuer: &str,
        jwks: Option<&str>,
        jwks_uri: Option<&str>,
    ) -> Result<(), ironauth_store::StoreError> {
        let id = ExternalIssuerId::generate(&self.env, &self.scope);
        let (actor, corr) = self.seeding_actor();
        self.store()
            .scoped(self.scope)
            .acting(actor, corr)
            .external_assertion_issuers()
            .register(
                &self.env,
                NewExternalAssertionIssuer {
                    id: &id,
                    issuer,
                    jwks,
                    jwks_uri,
                    signing_alg_allow: None,
                    enabled: true,
                },
            )
            .await
    }

    /// Author a subject-mapping rule for the JWT bearer assertion grant (issue #26):
    /// map an external (`issuer` + `external_subject`), optionally gated on a claim,
    /// to `principal` (the issued token's `sub`). Unmapped subjects are rejected.
    /// Returns the rule's `asm_` identifier so a test can later toggle its enable
    /// switch.
    pub async fn create_subject_mapping(
        &self,
        issuer: &str,
        external_subject: &str,
        match_claim: Option<&str>,
        match_value: Option<&str>,
        principal: &str,
    ) -> AssertionMappingId {
        let id = AssertionMappingId::generate(&self.env, &self.scope);
        let (actor, corr) = self.seeding_actor();
        self.store()
            .scoped(self.scope)
            .acting(actor, corr)
            .external_assertion_subject_mappings()
            .create(
                &self.env,
                NewAssertionSubjectMapping {
                    id: &id,
                    issuer,
                    external_subject,
                    match_claim,
                    match_value,
                    principal,
                },
            )
            .await
            .expect("create subject mapping");
        id
    }

    /// Toggle a subject-mapping rule's enable switch (issue #26) through the
    /// column-scoped data-plane grant. Proves the revocability capability end to end:
    /// disabling a live mapping makes the grant reject the subject as unmapped.
    pub async fn set_subject_mapping_enabled(&self, id: &AssertionMappingId, enabled: bool) {
        let (actor, corr) = self.seeding_actor();
        self.store()
            .scoped(self.scope)
            .acting(actor, corr)
            .external_assertion_subject_mappings()
            .set_enabled(&self.env, id, enabled)
            .await
            .expect("set subject mapping enabled");
    }

    /// Issue an `authorization_code` bound to `client_id` WITH PKCE (the RFC 7636
    /// Appendix B S256 challenge), for a fresh consenting subject, returning the
    /// raw code. Used where the target client requires PKCE (a public client always
    /// does): the caller redeems it with [`PKCE_VERIFIER`], or exercises a failure
    /// that trips before the PKCE check.
    pub async fn issue_authenticated_code_pkce(&self, client_id: &str) -> String {
        let subject = self.seed_unique_user().await;
        self.grant_consent(&subject, client_id).await;
        let cookie = self.session_cookie(&subject).await;
        let query = format!(
            "response_type=code&client_id={client_id}&redirect_uri={}&\
             code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
            enc(REDIRECT_URI)
        );
        let (status, headers, body) = self.authorize_with_cookie(&query, &cookie).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {body}");
        location_param(&headers, "code").expect("code in redirect")
    }

    /// Mint a DCR initial access token (issue #31) exactly as the management API does:
    /// only the SHA-256 of `plaintext` is stored, alongside the `chain_text` policy
    /// snapshot (`"[]"` for unconstrained). A later registration that presents
    /// `plaintext` as a bearer token consumes THIS token. `max_uses` bounds how many
    /// registrations it may authorize (None = unlimited within the expiry).
    ///
    /// Minting is a CONTROL-plane operation, so it runs through the control-plane
    /// store: the data-plane (app) role holds no INSERT on the token table (it only
    /// SELECT/UPDATEs to consume), which is exactly the two-role separation the #31
    /// migration enforces.
    pub async fn mint_iat(
        &self,
        plaintext: &str,
        chain_text: &str,
        expires_at_micros: i64,
        max_uses: Option<i32>,
    ) {
        let id = InitialAccessTokenId::generate(&self.env, &self.scope);
        self.db
            .control_store()
            .scoped(self.scope)
            .acting(
                self.db.test_actor(&self.env),
                CorrelationId::generate(&self.env),
            )
            .initial_access_tokens()
            .mint(
                &self.env,
                &id,
                0,
                NewInitialAccessToken {
                    token_hash: &ironauth_oidc::hash_secret(plaintext),
                    policy_chain: chain_text,
                    expires_at_unix_micros: expires_at_micros,
                    max_uses,
                },
                None,
            )
            .await
            .expect("mint initial access token");
    }

    /// Verify a dynamically registered client (issue #31), lifting its quarantine,
    /// exactly as the management verify action does. Runs through the CONTROL-plane
    /// store (verification is a control operation, permitted by the narrow
    /// `UPDATE(quarantined, verified_at)` grant on `clients`).
    pub async fn verify_client(&self, client_id: &ClientId) {
        self.db
            .control_store()
            .scoped(self.scope)
            .acting(
                self.db.test_actor(&self.env),
                CorrelationId::generate(&self.env),
            )
            .clients()
            .verify_dynamic_client(&self.env, client_id, None)
            .await
            .expect("verify dynamic client");
    }

    /// Whether a client is currently quarantined (issue #31), read from the store.
    pub async fn client_quarantined(&self, client_id: &ClientId) -> bool {
        self.store()
            .scoped(self.scope)
            .clients()
            .get(client_id)
            .await
            .expect("get client")
            .quarantined
    }
}

/// A clock at the token's issuance time (the frozen epoch), for verification.
#[must_use]
pub fn verify_clock() -> ManualClock {
    ManualClock::new(SystemTime::UNIX_EPOCH)
}

/// Drive one request through a router, returning status, headers, and body.
pub async fn send_through(
    router: Router,
    request: Request<Body>,
) -> (StatusCode, HeaderMap, String) {
    let response = router.oneshot(request).await.expect("router is infallible");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body collects")
        .to_bytes();
    (
        status,
        headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

/// Percent-encode a query/form value (unreserved characters pass through).
#[must_use]
pub fn enc(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// Build an `x-www-form-urlencoded` string from key/value pairs (values encoded).
#[must_use]
pub fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Read a query parameter from a `Location` header value (percent-decoding it).
#[must_use]
pub fn location_param(headers: &HeaderMap, name: &str) -> Option<String> {
    let location = headers.get(header::LOCATION)?.to_str().ok()?;
    let query = location.split_once('?').map_or("", |(_, q)| q);
    for pair in query.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            if key == name {
                return Some(percent_decode(value));
            }
        }
    }
    None
}

/// Read a parameter from the FRAGMENT of a `Location` header value (the part after
/// `#`), percent-decoding it. Used by the front-channel (`id_token` /
/// `code id_token`) tests, whose default response mode is `fragment` (issue #17).
#[must_use]
pub fn location_fragment_param(headers: &HeaderMap, name: &str) -> Option<String> {
    let location = headers.get(header::LOCATION)?.to_str().ok()?;
    let fragment = location.split_once('#').map_or("", |(_, f)| f);
    for pair in fragment.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            if key == name {
                return Some(percent_decode(value));
            }
        }
    }
    None
}

/// Minimal percent-decoding for reading redirect query values back.
#[must_use]
pub fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&value[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse the JSON body of a token response and return `(field lookups)`.
#[must_use]
pub fn json(body: &str) -> serde_json::Value {
    serde_json::from_str(body).expect("response body is JSON")
}

/// The `Location` header value (a path or URL), if present.
#[must_use]
pub fn location(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::LOCATION)?
        .to_str()
        .ok()
        .map(str::to_owned)
}

/// The `name=value` pair from a `Set-Cookie` header (dropping the attributes),
/// ready to be echoed back as a `Cookie` header value.
#[must_use]
pub fn set_cookie_pair(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::SET_COOKIE)?.to_str().ok()?;
    Some(value.split(';').next()?.trim().to_owned())
}

/// Extract the value of a form input by `name` from a rendered HTML page. Used by
/// the end-to-end test to genuinely round-trip the hidden `return_to` field
/// through the login/registration/consent forms rather than shortcutting it.
#[must_use]
pub fn form_field(html: &str, name: &str) -> Option<String> {
    let needle = format!("name=\"{name}\"");
    let start = html.find(&needle)?;
    let value_marker = "value=\"";
    let after = &html[start..];
    let value_start = after.find(value_marker)? + value_marker.len();
    let value = &after[value_start..];
    let end = value.find('"')?;
    Some(html_unescape(&value[..end]))
}

/// Reverse the small set of HTML entities the page escaper emits, so a value read
/// back out of a rendered form matches what was put in.
#[must_use]
pub fn html_unescape(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .replace("&amp;", "&")
}
