// SPDX-License-Identifier: MIT OR Apache-2.0

//! The JWT-assertion client-authentication suite (issue #25), over a real
//! database.
//!
//! Exercises `private_key_jwt` end to end through the reusable
//! [`ironauth_oidc::authenticate_client`] seam (the SAME seam the token endpoint
//! uses now and introspection/revocation, #22, will use): the per-algorithm
//! matrix (`RS256`/384/512, `ES256`/384, `PS256`/384/512, `EdDSA`) with an
//! `ES512`-rejected
//! negative, the RFC 7523 claim rules (`iss`/`sub` == client id, the audience
//! policy, `exp` within skew, single-use `jti`), the opaque `invalid_client` wire
//! error paired with the out-of-band diagnostic, `jwks_uri` resolution and caching
//! through the SSRF-hardened fetcher, and a full token-endpoint exchange.

mod common;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::http::{StatusCode, header};
use common::{Harness, REDIRECT_URI, form, json};
use ironauth_config::{ClientAssertionAudience, OidcConfig};
use ironauth_fetch::{FetchLimits, Fetcher, RecordingDialer, StaticResolver};
use ironauth_jose::{EmissionOptions, JwkSet, JwsAlgorithm, SigningKey, sign_jws};
use ironauth_oidc::{
    ClientAuthError, ClientAuthInputs, ClientAuthMethod, ClientKeyResolver,
    JWT_BEARER_ASSERTION_TYPE, authenticate_client,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// Committed throwaway private-key fixtures (generated once offline, exactly like
// the ironauth-jose signing fixtures): an ES256 and ES384 PKCS#8 from ring's
// `generate_pkcs8`, and a 2048-bit RSA PKCS#1 DER `ring` accepts. Secret only in
// the technical sense.
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
const ES384_PKCS8: &[u8] = &[
    0x30, 0x81, 0xb6, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x04, 0x81, 0x9e, 0x30, 0x81, 0x9b, 0x02, 0x01,
    0x01, 0x04, 0x30, 0x80, 0xb4, 0x3b, 0xcf, 0x7b, 0x6f, 0x17, 0x5d, 0x0d, 0x34, 0x6a, 0x0a, 0x11,
    0x02, 0x98, 0x9c, 0xea, 0x77, 0x0e, 0xd5, 0x5a, 0x79, 0x5e, 0xb3, 0x45, 0xcf, 0xee, 0xa1, 0x7d,
    0x36, 0x96, 0x54, 0x49, 0x99, 0x84, 0x6d, 0x3e, 0xbf, 0x78, 0x0a, 0xdc, 0x19, 0xe3, 0xd2, 0x34,
    0x2d, 0x3e, 0x01, 0xa1, 0x64, 0x03, 0x62, 0x00, 0x04, 0x41, 0x2b, 0x1c, 0x7b, 0xfb, 0x53, 0xd7,
    0x06, 0xb5, 0xf9, 0x80, 0x88, 0x9d, 0x87, 0x15, 0x38, 0x23, 0x42, 0x85, 0xb8, 0xd3, 0xeb, 0x44,
    0xcb, 0x8a, 0x5d, 0xae, 0x1c, 0xa7, 0xb4, 0xca, 0xc9, 0x3b, 0xbe, 0x43, 0x4a, 0xf9, 0xb3, 0xc9,
    0x47, 0x54, 0x76, 0xb6, 0xb3, 0xe2, 0x30, 0xab, 0x82, 0xc9, 0x2e, 0x15, 0x85, 0xae, 0xf2, 0xeb,
    0xf7, 0xc8, 0xf3, 0x97, 0xb1, 0xda, 0x5d, 0x7c, 0xfc, 0x50, 0x22, 0x5c, 0xb2, 0x0d, 0xd9, 0x6a,
    0xf2, 0xa1, 0x13, 0xa3, 0xdc, 0x60, 0xc9, 0x9c, 0x3c, 0x8a, 0x36, 0xba, 0xa5, 0x14, 0x8b, 0x24,
    0x1d, 0xa3, 0x0d, 0x19, 0x19, 0x93, 0xa5, 0xa8, 0x40,
];
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

/// Every `private_key_jwt` algorithm the matrix covers.
const MATRIX_ALGS: &[JwsAlgorithm] = &[
    JwsAlgorithm::EdDsa,
    JwsAlgorithm::Es256,
    JwsAlgorithm::Es384,
    JwsAlgorithm::Rs256,
    JwsAlgorithm::Rs384,
    JwsAlgorithm::Rs512,
    JwsAlgorithm::Ps256,
    JwsAlgorithm::Ps384,
    JwsAlgorithm::Ps512,
];

/// A signing key for `alg` from a committed fixture (one RSA key serves the whole
/// RS/PS family; `algorithm` fixes which one it signs).
fn signing_key_for(alg: JwsAlgorithm) -> SigningKey {
    let kid = Some("ck".to_owned());
    match alg {
        JwsAlgorithm::EdDsa => SigningKey::ed25519_from_seed(kid, &[9_u8; 32]).expect("ed25519"),
        JwsAlgorithm::Es256 => SigningKey::ecdsa_p256_from_pkcs8(kid, ES256_PKCS8).expect("es256"),
        JwsAlgorithm::Es384 => SigningKey::ecdsa_p384_from_pkcs8(kid, ES384_PKCS8).expect("es384"),
        rsa => SigningKey::rsa_from_pkcs1_der(kid, rsa, RSA_PKCS1).expect("rsa"),
    }
}

/// The public JWK Set JSON for `key`, exactly what a client publishes.
fn jwks_json(key: &SigningKey) -> String {
    JwkSet::from_signing_keys([key])
        .expect("jwk set")
        .to_json()
        .expect("jwks json")
}

/// Build a signed client assertion with the given claims.
fn build_assertion(
    key: &SigningKey,
    iss: &str,
    sub: &str,
    aud: &str,
    exp: i64,
    jti: &str,
) -> String {
    let claims = serde_json::json!({
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "exp": exp,
        "iat": 0,
        "jti": jti,
    });
    let payload = serde_json::to_vec(&claims).expect("serialize claims");
    sign_jws(key, &payload, &EmissionOptions::new()).expect("sign assertion")
}

/// Present a client assertion to the reusable seam in the harness scope.
async fn present(
    h: &Harness,
    assertion: &str,
) -> Result<ironauth_oidc::AuthenticatedClient, ClientAuthError> {
    authenticate_client(
        h.state(),
        h.scope(),
        ClientAuthInputs {
            client_assertion: Some(assertion),
            client_assertion_type: Some(JWT_BEARER_ASSERTION_TYPE),
            ..ClientAuthInputs::default()
        },
    )
    .await
}

#[tokio::test]
async fn private_key_jwt_authenticates_across_the_whole_algorithm_matrix() {
    let h = Harness::start().await;
    for &alg in MATRIX_ALGS {
        let key = signing_key_for(alg);
        let jwks = jwks_json(&key);
        let client = h
            .create_jwt_auth_client(ClientAuthMethod::PrivateKeyJwt, Some(&jwks), None, None)
            .await;
        let cid = client.to_string();
        let assertion = build_assertion(
            &key,
            &cid,
            &cid,
            h.issuer(),
            3600,
            &format!("jti-{}", alg.as_jose_name()),
        );
        let result = present(&h, &assertion).await;
        let authenticated =
            result.unwrap_or_else(|e| panic!("{} should authenticate: {e:?}", alg.as_jose_name()));
        assert_eq!(authenticated.client_id, cid);
    }
}

#[tokio::test]
async fn an_es512_assertion_is_rejected_and_diagnosed() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let h = Harness::start().await;
    // A private_key_jwt client with a P-384 key; a genuine ES384 would verify.
    let key = signing_key_for(JwsAlgorithm::Es384);
    let jwks = jwks_json(&key);
    let client = h
        .create_jwt_auth_client(ClientAuthMethod::PrivateKeyJwt, Some(&jwks), None, None)
        .await;
    let cid = client.to_string();

    // Hand-craft an assertion whose header claims the EXCLUDED ES512 (M1 exclusion,
    // the P-521 family). Even with a plausible payload it is rejected at the alg
    // stage, before any signature check, so a garbage signature suffices.
    let head = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES512","kid":"ck"}"#);
    let claims = serde_json::json!({
        "iss": cid, "sub": cid, "aud": h.issuer(), "exp": 3600, "iat": 0, "jti": "jti-es512",
    });
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims"));
    let assertion = format!("{head}.{payload}.c2lnbmF0dXJl");

    let result = present(&h, &assertion).await;
    assert!(
        matches!(result, Err(ClientAuthError::InvalidClient { .. })),
        "an ES512 assertion must be rejected: {result:?}"
    );
    let diags = h.client_auth_diagnostics(&cid).await;
    assert!(
        diags
            .iter()
            .any(|d| d.signing_alg.as_deref() == Some("ES512")
                && d.failure_reason == "assertion_invalid"),
        "the ES512 attempt is diagnosed out of band: {diags:?}"
    );
}

#[tokio::test]
async fn the_rfc7523_claim_rules_are_enforced_with_opaque_errors_and_diagnostics() {
    let h = Harness::start().await;
    let key = signing_key_for(JwsAlgorithm::EdDsa);
    let jwks = jwks_json(&key);
    let client = h
        .create_jwt_auth_client(ClientAuthMethod::PrivateKeyJwt, Some(&jwks), None, None)
        .await;
    let cid = client.to_string();

    // A correct assertion authenticates (control).
    assert!(
        present(
            &h,
            &build_assertion(&key, &cid, &cid, h.issuer(), 3600, "jti-ok")
        )
        .await
        .is_ok()
    );

    // Bad sub: an assertion that names another subject. The client id is derived
    // from the sub, so this resolves to (and is diagnosed against) an unknown
    // client, itself a correct rejection.
    let bad_sub = build_assertion(
        &key,
        "cli_other",
        "cli_other",
        h.issuer(),
        3600,
        "jti-badsub",
    );
    assert!(matches!(
        present(&h, &bad_sub).await,
        Err(ClientAuthError::InvalidClient { via_basic: false })
    ));
    assert!(
        h.client_auth_diagnostics("cli_other")
            .await
            .iter()
            .any(|d| d.failure_reason == "unknown_client"),
        "an assertion for an unknown subject is diagnosed as an unknown client"
    );

    // Missing sub (a form client_id resolves the client, but the assertion carries
    // no sub): the RFC 7523 iss/sub == client_id rule refuses it.
    let no_sub = {
        let claims = serde_json::json!({
            "iss": cid, "aud": h.issuer(), "exp": 3600, "iat": 0, "jti": "jti-nosub",
        });
        let payload = serde_json::to_vec(&claims).expect("claims");
        sign_jws(&key, &payload, &EmissionOptions::new()).expect("sign")
    };
    assert!(matches!(
        authenticate_client(
            h.state(),
            h.scope(),
            ClientAuthInputs {
                client_id: Some(&cid),
                client_assertion: Some(&no_sub),
                client_assertion_type: Some(JWT_BEARER_ASSERTION_TYPE),
                ..ClientAuthInputs::default()
            },
        )
        .await,
        Err(ClientAuthError::InvalidClient { .. })
    ));

    // Bad iss (sub right, iss != client id).
    let bad_iss = build_assertion(&key, "cli_other", &cid, h.issuer(), 3600, "jti-badiss");
    assert!(matches!(
        present(&h, &bad_iss).await,
        Err(ClientAuthError::InvalidClient { .. })
    ));

    // Bad aud (an audience the policy does not accept).
    let bad_aud = build_assertion(&key, &cid, &cid, "https://evil.test", 3600, "jti-badaud");
    assert!(matches!(
        present(&h, &bad_aud).await,
        Err(ClientAuthError::InvalidClient { .. })
    ));

    // Expired (exp far before now, beyond skew): the epoch clock rejects it.
    let expired = build_assertion(&key, &cid, &cid, h.issuer(), -1000, "jti-expired");
    assert!(matches!(
        present(&h, &expired).await,
        Err(ClientAuthError::InvalidClient { .. })
    ));

    // Missing jti: single use is unprovable, so the assertion is refused.
    let no_jti = {
        let claims = serde_json::json!({
            "iss": cid, "sub": cid, "aud": h.issuer(), "exp": 3600, "iat": 0,
        });
        let payload = serde_json::to_vec(&claims).expect("claims");
        sign_jws(&key, &payload, &EmissionOptions::new()).expect("sign")
    };
    assert!(matches!(
        present(&h, &no_jti).await,
        Err(ClientAuthError::InvalidClient { .. })
    ));

    // Every failure recorded a diagnostic out of band (opaque on the wire, rich in
    // the store): several assertion_invalid rows for this client.
    let diags = h.client_auth_diagnostics(&cid).await;
    assert!(
        diags
            .iter()
            .filter(|d| d.failure_reason == "assertion_invalid")
            .count()
            >= 5,
        "each failed claim rule is diagnosed: {diags:?}"
    );
}

#[tokio::test]
async fn a_replayed_jti_is_rejected_through_the_seam() {
    // AC2: single use, enforced by the shared database (the store-level two-node
    // proof lives in ironauth-store; here it is proven through the OIDC seam).
    let h = Harness::start().await;
    let key = signing_key_for(JwsAlgorithm::EdDsa);
    let jwks = jwks_json(&key);
    let client = h
        .create_jwt_auth_client(ClientAuthMethod::PrivateKeyJwt, Some(&jwks), None, None)
        .await;
    let cid = client.to_string();
    let assertion = build_assertion(&key, &cid, &cid, h.issuer(), 3600, "jti-replay");

    assert!(present(&h, &assertion).await.is_ok(), "first use");
    assert!(
        matches!(
            present(&h, &assertion).await,
            Err(ClientAuthError::InvalidClient { .. })
        ),
        "the same jti cannot be reused"
    );
    let diags = h.client_auth_diagnostics(&cid).await;
    assert!(
        diags.iter().any(|d| d.failure_reason == "replayed_jti"),
        "the replay is diagnosed: {diags:?}"
    );
}

#[tokio::test]
async fn dual_authentication_methods_are_rejected_as_invalid_request() {
    // AC4: presenting two methods at once (a client_secret AND a client_assertion).
    let h = Harness::start().await;
    let key = signing_key_for(JwsAlgorithm::EdDsa);
    let assertion = build_assertion(&key, "cli_dual", "cli_dual", h.issuer(), 3600, "jti-dual");
    let result = authenticate_client(
        h.state(),
        h.scope(),
        ClientAuthInputs {
            client_id: Some("cli_dual"),
            client_secret: Some("a-secret"),
            client_assertion: Some(&assertion),
            client_assertion_type: Some(JWT_BEARER_ASSERTION_TYPE),
            ..ClientAuthInputs::default()
        },
    )
    .await;
    assert!(
        matches!(result, Err(ClientAuthError::InvalidRequest(_))),
        "two methods are an invalid_request: {result:?}"
    );
    // The dual-method attempt is diagnosed out of band too.
    let diags = h.client_auth_diagnostics("cli_dual").await;
    assert!(
        diags.iter().any(|d| d.failure_reason == "unparsable"),
        "dual-method is diagnosed: {diags:?}"
    );
}

#[tokio::test]
async fn the_audience_policy_accepts_issuer_or_token_endpoint_and_strict_rejects_the_endpoint() {
    // Default (token_endpoint_or_issuer): both audiences authenticate.
    let h = Harness::start().await;
    let key = signing_key_for(JwsAlgorithm::EdDsa);
    let jwks = jwks_json(&key);
    let client = h
        .create_jwt_auth_client(ClientAuthMethod::PrivateKeyJwt, Some(&jwks), None, None)
        .await;
    let cid = client.to_string();
    let token_endpoint = h.state().token_endpoint_url();

    assert!(
        present(
            &h,
            &build_assertion(&key, &cid, &cid, h.issuer(), 3600, "jti-iss")
        )
        .await
        .is_ok(),
        "issuer audience accepted by default"
    );
    assert!(
        present(
            &h,
            &build_assertion(&key, &cid, &cid, &token_endpoint, 3600, "jti-tep")
        )
        .await
        .is_ok(),
        "token-endpoint audience accepted by default"
    );

    // Strict (issuer_only): the token-endpoint audience is rejected, the issuer
    // still accepted.
    let strict = Harness::start_with(OidcConfig {
        require_pkce_for_confidential_clients: false,
        client_assertion_audience: ClientAssertionAudience::IssuerOnly,
        ..OidcConfig::default()
    })
    .await;
    let key2 = signing_key_for(JwsAlgorithm::EdDsa);
    let jwks2 = jwks_json(&key2);
    let client2 = strict
        .create_jwt_auth_client(ClientAuthMethod::PrivateKeyJwt, Some(&jwks2), None, None)
        .await;
    let cid2 = client2.to_string();
    let strict_endpoint = strict.state().token_endpoint_url();
    assert!(
        matches!(
            present(
                &strict,
                &build_assertion(&key2, &cid2, &cid2, &strict_endpoint, 3600, "jti-tep2")
            )
            .await,
            Err(ClientAuthError::InvalidClient { .. })
        ),
        "strict mode rejects a token-endpoint-audienced assertion"
    );
    assert!(
        present(
            &strict,
            &build_assertion(&key2, &cid2, &cid2, strict.issuer(), 3600, "jti-iss2")
        )
        .await
        .is_ok(),
        "strict mode still accepts the issuer audience"
    );
}

#[tokio::test]
async fn client_secret_jwt_registration_is_refused_loud() {
    // The tradeoff: IronAuth stores no retrievable secret to key an HMAC, so
    // client_secret_jwt is inert. Rather than register a client that would silently
    // fail every request, the registration itself is refused LOUD (a Conflict), so no
    // client_secret_jwt client can ever reach the token endpoint. The method also
    // stays unadvertised in discovery (asserted in discovery.rs) and the runtime
    // fail-closed arm remains as defense in depth.
    let h = Harness::start().await;
    let rejected = h
        .try_create_jwt_auth_client(ClientAuthMethod::ClientSecretJwt, None, None, None)
        .await;
    assert!(
        matches!(rejected, Err(ironauth_store::StoreError::Conflict)),
        "client_secret_jwt registration is refused: {rejected:?}"
    );
}

#[tokio::test]
async fn a_jti_cannot_replay_anywhere_in_the_final_acceptance_second() {
    // FIX (issue #25 review): acceptance (enforce_exp) floors `now` to WHOLE seconds
    // and rejects only once now_secs > exp+skew, so an assertion is acceptable for the
    // ENTIRE wall-clock second [exp+skew, exp+skew+1). The recorder retains the jti to
    // exp+skew+1s, so a replay is caught across that whole second; it stops being
    // replay-relevant only once the assertion itself is no longer acceptable.
    let h = Harness::start().await;
    let key = signing_key_for(JwsAlgorithm::EdDsa);
    let jwks = jwks_json(&key);
    let client = h
        .create_jwt_auth_client(ClientAuthMethod::PrivateKeyJwt, Some(&jwks), None, None)
        .await;
    let cid = client.to_string();

    let skew_secs = h.state().client_assertion_skew().as_secs();
    let exp_secs: u64 = 100;
    let assertion = build_assertion(
        &key,
        &cid,
        &cid,
        h.issuer(),
        i64::try_from(exp_secs).expect("small exp"),
        "jti-boundary",
    );

    // First use at the epoch (now = 0): recorded.
    assert!(present(&h, &assertion).await.is_ok(), "first use");

    // Advance to EXACTLY exp+skew (the last acceptable whole second). The assertion is
    // still acceptable, so the replay is caught by the single-use cache (not slipped
    // through by a prune): opaque invalid_client with a replayed_jti diagnostic.
    h.clock().advance(Duration::from_secs(exp_secs + skew_secs));
    assert!(
        matches!(
            present(&h, &assertion).await,
            Err(ClientAuthError::InvalidClient { .. })
        ),
        "replay at exp+skew is rejected"
    );

    // Half a second later (still the same acceptance second): still a replay.
    h.clock().advance(Duration::from_millis(500));
    assert!(
        matches!(
            present(&h, &assertion).await,
            Err(ClientAuthError::InvalidClient { .. })
        ),
        "replay at exp+skew+0.5s is rejected"
    );
    let diags = h.client_auth_diagnostics(&cid).await;
    assert!(
        diags.iter().any(|d| d.failure_reason == "replayed_jti"),
        "the replay is diagnosed within the window: {diags:?}"
    );

    // Advance to exp+skew+1s: now_secs > exp+skew, so the assertion is no longer
    // acceptable. It is still rejected (fail closed), now because verification refuses
    // the expired assertion rather than because the jti is spent.
    h.clock().advance(Duration::from_millis(500));
    assert!(
        matches!(
            present(&h, &assertion).await,
            Err(ClientAuthError::InvalidClient { .. })
        ),
        "the assertion is refused once it is no longer acceptable"
    );
}

#[tokio::test]
async fn a_client_pinned_to_eddsa_rejects_an_rs256_assertion() {
    // FIX (issue #25 review): the per-client token_endpoint_auth_signing_alg is a
    // strict allowlist. A client pinned to EdDSA must REJECT an otherwise-valid RS256
    // assertion end to end (the per-client pin was only unit-tested on the returned
    // Vec before). The key is RSA (so the RS256 signature itself is genuine), but the
    // pin bans RS256, so verification refuses it before ever recording the jti.
    let h = Harness::start().await;
    let key = signing_key_for(JwsAlgorithm::Rs256);
    let jwks = jwks_json(&key);
    let client = h
        .create_jwt_auth_client(
            ClientAuthMethod::PrivateKeyJwt,
            Some(&jwks),
            None,
            Some("EdDSA"),
        )
        .await;
    let cid = client.to_string();
    let assertion = build_assertion(&key, &cid, &cid, h.issuer(), 3600, "jti-pinned-rs256");
    assert!(
        matches!(
            present(&h, &assertion).await,
            Err(ClientAuthError::InvalidClient { .. })
        ),
        "an EdDSA-pinned client rejects an RS256 assertion"
    );
    let diags = h.client_auth_diagnostics(&cid).await;
    assert!(
        diags
            .iter()
            .any(|d| d.failure_reason == "assertion_invalid"),
        "the disallowed algorithm is diagnosed: {diags:?}"
    );
}

#[tokio::test]
async fn an_empty_or_whitespace_jti_is_treated_as_missing_and_rejected() {
    // FIX (issue #25 review): jti = "" parsed to Some("") and was accepted. RFC 7523
    // intends a real token identifier, so an empty or whitespace-only jti is no jti:
    // single use is unprovable and the assertion is refused (never recorded as a blank
    // single-use key).
    let h = Harness::start().await;
    let key = signing_key_for(JwsAlgorithm::EdDsa);
    let jwks = jwks_json(&key);
    let client = h
        .create_jwt_auth_client(ClientAuthMethod::PrivateKeyJwt, Some(&jwks), None, None)
        .await;
    let cid = client.to_string();
    for blank in ["", "   "] {
        let assertion = build_assertion(&key, &cid, &cid, h.issuer(), 3600, blank);
        assert!(
            matches!(
                present(&h, &assertion).await,
                Err(ClientAuthError::InvalidClient { .. })
            ),
            "an empty/whitespace jti ({blank:?}) is rejected"
        );
    }
}

#[tokio::test]
async fn eddsa_private_key_jwt_via_jwks_uri_authenticates_and_caches() {
    // AC1: an EdDSA assertion authenticates with keys served from jwks_uri, fetched
    // through the SSRF-hardened fetcher; a second use hits the cache (no refetch).
    let key = signing_key_for(JwsAlgorithm::EdDsa);
    let jwks = jwks_json(&key);
    let server = start_jwks_server(jwks).await;

    // A fetcher whose resolver returns a public sentinel (so the SSRF deny policy
    // passes) and whose dialer forwards to the loopback JWKS server, wrapped in a
    // resolver that permits the plaintext test target.
    let dialer = Arc::new(RecordingDialer::new(server));
    let resolver_seam = Arc::new(StaticResolver::new(vec![IpAddr::from([8, 8, 8, 8])]));
    let fetcher = Fetcher::from_parts(FetchLimits::default(), resolver_seam, Arc::clone(&dialer));
    let resolver = Arc::new(ClientKeyResolver::new_allow_http(
        Arc::new(fetcher),
        Duration::from_secs(300),
    ));

    let h = Harness::start_with_resolver(
        OidcConfig {
            require_pkce_for_confidential_clients: false,
            ..OidcConfig::default()
        },
        resolver,
    )
    .await;
    let client = h
        .create_jwt_auth_client(
            ClientAuthMethod::PrivateKeyJwt,
            None,
            Some("http://client.test/jwks.json"),
            None,
        )
        .await;
    let cid = client.to_string();

    assert!(
        present(
            &h,
            &build_assertion(&key, &cid, &cid, h.issuer(), 3600, "jti-uri-1")
        )
        .await
        .is_ok(),
        "first authentication fetches the jwks_uri"
    );
    assert!(
        present(
            &h,
            &build_assertion(&key, &cid, &cid, h.issuer(), 3600, "jti-uri-2")
        )
        .await
        .is_ok(),
        "second authentication uses the cached keys"
    );
    assert_eq!(
        dialer.requested().len(),
        1,
        "the jwks_uri is fetched exactly once (the resolution is cached)"
    );
}

#[tokio::test]
async fn a_private_key_jwt_client_completes_a_token_exchange_and_a_bad_assertion_is_opaque_401() {
    // AC6: the token endpoint enforces the registered method through the same seam.
    let h = Harness::start().await;
    let key = signing_key_for(JwsAlgorithm::EdDsa);
    let jwks = jwks_json(&key);
    let client = h
        .create_jwt_auth_client(ClientAuthMethod::PrivateKeyJwt, Some(&jwks), None, None)
        .await;
    let cid = client.to_string();

    let code = h.issue_authenticated_code(&cid).await;
    let assertion = build_assertion(&key, &cid, &cid, h.issuer(), 3600, "jti-http-ok");
    let body = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_assertion_type", JWT_BEARER_ASSERTION_TYPE),
        ("client_assertion", &assertion),
    ]);
    let (status, _headers, response) = h.token(&body).await;
    assert_eq!(status, StatusCode::OK, "exchange: {response}");
    assert!(json(&response)["access_token"].is_string());

    // A bad assertion (wrong sub) on a fresh code: opaque 401 invalid_client with
    // NO WWW-Authenticate (the credential was in the body, not the header).
    let code2 = h.issue_authenticated_code(&cid).await;
    let bad = build_assertion(&key, &cid, "cli_wrong", h.issuer(), 3600, "jti-http-bad");
    let body2 = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code2),
        ("redirect_uri", REDIRECT_URI),
        ("client_assertion_type", JWT_BEARER_ASSERTION_TYPE),
        ("client_assertion", &bad),
    ]);
    let (status2, headers2, response2) = h.token(&body2).await;
    assert_eq!(status2, StatusCode::UNAUTHORIZED, "{response2}");
    assert_eq!(json(&response2)["error"], "invalid_client");
    assert!(
        !headers2.contains_key(header::WWW_AUTHENTICATE),
        "an assertion failure carries no WWW-Authenticate"
    );
}

/// Start an in-process loopback HTTP server that serves `body` as a JSON JWKS to
/// every request, returning its address. The fetcher's injected dialer forwards
/// to this address, so the fetch exercises the real hardened dispatcher over
/// plaintext http without a public network.
async fn start_jwks_server(body: String) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let body = body.clone();
            tokio::spawn(async move {
                // Drain the request head (up to the blank line); the content is
                // irrelevant, the server answers the same JWKS regardless.
                let mut buf = [0_u8; 2048];
                let _ = socket.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });
    addr
}
