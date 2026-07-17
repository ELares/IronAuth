// SPDX-License-Identifier: MIT OR Apache-2.0

//! Registration abuse defenses: the invisible proof-of-work challenge and the pluggable
//! challenge-provider interface (issue #80).
//!
//! # The self-contained proof-of-work (the DEFAULT)
//!
//! The built-in defense is a Rauthy-spow-style hashcash. The server issues a random
//! challenge and a difficulty; the client finds a nonce such that
//! `SHA-256(challenge || nonce)` has at least N leading zero bits; the server verifies the
//! nonce meets the difficulty and that the challenge is UNSPENT, UNEXPIRED, and
//! CONTEXT-BOUND. Verification is FULLY server-side and makes ZERO third-party calls, so
//! the defense works self-hosted, air-gapped, and privacy-clean, and can never fail
//! open/closed on an external outage. The single-use latch, the expiry, and the context
//! binding live in the `pow_challenges` store table (issue #80); the challenge randomness
//! comes from `env.entropy()` and the expiry from `env.clock()`, so the whole path is
//! deterministic under a test's manual clock and fixed entropy.
//!
//! # The pluggable interface
//!
//! [`ChallengeProvider`] is the seam: the built-in [`BuiltinPowProvider`] is the DEFAULT
//! implementation, and [`TurnstileProvider`] and [`RecaptchaProvider`] ship as OPTIONAL
//! adapters (honoring the no-mandatory-third-party-infrastructure covenant). An adapter's
//! real network verification goes through the audited `ironauth-fetch` seam behind a
//! [`RemoteChallengeVerifier`]; a mocked verifier satisfies the contract test. An adapter
//! OUTAGE degrades per a configurable fail-open / fail-closed policy applied by the caller;
//! the built-in `PoW` never depends on an external service, so it has no outage mode.

use std::fmt;
use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::sync::Arc;

use ironauth_config::SecretString;
use sha2::{Digest, Sha256};

/// The closed set of challenge providers (issue #80). The stable wire strings match the
/// `ironauth_config::PowProvider` config vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeProviderKind {
    /// The built-in, self-contained hashcash proof-of-work (the default). ZERO external
    /// calls.
    BuiltinPow,
    /// Cloudflare Turnstile (external adapter).
    Turnstile,
    /// Google reCAPTCHA (external adapter).
    Recaptcha,
}

impl ChallengeProviderKind {
    /// The stable wire string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ChallengeProviderKind::BuiltinPow => "builtin_pow",
            ChallengeProviderKind::Turnstile => "turnstile",
            ChallengeProviderKind::Recaptcha => "recaptcha",
        }
    }

    /// Whether this provider makes an OUTBOUND call to verify (issue #80). The built-in
    /// `PoW` never does (it is fully server-side), so it has no outage mode and the
    /// fail-open/closed policy never applies to it.
    #[must_use]
    pub fn is_external(self) -> bool {
        !matches!(self, ChallengeProviderKind::BuiltinPow)
    }
}

/// The outcome of a challenge verification (issue #80). `Unavailable` is distinct from
/// `Failed`: only an EXTERNAL adapter can be unavailable (an outage), and the caller maps
/// it through the configured fail-open / fail-closed policy. The built-in `PoW` returns only
/// `Passed` or `Failed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeVerdict {
    /// The solution satisfied the challenge.
    Passed,
    /// The solution did not satisfy the challenge (a wrong nonce, a rejected token, or a
    /// missing solution).
    Failed,
    /// An external adapter could not be reached (only ever returned by an adapter).
    Unavailable,
}

/// The built-in proof-of-work solution presented for verification (issue #80): the
/// challenge bytes the server issued (recovered from the store on the presented id) and
/// the nonce the client found, plus the required difficulty.
#[derive(Debug, Clone, Copy)]
pub struct PowSolution<'a> {
    /// The challenge bytes the server issued.
    pub challenge: &'a [u8],
    /// The nonce the client found.
    pub nonce: &'a [u8],
    /// The number of leading zero bits `SHA-256(challenge || nonce)` must have.
    pub difficulty_bits: u8,
}

/// The inputs one challenge verification reads (issue #80). Exactly one of `pow` (the
/// built-in path) or `token` (an external adapter path) is populated by the caller,
/// matching the configured provider; `remote_ip` is forwarded to an adapter as the
/// end-user address (never trusted for the built-in path).
#[derive(Debug, Clone, Copy, Default)]
pub struct ChallengeVerifyRequest<'a> {
    /// The resolved peer IP, forwarded to an external adapter (never used by the built-in
    /// `PoW`).
    pub remote_ip: Option<&'a str>,
    /// The built-in proof-of-work solution (present iff the configured provider is the
    /// built-in `PoW`).
    pub pow: Option<PowSolution<'a>>,
    /// The external adapter response token from the client widget (present iff the
    /// configured provider is an adapter).
    pub token: Option<&'a str>,
}

/// A boxed challenge-verification future (issue #80). An adapter awaits its outbound
/// verify here; the built-in `PoW` resolves immediately (it does no I/O).
pub type ChallengeFuture<'a> = Pin<Box<dyn Future<Output = ChallengeVerdict> + Send + 'a>>;

/// The pluggable challenge-provider interface (issue #80). The built-in
/// [`BuiltinPowProvider`] is the DEFAULT; Turnstile and reCAPTCHA ship as adapters behind
/// this same trait. `verify` is async so an adapter can await its outbound call; the
/// built-in `PoW`'s future is immediately ready (it makes ZERO third-party calls).
pub trait ChallengeProvider: Send + Sync + fmt::Debug {
    /// Which provider this is.
    fn kind(&self) -> ChallengeProviderKind;

    /// Verify a presented solution. The built-in `PoW` checks the nonce meets the difficulty
    /// for the issued challenge (single-use/expiry/context binding is enforced by the
    /// caller's store consume BEFORE this call); an adapter verifies the response token via
    /// its [`RemoteChallengeVerifier`], returning [`ChallengeVerdict::Unavailable`] on an
    /// outage.
    fn verify<'a>(&'a self, request: ChallengeVerifyRequest<'a>) -> ChallengeFuture<'a>;
}

// ===========================================================================
// The hashcash core (pure, sha2, ZERO third-party dependency)
// ===========================================================================

/// The number of LEADING ZERO BITS of `digest`, counted from the most significant bit of
/// the first byte (issue #80). A full-zero digest yields `8 * digest.len()`.
#[must_use]
pub fn leading_zero_bits(digest: &[u8]) -> u32 {
    let mut count = 0_u32;
    for byte in digest {
        if *byte == 0 {
            count += 8;
        } else {
            // `u8::leading_zeros` already reports the count within the 8-bit width.
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// Whether `nonce` solves the `challenge` at `difficulty_bits` (issue #80): whether
/// `SHA-256(challenge || nonce)` has at least `difficulty_bits` leading zero bits. Pure and
/// fully server-side; no third-party call.
#[must_use]
pub fn nonce_meets_difficulty(challenge: &[u8], nonce: &[u8], difficulty_bits: u8) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(challenge);
    hasher.update(nonce);
    let digest = hasher.finalize();
    leading_zero_bits(&digest) >= u32::from(difficulty_bits)
}

/// The context binding of a challenge (issue #80): `SHA-256(endpoint || 0x00 || context)`.
/// The challenge is BOUND to this digest, so a solution issued for one endpoint/context
/// cannot be replayed or outsourced to another: the store consume requires an exact match
/// on this value. `endpoint` is a stable per-endpoint label (`register`, `otp_send`,
/// `recover`); `context` is an optional caller-supplied request context.
#[must_use]
pub fn context_binding(endpoint: &str, context: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(endpoint.as_bytes());
    hasher.update([0_u8]);
    hasher.update(context.as_bytes());
    hasher.finalize().to_vec()
}

/// A REFERENCE solver (issue #80): find a nonce that solves `challenge` at
/// `difficulty_bits`, by scanning an incrementing counter. Returns `None` if no nonce is
/// found within `max_iterations` (a guard so a misconfigured difficulty cannot loop
/// forever). This is the client-side work the invisible browser solver performs; it is
/// also what the offline integration test uses to prove the built-in path is
/// self-contained (the whole solve/verify loop touches no network).
#[must_use]
pub fn solve(challenge: &[u8], difficulty_bits: u8, max_iterations: u64) -> Option<Vec<u8>> {
    for counter in 0..max_iterations {
        let nonce = counter.to_be_bytes();
        if nonce_meets_difficulty(challenge, &nonce, difficulty_bits) {
            return Some(nonce.to_vec());
        }
    }
    None
}

// ===========================================================================
// The built-in provider (the DEFAULT): self-contained, ZERO external calls
// ===========================================================================

/// The built-in proof-of-work provider (issue #80): the DEFAULT. It verifies the presented
/// nonce meets the challenge difficulty, fully server-side, with ZERO third-party calls, so
/// it can never fail open/closed on an outage. The single-use/expiry/context binding is
/// enforced by the caller's `pow_challenges` store consume before `verify` is reached.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinPowProvider;

impl ChallengeProvider for BuiltinPowProvider {
    fn kind(&self) -> ChallengeProviderKind {
        ChallengeProviderKind::BuiltinPow
    }

    fn verify<'a>(&'a self, request: ChallengeVerifyRequest<'a>) -> ChallengeFuture<'a> {
        let verdict = match request.pow {
            Some(solution)
                if nonce_meets_difficulty(
                    solution.challenge,
                    solution.nonce,
                    solution.difficulty_bits,
                ) =>
            {
                ChallengeVerdict::Passed
            }
            _ => ChallengeVerdict::Failed,
        };
        // The built-in path does NO I/O: the future is immediately ready. Boxing an
        // already-ready future keeps the trait object's return type uniform without
        // introducing any await point or third-party call.
        let ready: Ready<ChallengeVerdict> = ready(verdict);
        Box::pin(ready)
    }
}

// ===========================================================================
// The external adapters (OPTIONAL): Turnstile and reCAPTCHA
// ===========================================================================

/// The verdict of an EXTERNAL siteverify call (issue #80). Distinct from
/// [`ChallengeVerdict`] so an adapter maps its transport outcome (a 2xx `success:true`, a
/// 2xx `success:false`, or an unreachable provider) onto the uniform verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteVerdict {
    /// The provider confirmed the token.
    Success,
    /// The provider rejected the token.
    Failure,
    /// The provider could not be reached or returned an unusable response (an outage).
    Unavailable,
}

/// A boxed remote-verify future (issue #80).
pub type RemoteVerifyFuture<'a> = Pin<Box<dyn Future<Output = RemoteVerdict> + Send + 'a>>;

/// The outbound siteverify seam an external adapter calls (issue #80). The real
/// implementation posts the secret and the client token to the provider through the
/// audited `ironauth-fetch` path; a MOCK implementation satisfies the contract test with
/// no network. Keeping the outbound call behind this seam is what lets the adapters be
/// contract-tested without a live provider.
pub trait RemoteChallengeVerifier: Send + Sync + fmt::Debug {
    /// Verify `token` (the client widget response) with the provider, authenticated by the
    /// site `secret`, forwarding the end-user `remote_ip` when known.
    fn verify<'a>(
        &'a self,
        secret: &'a str,
        token: &'a str,
        remote_ip: Option<&'a str>,
    ) -> RemoteVerifyFuture<'a>;
}

/// Parse a provider siteverify JSON response body (issue #80): both Turnstile and reCAPTCHA
/// return a JSON object with a boolean `success` field. Returns `Some(true)`/`Some(false)`
/// for a well-formed response, or `None` when the body is not the expected shape (which the
/// caller treats as unavailable). Pure and unit-testable, so the adapter's response mapping
/// is covered without a live provider.
#[must_use]
pub fn parse_siteverify_success(body: &[u8]) -> Option<bool> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value.get("success")?.as_bool()
}

/// Map a raw siteverify body plus a reachability flag onto a [`RemoteVerdict`] (issue #80).
/// A body that is missing or malformed is `Unavailable` (treated as an outage), so a
/// provider that changes its wire shape fails per policy rather than silently admitting.
#[must_use]
pub fn remote_verdict_from_body(reachable: bool, body: &[u8]) -> RemoteVerdict {
    if !reachable {
        return RemoteVerdict::Unavailable;
    }
    match parse_siteverify_success(body) {
        Some(true) => RemoteVerdict::Success,
        Some(false) => RemoteVerdict::Failure,
        None => RemoteVerdict::Unavailable,
    }
}

/// Cloudflare Turnstile's default siteverify endpoint (issue #80).
pub const TURNSTILE_SITEVERIFY_URL: &str =
    "https://challenges.cloudflare.com/turnstile/v0/siteverify";
/// Google reCAPTCHA's default siteverify endpoint (issue #80).
pub const RECAPTCHA_SITEVERIFY_URL: &str = "https://www.google.com/recaptcha/api/siteverify";

/// An external siteverify adapter (issue #80): Turnstile or reCAPTCHA. Both providers share
/// the same request/response shape (POST `secret` + `response`, receive JSON `success`), so
/// one struct backs both, distinguished by its [`ChallengeProviderKind`]. The outbound call
/// is delegated to a [`RemoteChallengeVerifier`] seam, so the adapter is contract-tested
/// with a mock and reaches the real network only behind `ironauth-fetch`.
#[derive(Debug, Clone)]
pub struct SiteverifyProvider {
    kind: ChallengeProviderKind,
    secret: SecretString,
    verifier: Arc<dyn RemoteChallengeVerifier>,
}

impl SiteverifyProvider {
    /// A Cloudflare Turnstile adapter with the given site `secret` and outbound `verifier`.
    #[must_use]
    pub fn turnstile(secret: SecretString, verifier: Arc<dyn RemoteChallengeVerifier>) -> Self {
        Self {
            kind: ChallengeProviderKind::Turnstile,
            secret,
            verifier,
        }
    }

    /// A Google reCAPTCHA adapter with the given site `secret` and outbound `verifier`.
    #[must_use]
    pub fn recaptcha(secret: SecretString, verifier: Arc<dyn RemoteChallengeVerifier>) -> Self {
        Self {
            kind: ChallengeProviderKind::Recaptcha,
            secret,
            verifier,
        }
    }
}

impl ChallengeProvider for SiteverifyProvider {
    fn kind(&self) -> ChallengeProviderKind {
        self.kind
    }

    fn verify<'a>(&'a self, request: ChallengeVerifyRequest<'a>) -> ChallengeFuture<'a> {
        Box::pin(async move {
            let Some(token) = request.token else {
                // No token presented: an ordinary failure, not an outage.
                return ChallengeVerdict::Failed;
            };
            let remote = self
                .verifier
                .verify(self.secret.expose(), token, request.remote_ip)
                .await;
            match remote {
                RemoteVerdict::Success => ChallengeVerdict::Passed,
                RemoteVerdict::Failure => ChallengeVerdict::Failed,
                RemoteVerdict::Unavailable => ChallengeVerdict::Unavailable,
            }
        })
    }
}

/// A Turnstile adapter (issue #80): [`SiteverifyProvider::turnstile`].
#[must_use]
pub fn turnstile_provider(
    secret: SecretString,
    verifier: Arc<dyn RemoteChallengeVerifier>,
) -> SiteverifyProvider {
    SiteverifyProvider::turnstile(secret, verifier)
}

/// A reCAPTCHA adapter (issue #80): [`SiteverifyProvider::recaptcha`].
#[must_use]
pub fn recaptcha_provider(
    secret: SecretString,
    verifier: Arc<dyn RemoteChallengeVerifier>,
) -> SiteverifyProvider {
    SiteverifyProvider::recaptcha(secret, verifier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_zero_bits_counts_from_the_top() {
        assert_eq!(leading_zero_bits(&[0xFF]), 0);
        assert_eq!(leading_zero_bits(&[0x00, 0xFF]), 8);
        assert_eq!(leading_zero_bits(&[0x0F]), 4);
        assert_eq!(leading_zero_bits(&[0x00, 0x00]), 16);
        assert_eq!(leading_zero_bits(&[0x01]), 7);
    }

    #[test]
    fn solve_finds_a_qualifying_nonce_and_verify_accepts_it() {
        let challenge = b"a-random-challenge";
        let difficulty = 12;
        let nonce = solve(challenge, difficulty, 1_000_000).expect("a nonce exists at low bits");
        assert!(nonce_meets_difficulty(challenge, &nonce, difficulty));
        // A different challenge is not satisfied by the same nonce (overwhelmingly).
        assert!(!nonce_meets_difficulty(
            b"other-challenge",
            &nonce,
            difficulty
        ));
    }

    #[test]
    fn context_binding_differs_per_endpoint_and_context() {
        let a = context_binding("register", "ctx");
        let b = context_binding("otp_send", "ctx");
        let c = context_binding("register", "other");
        assert_ne!(a, b, "the endpoint label changes the binding");
        assert_ne!(a, c, "the request context changes the binding");
    }

    #[tokio::test]
    async fn builtin_provider_passes_a_valid_nonce_and_fails_a_bad_one() {
        let provider = BuiltinPowProvider;
        assert_eq!(provider.kind(), ChallengeProviderKind::BuiltinPow);
        assert!(!provider.kind().is_external());
        let challenge = b"challenge-bytes";
        let difficulty = 10;
        let nonce = solve(challenge, difficulty, 1_000_000).expect("solvable");
        let passed = provider
            .verify(ChallengeVerifyRequest {
                pow: Some(PowSolution {
                    challenge,
                    nonce: &nonce,
                    difficulty_bits: difficulty,
                }),
                ..ChallengeVerifyRequest::default()
            })
            .await;
        assert_eq!(passed, ChallengeVerdict::Passed);
        let failed = provider
            .verify(ChallengeVerifyRequest {
                pow: Some(PowSolution {
                    challenge,
                    nonce: b"wrong",
                    difficulty_bits: difficulty,
                }),
                ..ChallengeVerifyRequest::default()
            })
            .await;
        assert_eq!(failed, ChallengeVerdict::Failed);
        // A missing solution is a failure, never a pass.
        let missing = provider.verify(ChallengeVerifyRequest::default()).await;
        assert_eq!(missing, ChallengeVerdict::Failed);
    }

    /// A mock outbound verifier for the adapter contract test: it returns a canned verdict
    /// with NO network, standing in for the real `ironauth-fetch`-backed verifier.
    #[derive(Debug)]
    struct MockRemoteVerifier(RemoteVerdict);

    impl RemoteChallengeVerifier for MockRemoteVerifier {
        fn verify<'a>(
            &'a self,
            _secret: &'a str,
            _token: &'a str,
            _remote_ip: Option<&'a str>,
        ) -> RemoteVerifyFuture<'a> {
            let verdict = self.0;
            Box::pin(async move { verdict })
        }
    }

    #[tokio::test]
    async fn adapters_map_the_remote_verdict_uniformly() {
        for (make, kind) in [
            (
                SiteverifyProvider::turnstile
                    as fn(SecretString, Arc<dyn RemoteChallengeVerifier>) -> SiteverifyProvider,
                ChallengeProviderKind::Turnstile,
            ),
            (
                SiteverifyProvider::recaptcha,
                ChallengeProviderKind::Recaptcha,
            ),
        ] {
            for (remote, expected) in [
                (RemoteVerdict::Success, ChallengeVerdict::Passed),
                (RemoteVerdict::Failure, ChallengeVerdict::Failed),
                (RemoteVerdict::Unavailable, ChallengeVerdict::Unavailable),
            ] {
                let provider = make(
                    SecretString::new("site-secret"),
                    Arc::new(MockRemoteVerifier(remote)),
                );
                assert_eq!(provider.kind(), kind);
                assert!(provider.kind().is_external());
                let verdict = provider
                    .verify(ChallengeVerifyRequest {
                        token: Some("client-token"),
                        remote_ip: Some("203.0.113.7"),
                        ..ChallengeVerifyRequest::default()
                    })
                    .await;
                assert_eq!(verdict, expected, "{} maps {remote:?}", kind.as_str());
            }
            // A missing token is an ordinary failure, never an outage.
            let provider = make(
                SecretString::new("s"),
                Arc::new(MockRemoteVerifier(RemoteVerdict::Success)),
            );
            let verdict = provider.verify(ChallengeVerifyRequest::default()).await;
            assert_eq!(verdict, ChallengeVerdict::Failed);
        }
    }

    #[test]
    fn parse_siteverify_reads_the_success_flag() {
        assert_eq!(parse_siteverify_success(br#"{"success":true}"#), Some(true));
        assert_eq!(
            parse_siteverify_success(br#"{"success":false,"error-codes":[]}"#),
            Some(false)
        );
        assert_eq!(parse_siteverify_success(b"not json"), None);
        assert_eq!(
            remote_verdict_from_body(false, b""),
            RemoteVerdict::Unavailable
        );
        assert_eq!(
            remote_verdict_from_body(true, br#"{"success":true}"#),
            RemoteVerdict::Success
        );
        assert_eq!(
            remote_verdict_from_body(true, b"garbage"),
            RemoteVerdict::Unavailable
        );
    }
}
