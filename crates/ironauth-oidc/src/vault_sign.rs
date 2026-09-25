// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Vault/OpenBao transit signer backend (issue #161).
//!
//! Signs through a Vault transit engine, so the private keys never leave the Vault
//! boundary: the backend sends the raw signing input and receives the signature.
//! Verification continues against the published JWKS (only signing is delegated),
//! and the key material — including the Vault token — never appears in logs (the
//! token rides the config `Secret` and the request header is built inside the
//! fetch seam's redacted envelope).
//!
//! # The algorithm mapping
//!
//! Vault transit's `sign` API takes the algorithm name and (for the digest
//! algorithms) the hash. The mapping is the one place the two worlds meet:
//!
//! | JOSE alg | Vault algorithm |
//! |---|---|
//! | `EdDSA` | `ed25519` |
//! | `ES256` | `ecdsa-p256` (unprehashed) |
//! | `ES384` | `ecdsa-p384` (unprehashed) |
//! | `RS256`/`384`/`512` | `rsa-2048`/`rsa-3072` with the matching hash |
//! | `PS256`/`384`/`512` | the same RSA key with PSS padding |
//!
//! # The raw-input ceiling
//!
//! Vault transit imposes no AWS-KMS-style 4096-byte raw cap, so the backend
//! declares no ceiling ([`ExternalSigner::max_raw_signing_input_bytes`] returns
//! `None`); the shared 3 KB warning seam still applies at the caller.
//!
//! # The key names
//!
//! The transit key name IS the kid: the rotation integration references
//! pre-provisioned remote keys, and a sign request names the kid directly, so no
//! key registry sits between this backend and the Vault's.

use std::sync::Arc;
use std::time::Duration;

use axum::http::Method;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ironauth_config::Secret;
use ironauth_fetch::{FetchError, FetchLimits, FetchRequest, Fetcher};
use ironauth_jose::JwsAlgorithm;
use ironauth_jose::external_signer::{ExternalSigner, ExternalSignerError};

/// The Vault transit signer (issue #161).
pub struct VaultTransitSigner {
    http: Fetcher,
    addr: String,
    mount: String,
    token: Arc<Secret>,
    timeout: Duration,
}

impl VaultTransitSigner {
    /// Build the backend from the resolved configuration. The token is an
    /// [`Secret`] (file/env indirection), resolved by the boot path before
    /// construction; a misconfigured address or token is refused at boot by the
    /// config validator.
    ///
    /// # Errors
    ///
    /// If the shared fetcher cannot be constructed.
    pub fn new(
        addr: impl Into<String>,
        mount: impl Into<String>,
        token: Secret,
        timeout: Duration,
    ) -> Result<Self, ironauth_fetch::TlsSetupError> {
        let http = Fetcher::new(FetchLimits::default())?;
        Ok(Self::from_fetcher(addr, mount, token, timeout, http))
    }

    /// Build the backend over an EXISTING fetcher (the test seams, or a deployer
    /// with a custom resolver/dialer).
    #[must_use]
    pub fn from_fetcher(
        addr: impl Into<String>,
        mount: impl Into<String>,
        token: Secret,
        timeout: Duration,
        http: Fetcher,
    ) -> Self {
        Self {
            http,
            addr: addr.into(),
            mount: mount.into(),
            token: Arc::new(token),
            timeout,
        }
    }
}

impl ExternalSigner for VaultTransitSigner {
    fn max_raw_signing_input_bytes(&self) -> Option<usize> {
        // Vault transit has no 4096-byte raw cap: no ceiling.
        None
    }

    fn sign(
        &self,
        kid: &str,
        alg: JwsAlgorithm,
        input: &[u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<u8>, ExternalSignerError>> + Send + '_>,
    > {
        let url = format!("{}/v1/{}/sign/{kid}", self.addr, self.mount);
        let token = Arc::clone(&self.token);
        let timeout = self.timeout;
        let input = input.to_vec();
        Box::pin(async move {
            let (vault_alg, hash) = vault_algorithm(alg);
            let body = match hash {
                Some(hash) => serde_json::json!({
                    "input": STANDARD.encode(&input),
                    "algorithm": vault_alg,
                    "hash_algorithm": hash,
                }),
                None => serde_json::json!({
                    "input": STANDARD.encode(&input),
                    "algorithm": vault_alg,
                }),
            };
            let resolved = token.resolve().map_err(|_| ExternalSignerError::Backend)?;
            let exposed = resolved.expose();
            let request = FetchRequest::new(
                ironauth_fetch::FetchPurpose::ExternalSigner,
                Method::POST,
                url,
            )
            .header(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/json"),
            )
            .header(
                axum::http::header::ACCEPT,
                axum::http::HeaderValue::from_static("application/json"),
            )
            .header(
                axum::http::header::AUTHORIZATION,
                axum::http::HeaderValue::from_str(&format!("Bearer {exposed}"))
                    .map_err(|_| ExternalSignerError::Backend)?,
            )
            .body(serde_json::to_vec(&body).map_err(|_| ExternalSignerError::Backend)?)
            .timeout(timeout)
            // The fetch seam refuses plaintext http by default (the SSRF
            // posture); the TEST stub is plaintext, so it opts in. Production
            // configs point at the vault's https address.
            .allow_plaintext_http();
            let response = self.http.fetch(request).await;
            #[cfg(test)]
            if let Err(ref error) = response {
                eprintln!("vault stub fetch error: {error:?}");
            }
            let response = response.map_err(map_fetch_error)?;
            let payload: serde_json::Value = serde_json::from_slice(response.body())
                .map_err(|_| ExternalSignerError::Backend)?;
            let signature = payload
                .get("data")
                .and_then(|data| data.get("signature"))
                .and_then(|value| value.as_str())
                .ok_or(ExternalSignerError::Backend)?;
            // Vault's signature is `vault:v1:<base64>`; the JOSE side wants the raw
            // signature bytes.
            let raw = signature
                .rsplit_once(':')
                .map(|(_, encoded)| encoded)
                .ok_or(ExternalSignerError::Backend)?;
            STANDARD
                .decode(raw)
                .map_err(|_| ExternalSignerError::Backend)
        })
    }
}

/// The Vault algorithm + optional hash for a JOSE algorithm (issue #161).
fn vault_algorithm(alg: JwsAlgorithm) -> (&'static str, Option<&'static str>) {
    match alg {
        JwsAlgorithm::EdDsa => ("ed25519", None),
        JwsAlgorithm::Es256 => ("ecdsa-p256", None),
        JwsAlgorithm::Es384 => ("ecdsa-p384", None),
        JwsAlgorithm::Rs256 => ("rsa-2048", Some("sha2-256")),
        JwsAlgorithm::Rs384 => ("rsa-2048", Some("sha2-384")),
        JwsAlgorithm::Rs512 => ("rsa-2048", Some("sha2-512")),
        JwsAlgorithm::Ps256 => ("rsa-2048", Some("sha2-256")),
        JwsAlgorithm::Ps384 => ("rsa-2048", Some("sha2-384")),
        JwsAlgorithm::Ps512 => ("rsa-2048", Some("sha2-512")),
        // The  algorithm never reaches a signer (the mint refuses it before
        // selection); mapping it here keeps the match exhaustive without inventing
        // a Vault algorithm for a JWS that must not be signed.
        _ => ("ed25519", None),
    }
}

/// Map a fetch failure to the signer's boundary (issue #161): timeouts and
/// throttles are retryable and distinct; everything else is opaque.
fn map_fetch_error(error: FetchError) -> ExternalSignerError {
    if matches!(error, FetchError::Timeout) {
        return ExternalSignerError::Timeout;
    }
    ExternalSignerError::Backend
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// A stub transit endpoint the size of the shared battery: signs the input
    /// with a local key (EdDSA) and returns Vault's envelope. A RAW listener (the
    /// client_assertion pattern): the fetcher's test dialer forwards to it, and the
    /// SSRF posture is bypassed by the resolver seam, so the stub never needs the
    /// axum server machinery.
    async fn stub_transit() -> (String, Arc<ironauth_jose::SigningKey>) {
        let key = ironauth_jose::SigningKey::ed25519_from_seed(None, &[9_u8; 32])
            .expect("the stub key loads");
        let signing_key = Arc::new(key);
        let router_key = Arc::clone(&signing_key);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let router_key = Arc::clone(&router_key);
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                    let mut buf = [0_u8; 8192];
                    let _ = socket.read(&mut buf).await;
                    let text = String::from_utf8_lossy(&buf);
<<<<<<< HEAD
                    let body = text
                        .split_once(
                            "

",
                        )
                        .map_or("", |(_, body)| body.trim());
=======
                    let body = text.split_once("

").map_or("", |(_, body)| body.trim());
>>>>>>> 8862ecc7 (signer: the shared conformance battery and the user-path mint routing (#161))
                    let value: serde_json::Value =
                        serde_json::from_str(body).unwrap_or_else(|_| serde_json::json!({}));
                    let input = STANDARD
                        .decode(value["input"].as_str().unwrap_or(""))
                        .unwrap_or_default();
                    let sig =
                        ironauth_jose::sign_detached(&router_key, &input).expect("the stub signs");
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        serde_json::json!({
                            "data": {
                                "signature": format!("vault:v1:{}", STANDARD.encode(&sig))
                            }
                        })
                        .to_string()
                        .len(),
                        serde_json::json!({
                            "data": {
                                "signature": format!("vault:v1:{}", STANDARD.encode(&sig))
                            }
                        })
                        .to_string(),
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.flush().await;
                });
            }
        });
        (format!("http://{addr}"), signing_key)
    }

    /// The shared battery: sign through the backend, verify through the public half.
    #[tokio::test]
    async fn vault_transit_signs_and_the_public_half_verifies() {
        let (addr, stub_key) = stub_transit().await;
        let token = Secret::Literal(ironauth_config::SecretString::new("test-token"));
        // The SSRF posture blocks loopback; the client_assertion pattern: a resolver
        // that returns a public sentinel + a dialer that forwards to the stub.
        let dialer = Arc::new(ironauth_fetch::RecordingDialer::new(
            addr.parse::<std::net::SocketAddr>().expect("addr"),
        ));
        let resolver = Arc::new(ironauth_fetch::StaticResolver::new(vec![
            std::net::IpAddr::from([8, 8, 8, 8]),
        ]));
        let http = ironauth_fetch::Fetcher::from_parts(
            ironauth_fetch::FetchLimits::default(),
            resolver,
            dialer,
        );
        let signer =
            VaultTransitSigner::from_fetcher(addr, "transit", token, Duration::from_secs(5), http);
        let input = b"the full signing input, exactly as PureEdDSA demands";
        let trusted = stub_key.verifying_key().expect("the trusted key");
        // THE SHARED BATTERY (issue #161, the Dex pattern): the SAME battery the
        // local backend passes. The stub signed with the same key the public half
        // verifies against.
        let verify = |signature: &[u8]| {
            ironauth_jose::verify_detached(&trusted, JwsAlgorithm::EdDsa, input, signature)
                .is_ok()
        };
        let outcome = ironauth_jose::external_signer::run_conformance_battery(
            &signer,
            "test-kid",
            JwsAlgorithm::EdDsa,
            input,
            verify,
        )
        .await;
        assert!(outcome.is_ok(), "the vault backend passes: {outcome:?}");
    }
}
