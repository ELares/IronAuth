// SPDX-License-Identifier: MIT OR Apache-2.0

//! Browser binding for hosted password reset, never an authentication session.
//! The store remains authoritative for scope, lifetime, proof and completion.
//! These helpers do not install a route or enable the unfinished ceremony.

use axum::http::{HeaderMap, HeaderValue, header};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use ironauth_env::Env;
use ironauth_store::PasswordResetChallengeId;
use sha2::{Digest, Sha256};

/// Host-only reset binding; deliberately separate from login/session cookies.
pub const RESET_COOKIE: &str = "__Host-ironauth_reset";
const MAX_COOKIE_BYTES: usize = 8192;
const CSRF_DOMAIN: &[u8] = b"ironauth/password-reset/csrf/v1";
const RECEIPT_DOMAIN: &[u8] = b"ironauth/password-reset/completion/v1";

/// A short-lived browser secret and scoped challenge handle. No Debug, Clone or
/// serialization: the secret may leave this type only in the sensitive cookie.
pub struct ResetBrowserBinding {
    challenge: PasswordResetChallengeId,
    secret: [u8; 32],
}

impl Drop for ResetBrowserBinding {
    fn drop(&mut self) {
        ironauth_jose::wipe(&mut self.secret);
    }
}

impl ResetBrowserBinding {
    /// Mint a separate 256-bit binding through the environment entropy seam.
    #[must_use]
    pub fn generate(env: &Env, challenge: PasswordResetChallengeId) -> Self {
        let mut secret = [0; 32];
        env.entropy().fill_bytes(&mut secret);
        Self { challenge, secret }
    }

    /// Read one canonical reset cookie, rejecting duplicate names across every
    /// Cookie header and bounding the aggregate input before parsing. Absence and
    /// malformed inputs are uniform. This does not prove the challenge is live.
    #[must_use]
    pub fn from_headers(headers: &HeaderMap) -> Option<Self> {
        let mut bytes = 0_usize;
        let mut value = None;
        for header in headers.get_all(header::COOKIE) {
            bytes = bytes.checked_add(header.as_bytes().len())?;
            if bytes > MAX_COOKIE_BYTES {
                return None;
            }
            for pair in header.to_str().ok()?.split(';') {
                let pair = pair.trim();
                let Some((name, candidate)) = pair.split_once('=') else {
                    if pair == RESET_COOKIE {
                        return None;
                    }
                    continue;
                };
                if name.trim() == RESET_COOKIE {
                    if name != RESET_COOKIE || value.is_some() {
                        return None;
                    }
                    value = Some(candidate);
                }
            }
        }
        let (handle, encoded) = value?.split_once('~')?;
        if handle.len() > 512 || encoded.len() != 43 {
            return None;
        }
        let challenge = PasswordResetChallengeId::parse_declared_scope(handle).ok()?;
        let mut secret = [0_u8; 32];
        if URL_SAFE_NO_PAD.decode_slice(encoded, &mut secret).ok() != Some(32) {
            ironauth_jose::wipe(&mut secret);
            return None;
        }
        Some(Self { challenge, secret })
    }

    /// Scoped handle only; the handler must resolve its authoritative store row.
    #[must_use]
    pub fn challenge(&self) -> &PasswordResetChallengeId {
        &self.challenge
    }

    /// One-way binding stored with the challenge, never the cookie's secret.
    #[must_use]
    pub fn binding_hash(&self) -> [u8; 32] {
        Sha256::digest(self.secret).into()
    }

    /// Issue once at ceremony creation. Do not roll this lifetime on reads or
    /// delete on success: the original bounded cookie permits lost-response retry.
    /// The database's exact expiry, at most ten minutes, remains authoritative.
    ///
    /// # Panics
    /// Never for generated or parsed bindings: typed IDs and base64url are ASCII.
    #[must_use]
    pub fn cookie(&self) -> HeaderValue {
        let mut value = HeaderValue::from_str(&format!(
            "{RESET_COOKIE}={}~{}; Path=/; Max-Age=600; Secure; HttpOnly; SameSite=Lax",
            self.challenge,
            URL_SAFE_NO_PAD.encode(self.secret)
        ))
        .expect("typed reset cookie is an ASCII header");
        value.set_sensitive(true);
        value
    }

    /// Form CSRF proof bound to this browser and exact challenge. The hosted
    /// handler must also enforce same-origin POST and no-store/referrer policy.
    #[must_use]
    pub fn csrf_token(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.mac(CSRF_DOMAIN).finalize().into_bytes())
    }

    /// Check the form proof with the MAC's constant-time verifier.
    #[must_use]
    pub fn accepts_csrf(&self, presented: &str) -> bool {
        if presented.len() != 43 {
            return false;
        }
        let mut decoded = [0_u8; 32];
        if URL_SAFE_NO_PAD.decode_slice(presented, &mut decoded).ok() != Some(32) {
            return false;
        }
        self.mac(CSRF_DOMAIN).verify_slice(&decoded).is_ok()
    }

    /// Stable keyed receipt digest of the exact normalized completion request.
    /// The caller must bound the body, normalize/screen the password and validate
    /// the code before using this alongside admitted Argon2 hashing. Fields are
    /// length-prefixed; neither an Argon2 salt nor a server process key is used,
    /// so the same browser can retry after a provider restart without rewriting
    /// a committed password. No plaintext password enters the stored receipt.
    #[must_use]
    pub fn completion_request_hash(&self, code: &str, normalized_password: &str) -> [u8; 32] {
        let mut mac = self.mac(RECEIPT_DOMAIN);
        append_field(&mut mac, code.as_bytes());
        append_field(&mut mac, normalized_password.as_bytes());
        mac.finalize().into_bytes().into()
    }

    fn mac(&self, domain: &[u8]) -> Hmac<Sha256> {
        let mut mac =
            <Hmac<Sha256>>::new_from_slice(&self.secret).expect("HMAC accepts a 32-byte key");
        append_field(&mut mac, domain);
        append_field(&mut mac, self.challenge.to_string().as_bytes());
        mac
    }
}

fn append_field(mac: &mut Hmac<Sha256>, value: &[u8]) {
    mac.update(&(value.len() as u64).to_be_bytes());
    mac.update(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironauth_store::{EnvironmentId, Scope, TenantId};

    fn binding(env: &Env) -> ResetBrowserBinding {
        let scope = Scope::new(TenantId::generate(env), EnvironmentId::generate(env));
        ResetBrowserBinding::generate(env, PasswordResetChallengeId::generate(env, &scope))
    }

    fn headers(binding: &ResetBrowserBinding) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let cookie = binding.cookie();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(cookie.to_str().unwrap().split(';').next().unwrap()).unwrap(),
        );
        headers
    }

    #[test]
    fn cookie_is_host_only_sensitive_and_round_trips_without_process_state() {
        let env = Env::system();
        let original = binding(&env);
        let cookie = original.cookie();
        assert!(cookie.is_sensitive());
        let rendered = cookie.to_str().unwrap();
        for attribute in [
            "Path=/",
            "Max-Age=600",
            "Secure",
            "HttpOnly",
            "SameSite=Lax",
        ] {
            assert!(rendered.contains(attribute));
        }
        assert!(!rendered.contains("Domain="));
        let restored = ResetBrowserBinding::from_headers(&headers(&original)).unwrap();
        assert_eq!(restored.challenge(), original.challenge());
        assert_eq!(restored.binding_hash(), original.binding_hash());
        assert!(restored.accepts_csrf(&original.csrf_token()));
        assert_eq!(
            restored.completion_request_hash("12345678", "normalized password"),
            original.completion_request_hash("12345678", "normalized password")
        );
    }

    #[test]
    fn csrf_and_completion_are_bound_to_browser_challenge_and_exact_fields() {
        let env = Env::system();
        let original = binding(&env);
        let other_browser = ResetBrowserBinding::generate(&env, *original.challenge());
        assert!(!other_browser.accepts_csrf(&original.csrf_token()));
        let mut other_challenge = binding(&env);
        other_challenge.secret = original.secret;
        assert!(!other_challenge.accepts_csrf(&original.csrf_token()));
        let digest = original.completion_request_hash("12345678", "password");
        assert!(!original.accepts_csrf(&URL_SAFE_NO_PAD.encode(digest)));
        for different in [
            original.completion_request_hash("12345679", "password"),
            original.completion_request_hash("12345678", "password "),
            other_browser.completion_request_hash("12345678", "password"),
            other_challenge.completion_request_hash("12345678", "password"),
        ] {
            assert_ne!(digest, different);
        }
        assert_ne!(
            original.completion_request_hash("ab", "c"),
            original.completion_request_hash("a", "bc")
        );
        assert!(!original.accepts_csrf(""));
        assert!(!original.accepts_csrf(&"!".repeat(43)));
    }

    #[test]
    fn cookie_parser_refuses_duplicates_malformed_and_oversized_input() {
        let env = Env::system();
        let original = binding(&env);
        let valid = headers(&original)[header::COOKIE].clone();
        let mut duplicate = headers(&original);
        duplicate.append(header::COOKIE, valid.clone());
        assert!(ResetBrowserBinding::from_headers(&duplicate).is_none());
        duplicate.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!(
                "{}; {}",
                valid.to_str().unwrap(),
                valid.to_str().unwrap()
            ))
            .unwrap(),
        );
        assert!(ResetBrowserBinding::from_headers(&duplicate).is_none());
        for value in [
            String::new(),
            format!("{RESET_COOKIE}=wrong~{}", "a".repeat(43)),
            format!("{RESET_COOKIE}={}~{}", original.challenge(), "a".repeat(42)),
            format!("{RESET_COOKIE}={}~{}", original.challenge(), "!".repeat(43)),
            format!("unrelated={}", "a".repeat(MAX_COOKIE_BYTES)),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::COOKIE, HeaderValue::from_str(&value).unwrap());
            assert!(ResetBrowserBinding::from_headers(&headers).is_none());
        }
        for malformed in [RESET_COOKIE.to_string(), format!("{RESET_COOKIE} =invalid")] {
            let mut duplicate = headers(&original);
            duplicate.append(header::COOKIE, HeaderValue::from_str(&malformed).unwrap());
            assert!(ResetBrowserBinding::from_headers(&duplicate).is_none());
        }
        let mut aggregate = headers(&original);
        for _ in 0..3 {
            aggregate.append(
                header::COOKIE,
                HeaderValue::from_str(&format!("other={}", "a".repeat(3000))).unwrap(),
            );
        }
        assert!(ResetBrowserBinding::from_headers(&aggregate).is_none());
        let mut valid_with_unrelated = headers(&original);
        valid_with_unrelated.append(header::COOKIE, HeaderValue::from_static("other=value"));
        assert!(ResetBrowserBinding::from_headers(&valid_with_unrelated).is_some());
    }
}
