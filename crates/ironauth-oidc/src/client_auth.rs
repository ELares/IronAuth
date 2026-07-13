// SPDX-License-Identifier: MIT OR Apache-2.0

//! Secret-based client authentication for the token endpoint (issue #20).
//!
//! Two methods are supported, `client_secret_basic` and `client_secret_post`, and
//! a client is registered for exactly ONE of them (or for `none`, a public
//! PKCE-only client). The token endpoint enforces the registered method: a client
//! registered for one method that presents another fails with the spec-exact
//! `invalid_client` (RFC 6749 5.2), never a different error.
//!
//! # The `client_secret_basic` encoding landmine
//!
//! RFC 6749 2.3.1 requires the client to `application/x-www-form-urlencode` the
//! client id and secret BEFORE base64-encoding them into the `Authorization:
//! Basic` value, and the server to form-urldecode both halves after base64
//! decoding. Real client libraries disagree: some encode, some send the raw
//! bytes, and a strict server rejects a secret with a character that changes
//! under form-encoding. IronAuth sidesteps the ambiguity by GENERATING URL-safe
//! secrets ([`generate_secret`]): a 64-byte base64url value contains only
//! `A-Za-z0-9-_`, none of which form-encoding alters, so the raw and the
//! form-encoded interpretations are byte-identical. This module is nonetheless
//! spec-correct: it form-urldecodes both halves after base64 decoding, so a client
//! that DID encode still authenticates. The behavior is pinned by tests.
//!
//! # Secret storage
//!
//! A generated secret is shown once at creation and stored only as its SHA-256
//! hash. A 64-byte (512-bit) uniformly random secret carries far more entropy
//! than any password, so it does not need a slow password KDF: a single
//! cryptographic hash is sound and is exactly what the management-key credential
//! path uses. The plaintext is unrecoverable after creation.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use ironauth_env::Env;
use ironauth_store::ClientAuthRecord;
use sha2::{Digest, Sha256};

/// Bytes of entropy in a generated client secret. 64 bytes is 512 bits, well
/// beyond guessing, and base64url encodes to a URL-safe string so the two Basic
/// interpretations coincide.
const SECRET_BYTES: usize = 64;

/// A client's token-endpoint authentication method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuthMethod {
    /// `client_secret_basic`: the secret arrives in the `Authorization: Basic`
    /// header (RFC 6749 2.3.1).
    Basic,
    /// `client_secret_post`: the secret arrives as a `client_secret` form field.
    Post,
    /// `none`: a public client (PKCE only), no secret.
    None,
}

impl ClientAuthMethod {
    /// Every token-endpoint authentication method this build supports, in the
    /// order discovery advertises them (issue #18 sources
    /// `token_endpoint_auth_methods_supported` from here). Asymmetric/JWT client
    /// authentication is a later milestone and is absent until it lands.
    pub const ALL: &'static [ClientAuthMethod] = &[
        ClientAuthMethod::Basic,
        ClientAuthMethod::Post,
        ClientAuthMethod::None,
    ];

    /// The wire / stored string for this method.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ClientAuthMethod::Basic => "client_secret_basic",
            ClientAuthMethod::Post => "client_secret_post",
            ClientAuthMethod::None => "none",
        }
    }

    /// Parse a stored/registered method string. An unknown value is treated as
    /// `none` by the caller only after this returns `None`, but the token endpoint
    /// fails closed on an unrecognized registered method rather than guessing.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "client_secret_basic" => Some(ClientAuthMethod::Basic),
            "client_secret_post" => Some(ClientAuthMethod::Post),
            "none" => Some(ClientAuthMethod::None),
            _ => None,
        }
    }
}

/// Generate a fresh client secret: 64 random bytes from the entropy seam, encoded
/// URL-safe base64 with no padding. URL-safe so the `client_secret_basic`
/// form-encoded and raw interpretations coincide.
#[must_use]
pub fn generate_secret(env: &Env) -> String {
    let mut bytes = [0_u8; SECRET_BYTES];
    env.entropy().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The SHA-256 hex of a secret, the stored form. A high-entropy random secret
/// does not need a slow KDF; a single cryptographic hash is sound.
#[must_use]
pub fn hash_secret(secret: &str) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(secret.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The credentials a token request presented for client authentication, after
/// parsing the `Authorization` header and the form body.
#[derive(Debug, Clone)]
pub struct PresentedClientAuth {
    /// The client identifier the request authenticated as (from the Basic userid
    /// or the form `client_id`).
    pub client_id: String,
    /// The method the credentials arrived by.
    pub method: ClientAuthMethod,
    /// The presented secret, if any (absent for a public client).
    pub secret: Option<String>,
}

/// Why client authentication could not even be parsed into a coherent attempt.
/// Distinct from an authentication FAILURE (that is [`ClientAuthFailure`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuthParseError {
    /// More than one authentication method was presented (for example both a
    /// Basic header and a `client_secret` field), which RFC 6749 2.3 forbids.
    MultipleMethods,
    /// The `Authorization` header was present but not a decodable Basic
    /// credential.
    MalformedBasic,
    /// No client identifier was presented at all (neither a Basic userid nor a
    /// form `client_id`).
    MissingClientId,
    /// A Basic userid and a form `client_id` were both present but disagreed.
    ClientIdMismatch,
}

/// An authentication FAILURE: the client was identified but its credentials did
/// not satisfy its registered method. Always renders the spec-exact
/// `invalid_client`; `via_basic` drives the `WWW-Authenticate: Basic` header and
/// the 401 status RFC 6749 5.2 mandates for a failed Authorization-header attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientAuthFailure {
    /// Whether the client attempted authentication via the `Authorization`
    /// header (a Basic attempt), which mandates a 401 with `WWW-Authenticate`.
    pub via_basic: bool,
}

/// Parse the presented client credentials from the `Authorization` header and the
/// form `client_id`/`client_secret`. Enforces that at most one method is used and
/// that a client id is present.
///
/// # Errors
///
/// [`ClientAuthParseError`] if more than one method is presented, the Basic
/// header is malformed, no client id is present, or a Basic userid and a form
/// `client_id` disagree.
pub fn parse_presented(
    authorization: Option<&str>,
    body_client_id: Option<&str>,
    body_client_secret: Option<&str>,
) -> Result<PresentedClientAuth, ClientAuthParseError> {
    let basic = match authorization {
        Some(value) if is_basic(value) => {
            Some(parse_basic(value).ok_or(ClientAuthParseError::MalformedBasic)?)
        }
        // A non-Basic Authorization scheme is ignored here: asymmetric/JWT client
        // auth is #M3 and out of scope, so only Basic is recognized.
        _ => None,
    };
    let body_id = body_client_id
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let body_secret = body_client_secret
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if let Some((basic_id, basic_secret)) = basic {
        // A body client_secret alongside Basic is two methods: forbidden.
        if body_secret.is_some() {
            return Err(ClientAuthParseError::MultipleMethods);
        }
        // A body client_id alongside Basic is allowed only if it agrees.
        if let Some(body_id) = body_id {
            if body_id != basic_id {
                return Err(ClientAuthParseError::ClientIdMismatch);
            }
        }
        return Ok(PresentedClientAuth {
            client_id: basic_id,
            method: ClientAuthMethod::Basic,
            secret: Some(basic_secret),
        });
    }

    let client_id = body_id
        .ok_or(ClientAuthParseError::MissingClientId)?
        .to_owned();
    match body_secret {
        Some(secret) => Ok(PresentedClientAuth {
            client_id,
            method: ClientAuthMethod::Post,
            secret: Some(secret.to_owned()),
        }),
        None => Ok(PresentedClientAuth {
            client_id,
            method: ClientAuthMethod::None,
            secret: None,
        }),
    }
}

/// Authenticate the presented credentials against the client's registered record.
/// Enforces the registered method and verifies the secret.
///
/// # Errors
///
/// [`ClientAuthFailure`] if the client's registered method is unrecognized, the
/// presented method does not match the registered one, a secret is presented to a
/// public client, or the presented secret does not match the stored hash. Every
/// case renders the spec-exact `invalid_client`.
pub fn authenticate(
    record: &ClientAuthRecord,
    presented: &PresentedClientAuth,
) -> Result<(), ClientAuthFailure> {
    let via_basic = presented.method == ClientAuthMethod::Basic;
    let fail = || ClientAuthFailure { via_basic };

    // Fail closed on an unrecognized registered method rather than guessing.
    let registered = ClientAuthMethod::parse(&record.auth_method).ok_or_else(fail)?;

    // The presented method must be exactly the registered one. A client
    // registered for basic that presents post (and vice versa) is a mismatch, and
    // a public client that presents any secret is a mismatch.
    if presented.method != registered {
        return Err(fail());
    }

    match registered {
        ClientAuthMethod::None => {
            // Public client: no secret must be presented (guaranteed by the
            // method match above, but assert defensively).
            if presented.secret.is_some() {
                return Err(fail());
            }
            Ok(())
        }
        ClientAuthMethod::Basic | ClientAuthMethod::Post => {
            let stored = record.secret_hash.as_deref().ok_or_else(fail)?;
            let presented_secret = presented.secret.as_deref().ok_or_else(fail)?;
            let presented_hash = hash_secret(presented_secret);
            if constant_time_eq(presented_hash.as_bytes(), stored.as_bytes()) {
                Ok(())
            } else {
                Err(fail())
            }
        }
    }
}

/// Whether `value` is an `Authorization: Basic` header (case-insensitive scheme).
fn is_basic(value: &str) -> bool {
    // `get(..5)` (not `value[..5]`) so a non-ASCII byte straddling index 5 returns
    // None instead of panicking on a char boundary; the len check keeps `[5]` valid.
    value.len() >= 6
        && value
            .get(..5)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("basic"))
        && value.as_bytes()[5] == b' '
}

/// Parse an `Authorization: Basic` value into its (`client_id`, secret), applying
/// RFC 6749 2.3.1: base64-decode, split on the FIRST colon, then form-urldecode
/// each half. Accepts both padded and unpadded base64 for robustness.
fn parse_basic(value: &str) -> Option<(String, String)> {
    let encoded = value.get(6..)?.trim();
    let decoded = STANDARD
        .decode(encoded)
        .or_else(|_| STANDARD_NO_PAD.decode(encoded))
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (id, secret) = text.split_once(':')?;
    Some((form_urldecode(id), form_urldecode(secret)))
}

/// Decode an `application/x-www-form-urlencoded` component: `+` becomes a space
/// and `%XX` becomes the byte. A malformed trailing escape is passed through
/// verbatim. IronAuth's own URL-safe credentials contain neither `+` nor `%`, so
/// this is a no-op for them; it exists so a client that DID form-encode still
/// authenticates (RFC 6749 2.3.1).
fn form_urldecode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 3 <= bytes.len() => {
                if let Ok(byte) = u8::from_str_radix(&value[i + 1..i + 3], 16) {
                    out.push(byte);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Compare two byte strings in time independent of where they first differ. A
/// length difference short-circuits to `false`; the stored and presented values
/// here are both fixed-length SHA-256 hex, so equal-length is the normal path.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;

    fn record(method: ClientAuthMethod, secret: Option<&str>) -> ClientAuthRecord {
        ClientAuthRecord {
            display_name: "test".to_owned(),
            auth_method: method.as_str().to_owned(),
            secret_hash: secret.map(hash_secret),
        }
    }

    /// Base64 (standard, padded) of `client_id:client_secret`, the raw form.
    fn basic_header(client_id: &str, secret: &str) -> String {
        format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")))
    }

    #[test]
    fn generated_secret_is_64_byte_url_safe_base64() {
        let (env, _) = Env::deterministic(SystemTime::UNIX_EPOCH, 5);
        let secret = generate_secret(&env);
        let decoded = URL_SAFE_NO_PAD.decode(&secret).expect("url-safe base64");
        assert_eq!(decoded.len(), 64, "64 random bytes");
        // URL-safe alphabet only: no '+', '/', or '=' that form-encoding alters.
        assert!(
            secret
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "url-safe alphabet: {secret}"
        );
    }

    /// An independent WHATWG `application/x-www-form-urlencoded` serializer, so the
    /// coincidence test below does not reuse the `form_urldecode` it is checking
    /// against. Leaves the form-unreserved set `*-._0-9A-Za-z` as-is, maps space to
    /// `+`, and percent-encodes every other byte.
    fn form_urlencode(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        for &b in bytes {
            match b {
                b'*' | b'-' | b'.' | b'_' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' => {
                    out.push(b as char);
                }
                b' ' => out.push('+'),
                _ => {
                    let _ = write!(out, "%{b:02X}");
                }
            }
        }
        out
    }

    #[test]
    fn url_safe_secrets_are_form_urlencode_invariant_so_raw_and_encoded_agree() {
        // The RFC 6749 2.3.1 interop landmine: a client that form-urlencodes the
        // credential before base64 and one that sends it raw must BOTH authenticate.
        // IronAuth guarantees this by generating URL-safe secrets, whose form
        // encoding is a no-op, so the two wire spellings are byte-identical. Prove
        // that with an INDEPENDENT encoder (not our own form_urldecode), then
        // confirm both spellings parse to the same secret.
        let secret = "abcXYZ-0_9"; // the base64url alphabet generate_secret emits
        let encoded = form_urlencode(secret.as_bytes());
        assert_eq!(
            encoded, secret,
            "a url-safe secret is unchanged by form-urlencoding: raw == encoded on the wire"
        );
        // Negative control: a secret with reserved bytes genuinely transforms, so
        // the encoder is not a vacuous no-op that would make the above trivially true.
        assert_ne!(form_urlencode(b"a b/c"), "a b/c");
        // Both spellings of the url-safe secret parse to the identical secret.
        let raw = parse_basic(&basic_header("cli_x", secret)).expect("raw parses");
        let enc = parse_basic(&basic_header("cli_x", &encoded)).expect("encoded parses");
        assert_eq!(
            raw, enc,
            "raw and form-encoded Basic headers parse identically"
        );
        assert_eq!(raw.1, secret);
    }

    #[test]
    fn basic_form_urldecodes_an_encoded_secret() {
        // A secret containing a space and a percent, form-encoded by the client,
        // must decode back per RFC 6749 2.3.1 (proves we are spec-correct even
        // though IronAuth's own secrets never need it).
        let header = format!("Basic {}", STANDARD.encode("cli_x:a+b%2Fc"));
        let (id, secret) = parse_basic(&header).expect("parses");
        assert_eq!(id, "cli_x");
        assert_eq!(secret, "a b/c");
    }

    #[test]
    fn basic_method_authenticates_and_wrong_secret_is_invalid_client() {
        let rec = record(ClientAuthMethod::Basic, Some("s3cr3t"));
        let ok =
            parse_presented(Some(&basic_header("cli_x", "s3cr3t")), None, None).expect("parse");
        assert!(authenticate(&rec, &ok).is_ok());

        let bad =
            parse_presented(Some(&basic_header("cli_x", "wrong")), None, None).expect("parse");
        let failure = authenticate(&rec, &bad).expect_err("wrong secret");
        assert!(
            failure.via_basic,
            "a Basic attempt mandates WWW-Authenticate"
        );
    }

    #[test]
    fn post_method_authenticates_and_wrong_secret_is_invalid_client() {
        let rec = record(ClientAuthMethod::Post, Some("p0st"));
        let ok = parse_presented(None, Some("cli_x"), Some("p0st")).expect("parse");
        assert_eq!(ok.method, ClientAuthMethod::Post);
        assert!(authenticate(&rec, &ok).is_ok());

        let bad = parse_presented(None, Some("cli_x"), Some("nope")).expect("parse");
        let failure = authenticate(&rec, &bad).expect_err("wrong secret");
        assert!(!failure.via_basic, "a post attempt is not a Basic attempt");
    }

    #[test]
    fn a_mismatched_method_is_invalid_client_both_directions() {
        // Registered basic, presented post -> invalid_client.
        let basic_client = record(ClientAuthMethod::Basic, Some("s"));
        let via_post = parse_presented(None, Some("cli_x"), Some("s")).expect("parse");
        assert!(authenticate(&basic_client, &via_post).is_err());

        // Registered post, presented basic -> invalid_client.
        let post_client = record(ClientAuthMethod::Post, Some("s"));
        let via_basic = parse_presented(Some(&basic_header("cli_x", "s")), None, None).expect("p");
        assert!(authenticate(&post_client, &via_basic).is_err());
    }

    #[test]
    fn public_client_authenticates_without_a_secret_but_rejects_one() {
        let public = record(ClientAuthMethod::None, None);
        let no_secret = parse_presented(None, Some("cli_x"), None).expect("parse");
        assert_eq!(no_secret.method, ClientAuthMethod::None);
        assert!(authenticate(&public, &no_secret).is_ok());

        // Presenting a secret to a public client is a method mismatch.
        let with_secret = parse_presented(None, Some("cli_x"), Some("unexpected")).expect("parse");
        assert!(authenticate(&public, &with_secret).is_err());
    }

    #[test]
    fn presenting_two_methods_is_a_parse_error() {
        let err = parse_presented(Some(&basic_header("cli_x", "s")), Some("cli_x"), Some("s"))
            .expect_err("both basic and post");
        assert_eq!(err, ClientAuthParseError::MultipleMethods);
    }

    #[test]
    fn a_conflicting_body_client_id_is_rejected() {
        let err = parse_presented(Some(&basic_header("cli_a", "s")), Some("cli_b"), None)
            .expect_err("mismatched client_id");
        assert_eq!(err, ClientAuthParseError::ClientIdMismatch);
    }

    #[test]
    fn missing_client_id_is_a_parse_error() {
        let err = parse_presented(None, None, None).expect_err("no client id");
        assert_eq!(err, ClientAuthParseError::MissingClientId);
    }
}
