// SPDX-License-Identifier: MIT OR Apache-2.0

//! The API key and personal-access-token FORMAT (issue #99, criteria 2 and 4).
//!
//! One shape, two prefixes, mirroring the opaque access token (issue #29) rather than
//! inventing a second scheme:
//!
//! ```text
//! ira_ak_akey_<48-byte scoped id, 64 base64url chars>~<32 random bytes, 43 base64url chars>
//! ira_pat_akey_<...>~<...>
//! ```
//!
//! The `akey_` handle is a NON-SECRET scoped id: it declares the key's tenant and environment,
//! so a verifier can route to the right scope before it knows whether the key is real. The
//! suffix after the delimiter is 256 bits of entropy and is the only secret part. The whole
//! string is hashed with [`api_key_digest`] and only that digest is stored, so a database dump
//! yields nothing replayable.
//!
//! # Why two prefixes for one format
//!
//! A personal access token belongs to a HUMAN and an API key belongs to a service account or
//! an organization. They verify identically, and the schema stores them in one table, but a
//! secret scanner sweeping a public repository needs to tell them apart: a leaked `ira_pat_`
//! is somebody's individual access and a leaked `ira_ak_` is a machine identity's, and the two
//! have different revocation urgency and different humans to notify.
//!
//! # The published scanner regex
//!
//! `docs/design/TOKEN-FORMATS.md` publishes the regex a secret scanner matches. Criterion 2
//! requires that it match EVERY generated key type, which is not something to check by
//! reading: `the_published_scanner_regex_matches_every_generated_key_kind` generates one of
//! each and matches them against the regex read out of the document itself.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ironauth_env::Env;

use crate::id::ApiKeyId;
use crate::scope::Scope;

/// The prefix of an API key: a key owned by a service account or an organization.
pub const API_KEY_PREFIX: &str = "ira_ak_";

/// The prefix of a personal access token: a key owned by a user.
pub const PERSONAL_ACCESS_TOKEN_PREFIX: &str = "ira_pat_";

/// The delimiter between the non-secret handle and the secret, matching the opaque access
/// token so one scanner grammar covers both.
pub const API_KEY_DELIMITER: char = '~';

/// The secret's length in bytes. 256 bits, the same as the opaque access token: enough that a
/// digest collision is not a threat model and no salt is needed.
pub const API_KEY_SECRET_BYTES: usize = 32;

/// Which principal a key belongs to (issue #99).
///
/// This chooses the PREFIX, and it is also the discriminator the schema's exclusive-arc CHECK
/// enforces, so the wire form and the stored row cannot disagree about what kind of thing owns
/// the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyKindTag {
    /// Owned by a user: a personal access token.
    PersonalAccessToken,
    /// Owned by a service account or an organization: an API key.
    ApiKey,
}

impl ApiKeyKindTag {
    /// The wire prefix for this kind.
    #[must_use]
    pub fn prefix(self) -> &'static str {
        match self {
            Self::PersonalAccessToken => PERSONAL_ACCESS_TOKEN_PREFIX,
            Self::ApiKey => API_KEY_PREFIX,
        }
    }
}

/// A freshly minted key: the plaintext to hand back ONCE, and the row material to store.
///
/// The plaintext and the digest travel together in one value so a caller cannot store the row
/// and forget to return the plaintext, or return it and store the wrong digest. There is no
/// path that produces one without the other.
#[derive(Debug)]
pub struct MintedApiKey {
    /// The full key string. Return it in the creation response and DROP it. Nothing else in
    /// the system can recover it afterwards, which is the property criterion 4 asks for.
    pub plaintext: String,
    /// The non-secret handle, stored as `api_keys.id` and named by every audit row.
    pub id: ApiKeyId,
    /// The SHA-256 hex digest of `plaintext`, stored as `api_keys.key_digest`.
    pub digest: String,
}

/// Mint a key of `kind` in `scope`.
///
/// The secret comes from the environment's entropy seam, never from `getrandom` directly, so a
/// test can drive a deterministic generator and the `entropy-via-env` invariant lint holds.
#[must_use]
pub fn mint_api_key(env: &Env, scope: &Scope, kind: ApiKeyKindTag) -> MintedApiKey {
    let id = ApiKeyId::generate(env, scope);
    let mut bytes = [0_u8; API_KEY_SECRET_BYTES];
    env.entropy().fill_bytes(&mut bytes);
    let plaintext = format!(
        "{}{id}{API_KEY_DELIMITER}{}",
        kind.prefix(),
        URL_SAFE_NO_PAD.encode(bytes)
    );
    let digest = api_key_digest(&plaintext);
    MintedApiKey {
        plaintext,
        id,
        digest,
    }
}

/// The SHA-256 hex digest of a whole key, the lookup key stored in `api_keys.key_digest`.
///
/// The one canonical digest for the format: the mint hashes with this to store, and the
/// verifier hashes the presented key with this to look up, so the two can never disagree.
#[must_use]
pub fn api_key_digest(key: &str) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    let digest = Sha256::digest(key.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The non-secret handle from a presented key, if it is well formed for `kind`.
///
/// Returns the handle as a STRING rather than a parsed [`ApiKeyId`]: parsing is the caller's,
/// because the caller knows which scope it expects and a handle from another scope must be a
/// uniform not-found rather than a distinguishable parse failure.
#[must_use]
pub fn api_key_handle(key: &str, kind: ApiKeyKindTag) -> Option<&str> {
    let rest = key.strip_prefix(kind.prefix())?;
    let (handle, secret) = rest.split_once(API_KEY_DELIMITER)?;
    // Both halves must be present and non-empty. A key with an empty secret would otherwise
    // present a valid handle and hash to a stable digest, so a row written from a truncated
    // key would be verifiable by the same truncated key.
    if handle.is_empty() || secret.is_empty() {
        return None;
    }
    Some(handle)
}

#[cfg(test)]
mod tests {
    use super::{
        API_KEY_DELIMITER, API_KEY_PREFIX, API_KEY_SECRET_BYTES, ApiKeyKindTag,
        PERSONAL_ACCESS_TOKEN_PREFIX, api_key_digest, api_key_handle, mint_api_key,
    };
    use crate::id::ApiKeyKind;
    use crate::id::ScopedKind;
    use crate::scope::Scope;
    use ironauth_env::Env;

    /// The published scanner contract, read from the document itself.
    const TOKEN_FORMATS: &str = include_str!("../../../docs/design/TOKEN-FORMATS.md");

    /// The Base64url alphabet the published regex names.
    const ALPHABET_OK: fn(char) -> bool = |c| c.is_ascii_alphanumeric() || c == '_' || c == '-';

    /// The handle is 48 bytes of scoped id, Base64url no-pad: `ceil(48 * 4 / 3)`.
    const HANDLE_CHARS: usize = 64;

    fn scope(env: &Env) -> Scope {
        Scope::new(
            crate::id::TenantId::generate(env),
            crate::id::EnvironmentId::generate(env),
        )
    }

    /// The published regex matches every generated key kind, and the DOCUMENT says so.
    ///
    /// Both directions, because either alone is weak. Checking only that a generated key fits
    /// a hand-written pattern proves nothing about what a scanner was told to look for;
    /// checking only that the document contains a string proves nothing about what is minted.
    ///
    /// The expected pattern is DERIVED from the same constants the mint uses, so it cannot be
    /// updated to match a changed format by editing this test: change the secret length and
    /// the derived pattern changes, and the assertion then fails against the stale document.
    #[test]
    fn the_published_scanner_regex_matches_every_generated_key_kind() {
        let env = Env::system();
        let scope = scope(&env);
        let secret_chars = API_KEY_SECRET_BYTES * 4 / 3 + usize::from(API_KEY_SECRET_BYTES % 3 > 0);

        for (kind, prefix) in [
            (ApiKeyKindTag::ApiKey, API_KEY_PREFIX),
            (
                ApiKeyKindTag::PersonalAccessToken,
                PERSONAL_ACCESS_TOKEN_PREFIX,
            ),
        ] {
            let expected = format!(
                "{prefix}{}_[A-Za-z0-9_-]{{{HANDLE_CHARS}}}~[A-Za-z0-9_-]{{{secret_chars}}}",
                ApiKeyKind::PREFIX
            );
            assert!(
                TOKEN_FORMATS.contains(&expected),
                "docs/design/TOKEN-FORMATS.md does not publish the pattern this crate \
                 actually mints. A secret scanner registered from that document would not \
                 catch a leaked key. Expected to find: {expected}"
            );

            let minted = mint_api_key(&env, &scope, kind);
            let body = minted
                .plaintext
                .strip_prefix(prefix)
                .expect("the minted key carries its kind's prefix");
            let (handle, secret) = body
                .split_once(API_KEY_DELIMITER)
                .expect("the minted key carries the delimiter");
            let handle_body = handle
                .strip_prefix(&format!("{}_", ApiKeyKind::PREFIX))
                .expect("the handle is an akey_ scoped id");

            assert_eq!(
                handle_body.chars().count(),
                HANDLE_CHARS,
                "the handle length must be what the published regex states"
            );
            assert_eq!(
                secret.chars().count(),
                secret_chars,
                "the secret length must be what the published regex states"
            );
            assert!(handle_body.chars().all(ALPHABET_OK));
            assert!(secret.chars().all(ALPHABET_OK));
        }
    }

    /// The two kinds are distinguishable by prefix, and neither prefix is a prefix of the
    /// other.
    ///
    /// The second half is the part worth asserting. `ira_ak_` and `ira_pat_` are fine, but a
    /// future `ira_a_` would make every `ira_ak_` key match the shorter prefix first, and a
    /// scanner or a verifier that tried prefixes in the wrong order would silently
    /// misclassify. The split exists so a leaked key names the kind of principal it belongs
    /// to; a prefix that swallows another destroys exactly that.
    #[test]
    fn neither_key_prefix_is_a_prefix_of_the_other() {
        assert_ne!(API_KEY_PREFIX, PERSONAL_ACCESS_TOKEN_PREFIX);
        assert!(!API_KEY_PREFIX.starts_with(PERSONAL_ACCESS_TOKEN_PREFIX));
        assert!(!PERSONAL_ACCESS_TOKEN_PREFIX.starts_with(API_KEY_PREFIX));
    }

    /// A key of one kind never parses as the other.
    #[test]
    fn a_key_of_one_kind_never_parses_as_the_other() {
        let env = Env::system();
        let scope = scope(&env);
        let api = mint_api_key(&env, &scope, ApiKeyKindTag::ApiKey);
        let pat = mint_api_key(&env, &scope, ApiKeyKindTag::PersonalAccessToken);

        assert!(api_key_handle(&api.plaintext, ApiKeyKindTag::ApiKey).is_some());
        assert!(api_key_handle(&api.plaintext, ApiKeyKindTag::PersonalAccessToken).is_none());
        assert!(api_key_handle(&pat.plaintext, ApiKeyKindTag::PersonalAccessToken).is_some());
        assert!(api_key_handle(&pat.plaintext, ApiKeyKindTag::ApiKey).is_none());
    }

    /// A truncated key, with the delimiter but no secret, is refused.
    ///
    /// Without the emptiness check this would present a valid handle and hash to a stable
    /// digest, so a row written from a truncated key would be verifiable by that same
    /// truncated key: a credential whose secret is nothing.
    #[test]
    fn a_key_with_an_empty_secret_is_refused() {
        let env = Env::system();
        let scope = scope(&env);
        let minted = mint_api_key(&env, &scope, ApiKeyKindTag::ApiKey);
        let handle = api_key_handle(&minted.plaintext, ApiKeyKindTag::ApiKey).expect("handle");
        let truncated = format!("{API_KEY_PREFIX}{handle}{API_KEY_DELIMITER}");
        assert!(api_key_handle(&truncated, ApiKeyKindTag::ApiKey).is_none());
        let no_delimiter = format!("{API_KEY_PREFIX}{handle}");
        assert!(api_key_handle(&no_delimiter, ApiKeyKindTag::ApiKey).is_none());
    }

    /// Two mints never collide, and the digest is of the WHOLE key.
    ///
    /// The second half matters: a digest over the secret alone would let a key from one scope
    /// verify against a row from another, because the scope lives in the handle.
    #[test]
    fn every_mint_is_distinct_and_the_digest_covers_the_whole_key() {
        let env = Env::system();
        let scope = scope(&env);
        let first = mint_api_key(&env, &scope, ApiKeyKindTag::ApiKey);
        let second = mint_api_key(&env, &scope, ApiKeyKindTag::ApiKey);
        assert_ne!(first.plaintext, second.plaintext);
        assert_ne!(first.digest, second.digest);
        assert_eq!(first.digest, api_key_digest(&first.plaintext));

        // Changing ONLY the handle changes the digest, so the digest is not over the secret
        // alone.
        let (_, secret) = first
            .plaintext
            .split_once(API_KEY_DELIMITER)
            .expect("delimiter");
        let other_handle = format!(
            "{API_KEY_PREFIX}{}{API_KEY_DELIMITER}{secret}",
            crate::id::ApiKeyId::generate(&env, &scope)
        );
        assert_ne!(first.digest, api_key_digest(&other_handle));
    }

    /// The plaintext is never derivable from what is stored.
    ///
    /// Criterion 4 asks that the plaintext be retrievable only in the creation response. The
    /// schema half is that no column holds it; this is the format half: the digest is one way,
    /// and the non-secret handle that IS stored reveals the scope and nothing else.
    #[test]
    fn the_stored_material_contains_no_part_of_the_secret() {
        let env = Env::system();
        let scope = scope(&env);
        let minted = mint_api_key(&env, &scope, ApiKeyKindTag::ApiKey);
        let (_, secret) = minted
            .plaintext
            .split_once(API_KEY_DELIMITER)
            .expect("delimiter");

        assert!(
            !minted.digest.contains(secret),
            "the digest contains the secret verbatim"
        );
        assert!(
            !minted.id.to_string().contains(secret),
            "the stored handle contains the secret verbatim"
        );
        // The digest is hex, so it cannot carry base64url material with `-` or `_` at all.
        assert!(minted.digest.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
