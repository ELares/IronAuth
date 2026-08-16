// SPDX-License-Identifier: MIT OR Apache-2.0

//! Where the CLI's credentials live (issue #120).
//!
//! # The platform keychain, and no file
//!
//! The criterion is "credentials are stored in the platform keychain with expiry on macOS,
//! Windows, and Linux; no plaintext token files exist after login in default mode". That is
//! a deliberate departure from the CLI convention of a dotfile under `$HOME`: a refresh
//! token in a plaintext file is readable by every process running as that user, survives
//! into backups, and is the one credential that regenerates all the others.
//!
//! The keychain is the macOS Keychain, the Windows Credential Manager, and the Secret
//! Service on Linux, each reached through the same `keyring` API, and each already provides
//! what a hand-rolled file would have to build: per-user access control enforced by the OS,
//! encryption at rest, and a UI the user already knows for auditing and revoking.
//!
//! # This module is deliberately only as large as its callers
//!
//! The operations here are exactly the ones something calls: [`CredentialStore::store`] for
//! `ironauth login` and [`CredentialStore::delete`] for `ironauth logout`. There is no
//! `load` yet, because nothing reads a stored credential back; it lands with the command
//! that does.
//!
//! That is a deliberate response to a measured problem in this milestone rather than
//! minimalism for its own sake. `device_login.rs`, `login_flow.rs`, and `loopback.rs` all
//! shipped earlier under this same issue, are individually well tested, and have zero call
//! sites; each carries a module-level `allow(dead_code)` because of it. The tests pass
//! because they call those modules directly, which is exactly why they cannot notice that
//! nothing else does. Adding a `store`/`load` pair here with no caller would repeat that,
//! and would need the same `allow` to stay quiet.
//!
//! # Why the store is a TRAIT
//!
//! Every keychain backend needs a real desktop session. A CI container has no Keychain, no
//! Credential Manager, and usually no Secret Service, so a test against the real backend
//! would either fail on the runner or pass on a laptop and fail in CI for a reason that
//! looks nothing like the change that provoked it.
//!
//! The seam is therefore the store, not the keychain: `logout` is written against
//! [`CredentialStore`], production passes [`KeyringStore`], and the tests drive an in-memory
//! implementation. What that deliberately does NOT prove is that the keychain backend works
//! on all three platforms; only running it there does. [`KeyringStore`] is kept as thin as
//! possible so that what these tests leave unproved is a delegation, not a decision.

/// What a successful login obtained, as stored.
///
/// The refresh token shares the entry rather than getting its own, so a `logout` cannot
/// partially succeed and leave the regenerating half behind.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredCredential {
    /// The access token.
    pub access_token: String,
    /// The refresh token, when the flow returned one.
    pub refresh_token: Option<String>,
    /// Expiry of the ACCESS token, epoch seconds.
    ///
    /// Stored rather than derived, so "am I still signed in" is answerable without a round
    /// trip: asking the server would turn every command into a network call, and treating a
    /// token as good until a 401 makes the first command after expiry fail for a reason the
    /// user reads as an outage.
    pub expires_at_unix_secs: i64,
    /// The issuer these tokens came from, so a credential is never presented to a different
    /// deployment than the one that minted it.
    pub issuer: String,
}

/// Whether an existing credential still stands in for a login: present, from the SAME
/// issuer, and not expired.
///
/// The issuer check is not a nicety. A credential minted by one deployment presented to
/// another is the mix-up this field exists to prevent, and "already signed in" is exactly
/// where that would happen: the user asked to sign in to a deployment, and the answer must
/// not be "you already are" on the strength of a token from somewhere else.
///
/// `now_unix_secs` is passed in rather than read, so the boundary is testable at the exact
/// second rather than approximately.
#[must_use]
pub fn still_valid(
    credential: Option<&StoredCredential>,
    issuer: &str,
    now_unix_secs: i64,
) -> bool {
    credential.is_some_and(|credential| {
        credential.issuer == issuer && credential.expires_at_unix_secs > now_unix_secs
    })
}

/// The service name every entry is filed under, so `logout` finds what `login` wrote and a
/// user can recognise the entries in their platform's keychain UI.
const SERVICE: &str = "ironauth-cli";

/// Why a credential operation failed.
#[derive(Debug)]
pub enum CredentialError {
    /// The platform keychain refused or is unavailable.
    Backend(String),
}

impl std::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backend(message) => write!(
                f,
                "the platform keychain is unavailable ({message}). On Linux this needs a \
                 desktop session with a Secret Service provider (gnome-keyring, kwallet)"
            ),
        }
    }
}

/// Where credentials live. See the module docs for why the seam is here.
pub trait CredentialStore {
    /// Store `credential` for `account`, replacing any existing entry.
    ///
    /// # Errors
    ///
    /// [`CredentialError::Backend`] when the platform keychain refuses. A login MUST fail
    /// on that: reporting success would tell the user they are signed in on a machine that
    /// has nothing stored, and the next command would fail for an unrelated-looking reason.
    fn store(&self, account: &str, credential: &StoredCredential) -> Result<(), CredentialError>;

    /// The credential stored for `account`, or `None` when there is none.
    ///
    /// Without this the stored expiry is write-only, and the promise on
    /// [`StoredCredential::expires_at_unix_secs`] -- that "am I still signed in" is
    /// answerable without a round trip -- is one nothing can keep. It is also the only way to
    /// verify the criterion this store exists for: that a credential survives a real platform
    /// keychain WITH its expiry intact can be asserted by reading it back and by nothing else.
    ///
    /// # Errors
    ///
    /// [`CredentialError::Backend`] when the platform keychain refuses, or when what came
    /// back cannot be decoded. A corrupt entry is an error and NOT `None`: reporting "not
    /// signed in" for a credential that is present but unreadable would send the user to log
    /// in again over a fault that a fresh login will reproduce.
    fn get(&self, account: &str) -> Result<Option<StoredCredential>, CredentialError>;

    /// Remove the credential for `account`. Removing an absent one SUCCEEDS.
    ///
    /// Idempotent on purpose: `logout` must leave the machine in a known state from ANY
    /// starting state, and a user running it twice, or after a login that failed halfway,
    /// should not see a failure suggesting something is still stored.
    ///
    /// # Errors
    ///
    /// [`CredentialError::Backend`] when the platform keychain refuses. That case must NOT
    /// be reported as success: the credential may still be there, and a logout that lies
    /// about a credential is the one failure this command cannot have.
    fn delete(&self, account: &str) -> Result<(), CredentialError>;
}

/// The platform keychain: macOS Keychain, Windows Credential Manager, Linux Secret Service.
pub struct KeyringStore;

impl CredentialStore for KeyringStore {
    fn store(&self, account: &str, credential: &StoredCredential) -> Result<(), CredentialError> {
        let encoded = serde_json::to_string(credential)
            .map_err(|error| CredentialError::Backend(error.to_string()))?;
        keyring::Entry::new(SERVICE, account)
            .map_err(|error| CredentialError::Backend(error.to_string()))?
            .set_password(&encoded)
            .map_err(|error| CredentialError::Backend(error.to_string()))
    }

    fn get(&self, account: &str) -> Result<Option<StoredCredential>, CredentialError> {
        let entry = keyring::Entry::new(SERVICE, account)
            .map_err(|error| CredentialError::Backend(error.to_string()))?;
        let encoded = match entry.get_password() {
            Ok(encoded) => encoded,
            Err(keyring::Error::NoEntry) => return Ok(None),
            Err(error) => return Err(CredentialError::Backend(error.to_string())),
        };
        serde_json::from_str(&encoded)
            .map(Some)
            .map_err(|error| CredentialError::Backend(error.to_string()))
    }

    fn delete(&self, account: &str) -> Result<(), CredentialError> {
        let entry = keyring::Entry::new(SERVICE, account)
            .map_err(|error| CredentialError::Backend(error.to_string()))?;
        match entry.delete_credential() {
            // An absent entry is the state `logout` is trying to reach, so reaching it
            // already is success, not a failure to find something.
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(CredentialError::Backend(error.to_string())),
        }
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use super::{CredentialError, CredentialStore, StoredCredential};

    /// An in-memory store holding what was written, so a test can assert the CONTENT and
    /// not merely the presence of a credential.
    #[derive(Default)]
    pub(crate) struct MemoryStore {
        accounts: Mutex<BTreeMap<String, StoredCredential>>,
    }

    impl MemoryStore {
        /// Seed an account as holding a credential.
        pub(crate) fn seed(&self, account: &str) {
            self.accounts
                .lock()
                .expect("credential store mutex")
                .insert(account.to_owned(), sample());
        }

        /// Whether `account` still holds one.
        pub(crate) fn holds(&self, account: &str) -> bool {
            self.accounts
                .lock()
                .expect("credential store mutex")
                .contains_key(account)
        }

        /// The stored expiry, so the derived instant is assertable.
        pub(crate) fn expiry_of(&self, account: &str) -> Option<i64> {
            self.accounts
                .lock()
                .expect("credential store mutex")
                .get(account)
                .map(|credential| credential.expires_at_unix_secs)
        }
    }

    /// A filler credential for `seed`.
    fn sample() -> StoredCredential {
        StoredCredential {
            access_token: "seeded".to_owned(),
            refresh_token: Some("seeded-refresh".to_owned()),
            expires_at_unix_secs: 0,
            issuer: "https://issuer.example.test".to_owned(),
        }
    }

    impl CredentialStore for MemoryStore {
        fn store(
            &self,
            account: &str,
            credential: &StoredCredential,
        ) -> Result<(), CredentialError> {
            self.accounts
                .lock()
                .expect("credential store mutex")
                .insert(account.to_owned(), credential.clone());
            Ok(())
        }

        fn get(&self, account: &str) -> Result<Option<StoredCredential>, CredentialError> {
            Ok(self
                .accounts
                .lock()
                .expect("credential store mutex")
                .get(account)
                .cloned())
        }

        fn delete(&self, account: &str) -> Result<(), CredentialError> {
            self.accounts
                .lock()
                .expect("credential store mutex")
                .remove(account);
            Ok(())
        }
    }

    /// A keychain that refuses every operation.
    pub(crate) struct RefusingStore;

    impl CredentialStore for RefusingStore {
        fn store(&self, _: &str, _: &StoredCredential) -> Result<(), CredentialError> {
            Err(CredentialError::Backend("refused".to_owned()))
        }

        fn get(&self, _: &str) -> Result<Option<StoredCredential>, CredentialError> {
            Err(CredentialError::Backend("refused".to_owned()))
        }

        fn delete(&self, _account: &str) -> Result<(), CredentialError> {
            Err(CredentialError::Backend("refused".to_owned()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CredentialStore;
    use super::testing::MemoryStore;
    use super::{KeyringStore, StoredCredential};

    /// A round trip through the REAL platform keychain (issue #120, criterion 4:
    /// "Credentials are stored in the platform keychain WITH EXPIRY on macOS, Windows, and
    /// Linux").
    ///
    /// Ignored by default, because it writes to the developer's own keychain and because a
    /// Linux box with no Secret Service running has nothing to write to. CI runs it with
    /// `--ignored` on all three platforms; see the `keychain` job.
    ///
    /// Every other test in this file runs against `MemoryStore`, which is a `BTreeMap`. That
    /// proves the SEAM and says nothing about a keychain -- the criterion names three
    /// operating systems, and until this existed no test touched any of them. The closest
    /// thing was an assertion about the text of an error message.
    ///
    /// The account name is unique per run, so a leftover entry from an interrupted run
    /// cannot make a later one pass by being already present.
    #[test]
    #[ignore = "writes to the real platform keychain; run with --ignored"]
    fn a_credential_survives_the_real_platform_keychain_with_its_expiry() {
        let store = KeyringStore;
        let account = format!("ironauth-selftest-{}", std::process::id());

        // Delete on the way out, INCLUDING on panic. Without this a failing assertion leaves
        // an entry in the developer's own keychain, which is exactly what happened while this
        // test was being written: a mutation run failed before reaching the delete below and
        // left one behind. The unique account name keeps a leftover from making a later run
        // pass, but it does not clean it up.
        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = KeyringStore.delete(&self.0);
            }
        }
        let _cleanup = Cleanup(account.clone());

        // Nothing stored yet. This is also the first assertion `get` has to satisfy, and it
        // is what makes the read below evidence: without it, a keychain that returned some
        // OTHER entry would look like a successful round trip.
        assert_eq!(
            store.get(&account).expect("reading an absent entry"),
            None,
            "no credential must exist for a freshly generated account name"
        );

        let credential = StoredCredential {
            access_token: "access-token-value".to_owned(),
            refresh_token: Some("refresh-token-value".to_owned()),
            // A specific, non-zero, non-default instant. A zero expiry would be
            // indistinguishable from a field that was dropped and defaulted on the way back.
            expires_at_unix_secs: 1_767_225_600,
            issuer: "https://issuer.example/t/ten_x/e/env_y".to_owned(),
        };
        store.store(&account, &credential).expect("storing");

        // Read back through the platform, comparing the WHOLE value. Asserting only the
        // access token would pass for a keychain round trip that silently lost the expiry,
        // which is the half of the criterion that is easiest to lose and hardest to notice.
        let read_back = store
            .get(&account)
            .expect("reading the credential back")
            .expect("the credential is present after storing it");
        assert_eq!(read_back, credential, "the credential survives unchanged");
        assert_eq!(
            read_back.expires_at_unix_secs, 1_767_225_600,
            "the expiry survives the keychain"
        );

        store.delete(&account).expect("deleting");
        assert_eq!(
            store.get(&account).expect("reading after deletion"),
            None,
            "logout leaves nothing behind"
        );

        // Deleting again is not an error: `logout` must reach a known state from any
        // starting state.
        store.delete(&account).expect("deleting twice is idempotent");
    }

    /// The consumer of the stored expiry. Without one, the promise on
    /// `expires_at_unix_secs` -- that "am I still signed in" is answerable without a round
    /// trip -- was one nothing could keep, and the field was written and never read.
    #[test]
    fn an_unexpired_credential_from_the_same_issuer_stands_in_for_a_login() {
        let credential = super::StoredCredential {
            access_token: "a".to_owned(),
            refresh_token: None,
            expires_at_unix_secs: 100,
            issuer: "https://one.example".to_owned(),
        };
        assert!(super::still_valid(Some(&credential), "https://one.example", 99));

        // Expiry is exclusive at the boundary: a token expiring exactly now is spent. The
        // alternative sends the user into a flow with a credential that dies mid-request.
        assert!(!super::still_valid(Some(&credential), "https://one.example", 100));
        assert!(!super::still_valid(Some(&credential), "https://one.example", 101));

        // A DIFFERENT deployment. The whole point of storing the issuer: answering "you are
        // already signed in" here would be answering about somewhere else.
        assert!(!super::still_valid(
            Some(&credential),
            "https://two.example",
            99
        ));

        // Nothing stored is not a login.
        assert!(!super::still_valid(None, "https://one.example", 99));
    }

    #[test]
    fn deleting_removes_the_credential() {
        let store = MemoryStore::default();
        store.seed("default");
        store.delete("default").expect("delete");
        assert!(!store.holds("default"));
    }

    #[test]
    fn deleting_an_absent_credential_succeeds_and_repeats() {
        let store = MemoryStore::default();
        store.delete("never-logged-in").expect("idempotent");
        store.delete("never-logged-in").expect("and repeatable");
    }

    #[test]
    fn accounts_are_independent() {
        let store = MemoryStore::default();
        store.seed("prod");
        store.seed("staging");
        store.delete("prod").expect("delete");
        assert!(!store.holds("prod"));
        assert!(
            store.holds("staging"),
            "logging out of one deployment must not touch another"
        );
    }

    /// The error message names the Linux case explicitly, because that is the platform
    /// where the keychain is genuinely absent rather than merely locked, and "the keychain
    /// is unavailable" alone sends someone looking at their own machine's settings.
    #[test]
    fn the_backend_error_names_what_linux_needs() {
        let message = super::CredentialError::Backend("no such interface".to_owned()).to_string();
        assert!(message.contains("Secret Service"), "{message}");
    }
}
