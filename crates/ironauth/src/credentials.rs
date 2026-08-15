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

        fn delete(&self, _account: &str) -> Result<(), CredentialError> {
            Err(CredentialError::Backend("refused".to_owned()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CredentialStore;
    use super::testing::MemoryStore;

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
