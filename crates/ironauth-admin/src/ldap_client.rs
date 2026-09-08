// SPDX-License-Identifier: MIT OR Apache-2.0

//! Talking to a directory server (issue #142).
//!
//! # The transport decision is made before a socket is opened
//!
//! A connector stores a `tls_mode`. The dangerous failure is not a refused connection, it is a
//! connection that succeeds in the CLEAR while the operator believes it is encrypted -- a bind
//! sends the service account password, so a silent downgrade hands the directory over.
//!
//! Two ways that happens, and both are refused here by [`DirectoryConfig::validate`] before any
//! connection is attempted:
//!
//!   * **The scheme disagrees with the mode.** `tls_mode = ldaps` against an `ldap://` URL is a
//!     configuration that reads as encrypted and is not. Checking at connect time rather than
//!     trusting the mode string means the two cannot drift apart.
//!   * **`StartTLS` is not verified.** `StartTLS` upgrades a plaintext connection in-band, so a
//!     server (or anybody in the path) that simply declines the upgrade leaves a working
//!     plaintext socket. `ldap3` surfaces the refusal as an error and this module treats it as
//!     fatal rather than continuing.
//!
//! There is deliberately NO option to skip certificate verification. `ldap3` offers
//! `set_no_tls_verify`, it is not plumbed to configuration, and a connector cannot ask for it.
//! An escape hatch that disables verification is the thing that ends up set in production.
//!
//! # Operational attributes have to be asked for
//!
//! Verified against a live `OpenLDAP`: a search that does not name `entryUUID` does not receive
//! it. `entryUUID` (RFC 4530) and Active Directory's `objectGUID` are OPERATIONAL attributes,
//! returned only on request.
//!
//! That matters more than it sounds. [`crate::ldap_mapping`] picks the stable identifier as
//! `objectGUID`, then `entryUUID`, then the DN, and the DN is rename-fragile. A search that
//! forgot to request the identifier would make every entry look like it had none, so every entry
//! would take the fallback and the rename safety would be off across the board with nothing
//! logged. So the attribute list is DERIVED by
//! [`crate::ldap_mapping::attributes_to_request`] rather than written at the call site.

use std::time::Duration;

use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};

use crate::ldap_mapping::DirectoryEntry;

/// How the connection to the directory is protected. Mirrors the `tls_mode` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// TLS from the first byte, on an `ldaps://` URL.
    Ldaps,
    /// A plaintext connection immediately upgraded in-band, on an `ldap://` URL.
    StartTls,
    /// No encryption at all.
    ///
    /// Never a default and never inferred: an operator has to choose it, and
    /// [`DirectoryConfig::validate`] is the only place that lets it through.
    Plaintext,
}

/// What went wrong talking to the directory.
#[derive(Debug)]
pub enum DirectoryError {
    /// The URL scheme and the configured TLS mode disagree.
    ///
    /// Refused before connecting, because the whole point is that the mode is not merely a label.
    SchemeDisagreesWithTlsMode {
        /// The mode the connector asked for.
        mode: TlsMode,
        /// The URL it was pointed at.
        url: String,
    },
    /// The URL is not an LDAP URL at all.
    UnsupportedScheme {
        /// What was configured.
        url: String,
    },
    /// The directory refused, or the transport failed. Includes a `StartTLS` upgrade the server
    /// declined, which is fatal rather than a reason to continue in the clear.
    Transport(ldap3::LdapError),
}

impl std::fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SchemeDisagreesWithTlsMode { mode, url } => write!(
                f,
                "tls_mode {mode:?} cannot be used with {url}: the connection would not be \
                 protected the way the connector says it is"
            ),
            Self::UnsupportedScheme { url } => write!(f, "{url} is not an ldap:// or ldaps:// URL"),
            Self::Transport(e) => write!(f, "directory transport failed: {e}"),
        }
    }
}

impl std::error::Error for DirectoryError {}

impl From<ldap3::LdapError> for DirectoryError {
    fn from(e: ldap3::LdapError) -> Self {
        Self::Transport(e)
    }
}

/// Everything needed to reach one directory.
#[derive(Debug, Clone)]
pub struct DirectoryConfig {
    /// `ldap://host:389` or `ldaps://host:636`.
    pub url: String,
    /// How the connection is protected.
    pub tls_mode: TlsMode,
    /// The service account DN.
    pub bind_dn: String,
    /// The service account password, resolved from the secret store by the caller.
    pub bind_password: String,
    /// RFC 2696 page size.
    pub page_size: i32,
    /// How long to wait for the connection.
    pub connect_timeout: Duration,
}

impl DirectoryConfig {
    /// Check the transport before a socket is opened.
    ///
    /// # Errors
    ///
    /// [`DirectoryError::SchemeDisagreesWithTlsMode`] when the URL would not be protected the way
    /// `tls_mode` says, and [`DirectoryError::UnsupportedScheme`] for a non-LDAP URL.
    pub fn validate(&self) -> Result<(), DirectoryError> {
        let lower = self.url.to_ascii_lowercase();
        let is_ldaps = lower.starts_with("ldaps://");
        let is_ldap = lower.starts_with("ldap://");
        if !is_ldaps && !is_ldap {
            return Err(DirectoryError::UnsupportedScheme {
                url: self.url.clone(),
            });
        }
        // `ldaps` needs the wrapped scheme; `starttls` and `plaintext` both begin in the clear and
        // so need the plain one. An `ldaps://` URL with `tls_mode = starttls` is refused too: it
        // would be encrypted, but not the way the connector describes, and the mismatch means one
        // of the two is a mistake worth surfacing.
        let agrees = match self.tls_mode {
            TlsMode::Ldaps => is_ldaps,
            TlsMode::StartTls | TlsMode::Plaintext => is_ldap,
        };
        if !agrees {
            return Err(DirectoryError::SchemeDisagreesWithTlsMode {
                mode: self.tls_mode,
                url: self.url.clone(),
            });
        }
        Ok(())
    }
}

/// A bound connection to a directory.
pub struct Directory {
    ldap: ldap3::Ldap,
}

impl Directory {
    /// Validate the transport, connect, and bind.
    ///
    /// # Errors
    ///
    /// [`DirectoryError`]. A refused `StartTLS` upgrade arrives here as
    /// [`DirectoryError::Transport`] and is fatal: this never falls back to plaintext.
    pub async fn connect(config: &DirectoryConfig) -> Result<Self, DirectoryError> {
        config.validate()?;

        let settings = LdapConnSettings::new()
            .set_conn_timeout(config.connect_timeout)
            .set_starttls(matches!(config.tls_mode, TlsMode::StartTls));

        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &config.url).await?;
        ldap3::drive!(conn);
        ldap.simple_bind(&config.bind_dn, &config.bind_password)
            .await?
            .success()?;
        Ok(Self { ldap })
    }

    /// Search, following RFC 2696 paging until the server stops returning pages.
    ///
    /// `attributes` should come from [`crate::ldap_mapping::attributes_to_request`] so the
    /// identifier attributes are always asked for -- see the module header for what silently
    /// omitting them costs.
    ///
    /// # Errors
    ///
    /// [`DirectoryError::Transport`] if any page fails. A partial result is never returned: a
    /// short member list reaching a deprovisioning comparison is the failure this subsystem must
    /// not have.
    pub async fn search_all(
        &mut self,
        base: &str,
        filter: &str,
        attributes: &[String],
        page_size: i32,
    ) -> Result<Vec<DirectoryEntry>, DirectoryError> {
        let adapters: Vec<Box<dyn ldap3::adapters::Adapter<_, _>>> = vec![
            Box::new(ldap3::adapters::EntriesOnly::new()),
            Box::new(ldap3::adapters::PagedResults::new(page_size)),
        ];
        let mut stream = self
            .ldap
            .streaming_search_with(adapters, base, Scope::Subtree, filter, attributes)
            .await?;

        let mut out = Vec::new();
        while let Some(entry) = stream.next().await? {
            let entry = SearchEntry::construct(entry);
            out.push(DirectoryEntry::new(
                entry.dn,
                entry.attrs.into_iter().collect(),
            ));
        }
        stream.finish().await.success()?;
        Ok(out)
    }

    /// Close the connection.
    ///
    /// # Errors
    ///
    /// [`DirectoryError::Transport`] if the unbind fails.
    pub async fn disconnect(&mut self) -> Result<(), DirectoryError> {
        self.ldap.unbind().await?;
        Ok(())
    }
}
