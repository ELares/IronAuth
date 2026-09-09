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

/// How much of the tree one search covers.
///
/// Explicit because the difference is not cosmetic here. Reading a GROUP to get its member list
/// must be a base read: a subtree read rooted at the group's DN also returns that group's
/// children, and the code then takes `first()` of a set whose order the protocol does not
/// specify. The first version of this module hardcoded subtree and carried a comment saying
/// "(base scope)", which was false about the call it annotated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchScope {
    /// The named entry only.
    Base,
    /// The named entry and everything beneath it.
    Subtree,
}

impl From<SearchScope> for Scope {
    fn from(scope: SearchScope) -> Self {
        match scope {
            SearchScope::Base => Self::Base,
            SearchScope::Subtree => Self::Subtree,
        }
    }
}

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
    /// The search returned more entries than the connector's ceiling allows.
    ///
    /// REFUSED RATHER THAN TRUNCATED, for the reason the referral refusal gives: a short read
    /// reaches the diff as everybody who did not fit having departed.
    TooManyEntries {
        /// The ceiling that was reached.
        ceiling: usize,
    },
    /// A group DN the connector names does not resolve.
    ///
    /// Refused rather than treated as an empty group: an empty member set makes the expansion
    /// report itself COMPLETE, so nothing downstream refuses, and every principal reads as
    /// departed.
    GroupNotFound {
        /// The DN that did not resolve.
        dn: String,
    },
    /// The server referred part of the subtree to another directory, which this module does not
    /// chase.
    ///
    /// Returned rather than ignored: the entries behind a referral are missing from the result,
    /// and a short member set is indistinguishable from a departure.
    Referred {
        /// The referral URLs the server returned.
        referrals: Vec<String>,
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
            Self::TooManyEntries { ceiling } => write!(
                f,
                "the directory returned more than {ceiling} entries, which is this connector's \
                 ceiling; the search is refused rather than truncated, because a short read \
                 reaches the diff as everybody who did not fit having departed"
            ),
            Self::GroupNotFound { dn } => write!(
                f,
                "the group {dn} does not resolve; treating it as empty would report a complete \
                 walk over nobody"
            ),
            Self::Referred { referrals } => write!(
                f,
                "the server referred part of the subtree to {}, so the result is incomplete",
                referrals.join(", ")
            ),
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
    /// The most entries one search may return before it is refused.
    ///
    /// A CEILING RATHER THAN A STREAM. The diff this feeds compares the WHOLE directory against
    /// the whole previous snapshot, so the set is held in memory by construction and no amount
    /// of paging changes that: paging bounds what is on the wire at once, not what the process
    /// holds. MEASURED on a real server at between about 2.6KB and 1.8KB per entry, falling as
    /// the directory grows; `ldap_boot`'s `MAX_ENTRIES` carries the four-point table and the
    /// caveat that the large figures are extrapolations from 40,005 rather than measurements.
    ///
    /// What this buys is that the failure is a REFUSAL naming the directory, rather than an
    /// allocator killing the process mid-sweep and taking every other connector's pass with it.
    pub max_entries: usize,
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

/// Where a long search reports how far it has got.
///
/// AN EXPLICIT SEAM, not a log line. The first version of this emitted `tracing::info!` and
/// asserted on it with a captured subscriber; that test passed alone and FAILED in the suite,
/// because `tracing` caches callsite interest globally and a thread-local subscriber loses the
/// race against sibling threads running with none. A progress signal whose test is a coin flip
/// is not a progress signal. This is the same shape `ScimPushObserver` uses next door, and it is
/// deterministic.
pub trait SearchProgress: Send + Sync {
    /// `read` entries have arrived so far, out of a ceiling of `ceiling`.
    ///
    /// Called every `page_size` entries AND once when the read finishes, so the last call always
    /// carries the total. Not once per entry: one line per five hundred is a readable trickle,
    /// one per entry is a flood that hides everything else.
    ///
    /// THE FINAL CALL IS WHY A SMALL DIRECTORY REPORTS AT ALL. The first version fired only on
    /// `read % page_size == 0`, and the production page size is 500 -- so every directory of
    /// fewer than five hundred people, which is most of them, produced no progress whatsoever
    /// and a partial last page was never announced at any size.
    fn entries_read(&self, _base: &str, _read: usize, _ceiling: usize) {}
}

/// The default: report progress to the log, which is where an operator watching a sweep looks.
pub struct LogProgress;

impl SearchProgress for LogProgress {
    fn entries_read(&self, base: &str, read: usize, ceiling: usize) {
        tracing::info!(read, ceiling, %base, "ldap search in progress");
    }
}

/// A bound connection to a directory.
pub struct Directory {
    /// Behind a mutex so the sync's traits can take `&self`.
    ///
    /// `ldap3::Ldap` needs `&mut` for every operation, but `ldap_sync::plan` holds ONE source and
    /// asks it two different questions (enumerate people, walk groups) through two traits. Taking
    /// `&mut` in both would mean either two connections or threading a mutable borrow through the
    /// walk. One connection, serialised, is what a directory expects anyway: a bind is a session.
    ldap: tokio::sync::Mutex<ldap3::Ldap>,
    /// The ceiling on one search's entries, carried from the config for the same reason the page
    /// size is: a caller that could pass its own would be able to disagree with the connector.
    max_entries: usize,
    /// Where a long search reports how far it has got. Logs by default.
    progress: std::sync::Arc<dyn SearchProgress>,
    /// Carried from the config so a caller cannot pass a page size that disagrees with the
    /// connector's. The first version took it as a `search_all` argument while the config field
    /// went unread, which made the field decoration.
    page_size: i32,
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
        Ok(Self {
            ldap: tokio::sync::Mutex::new(ldap),
            max_entries: config.max_entries,
            progress: std::sync::Arc::new(LogProgress),
            page_size: config.page_size,
        })
    }

    /// What this connection will refuse above, as configured.
    ///
    /// Exposed so a caller can assert the PRODUCTION wiring supplies a real ceiling. Setting
    /// `ldap_boot`'s `MAX_ENTRIES` to `usize::MAX` -- the feature switched off in production --
    /// left every test in the tree green, because each supplied its own value and none observed
    /// the one the sweep uses.
    #[must_use]
    pub fn ceiling(&self) -> usize {
        self.max_entries
    }

    /// Report this search's progress somewhere other than the log.
    ///
    /// Builder rather than a `DirectoryConfig` field because the config is what a CONNECTOR row
    /// says, and where progress goes is not: it is the caller's choice, and the sweep and a test
    /// want different answers from the same row. (The three `DirectoryConfig` literals in the
    /// tree would each have gained a field; that is a small cost, and not the reason.)
    #[must_use]
    pub fn with_progress(mut self, progress: std::sync::Arc<dyn SearchProgress>) -> Self {
        self.progress = progress;
        self
    }

    /// Search, following RFC 2696 paging until the server stops returning pages.
    ///
    /// `attributes` should come from [`crate::ldap_mapping::attributes_to_request`] so the
    /// identifier attributes are always asked for -- see the module header for what silently
    /// omitting them costs. The page size is the connector's, taken at connect time.
    ///
    /// # Errors
    ///
    /// [`DirectoryError::Transport`] if any page fails, [`DirectoryError::Referred`] if the
    /// server referred part of the subtree elsewhere, and [`DirectoryError::TooManyEntries`] if
    /// the directory holds more than this connector's ceiling. A partial result is never returned: a short
    /// member list reaching a deprovisioning comparison is the failure this subsystem must not
    /// have, and a dropped referral is one of the ways a list gets short.
    pub async fn search_all(
        &self,
        base: &str,
        scope: SearchScope,
        filter: &str,
        attributes: &[String],
    ) -> Result<Vec<DirectoryEntry>, DirectoryError> {
        let mut ldap = self.ldap.lock().await;
        let adapters: Vec<Box<dyn ldap3::adapters::Adapter<_, _>>> = vec![
            Box::new(ldap3::adapters::EntriesOnly::new()),
            Box::new(ldap3::adapters::PagedResults::new(self.page_size)),
        ];
        let mut stream = ldap
            .streaming_search_with(adapters, base, scope.into(), filter, attributes)
            .await?;
        let page = usize::try_from(self.page_size).unwrap_or(1).max(1);

        let mut out = Vec::new();
        while let Some(entry) = stream.next().await? {
            if out.len() >= self.max_entries {
                // REFUSED, NOT TRUNCATED. A short read is the one thing this module must never
                // hand the diff: `previous - observed` over a truncated observation reports
                // everybody who did not fit as departed, which under a delete policy is
                // unrecoverable. The same reasoning as the referral refusal below.
                return Err(DirectoryError::TooManyEntries {
                    ceiling: self.max_entries,
                });
            }
            let entry = SearchEntry::construct(entry);
            // BOTH MAPS. `ldap3` routes any value that is not valid UTF-8 into `bin_attrs` and
            // never into `attrs`, and Active Directory's `objectGUID` is sixteen raw bytes. The
            // first version of this loop carried only `attrs`, so the octet-string support in
            // `ldap_mapping` had no producer: every AD entry arrived with no identifier and took
            // the rename-fragile DN fallback, silently. Requesting the attribute is necessary
            // and was not sufficient.
            out.push(
                DirectoryEntry::new(entry.dn, entry.attrs.into_iter().collect())
                    .with_binary(entry.bin_attrs.into_iter().collect()),
            );
            // PROGRESS WHILE IT RUNS. A pass over twenty thousand people takes half a minute and
            // reported nothing until it ended, so an operator watching a large directory could
            // not tell a slow read from a wedged one.
            if out.len() % page == 0 {
                self.progress
                    .entries_read(base, out.len(), self.max_entries);
            }
        }

        // THE FINAL COUNT, always, so a directory smaller than one page still reports and a
        // partial last page is announced. Skipped only when the last in-loop call already said
        // exactly this, which happens when the total is an exact multiple of the page size.
        if out.is_empty() || out.len() % page != 0 {
            self.progress
                .entries_read(base, out.len(), self.max_entries);
        }

        // A SEARCH THAT WAS REFERRED SOMEWHERE ELSE IS NOT A COMPLETE SEARCH. `EntriesOnly`
        // collects continuation references and `LdapResult::success` only inspects the result
        // code, so a subtree spanning a referral would return Ok with a SHORT list -- which is
        // exactly the input that must not reach a deprovisioning comparison. This module does
        // not chase referrals, so the honest answer is to refuse rather than under-report.
        let result = stream.finish().await;
        let refs = result.refs.clone();
        result.success()?;
        if !refs.is_empty() {
            return Err(DirectoryError::Referred { referrals: refs });
        }
        Ok(out)
    }

    /// Close the connection.
    ///
    /// # Errors
    ///
    /// [`DirectoryError::Transport`] if the unbind fails.
    pub async fn disconnect(&self) -> Result<(), DirectoryError> {
        self.ldap.lock().await.unbind().await?;
        Ok(())
    }
}

/// The live client is what `ldap_sync::plan` enumerates people with.
///
/// Without this impl the sync would be generic over a trait no shipped type satisfies, which is
/// the shape `scripts/dormant-module-scan.sh` exists to catch.
impl crate::ldap_sync::EntrySource for Directory {
    type Error = DirectoryError;

    async fn search(
        &self,
        base: &str,
        filter: &str,
        attributes: &[String],
    ) -> Result<Vec<DirectoryEntry>, DirectoryError> {
        // SUBTREE here, deliberately: people live under the base DN, often in sub-OUs.
        self.search_all(base, SearchScope::Subtree, filter, attributes)
            .await
    }
}

/// And the same connection walks the groups.
///
/// A member is a group when its entry carries one of the group object classes. The class differs
/// by server -- `group` on Active Directory, `groupOfNames` and `groupOfUniqueNames` on
/// `OpenLDAP` -- so all three are accepted rather than baking one dialect in.
impl crate::ldap_groups::GroupSource for Directory {
    type Error = DirectoryError;

    async fn direct_members(
        &self,
        group_dn: &str,
    ) -> Result<Vec<crate::ldap_groups::Member>, DirectoryError> {
        // ONE BASE READ for the group, then one per member to ask what it IS -- so the cost is
        // 1 + N searches per group, not two. An earlier version of this comment said "two round
        // trips", which is wrong by two orders of magnitude on a 500-member group, and said
        // "(base scope)" while the call hardcoded a subtree read.
        //
        // The base read matters beyond cost: a subtree read rooted at the group's DN also returns
        // the group's CHILDREN, and `first()` would then pick from a set whose order the protocol
        // does not specify.
        // TWO WAYS A GROUP FAILS TO RESOLVE, and both must land on the same refusal. A server
        // that does not know the DN answers `noSuchObject` (32); one where an ACL hides it can
        // instead answer success with no entries. Only the first is an error on its own, so the
        // second needs the guard below or it becomes "an empty group".
        let group = match self
            .search_all(
                group_dn,
                SearchScope::Base,
                "(objectClass=*)",
                &["member".to_owned()],
            )
            .await
        {
            Ok(entries) => entries,
            Err(DirectoryError::Transport(ldap3::LdapError::LdapResult { result }))
                if result.rc == 32 =>
            {
                return Err(DirectoryError::GroupNotFound {
                    dn: group_dn.to_owned(),
                });
            }
            Err(other) => return Err(other),
        };
        let Some(entry) = group.first() else {
            // A GROUP THAT DOES NOT RESOLVE IS NOT AN EMPTY GROUP. Returning `Ok(vec![])` here
            // made the walk report `complete: true` over a member set of nobody, so the diff did
            // not refuse and every principal read as departed -- the exact outcome this
            // subsystem exists to prevent, reached through a typo in a group DN.
            return Err(DirectoryError::GroupNotFound {
                dn: group_dn.to_owned(),
            });
        };

        let mut members = Vec::new();
        for dn in entry.values("member") {
            let found = self
                .search_all(
                    dn,
                    SearchScope::Base,
                    "(objectClass=*)",
                    &["objectClass".to_owned()],
                )
                .await?;
            // A member the search cannot resolve is carried as a NON-group: it may be a person
            // outside the base, and dropping it silently would shrink the member set, which the
            // diff reads as a departure.
            let is_group = found.first().is_some_and(|e| {
                e.values("objectclass").iter().any(|c| {
                    let c = c.to_ascii_lowercase();
                    c == "group" || c == "groupofnames" || c == "groupofuniquenames"
                })
            });
            members.push(crate::ldap_groups::Member {
                dn: dn.clone(),
                is_group,
            });
        }
        Ok(members)
    }
}
