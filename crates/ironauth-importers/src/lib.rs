// SPDX-License-Identifier: MIT OR Apache-2.0

//! IronAuth first-party migration importers (issue #57).
//!
//! Migration is a product, not a doc page. This crate ships the vendor-specific
//! FRONT-ENDS over the #55 streaming bulk-import engine: each importer parses a
//! documented vendor export format and emits the engine's line-delimited record
//! format ([`ironauth_import::ImportRecord`]), so every source inherits the
//! streaming job's resumability, progress, denial-of-service bounds, and per-record
//! error reporting for free. The importers never reimplement the job, never touch
//! the store, and never verify or rehash a password: they are pure format
//! transforms that produce records the engine consumes.
//!
//! # The four sources
//!
//! * [`keycloak`]: a realm export (`realm.json`), with its PBKDF2 credentials.
//! * [`auth0`]: the bulk user export joined to the separate password-hash export
//!   (bcrypt).
//! * [`firebase`]: `auth:export`, re-encoding the modified-scrypt hash with the
//!   project-level parameters ([`firebase::FirebaseHashParams`]).
//! * [`scim`] and [`ldap`]: the generic escape hatch for everything else (SCIM 2.0
//!   core user resources, RFC 7643; LDAP entries with LDAP password schemes).
//!
//! # Gap reporting and the validation-only pass
//!
//! Every importer returns a [`Mapping`]: a per-user list of outcomes where nothing
//! is silently dropped. A construct with no representable IronAuth target is
//! recorded as a [`Gap`] naming WHAT was skipped and WHY. Run the VALIDATION-ONLY
//! pass by mapping and calling [`Mapping::gap_report`] (it creates no user); run the
//! COMMIT pass by feeding [`Mapping::record_lines`] to
//! [`ironauth_import::import_stream`].
//!
//! ```no_run
//! # fn demo(realm_json: &str) -> Result<(), Box<dyn std::error::Error>> {
//! use ironauth_importers::keycloak;
//!
//! // Validation-only: the full gap report, no user created.
//! let mapping = keycloak::map_realm(realm_json)?;
//! let report = mapping.gap_report();
//! println!("{}", report.render());
//!
//! // Commit: hand the record lines to the #55 streaming engine.
//! let lines = mapping.record_lines()?;
//! // ironauth_import::import_stream(&ctx, lines, on_record).await;
//! # let _ = lines;
//! # Ok(())
//! # }
//! ```
//!
//! # Out of scope
//!
//! One-shot correctness over a static export. Scheduled or continuous sync is a
//! documented later extension, not part of this crate. The streaming engine, hash
//! verification, and rehash behavior live in `ironauth-import` (issue #55) and are
//! reused, not reimplemented. A SCIM 2.0 protocol SERVER is M14; this crate only
//! consumes SCIM-shaped data offline.

pub mod auth0;
pub mod firebase;
pub mod gap;
pub mod keycloak;
pub mod ldap;
mod parse;
mod phc;
pub mod scim;

pub use gap::{Gap, GapEntry, GapReport, MapOutcome, MappedUser, Mapping, Source};
pub use parse::ParseError;
