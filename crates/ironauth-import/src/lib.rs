// SPDX-License-Identifier: MIT OR Apache-2.0

//! Streaming bulk user import with foreign password-hash support (issue #55).
//!
//! IronAuth's migration on-ramp. A tenant moving off another identity provider
//! imports its user set here without re-prompting a single password: each record
//! carries a foreign password hash (bcrypt, scrypt, PBKDF2, the Argon2 family, or
//! Firebase's modified scrypt) in a recognized, algorithm-tagged format, which
//! IronAuth stores AS-IS. On the user's NEXT login the foreign hash is verified
//! and, on success, transparently REHASHED to IronAuth's native Argon2id so the
//! foreign hash is retired (the verify-then-rehash mechanism that makes migration
//! lossless). No plaintext password is ever stored.
//!
//! # The two halves
//!
//! * [`scheme`] is the passwap-style, self-contained hash-scheme layer: parse, tag,
//!   bounds-check (the denial-of-service guard on attacker-supplied cost
//!   parameters), and verify. It has no database dependency, so the login path
//!   consumes it directly.
//! * [`engine`] is the streaming import engine: it consumes an iterator of
//!   [`record::ImportRecord`] one at a time (bounded memory, never collecting the
//!   whole input), creates each user THROUGH the audited, isolation-scoped
//!   `ActingUserRepo` (issue #52) so imported users get lifecycle, isolation, and
//!   PII encryption for free, isolates a per-record failure (a bad record is
//!   reported and skipped, the stream continues), and is idempotent on a stable
//!   per-record key so a re-run neither duplicates nor loses records.
//!
//! # Determinism seam
//!
//! Every wall-clock read flows through [`ironauth_env::Env::clock`] and every
//! random byte (the rehash salt) through [`ironauth_env::Env::entropy`], so the
//! engine is reproducible under a fixed test environment and the invariant lints
//! stay satisfied.

pub mod engine;
pub mod record;
pub mod run;
pub mod scheme;

pub use engine::{ImportContext, ImportReport, RecordError, RecordOutcome, import_stream};
pub use record::{
    ImportCredential, ImportRecord, ImportRecoveryCode, ImportTotp, RecordParseError,
    parse_record_line, to_record_line,
};
pub use run::import_into_run;
pub use scheme::{ForeignHash, HashError, Scheme};
