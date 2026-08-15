// SPDX-License-Identifier: MIT OR Apache-2.0

//! `ironauth dev`: the local emulator (issue #121).
//!
//! # Why a throwaway cluster rather than an embedded database
//!
//! The issue asks for "embedded or lightweight storage requiring no external services", and
//! two of the three readings of that are already ruled out by decisions recorded in this
//! repo.
//!
//! Embedding a database is FORBIDDEN, not merely disfavoured: `docs/design/TENANCY.md`
//! records that the only maintained pure-Rust embedded-Postgres crate pulls a dependency
//! tree with licences outside the project's permissive allowlist, which the supply-chain
//! policy forbids and `cargo deny check licenses` enforces. Substituting a different store
//! for dev contradicts this issue's own requirement to boot "the real server binary (not a
//! mock)": it would mean dev and CI never exercise row-level security, so the emulator
//! would be green on exactly the class of bug it exists to catch early.
//!
//! What is left, and what this does, is manage a DISPOSABLE cluster in a temp directory for
//! the process's lifetime. That is the mechanism `scripts/with-test-db.sh` already proves,
//! and it keeps the real store, the real migrations, and the real isolation behaviour.
//!
//! The honest cost is that it needs Postgres BINARIES on the host. That is stated in the
//! error when they are missing, naming what to install, rather than left to be discovered.
//!
//! The cluster lifecycle itself (locating `initdb`/`pg_ctl`, `initdb`, start, create,
//! teardown) is NOT here yet: `DATABASE_URL` is used when the developer already has one.
//! The binary search order it will need is the one `scripts/with-test-db.sh` already
//! encodes, and it should be copied from there rather than re-derived, so the two agree on
//! a host with more than one Postgres.
//!
//! # The emulator boots the REAL server
//!
//! `dev` prepares an environment (a cluster, a `DATABASE_URL`, a generated config) and then
//! hands off to the same `serve` path production uses. It deliberately does not carry its
//! own boot sequence: a second one would drift, and the drift would be invisible precisely
//! because dev is where nobody is looking for a production difference.

use std::net::IpAddr;

/// The message shown when no Postgres binaries can be found.
///
/// Names what to install and the escape hatch, because "could not start the emulator" sends
/// a developer looking at IronAuth for a missing dependency of the host.
#[must_use]
pub fn missing_postgres_message() -> String {
    "ironauth dev needs the PostgreSQL binaries (initdb, pg_ctl) to bring up its \
     throwaway database. Install PostgreSQL, or set PG_BIN to the directory holding \
     them, or set DATABASE_URL to point at a database you already have."
        .to_owned()
}

/// Why dev mode refused to start.
#[derive(Debug, PartialEq, Eq)]
pub enum DevRefusal {
    /// The bind address is reachable from outside this machine.
    NotLoopback(String),
}

impl std::fmt::Display for DevRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotLoopback(addr) => write!(
                f,
                "refusing to start: dev mode uses DETERMINISTIC secrets, which are safe \
                 only on loopback, and {addr} is reachable from outside this machine. Use \
                 `ironauth serve` with real configuration to run somewhere exposed."
            ),
        }
    }
}

/// Refuse to run dev mode anywhere it could be reached from outside the machine.
///
/// This is the criterion's guardrail, and the coupling is the point: dev mode's value comes
/// from deterministic secrets and seeded identities, and those two properties are exactly
/// what make it catastrophic to expose. Making the bind address the gate means the unsafe
/// combination cannot be assembled by setting one flag and forgetting the other.
///
/// A hostname is treated as NOT loopback even if it would resolve there. `localhost`
/// resolves to `::1` on some hosts and `127.0.0.1` on others, and to something else
/// entirely on a host with a creative `/etc/hosts`; a guard that trusts a name is a guard
/// that can be talked out of its answer.
///
/// # Errors
///
/// [`DevRefusal::NotLoopback`] when the address is not a loopback IP literal.
pub fn guard_loopback_only(bind: &str) -> Result<(), DevRefusal> {
    let host = bind.rsplit_once(':').map_or(bind, |(host, _)| host);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    match host.parse::<IpAddr>() {
        Ok(addr) if addr.is_loopback() => Ok(()),
        _ => Err(DevRefusal::NotLoopback(bind.to_owned())),
    }
}

/// The generated dev configuration.
///
/// Everything here is deliberately fixed rather than random: the point of the emulator is
/// that two runs, on two machines, produce the same identities and the same codes, so a CI
/// assertion can name them. Randomising any of it would make the emulator reproducible only
/// by accident.
#[must_use]
pub fn dev_config_toml(database_url: &str, bind: &str) -> String {
    format!(
        "# Generated by `ironauth dev` (issue #121). Not for production: every secret here\n\
         # is deterministic by design, which is why dev mode refuses a non-loopback bind.\n\
         [server]\n\
         bind = \"{bind}\"\n\
         \n\
         [database]\n\
         url = \"{database_url}\"\n"
    )
}

/// The startup banner.
///
/// Loud on purpose. The failure this prevents is somebody reading a dev process's output in
/// a terminal they have forgotten the history of and concluding it is a real deployment.
#[must_use]
pub fn banner(bind: &str) -> String {
    format!(
        "\n\
         ================================================================\n\
           ironauth dev  --  DEVELOPMENT EMULATOR, NOT A PRODUCTION SERVER\n\
         \n\
           Every secret is deterministic. Every identity is seeded.\n\
           Storage is a throwaway cluster, discarded when this exits.\n\
           Listening on {bind} (loopback only, enforced).\n\
         ================================================================\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Loopback literals are accepted, in both families.
    #[test]
    fn loopback_literals_are_allowed() {
        assert_eq!(guard_loopback_only("127.0.0.1:8080"), Ok(()));
        assert_eq!(guard_loopback_only("[::1]:8080"), Ok(()));
        // Anywhere in 127/8 is loopback, not just .0.1.
        assert_eq!(guard_loopback_only("127.9.9.9:8080"), Ok(()));
    }

    /// An address reachable from outside the machine is refused. This is the criterion:
    /// deterministic secrets and an exposed listener must not be assemblable.
    #[test]
    fn an_exposed_bind_is_refused() {
        for exposed in ["0.0.0.0:8080", "192.168.1.10:8080", "[::]:8080"] {
            assert_eq!(
                guard_loopback_only(exposed),
                Err(DevRefusal::NotLoopback(exposed.to_owned())),
                "{exposed} must be refused"
            );
        }
    }

    /// A NAME is refused even though it usually resolves to loopback. `localhost` resolves
    /// to `::1` on some hosts and `127.0.0.1` on others, and to whatever `/etc/hosts` says
    /// on a host somebody has edited; a guard that trusts a name can be talked out of its
    /// answer.
    #[test]
    fn a_hostname_is_refused_even_when_it_looks_local() {
        assert!(guard_loopback_only("localhost:8080").is_err());
        assert!(guard_loopback_only("my-dev-box:8080").is_err());
    }

    /// The refusal says WHY, and points at the command to use instead. "Refusing to start"
    /// alone sends someone editing config at random.
    #[test]
    fn the_refusal_explains_itself() {
        let message = DevRefusal::NotLoopback("0.0.0.0:8080".to_owned()).to_string();
        assert!(
            message.to_lowercase().contains("deterministic"),
            "{message}"
        );
        assert!(message.contains("ironauth serve"), "{message}");
    }

    /// The missing-binaries message names what to install and both escape hatches, because
    /// a bare failure sends a developer looking inside IronAuth for a host dependency.
    #[test]
    fn the_missing_postgres_message_names_the_fix() {
        let message = missing_postgres_message();
        assert!(message.contains("PostgreSQL"), "{message}");
        assert!(message.contains("PG_BIN"), "{message}");
        assert!(message.contains("DATABASE_URL"), "{message}");
    }

    /// The generated config carries the throwaway database and the guarded bind, and says
    /// in the file itself that it is not production.
    #[test]
    fn the_generated_config_records_what_it_is() {
        let toml = dev_config_toml("postgres://localhost/dev", "127.0.0.1:8080");
        assert!(toml.contains("postgres://localhost/dev"), "{toml}");
        assert!(toml.contains("127.0.0.1:8080"), "{toml}");
        assert!(toml.contains("Not for production"), "{toml}");
    }

    /// The banner names the emulator loudly. The failure it prevents is somebody reading a
    /// dev process's output and concluding it is a real deployment.
    #[test]
    fn the_banner_is_unmistakable() {
        let banner = banner("127.0.0.1:8080");
        assert!(banner.contains("NOT A PRODUCTION SERVER"), "{banner}");
        assert!(banner.to_lowercase().contains("deterministic"), "{banner}");
    }
}
