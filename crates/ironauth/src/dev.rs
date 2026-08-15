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

use std::net::{IpAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Locate a directory holding both `initdb` and `pg_ctl`.
///
/// The search order is the one `scripts/with-test-db.sh` already encodes, deliberately: a
/// developer whose shell script works must find the same binaries here, or the two disagree
/// on a host with more than one Postgres, which is the confusing case rather than the rare
/// one. `PG_BIN` is honoured first so that host can pin which install is used.
#[must_use]
pub fn locate_bin_dir(pg_bin_env: Option<&str>) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(dir) = pg_bin_env {
        candidates.push(PathBuf::from(dir));
    }
    // Whatever `pg_ctl` is on PATH, via its own directory.
    if let Ok(output) = Command::new("sh")
        .args(["-c", "command -v pg_ctl"])
        .output()
    {
        let found = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if !found.is_empty() {
            if let Some(parent) = Path::new(&found).parent() {
                candidates.push(parent.to_path_buf());
            }
        }
    }
    // The versioned install roots, EXACTLY the ones `with-test-db.sh` globs. The
    // `~/.theseus` entry is not optional trivia: it is where this project's own tooling
    // puts Postgres, and omitting it made this function fail on a host where the shell
    // script succeeds. The claim above that the orders match has to be true, not intended.
    let mut roots = vec![PathBuf::from("/usr/lib/postgresql")];
    if let Ok(home) = std::env::var("HOME") {
        roots.push(PathBuf::from(home).join(".theseus/postgresql"));
    }
    roots.push(PathBuf::from("/opt/homebrew/opt"));
    for base in roots {
        if let Ok(entries) = std::fs::read_dir(&base) {
            for entry in entries.flatten() {
                candidates.push(entry.path().join("bin"));
            }
        }
    }
    candidates
        .into_iter()
        .find(|dir| dir.join("initdb").is_file() && dir.join("pg_ctl").is_file())
}

/// A throwaway Postgres cluster owned by this process.
///
/// Stopped and DELETED on drop. That is the whole contract: an emulator that left a cluster
/// behind would accumulate one per run in a temp directory nobody reads, which is exactly
/// the leak that has bitten this project's gate before.
pub struct DevCluster {
    workdir: PathBuf,
    pg_ctl: PathBuf,
    /// The connection string for the cluster, on loopback TCP.
    pub database_url: String,
}

impl DevCluster {
    /// Initialise and start a cluster under a fresh temp directory.
    ///
    /// Listens on LOOPBACK TCP only and trusts local connections, which is safe for exactly
    /// the reason dev mode is: nothing outside this machine can reach it. That is the same
    /// posture `with-test-db.sh` uses and the same one the bind guard enforces above.
    ///
    /// # Errors
    ///
    /// A message naming the step that failed, so a developer can run it by hand.
    pub fn start(bin_dir: &Path, unique: &str) -> Result<Self, String> {
        let workdir = std::env::temp_dir().join(format!("ironauth-dev-pg-{unique}"));
        let data = workdir.join("data");
        let sock = workdir.join("sock");
        std::fs::create_dir_all(&sock)
            .map_err(|error| format!("creating {}: {error}", sock.display()))?;

        // An ephemeral port, chosen the same way the shell script does: bind, read, release.
        // There is an unavoidable race between releasing and Postgres binding; it is the
        // same one every ephemeral-port allocator has, and the failure is a clean startup
        // error rather than a silent misbind.
        let port = TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .map(|addr| addr.port())
            .map_err(|error| format!("choosing a port: {error}"))?;

        let superuser = "ironauth_super";
        run_step(
            &bin_dir.join("initdb"),
            &[
                "-D",
                &data.display().to_string(),
                "-U",
                superuser,
                "-A",
                "trust",
            ],
            "initdb",
        )?;

        let options = format!(
            "-p {port} -k {} -c listen_addresses=127.0.0.1",
            sock.display()
        );
        let pg_ctl = bin_dir.join("pg_ctl");
        let logfile = workdir.join("postgres.log");
        start_server(&pg_ctl, &data, &options, &logfile)?;

        Ok(Self {
            workdir,
            pg_ctl,
            database_url: format!("postgres://{superuser}@127.0.0.1:{port}/postgres"),
        })
    }
}

impl Drop for DevCluster {
    fn drop(&mut self) {
        // `immediate` rather than a graceful stop: there is nothing to preserve, and a
        // clean shutdown that hangs would leave the directory behind, which is the failure
        // this drop exists to prevent.
        let _ = Command::new(&self.pg_ctl)
            .args([
                "-D",
                &self.workdir.join("data").display().to_string(),
                "-m",
                "immediate",
                "stop",
            ])
            .output();
        let _ = std::fs::remove_dir_all(&self.workdir);
    }
}

/// Start the server WITHOUT inheriting this process's pipes.
///
/// `pg_ctl start` launches a daemon that inherits whatever stdout and stderr it is given
/// and holds them for its lifetime. Capturing those (via `Command::output`) therefore blocks
/// forever waiting for an EOF that arrives only when the database shuts down, which is the
/// very thing this is bringing up. Measured, not theorised: it hung for ten minutes with a
/// perfectly healthy cluster already running, which is why `with-test-db.sh` redirects to
/// /dev/null at exactly this step.
///
/// So the server's output goes to a LOG FILE (`pg_ctl -l`), this process's handles are
/// closed, and the exit status is what is waited on. The log is read back only on failure,
/// which is the one time its contents matter.
fn start_server(pg_ctl: &Path, data: &Path, options: &str, logfile: &Path) -> Result<(), String> {
    let status = Command::new(pg_ctl)
        .args([
            "-D",
            &data.display().to_string(),
            "-l",
            &logfile.display().to_string(),
            "-w",
            "-o",
            options,
            "start",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|error| format!("pg_ctl start: {error}"))?;
    if status.success() {
        return Ok(());
    }
    let log = std::fs::read_to_string(logfile).unwrap_or_default();
    Err(format!("pg_ctl start failed. Server log:\n{}", log.trim()))
}

/// Run one cluster-setup command, reporting its stderr on failure.
fn run_step(program: &Path, args: &[&str], step: &str) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("{step}: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "{step} failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

/// The `Env` the server boots with: deterministic entropy under a dev seed, the system one
/// otherwise, and a REAL clock either way.
///
/// A function rather than an expression inline in `serve`, so the SELECTION is testable.
/// Testing `Env::from_parts` directly would prove the primitive works and leave the thing
/// that can actually be wrong -- whether the boot path consults the seed at all -- unproved.
/// Measured: with the selection inline, a mutant that ignored the seed entirely compiled and
/// failed no test.
///
/// The clock stays real under a seed. `Env::deterministic` would freeze time, and a server
/// whose clock never advances cannot expire a token or a code, so the emulator would diverge
/// from production in exactly the behaviour most tests are about.
#[must_use]
pub fn boot_env(dev_seed: Option<u64>) -> ironauth_env::Env {
    match dev_seed {
        Some(seed) => ironauth_env::Env::from_parts(
            std::sync::Arc::new(ironauth_env::SystemClock),
            std::sync::Arc::new(ironauth_env::FixedEntropy::new(seed)),
        ),
        None => ironauth_env::Env::system(),
    }
}

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

    /// The cluster starts, is reachable on the port it reports, and is GONE after drop.
    ///
    /// Ignored by default because it spawns a real Postgres, which is the point: the parts
    /// that can be wrong here (the `initdb` flags, the `pg_ctl` options, the teardown) are
    /// exactly the parts a mock would not exercise. Run with `--ignored` on a host with
    /// Postgres installed.
    #[test]
    #[ignore = "spawns a real Postgres cluster; run with --ignored"]
    fn the_cluster_starts_and_is_removed_on_drop() {
        let Some(bin_dir) = locate_bin_dir(std::env::var("PG_BIN").ok().as_deref()) else {
            panic!("no Postgres binaries found; set PG_BIN");
        };
        let workdir;
        {
            let cluster = DevCluster::start(&bin_dir, "selftest").expect("cluster starts");
            assert!(
                cluster
                    .database_url
                    .starts_with("postgres://ironauth_super@127.0.0.1:"),
                "{}",
                cluster.database_url
            );
            workdir = std::env::temp_dir().join("ironauth-dev-pg-selftest");
            assert!(
                workdir.join("data").is_dir(),
                "the data directory must exist"
            );
            // The reported port must actually be listening: a cluster that reported a port
            // it did not bind would fail later, in the server, as an unrelated-looking error.
            let port: u16 = cluster
                .database_url
                .rsplit(':')
                .next()
                .and_then(|tail| tail.split('/').next())
                .and_then(|p| p.parse().ok())
                .expect("a port in the url");
            assert!(
                std::net::TcpStream::connect(("127.0.0.1", port)).is_ok(),
                "nothing is listening on the reported port {port}"
            );
        }
        assert!(
            !workdir.exists(),
            "dropping the cluster must delete {workdir:?}"
        );
    }

    /// The property criterion 2 rests on: the SAME seed yields the same bytes, so a CI
    /// script can name the code it expects rather than scraping it back.
    ///
    /// Asserted through `Env::from_parts` exactly as the boot path builds it, not through
    /// `FixedEntropy` alone: the claim that matters is about what the SERVER will generate,
    /// and testing the primitive would leave the wiring unproved.
    #[test]
    fn the_same_seed_yields_the_same_secrets() {
        let draw = |seed: Option<u64>| {
            let env = boot_env(seed);
            let mut bytes = [0_u8; 16];
            env.entropy().fill_bytes(&mut bytes);
            bytes
        };
        assert_eq!(draw(Some(1)), draw(Some(1)), "the same seed must reproduce");
        assert_ne!(
            draw(Some(1)),
            draw(Some(2)),
            "a different seed must diverge, or --seed does nothing"
        );
        // And NO seed must not be deterministic, or production would ship fixed secrets.
        // That is the direction of this pair that actually matters.
        assert_ne!(
            draw(None),
            draw(None),
            "without a dev seed the entropy must be real"
        );
    }

    /// The clock stays REAL under a dev seed. `Env::deterministic` would freeze time, and a
    /// server whose clock never advances cannot expire a token or a code, so the emulator
    /// would diverge from production in exactly the behaviour most tests are about.
    #[test]
    fn a_dev_seed_does_not_freeze_the_clock() {
        let env = boot_env(Some(1));
        let now = env
            .clock()
            .now_utc()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_secs();
        // Any real clock is far past this; a frozen one would sit at the epoch.
        assert!(now > 1_600_000_000, "the clock must be real, got {now}");
    }

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
