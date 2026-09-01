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

/// The roles the schema's GRANTs name. Missing any one makes every migration that grants to
/// it fail, so they are provisioned before the chain runs.
///
/// The same three the test harness provisions, and for the same reason: they are created out
/// of band in production, so a database that has only just been `initdb`-ed has none of them.
const SCHEMA_ROLES: [&str; 3] = [
    "ironauth_app",
    "ironauth_control",
    "ironauth_audit_retention",
];

/// Create the schema roles, idempotently.
///
/// Uses `psql` from the SAME directory the cluster came from, so this cannot silently talk to
/// a different Postgres than the one just started. The `DO $$ ... EXCEPTION` form makes a
/// re-run a no-op rather than an error, which matters because `ironauth dev` may be pointed
/// at a `DATABASE_URL` that already has them.
///
/// # Errors
///
/// A message naming the role that could not be created.
pub fn provision_roles(bin_dir: &Path, database_url: &str) -> Result<(), String> {
    for role in SCHEMA_ROLES {
        let sql = format!(
            "DO $$ BEGIN CREATE ROLE {role} LOGIN PASSWORD '{role}'; \
             EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;"
        );
        let output = Command::new(bin_dir.join("psql"))
            .args(["-d", database_url, "-v", "ON_ERROR_STOP=1", "-c", &sql])
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|error| format!("psql for role {role}: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "creating role {role}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
    }
    Ok(())
}

/// The scope the emulator seeds: an operator, a tenant, and its first environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeededScope {
    /// The owning operator.
    pub operator: String,
    /// The tenant.
    pub tenant: String,
    /// The tenant's first environment.
    pub environment: String,
    /// A PUBLIC client registered for the loopback redirect, so `ironauth login` works
    /// against the emulator with no further setup.
    pub client: String,
    /// An organization in the seeded environment. The criterion names orgs alongside tenants
    /// and users, and without one every org-scoped surface (membership, org connections, the
    /// per-org policy overlay) has nothing to be exercised against in the emulator.
    pub organization: String,
    /// A second client, owning the seeded MACHINE IDENTITY.
    ///
    /// Separate from [`Self::client`] deliberately. The first is the PUBLIC client a browser
    /// or CLI signs in through; a machine identity belongs to a client that represents a
    /// workload, and conflating them would make "the token was issued as the mapped identity"
    /// satisfiable by a grant that simply resolved the presenting client's own account.
    pub workload_client: String,
    /// The seeded MACHINE IDENTITY (issue #126): the principal a workload-federation subject
    /// mapping points at.
    ///
    /// Seeded because there is otherwise NO WAY TO GET ONE. A service account is minted as a
    /// side effect of a client-credentials exchange (`service_accounts().ensure`) and has no
    /// creation route on the management API, so an operator setting up workload federation
    /// against a fresh environment has nothing to map a workload onto until some client has
    /// already exchanged for a token. Every `subject-mappings` registration names a principal;
    /// without this the emulator can register trust anchors and map them onto nothing.
    pub machine_identity: String,
}

/// Distinguishes the seeded-identifier stream from the running server's, which draws from
/// `FixedEntropy::new(seed)` directly. Any constant works; what matters is that it is not
/// zero and not shared with another stream.
const SEED_STREAM_SCOPE: u64 = 0x5EED_5C0B_E000_0001;

/// Derive the seeded identifiers from `seed`.
///
/// GENERATED rather than hardcoded, from a dedicated entropy stream. Hardcoding them would
/// mean writing identifier strings by hand, and a hand-written id that does not parse fails
/// at the first use with an error about the id rather than about the seed -- a trap this
/// milestone has already sprung once. Generating guarantees the format is whatever the id
/// type currently says it is.
///
/// The stream is dedicated so the values do NOT depend on how many draws happened earlier.
/// Sharing the server's entropy would make the seeded tenant change whenever anything else
/// in the boot drew a byte first, which is reproducibility that breaks when unrelated code
/// changes.
#[must_use]
pub fn seed_ids(seed: u64) -> SeededScope {
    // A DEDICATED stream, like the fake upstream provider's key. Both this and the running
    // server draw from `FixedEntropy`, and two of those built from the same seed replay the
    // same sequence from the start -- so the first tenant id the SERVER minted was
    // byte-identical to the one seeded here, and every `POST /v1/tenants` against the
    // emulator died on `duplicate key value violates unique constraint "tenants_pkey"`. It
    // surfaced as a bare 500, which the published spec does not even declare for that
    // operation, so a client could not tell a collision from an outage.
    //
    // Deterministic ids are the emulator's whole point; two INDEPENDENT things minting the
    // same ones is not. Separating the streams keeps both properties.
    let env = ironauth_env::Env::from_parts(
        std::sync::Arc::new(ironauth_env::SystemClock),
        std::sync::Arc::new(ironauth_env::FixedEntropy::new(seed ^ SEED_STREAM_SCOPE)),
    );
    let tenant = ironauth_store::TenantId::generate(&env);
    let environment = ironauth_store::EnvironmentId::generate(&env);
    let scope = ironauth_store::Scope::new(tenant, environment);
    SeededScope {
        // The BOOTSTRAP operator, not a freshly generated one. The management API
        // authenticates the bootstrap token as this exact operator id, so seeding any other
        // operator leaves the emulator's own tenant owned by a principal the management
        // plane never acts as -- it can list what it did not create and administer none of
        // it. The admin suite makes the same move deliberately
        // (`own_seeded_scopes_by(bootstrap_operator_id())`).
        operator: ironauth_admin::bootstrap_operator_id().to_string(),
        tenant: tenant.to_string(),
        environment: environment.to_string(),
        client: ironauth_store::ClientId::generate(&env, &scope).to_string(),
        organization: ironauth_store::OrganizationId::generate(&env, &scope).to_string(),
        workload_client: ironauth_store::ClientId::generate(&env, &scope).to_string(),
        machine_identity: ironauth_store::ServiceAccountId::generate(&env, &scope).to_string(),
    }
}

/// The loopback redirect the seeded client registers.
///
/// Registered because RFC 8252 loopback matching is PORT-AGNOSTIC but exact in every other
/// respect: `ironauth login` binds an ephemeral port and the server accepts any port for a
/// matching literal and path. Registering `127.0.0.1` (not `localhost`, which this server
/// does not match port-agnostically) is what makes the emulator usable with the CLI login
/// without further setup.
pub const DEV_REDIRECT_URI: &str = "http://127.0.0.1/callback";

/// The seed statements, in dependency order.
///
/// Every one is `ON CONFLICT DO NOTHING`, which together with the deterministic ids above is
/// what makes re-running a no-op rather than a duplicate. That pair IS the criterion's
/// idempotence: identifiers that change per run would insert a second tenant every time, and
/// conflict clauses alone would not help because nothing would ever conflict.
#[must_use]
pub fn seed_statements(scope: &SeededScope) -> Vec<String> {
    vec![
        format!(
            "INSERT INTO operators (id, display_name) VALUES ('{}', 'dev operator') \
             ON CONFLICT (id) DO NOTHING;",
            scope.operator
        ),
        format!(
            "INSERT INTO tenants (id, operator_id, display_name) \
             VALUES ('{}', '{}', 'dev tenant') ON CONFLICT (id) DO NOTHING;",
            scope.tenant, scope.operator
        ),
        format!(
            "INSERT INTO environments (id, tenant_id, display_name, kind) \
             VALUES ('{}', '{}', 'dev environment', 'dev') ON CONFLICT (id) DO NOTHING;",
            scope.environment, scope.tenant
        ),
        // The serving state, WITHOUT which every scoped endpoint is a 404.
        //
        // An environment row alone is not enough: the data plane reads
        // `environment_states`, and a scope with no row there is not served. That is the
        // lifecycle fence working correctly (a scope must be affirmatively serving), and it
        // is the difference between an emulator that answers and one that starts cleanly,
        // logs nothing, and 404s every request. Measured: with the first three statements
        // only, discovery returned 404 while the server reported no error at all.
        format!(
            "INSERT INTO environment_states /* query-audit-allow: dev-only seeding of a \
             scoped table's precondition, as the cluster owner, against a throwaway \
             database this process created, BEFORE any server exists to route it through a \
             scoped repository */ (tenant_id, environment_id, serving_status) \
             VALUES ('{}', '{}', 'active') \
             ON CONFLICT (tenant_id, environment_id) DO NOTHING;",
            scope.tenant, scope.environment
        ),
        // An organization. B2B is the shape most quickstarts model, and an emulator with no
        // org means every org-scoped surface has to be created by hand before it can be
        // driven at all.
        format!(
            "INSERT INTO organizations /* query-audit-allow: dev-only seeding as the \
             cluster owner, against a throwaway database this process created, BEFORE any \
             server exists to route it through a scoped repository */ \
             (id, tenant_id, environment_id, display_name) \
             VALUES ('{}', '{}', '{}', 'dev organization') ON CONFLICT (id) DO NOTHING;",
            scope.organization, scope.tenant, scope.environment
        ),
        // A PUBLIC client (`none`): the emulator's reason to exist is driving flows from a
        // CLI or a sample app, and a public client with a loopback redirect is what both
        // use. A confidential one would need a secret every quickstart then has to carry.
        //
        // `grant_types` is stated rather than left to the column default, which migration
        // 0021 sets to `authorization_code` alone. Omitting it made the seeded client unable
        // to start a DEVICE grant at all: `grant_types_allow_device` refuses and the endpoint
        // answers `unauthorized_client`, so the CLI's headless login could not be driven
        // against the emulator even though both halves shipped. The default is right for a
        // migration, which must not widen an existing client's grants, and wrong for a seed
        // whose whole purpose is to exercise the flows.
        //
        // `first_party` for the same reason. It defaults false, which makes the seeded client
        // THIRD-party, and the admin-consent gate then refuses a device authorization with
        // `access_denied` until an operator pre-authorizes it. In a single-tenant emulator the
        // dev client is the operator's own by construction, so third-party is the wrong
        // classification rather than a safety margin: it blocks the flows the emulator exists
        // to demonstrate while protecting nobody, since there is no second party.
        format!(
            "INSERT INTO clients /* query-audit-allow: dev-only seeding as the cluster \
             owner, against a throwaway database this process created, BEFORE any server \
             exists to route it through a scoped repository */ \
             (id, tenant_id, environment_id, display_name, token_endpoint_auth_method, \
              redirect_uris, grant_types, first_party) \
             VALUES ('{}', '{}', '{}', 'dev client', 'none', ARRAY['{}'], \
                     'authorization_code {} {}', true) \
             ON CONFLICT (id) DO NOTHING;",
            scope.client,
            scope.tenant,
            scope.environment,
            DEV_REDIRECT_URI,
            ironauth_oidc::GrantType::DEVICE_CODE_URN,
            // The jwt-bearer grant (issue #126), so a WORKLOAD can present an ambient
            // assertion through the emulator's public client. Public is the point: the
            // criterion's "zero stored secrets" means the presenter has no secret either,
            // and a confidential presenter would hide that the assertion is the only
            // credential in the exchange.
            ironauth_oidc::GrantType::JwtBearer.as_str()
        ),
        // The WORKLOAD client, which exists to OWN the machine identity below.
        //
        // NO SECRET IS SEEDED, so this client cannot authenticate, and that is deliberate
        // rather than an omission. Nothing in the workload-federation flow authenticates as
        // it: the mapping names the IDENTITY, and the assertion is presented by the public
        // client. Seeding a usable secret would mean printing a second credential into the
        // banner to make a client nothing uses slightly more complete.
        //
        // Separate from the public client for a reason `workload_federation.rs` measured: an
        // identity owned by the PRESENTING client makes "the token was issued as the mapped
        // identity" satisfiable by a grant that ignored the mapping and resolved the
        // presenter's own service account. Different owner, different id, no such shortcut.
        format!(
            "INSERT INTO clients /* query-audit-allow: dev-only seeding as the cluster \
             owner, before any server exists to route it through a scoped repository */ \
             (id, tenant_id, environment_id, display_name, token_endpoint_auth_method, \
              redirect_uris, grant_types, first_party) \
             VALUES ('{}', '{}', '{}', 'dev workload', 'client_secret_basic', ARRAY[]::text[], \
                     'client_credentials', true) \
             ON CONFLICT (id) DO NOTHING;",
            scope.workload_client, scope.tenant, scope.environment
        ),
        // THE MACHINE IDENTITY (issue #126). Seeded because there is otherwise no way to get
        // one: `service_accounts().ensure` runs as a side effect of a client-credentials
        // exchange and the management API has no creation route, so a fresh environment has
        // nothing for a workload-federation subject mapping to point at.
        format!(
            "INSERT INTO service_accounts /* query-audit-allow: dev-only seeding as the \
             cluster owner, before any server exists to route it through a scoped \
             repository */ \
             (id, tenant_id, environment_id, client_id, created_at) \
             VALUES ('{}', '{}', '{}', '{}', now()) \
             ON CONFLICT (id) DO NOTHING;",
            scope.machine_identity, scope.tenant, scope.environment, scope.workload_client
        ),
    ]
}

/// Apply the seed statements.
///
/// Through `psql` from the same directory the cluster came from, like the role provisioning,
/// so it cannot silently address a different Postgres than the one just started.
///
/// # Errors
///
/// A message naming the statement that failed.
pub fn apply_seeds(bin_dir: &Path, database_url: &str, scope: &SeededScope) -> Result<(), String> {
    for statement in seed_statements(scope) {
        let output = Command::new(bin_dir.join("psql"))
            .args([
                "-d",
                database_url,
                "-v",
                "ON_ERROR_STOP=1",
                "-c",
                &statement,
            ])
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|error| format!("psql: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "seeding failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
    }
    Ok(())
}

/// Provision the seeded environment's signing key.
///
/// Without one the environment has no issuer entry, and EVERY scoped endpoint answers 404
/// while the server logs nothing: `registry.entry_for(scope)` returns `None`, which is the
/// same answer it gives for a scope that never existed. Measured -- with the tenant,
/// environment and serving state all seeded, discovery still 404-ed until this ran.
///
/// Ed25519 from a seed drawn through the dev entropy, so the key is reproducible for a given
/// `--seed` like every other dev secret. It is published and active from the epoch, so it
/// signs and appears in the JWKS the moment the server answers rather than after a delay
/// nobody configured.
///
/// # Errors
///
/// A message naming the step that failed.
pub async fn provision_signing_key(
    store: &ironauth_store::Store,
    env: &ironauth_env::Env,
    scope: ironauth_store::Scope,
    seed: u64,
) -> Result<(), String> {
    // A DEDICATED stream, like the identifiers: the key must not change because unrelated
    // code drew a byte earlier in the boot.
    let key_env = ironauth_env::Env::from_parts(
        std::sync::Arc::new(ironauth_env::SystemClock),
        std::sync::Arc::new(ironauth_env::FixedEntropy::new(seed ^ 0x5f3d_9a21)),
    );
    let key_id = ironauth_store::SigningKeyId::generate(&key_env, &scope);

    let mut material = [0_u8; 32];
    ironauth_env::Entropy::fill_bytes(key_env.entropy(), &mut material);
    // Built here only to fail loudly on material the signer would reject, rather than
    // persisting bytes that first break at the token endpoint.
    ironauth_jose::SigningKey::ed25519_from_seed(Some(key_id.to_string()), &material)
        .map_err(|error| format!("building the dev signing key: {error:?}"))?;

    store
        .scoped(scope)
        .acting(
            ironauth_store::ActorRef::human(ironauth_store::HumanId::generate(&key_env)),
            ironauth_store::CorrelationId::generate(env),
        )
        .signing_keys()
        .provision(
            env,
            ironauth_store::NewSigningKey {
                id: &key_id,
                algorithm: "EdDSA",
                material_kind: ironauth_store::SigningKeyMaterialKind::Ed25519Seed,
                material: &material,
                publish_at_micros: 0,
                activate_at_micros: 0,
                retire_at_micros: None,
                expire_at_micros: None,
            },
        )
        .await
        .map_err(|error| format!("provisioning the dev signing key: {error}"))
}

/// The dev master key material.
///
/// Named once so the generated config and the SEED path derive the same key. They must
/// agree: the seed seals a user identifier with it and the server unseals with whatever the
/// config says, so two literals that drifted would produce a user nobody can log in as.
pub const DEV_MASTER_KEY: &str = "ironauth-dev-master-key-not-for-production";
/// The operator token the emulator's management API accepts.
///
/// Without one the management plane is NOT MOUNTED -- the server says so at boot and every
/// management route is absent. An emulator that serves the OIDC plane and not the management
/// plane cannot stand in for the real server for anything that administers it, which is what
/// issue #122's reference client needs to talk to.
///
/// Fixed, like every other dev secret, so a client can be written against it. That is exactly
/// why dev mode refuses a non-loopback bind and a remote `DATABASE_URL`.
pub const DEV_OPERATOR_TOKEN: &str = "ironauth-dev-operator-token-not-for-production";

/// The seeded user's credentials. Fixed, like every other dev secret.
pub const DEV_USER_IDENTIFIER: &str = "dev@example.test";
/// The seeded user's password.
pub const DEV_USER_PASSWORD: &str = "dev-password-not-for-production";

/// Seed the dev user.
///
/// Through the REPOSITORY, not a seed statement, and that is forced rather than chosen:
/// `users` stores `identifier_sealed`, `identifier_bidx` and `claims_sealed`, so a row
/// cannot be written as literal SQL the way the tenant, environment, client and serving
/// state are. The repository seals the identifier and provisions the envelope keys
/// (`ensure_scope_keys`, KEK then DEK, both Conflict-tolerant) as a side effect, so there is
/// no separate key-provisioning step to run first.
///
/// Idempotent by tolerating the conflict a second run produces, which is the same shape the
/// envelope provisioning uses internally: a dev restart against an existing `DATABASE_URL`
/// re-runs every seed.
///
/// # Errors
///
/// A message naming the failure, unless it is the already-seeded conflict.
pub async fn seed_user(
    store: &ironauth_store::Store,
    env: &ironauth_env::Env,
    scope: ironauth_store::Scope,
) -> Result<(), String> {
    // The pool is REQUEST-PATH admission control, so one tenant's hashing storm degrades
    // only that tenant. A single hash run once at startup, with no request behind it and no
    // OidcState in existence yet to route through, is not that path.
    let password_hash = ironauth_oidc::hash_password(env, DEV_USER_PASSWORD) // pool-boundary-allow: one-off boot-time seed, no server or pool exists yet
        .map_err(|error| format!("hashing the dev password: {error:?}"))?;
    match store
        .scoped(scope)
        .acting(
            ironauth_store::ActorRef::human(ironauth_store::HumanId::generate(env)),
            ironauth_store::CorrelationId::generate(env),
        )
        .users()
        // No async flow-target deliveries: the dev seed is an operator-initiated fixture
        // rather than a self-service signup, and the envelope says "signup" without
        // qualification. Announcing it would tell an integration a person signed up when an
        // operator ran a seed.
        .register(env, DEV_USER_IDENTIFIER, &password_hash, None)
        .await
    {
        // A Conflict is ALREADY SEEDED, not a failure: a dev restart against an existing
        // DATABASE_URL re-runs every seed, so the second run must be a no-op.
        Ok(_) | Err(ironauth_store::StoreError::Conflict) => Ok(()),
        Err(error) => Err(format!("seeding the dev user: {error}")),
    }
}

/// The slug the seeded upstream connector is registered under.
pub const DEV_CONNECTOR_SLUG: &str = "dev-upstream";

/// Seed a federation connector pointing at the fake upstream provider.
///
/// Through the REPOSITORY, not a seed statement, and that is forced: `connectors` stores
/// `client_secret_sealed` and `client_secret_dek_version`, so the row cannot be written as
/// literal SQL the way the tenant, environment, client and serving state are. The repository
/// seals the secret under the scope's active DEK and provisions the envelope keys as a side
/// effect, so there is no separate key step.
///
/// Idempotent by treating the already-exists conflict as success, because a dev restart
/// against an existing `DATABASE_URL` re-runs every seed.
///
/// # Errors
///
/// A message naming the failure, unless it is the already-seeded conflict.
pub async fn seed_upstream_connector(
    store: &ironauth_store::Store,
    env: &ironauth_env::Env,
    scope: ironauth_store::Scope,
    upstream_issuer: &str,
    client_id: &str,
) -> Result<(), String> {
    let definition = serde_json::json!({
        "connector_id": DEV_CONNECTOR_SLUG,
        "display_name": "Dev upstream",
        "protocol": "oidc",
        "endpoints": { "issuer": upstream_issuer },
        "scopes": ["openid", "email"],
        "client_id": client_id,
    })
    .to_string();

    let id = ironauth_store::ConnectorId::generate(env, &scope);
    match store
        .scoped(scope)
        .acting(
            ironauth_store::ActorRef::human(ironauth_store::HumanId::generate(env)),
            ironauth_store::CorrelationId::generate(env),
        )
        .connectors()
        .create(
            env,
            &id,
            0,
            ironauth_store::NewConnector {
                slug: DEV_CONNECTOR_SLUG,
                definition_json: &definition,
                client_secret: b"dev-upstream-secret",
                capabilities: ironauth_store::ConnectorCapabilities {
                    refresh: false,
                    groups: false,
                    logout_propagation: false,
                    // Only 'untrusted' or 'trusted' satisfy the CHECK on
                    // cap_email_verified_trust (migration 0056). 'untrusted' is also the
                    // right default for a provider that authenticates anyone who asks.
                    email_verified_trust: "untrusted",
                },
                enabled: true,
            },
            None,
        )
        .await
    {
        // A Conflict is ALREADY SEEDED, not a failure.
        Ok(()) | Err(ironauth_store::StoreError::Conflict) => Ok(()),
        Err(error) => Err(format!("seeding the upstream connector: {error}")),
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
    /// `DATABASE_URL` points at a database on another machine.
    RemoteDatabase(String),
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
            Self::RemoteDatabase(host) => write!(
                f,
                "refusing to start: dev mode SEEDS a fixed operator, tenant, environment, \
                 organization, client and user, with a known password and deterministic \
                 secrets, into whatever DATABASE_URL names -- and it names {host}, which is \
                 not this machine. Point DATABASE_URL at a local database, or unset it and \
                 let dev bring up a throwaway cluster."
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

/// Refuse to seed a database that is not on this machine.
///
/// The bind guard above stops dev mode being REACHED from outside. This stops it REACHING
/// outside, which is the other direction of the same hazard and the one an operator falls
/// into by accident: `DATABASE_URL` is commonly already exported in a shell, and `ironauth
/// dev` honours it. It would then write a fixed operator, tenant, environment, organization,
/// client and a user whose password is a published constant into that database.
///
/// The test is the same one the bind guard applies, for the same reason: a HOSTNAME is not
/// evidence. `localhost` resolves wherever the host's resolver says, and a guard that trusts
/// a name is a guard that can be talked out of its answer. A DSN with no host at all is a
/// Unix socket, which cannot leave the machine.
///
/// # Errors
///
/// [`DevRefusal::RemoteDatabase`] when the DSN names a host that is not a loopback literal.
pub fn guard_local_database(database_url: &str) -> Result<(), DevRefusal> {
    // Everything after the scheme separator, then past any credentials, is authority.
    let after_scheme = database_url
        .split_once("://")
        .map_or(database_url, |(_, rest)| rest);
    let authority = after_scheme.split(['/', '?']).next().unwrap_or_default();
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    // A bracketed IPv6 literal keeps its colons, so strip the brackets before the port split.
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        rest.split_once(']').map_or(rest, |(host, _)| host)
    } else {
        host_port
            .rsplit_once(':')
            .map_or(host_port, |(host, _)| host)
    };
    // No host: a Unix-socket DSN (`postgres:///name`, or `host=` given as a parameter). It
    // cannot address another machine, so there is nothing to refuse.
    if host.is_empty() {
        return Ok(());
    }
    match host.parse::<IpAddr>() {
        Ok(addr) if addr.is_loopback() => Ok(()),
        _ => Err(DevRefusal::RemoteDatabase(host.to_owned())),
    }
}

/// The generated dev configuration.
///
/// Everything here is deliberately fixed rather than random: the point of the emulator is
/// that two runs, on two machines, produce the same identities and the same codes, so a CI
/// assertion can name them. Randomising any of it would make the emulator reproducible only
/// by accident.
#[must_use]
pub fn dev_config_toml(database_url: &str, bind: &str, management_bind: &str) -> String {
    format!(
        "# Generated by `ironauth dev` (issue #121). Not for production: every secret here\n\
         # is deterministic by design, which is why dev mode refuses a non-loopback bind.\n\
         \n\
         # The server ASKS for this by name. Without it the management API, the scheduled\n\
         # offboarding worker, and outbox retention all refuse to start, each saying \"or run\n\
         # in dev_mode\": they need a control-plane DSN and dev_mode lets them fall back to\n\
         # `database.url`. An emulator missing all three is not the real server.\n\
         dev_mode = true\n\
         \n\
         [server]\n\
         bind = \"{bind}\"\n\
         # An EPHEMERAL port. The default is a fixed 9443, so two emulators, or one emulator\n\
         # beside anything else holding that port, fail to bind and the whole server exits.\n\
         management_bind = \"{management_bind}\"\n\
         \n\
         [database]\n\
         url = \"{database_url}\"\n\
         # Required for the encrypted-PII paths (registration, login, UserInfo); without it\n\
         # they fail CLOSED and no login works. Fixed, like every other dev secret.\n\
         master_key = \"{DEV_MASTER_KEY}\"\n\
         \n\
         [admin]\n\
         # Without this the management API is not mounted at all and the emulator serves only\n\
         # half the server. Deterministic like every other dev secret, so a client can be\n\
         # written against it.\n\
         bootstrap_operator_token = \"{DEV_OPERATOR_TOKEN}\"\n\
         \n\
         [oidc]\n\
         # Off by default, so an emulator that did not set it served no OIDC at all, which is\n\
         # the one thing it exists to serve.\n\
         enabled = true\n\
         \n\
         # Dynamic Client Registration. Off by default, because open self-service registration\n\
         # is an abuse surface a real deployment must decide about. On HERE because it is the\n\
         # only path in the product that creates an OAuth client, so an emulator without it\n\
         # cannot demonstrate a client registering at all, which is half of the MCP\n\
         # authorization model (issue #129). Still gated: registration needs an initial\n\
         # access token minted through the management API.\n\
         registration_enabled = true\n\
         \n\
         [oidc.federation]\n\
         # The federation routes exist unconditionally but are INERT (a uniform 404) until a\n\
         # runtime is installed, which this flag is what installs. Without it the seeded\n\
         # upstream connector is unreachable and the emulator cannot demonstrate a federation\n\
         # login at all.\n\
         enabled = true\n"
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

    /// The whole database bring-up: cluster, roles, schema. This is the path
    /// `ironauth dev` takes on a machine with no database, and it is the one that was
    /// BROKEN before this test existed: the cluster started and nothing ever created the
    /// roles or applied the schema, so the server booted against an empty database and
    /// failed deep in its own startup rather than saying the schema was missing.
    ///
    /// Ignored by default because it spawns a real Postgres. Run with `--ignored`.
    #[test]
    #[ignore = "spawns a real Postgres cluster; run with --ignored"]
    fn the_database_is_usable_after_bring_up() {
        let Some(bin_dir) = locate_bin_dir(std::env::var("PG_BIN").ok().as_deref()) else {
            panic!("no Postgres binaries found; set PG_BIN");
        };
        let cluster = DevCluster::start(&bin_dir, "schema-selftest").expect("cluster starts");
        provision_roles(&bin_dir, &cluster.database_url).expect("roles are created");
        // Idempotent: `ironauth dev` may be pointed at a database that already has them.
        provision_roles(&bin_dir, &cluster.database_url).expect("roles provision twice");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let store = ironauth_store::Store::connect(&cluster.database_url)
                .await
                .expect("connect");
            store.migrate().await.expect("the schema applies");
            // Applying twice must be a no-op, which is what makes a dev restart cheap.
            store.migrate().await.expect("the schema is idempotent");

            // The seeds, then the key. Re-running BOTH must be a no-op: a dev restart
            // reuses the same database when DATABASE_URL is set, and a second run that
            // duplicated a tenant or failed on a existing key would break it.
            let scope = seed_ids(7);
            apply_seeds(&bin_dir, &cluster.database_url, &scope).expect("seeds apply");

            // COUNT the rows, do not merely re-run without an error. The criterion is
            // "re-running seeds does not duplicate state", and a second `apply_seeds` that
            // returns `Ok` proves only that no statement FAILED: one that inserted a second
            // row under a different id would satisfy it exactly as well. The counts are
            // also asserted non-zero first, because a table the seeds never touched has the
            // same count before and after and would make the equality below vacuous.
            let counted = [
                "operators",
                "tenants",
                "environments",
                "organizations",
                "clients",
            ];
            let before = count_rows(&bin_dir, &cluster.database_url, &counted);
            for (table, count) in counted.iter().zip(&before) {
                assert!(
                    *count > 0,
                    "the seeds must populate {table}, found {count} rows"
                );
            }

            apply_seeds(&bin_dir, &cluster.database_url, &scope).expect("seeds are idempotent");
            let after = count_rows(&bin_dir, &cluster.database_url, &counted);
            assert_eq!(
                before, after,
                "re-running the seeds duplicated state; per-table counts for {counted:?}"
            );

            let env = boot_env(Some(7));
            let parsed = ironauth_store::Scope::new(
                ironauth_store::TenantId::parse(&scope.tenant).expect("tenant parses"),
                ironauth_store::EnvironmentId::parse(&scope.environment)
                    .expect("environment parses"),
            );
            // Without this the environment has no issuer entry and EVERY scoped endpoint
            // answers 404 while the server logs nothing.
            provision_signing_key(&store, &env, parsed, 7)
                .await
                .expect("the signing key provisions");
        });
    }

    /// Row counts for `tables`, read through the same `psql` the seeds are applied with so
    /// the count cannot address a different database than the one just seeded.
    fn count_rows(bin_dir: &Path, database_url: &str, tables: &[&str]) -> Vec<i64> {
        tables
            .iter()
            .map(|table| {
                let output = Command::new(bin_dir.join("psql"))
                    .args([
                        "-d",
                        database_url,
                        "-t",
                        "-A",
                        "-v",
                        "ON_ERROR_STOP=1",
                        "-c",
                        // query-audit-allow: a test counting rows in a throwaway database it
                        // just seeded, as the cluster owner, with no server in the picture.
                        &format!("SELECT count(*) FROM {table};"),
                    ])
                    .stdin(std::process::Stdio::null())
                    .output()
                    .unwrap_or_else(|error| panic!("psql counting {table}: {error}"));
                assert!(
                    output.status.success(),
                    "counting {table}: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
                String::from_utf8_lossy(&output.stdout)
                    .trim()
                    .parse()
                    .unwrap_or_else(|error| panic!("count for {table} is not a number: {error}"))
            })
            .collect()
    }

    /// The seeded identifiers are REPRODUCIBLE, which is half of what makes re-running a
    /// no-op. Ids that changed per run would insert a second tenant every time, and the
    /// conflict clauses would never fire because nothing would conflict.
    #[test]
    fn the_seeded_ids_are_reproducible_and_seed_dependent() {
        assert_eq!(seed_ids(1), seed_ids(1), "the same seed must reproduce");
        assert_ne!(seed_ids(1), seed_ids(2), "a different seed must diverge");
    }

    /// The ids PARSE as the types they name. Generated rather than hand-written for exactly
    /// this reason: a fabricated identifier fails at first use with an error about the id
    /// rather than about the seed.
    #[test]
    fn the_seeded_ids_parse_as_their_types() {
        let scope = seed_ids(1);
        ironauth_store::TenantId::parse(&scope.tenant).expect("a valid tenant id");
        ironauth_store::EnvironmentId::parse(&scope.environment).expect("a valid environment id");
        ironauth_store::OperatorId::parse(&scope.operator).expect("a valid operator id");
        ironauth_store::ClientId::parse_declared_scope(&scope.client).expect("a valid client id");
    }

    /// Every statement is conflict-tolerant, which is the other half of idempotence.
    #[test]
    fn every_seed_statement_tolerates_a_re_run() {
        let statements = seed_statements(&seed_ids(1));
        assert_eq!(
            statements.len(),
            6,
            "operator, tenant, environment, serving state, organization, client"
        );
        for statement in &statements {
            assert!(
                statement.contains("ON CONFLICT"),
                "a seed statement without a conflict clause duplicates on re-run: {statement}"
            );
        }
    }

    /// Dependency order: an environment referencing a tenant that does not exist yet fails
    /// the foreign key, and the failure names the constraint rather than the ordering.
    #[test]
    fn the_seed_statements_are_in_dependency_order() {
        let statements = seed_statements(&seed_ids(1));
        assert!(
            statements[0].contains("INTO operators"),
            "{:?}",
            statements[0]
        );
        assert!(
            statements[1].contains("INTO tenants"),
            "{:?}",
            statements[1]
        );
        assert!(
            statements[2].contains("INTO environments"),
            "{:?}",
            statements[2]
        );
        // The serving state comes last and is not optional: without it every scoped
        // endpoint is a 404 while the server reports no error, which reads as a broken
        // emulator rather than an unserved scope.
        assert!(
            statements[3].contains("INTO environment_states"), // query-audit-allow: an assertion about a statement, not SQL
            "{:?}",
            statements[3]
        );
        assert!(statements[3].contains("'active'"), "{:?}", statements[3]);
        // The organization is scoped to the environment above it, so it follows it.
        assert!(
            statements[4].contains("INTO organizations"), // query-audit-allow: an assertion about a statement, not SQL
            "{:?}",
            statements[4]
        );
        let client = &statements[5];
        assert!(client.contains("INTO clients"), "{client}"); // query-audit-allow: assertion
    }

    /// The seeded client is PUBLIC and registers the loopback redirect, which is what makes
    /// `ironauth login` work against the emulator with no further setup. A confidential
    /// client would need a secret every quickstart then has to carry.
    #[test]
    fn the_seeded_client_is_public_and_loopback_registered() {
        let statements = seed_statements(&seed_ids(1));
        let client = &statements[5];
        assert!(client.contains("'none'"), "{client}");
        assert!(client.contains(DEV_REDIRECT_URI), "{client}");
        // The DEVICE grant, stated rather than defaulted. Without it the seeded client cannot
        // start a device authorization at all, which is the emulator's headless-login path.
        assert!(
            client.contains(ironauth_oidc::GrantType::DEVICE_CODE_URN),
            "the seed grants the device code URN: {client}"
        );
        assert!(
            client.contains("authorization_code"),
            "and keeps the browser grant beside it: {client}"
        );
        // FIRST-PARTY, asserted on the VALUE. `contains("first_party")` alone matches the
        // column name in the INSERT's own column list, so it holds whatever value follows and
        // would pass on a seed that set it false. Left false, the admin-consent gate treats
        // the emulator's own client as a third party and refuses the device grant before it
        // starts, which is the failure this pins.
        assert!(
            client.contains("first_party)"),
            "the seed names the column: {client}"
        );
        assert!(
            client.contains(", true)"),
            "and sets it TRUE, which is the half a name match cannot see: {client}"
        );
        // The literal, never the name: this server does not match `localhost`
        // port-agnostically, so a registration naming it could never match an ephemeral port.
        assert!(!client.contains("localhost"), "{client}");
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
    /// The other direction of the same hazard: dev mode must not SEED a database that is
    /// not on this machine. `DATABASE_URL` is commonly already exported in a shell, and dev
    /// mode honours it, so this is the one an operator reaches by accident.
    #[test]
    fn a_database_on_another_machine_is_refused() {
        for remote in [
            "postgres://user:pw@db.internal.example:5432/ironauth",
            "postgres://10.0.0.5:5432/ironauth",
            "postgresql://ironauth@[2001:db8::1]:5432/ironauth",
            // A NAME, even one that usually resolves here. The resolver decides where
            // `localhost` points, and a guard that trusts a name can be talked out of it.
            "postgres://localhost:5432/ironauth",
        ] {
            assert!(
                guard_local_database(remote).is_err(),
                "must refuse a non-loopback database: {remote}"
            );
        }
    }

    /// The guard must not refuse the databases dev mode actually uses, or it would make the
    /// emulator unusable rather than safe. A refusal-only test would pass with a guard that
    /// refused everything.
    #[test]
    fn a_local_database_is_accepted() {
        for local in [
            "postgres://ironauth_super@127.0.0.1:59100/postgres",
            "postgres://127.9.9.9/ironauth",
            "postgresql://ironauth@[::1]:5432/ironauth",
            // No host at all: a Unix-socket DSN, which cannot address another machine.
            "postgres:///ironauth",
        ] {
            assert_eq!(
                guard_local_database(local),
                Ok(()),
                "must accept a local database: {local}"
            );
        }
    }

    /// The refusal has to say WHAT is unsafe, not just that it refused: the reason dev mode
    /// cannot touch a remote database is the seeded password and deterministic secrets, and
    /// an operator who does not learn that will assume the guard is being fussy.
    #[test]
    fn the_remote_database_refusal_names_the_hazard() {
        let message = DevRefusal::RemoteDatabase("db.internal.example".to_owned()).to_string();
        assert!(message.contains("db.internal.example"), "{message}");
        assert!(message.contains("deterministic"), "{message}");
        assert!(message.contains("DATABASE_URL"), "{message}");
    }

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
        let toml = dev_config_toml("postgres://localhost/dev", "127.0.0.1:8080", "127.0.0.1:0");
        assert!(toml.contains("postgres://localhost/dev"), "{toml}");
        assert!(toml.contains("127.0.0.1:8080"), "{toml}");
        assert!(toml.contains("Not for production"), "{toml}");
        // The four settings without which the emulator does not actually work. Each was
        // MEASURED by running it: OIDC was not mounted, the management API was not mounted,
        // the encrypted-PII paths failed closed, and the fixed management port collided and
        // took the whole server down with it.
        assert!(toml.contains("dev_mode = true"), "{toml}");
        assert!(
            toml.contains("[oidc]\nenabled = true") || toml.contains("enabled = true"),
            "{toml}"
        );
        assert!(toml.contains("master_key"), "{toml}");
        assert!(toml.contains("management_bind"), "{toml}");
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
