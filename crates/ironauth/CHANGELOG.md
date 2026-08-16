# ironauth changelog

All notable changes to the `ironauth` binary. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- **A complete offline email-OTP login, asserted in CI (issue #121, criterion 2).**
  `scripts/dev-otp-login.sh` boots the emulator, requests a code, reads it from the capture
  sink, and completes the login -- with no mail server and no network.

  ```
  dev-otp-login: captured code 334158
  dev-otp-login: authenticated, amr=['otp']
  ```

  - **It reads the code from the SINK, not the log.** The sink is the supported surface and
    returns structured JSON; scraping a log line would couple the assertion to a message
    format that exists for humans.

  - **The code is pinned to the seed (`EXPECT_CODE`).** Without that the job would pass
    against any code at all, and a regression that broke reproducibility -- the property the
    whole seeded emulator rests on -- would go unnoticed. The same seed produced `334158`
    across every run in this work, including on a database created from scratch each time.

  - **`authenticated: true` is asserted, not just the 200.** A future change returning 200
    with a refusal body would otherwise read as success. The 200 on `otp/send` is explicitly
    NOT treated as evidence: that response is identical whether or not the account exists,
    by the anti-enumeration contract, so it proves only that the request was accepted.


- **FIX (#842): the dev capture sink wedged the whole server on the first message delivery.**
  `println!` in the delivery path took the process-wide stdout lock that the tracing writer
  also uses. The delivery runs SYNCHRONOUSLY inside an async request handler, so it could sit
  on that lock and take an executor worker with it: after one `POST /otp/send`, discovery,
  JWKS and the token endpoint all stopped answering, with the process alive and no error
  logged. Routed through `tracing`, which every other line in this process already uses.

  - **Two wrong diagnoses before the right one, both mine.** I blamed the mutex twice: first
    for spanning the `println!`, then for being shared with the sink's HTTP reader. I even
    rebuilt the sink around an unbounded channel so the delivery path could not block on a
    reader at all. It still hung, because that redesign kept the `println!`. I reverted it
    rather than merge a plausible non-fix whose stated rationale would have read as a cure.

  - **Instrumentation settled it, not reasoning.** An `eprintln!` probe at the top of `push`
    printed; the next statement never did. That single run eliminated every remaining theory,
    and the fact that the probe went to STDERR while the hang was on STDOUT is the whole
    answer.

  - **Verified end to end**, which is also criterion 2's substance: `otp/send` 200 in 0.22s,
    discovery still 200 afterwards, and the sink returning a real captured code
    (`{"kind":"email","recipient":"dev@example.test","body":"334158"}`).

  - **Why nothing caught it.** The sink had unit tests, an endpoint check returning JSON, and
    a no-egress harness -- and not one of them ever delivered a message THROUGH it. Discovery,
    JWKS, `/authorize` and the boot budget never trigger a delivery, so every check run when
    it landed passed while the delivery path was broken. A regression guard worth adding is a
    source scan forbidding `println!` in this crate's request-path code; a unit test cannot
    see this, because the defect only exists with a live executor under it.


- **The emulator seeds a USER, and the master key is attached where the seeding happens
  (issue #121).** `ironauth dev` now prints an issuer, a client, and a working login.

  - **The user goes through the REPOSITORY, and that is forced rather than chosen.** `users`
    stores `identifier_sealed`, `identifier_bidx` and `claims_sealed`, so a row cannot be a
    seed statement the way the tenant, environment, client and serving state are. The
    repository seals the identifier and provisions the envelope keys as a side effect
    (`ensure_scope_keys`, KEK then DEK, both Conflict-tolerant), so there is no separate
    key-provisioning step to run first -- correcting my own earlier note on the issue, which
    claimed there was.

  - **FIX found by running it: the seeding store had no master key.** `Store::connect` alone
    does not carry one, and the envelope paths read it off the STORE, so the first attempt
    failed with "envelope decryption failed" -- a failure of the seed, not of the config the
    server later reads. The key is now attached with `with_master_key` at the point of
    seeding.

  - **The master key material is named ONCE** (`DEV_MASTER_KEY`) and used by both the
    generated config and the seed path. They have to agree: the seed seals a user identifier
    with it and the server unseals with whatever the config says, so two literals that drifted
    would produce a user nobody can log in as, with no error anywhere.

  - **Idempotent by treating `Conflict` as already-seeded**, because a dev restart against an
    existing `DATABASE_URL` re-runs every seed.

  - **A third gate exemption, and worth counting as such.** The hashing-pool boundary refused
    the seed's `hash_password` call: every request-path hash must run on the admission
    controlled pool so one tenant's hashing storm degrades only that tenant. This is a
    one-off boot-time hash with no request behind it and no `OidcState` in existence yet to
    route through, so it carries `pool-boundary-allow` with that reason. It joins the two
    `query-audit-allow` markers on the dev seeds. Each is defensible alone; three exemptions
    in one feature is a signal that dev seeding sits outside the seams the production paths
    are held to, which is worth a reviewer's judgement rather than mine.


- **A no-egress harness for the emulator (issue #121, criterion 2).**
  `scripts/dev-no-egress.sh` asserts that while `ironauth dev` is up and serving, the process
  holds no TCP connection whose peer is off this machine. A CI job runs it.

  - **Inspection, not enforcement, and that is the stronger check here.** A sandbox with the
    network severed would prove only that the emulator SURVIVES having no network. A process
    that quietly phoned a telemetry endpoint and ignored the failure would pass that and fail
    this one, and that is the failure worth catching.

  - **It exercises the surfaces before looking.** A check run against an idle process would
    pass without the emulator having done anything.

  - **The detection is proved to FIRE.** Run against synthetic peers it flags
    `140.82.113.4:443` while correctly ignoring loopback, IPv6 loopback, and listeners (which
    have no peer at all). A no-egress check that cannot detect egress is worse than none,
    because it certifies the property it never tested.

  - **What it does NOT claim**, stated in the script rather than left to be assumed: that no
    egress can ever happen. It observes one live process over a window in which it boots and
    serves discovery and JWKS. A call made only on some later path is out of its reach, and
    claiming otherwise would be the guarantee-by-assertion this project keeps finding and
    removing.


- **The emulator's boot time is MEASURED and asserted (issue #121, criterion 1).**
  `scripts/dev-boot-time.sh` times `ironauth dev` from launch to serving and fails over
  budget; a CI job runs it. Measured 1.16s against a 5 second budget, on a debug build.

  - **The measured instant is discovery answering 200**, not the process starting, not a log
    line, not the port opening. A server that has bound its socket but has no signing key
    answers 404, and calling that "ready" would let the emulator regress into exactly the
    state it shipped in TWICE during this issue: up, quiet, and useless.

  - **The whole cold path is inside the measurement** -- locate Postgres, initdb, start the
    cluster, provision roles, apply the schema, seed the scope and client, provision the
    signing key, boot the server -- because all of it happens before a user can do anything.
    `DATABASE_URL` is deliberately unset: measuring against a database somebody already
    started would report a number no user experiences.

  - **It polls rather than sleeping.** A fixed sleep measures the sleep.

  - **The assertion is proved to FAIL**, not merely to pass: run with `BUDGET_SECS=0.01` it
    exits non-zero, and cleans up its cluster on that path too. A budget check that cannot
    fail is not a check.

  - **The CI job installs the Postgres BINARIES, not a service container.** The emulator
    brings up its own cluster, and a database somebody else already started is not the cold
    path this measures.


- **The emulator seeds a usable CLIENT (issue #121).** `ironauth dev` now prints an issuer and
  a `client_id`, and the authorization endpoint accepts it: discovery 200, JWKS 200,
  `/authorize` 303 to the login page.

  - **Public (`none`), not confidential.** The emulator exists to drive flows from a CLI or a
    sample app, and both use a public client with a loopback redirect. A confidential one
    would need a secret every quickstart then has to carry.

  - **`127.0.0.1`, never `localhost`.** RFC 8252 loopback matching is port-agnostic but exact
    in every other respect, and this server does not treat the NAME as loopback, so a
    registration naming it could never match an ephemeral port. Verified end to end: an
    authorization request on port 5555 matched a registration of `http://127.0.0.1/callback`
    and returned 303, which is the same matching `ironauth login` depends on.

  - **Both values are PRINTED**, because a flow needs each and neither is derivable by the
    caller. An emulator that seeds a client without saying which one has made the developer
    read the database to use it.


- **The emulator now SERVES: `ironauth dev` provisions the seeded environment's signing key
  (issue #121).** Discovery and JWKS answer 200 with a real document. That is the last piece
  criterion 1 was missing.

  - **Why every scoped endpoint 404-ed before.** A tenant, an environment and a serving state
    are not enough: without a signing key the environment has no issuer entry, and
    `registry.entry_for(scope)` returns `None` -- the SAME answer it gives for a scope that
    never existed. So the server started cleanly, logged nothing, and 404-ed everything, which
    reads as a broken emulator rather than an unprovisioned one.

  - **Ed25519 from a DEDICATED entropy stream**, like the seeded identifiers, so the key does
    not change because unrelated code drew a byte earlier in the boot. Published and active
    from the epoch, so it signs and appears in the JWKS the moment the server answers rather
    than after a delay nobody configured.

  - **The key is built before it is persisted**, purely to fail loudly on material the signer
    would reject rather than storing bytes that first break at the token endpoint.

  - **The bring-up test now covers the whole path** -- cluster, roles, schema, seeds, key --
    and re-runs the seeds AND the schema to pin idempotence. A dev restart against an existing
    `DATABASE_URL` does exactly that, so a second run duplicating a tenant or failing on an
    existing key would break it.


- **Declarative idempotent seeds for the emulator (issue #121, criterion 3).** `ironauth dev`
  seeds an operator, a tenant, its first environment, and the environment's serving state
  before the server boots, and prints the resulting scoped issuer URL.

  - **Idempotence comes from TWO things together**, and neither works alone: the identifiers
    are derived deterministically from the dev seed, and every statement is `ON CONFLICT DO
    NOTHING`. Identifiers that changed per run would insert a second tenant every time and the
    conflict clauses would never fire, because nothing would conflict.

  - **The ids are GENERATED, not hand-written.** A fabricated identifier fails at its first use
    with an error about the id rather than about the seed, which is a trap this milestone has
    already sprung once. Generating them guarantees the format is whatever the id type
    currently says it is, and a test asserts each one parses back.

  - **They come from a DEDICATED entropy stream**, so the seeded tenant does not change
    whenever some unrelated code draws a byte earlier in the boot. Reproducibility that breaks
    when adjacent code changes is not reproducibility.

  - **The serving state is a seed statement, and that was found by running it.** An environment
    row alone is not enough: the data plane reads `environment_states`, and a scope with no row
    there is not served. With the first three statements only, discovery returned 404 while the
    server reported no error at all -- which reads as a broken emulator rather than an unserved
    scope. That is the lifecycle fence working correctly, and the seed has to satisfy it.

  - **Discovery still 404s, and the cause is now identified rather than guessed.**
    `registry.entry_for(scope)` returns `None` because the environment has no provisioned
    SIGNING KEY. That needs real key material rather than an insert, so it is the next change
    and not this one. The seeds themselves are verified: the rows land, and re-running is a
    no-op.


- **FIX: `ironauth dev` booted, but was not a working emulator (issue #121).** Found by RUNNING
  it rather than by reading it. The generated configuration was too minimal in four separate
  ways, each of which the server reported and none of which any test could see.

  - **`oidc.enabled` was false**, so the emulator served no OIDC at all. That is the one thing
    it exists to serve.
  - **`dev_mode` was unset.** The server asks for it by name: the management API, the scheduled
    offboarding worker, and outbox retention each refused to start saying "or run in dev_mode",
    because they need a control-plane DSN and `dev_mode` lets them fall back to `database.url`.
    An emulator missing all three is not the real server.
  - **`database.master_key` was unset**, so the encrypted-PII paths (registration, login,
    UserInfo) failed CLOSED and no login could work.
  - **`server.management_bind` defaulted to a fixed `127.0.0.1:9443`**, which on a machine
    already using that port did not degrade the emulator, it EXITED the server: "Address
    already in use", process dead. It is now an ephemeral port chosen the way the cluster's is.

  Verified by running it again: zero errors, the server answers, the capture sink endpoint
  returns its JSON, and the throwaway cluster is gone after the process is signalled.

  **Why no test caught any of this.** Every part had unit tests and they all passed. The
  generated config was asserted to CONTAIN the database URL and the bind address, which it did.
  Nothing started the binary, so nothing could observe that the server it produced refused to
  mount its own OIDC provider. Running the thing was worth more than every assertion about its
  pieces, which is the same lesson as the schema gap one change earlier.


- **FIX: `ironauth dev` brought up a database the server could not use (issue #121).** The
  cluster started, and then nothing created the roles the schema's GRANTs name or applied the
  schema at all, because `serve` does not migrate and a freshly `initdb`-ed cluster has neither.
  The server booted against an empty database and failed deep in its own startup, which reads
  as an unrelated fault rather than "the schema is not there".

  - **What was missing.** `ironauth_app`, `ironauth_control`, and `ironauth_audit_retention`
    are provisioned out of band in production and by the test harness in tests; a dev cluster
    had neither them nor a single table. Dev now creates all three (idempotently, via `psql`
    from the SAME directory the cluster came from, so it cannot talk to a different Postgres
    than the one just started) and applies the schema through `Store::migrate` before the
    server boots.

  - **It is skipped when the developer supplied their own `DATABASE_URL`.** That database is
    theirs, already managed by whatever manages it, and migrating somebody else's database
    because they pointed a dev tool at it would be the wrong default.

  - **The gap existed because nothing tested the PATH.** The cluster had a lifecycle test and
    the schema has an extensive migration suite, and both passed while the step joining them
    did not exist. The new test drives the whole bring-up (cluster, roles, schema) and applies
    the schema twice to pin idempotence, which is what makes a dev restart cheap. Measured
    against the bug: with role provisioning removed, it fails exactly where the shipped code
    did.


- **Deterministic secrets in the emulator (issue #121).** `ironauth dev [--seed N]` makes every
  generated secret reproducible: OTP codes, identifiers, client secrets. That is what criterion
  2 needs to assert a complete email-OTP login against a named code.

  - **Entropy is replaced, the CLOCK is not.** `Env::deterministic` would freeze time, and a
    server whose clock never advances cannot expire a token or a code, so the emulator would
    diverge from production in exactly the behaviour most tests are about. Only the entropy
    seam is swapped, through `Env::from_parts`.

  - **The seed defaults to a FIXED value, not a random one.** Two runs on two machines must
    produce the same codes, or a CI script cannot name the value it expects. Reproducibility by
    accident is not reproducibility.

  - **This is the other half of why dev mode refuses a non-loopback bind.** A deployment whose
    secrets are a function of a published seed has no secrets at all, so the guard and this
    feature are two ends of one decision.

  - **The selection is a FUNCTION because the wiring is what can be wrong.** The first version
    inlined it in `serve` and tested `Env::from_parts` directly. Measured: a mutant that ignored
    the seed entirely compiled and failed no test, because the tests proved the primitive while
    the thing that could break -- whether the boot path consults the seed at all -- was
    unproved. `boot_env` is now called by `serve` and asserted directly, and that same mutant is
    caught. The test also pins the direction that matters most: with NO dev seed the entropy
    must be real, or production would ship fixed secrets.


- **The emulator's message capture sink (issue #121, criterion 5).** Email and SMS one-time
  codes are captured and readable, so CI can assert a complete login without a mail server.

  - **A SEPARATE loopback listener, not a route on the OIDC router.** This endpoint hands out
    live one-time codes in plaintext, which is the entire point in dev and catastrophic
    anywhere else. Mounting it on the production router would make safety depend on a
    conditional staying correct forever: one refactor moving a route registration outside its
    `if`, and a deployment is serving OTP codes. On its own listener, started only by
    `ironauth dev`, the production router has no such route to leak. Structural, not a flag
    nobody re-reads.

  - **It reuses the existing delivery seam.** `VerificationSender` and `SmsSender` are already
    the boundary, and the boot chain already installed `LoggingVerificationSender` /
    `LoggingSmsSender` there. The sink is a third implementation of traits that existed, not
    new architecture.

  - **A process-global set once, rather than a parameter threaded through production
    signatures.** Installing it via `SharedPlaneInputs` would change three signatures for a
    dev-only switch, and every future caller would carry an argument that is `None` in every
    real deployment. A `OnceLock` states what this actually is: one process-lifetime decision
    made before anything boots. Nothing reads it unless `ironauth dev` set it.

  - **The buffer is bounded and drops the OLDEST**, because a test asserts against what it
    just triggered, and an unbounded log of every code in a long dev session is a slow leak.
    Responses are `no-store`: they carry live codes, so a cache holding them is the leak the
    loopback-only design exists to avoid.

  - **A codeless notification is deliberately not recorded**, so it cannot evict a message
    somebody is waiting for.


- **`ironauth dev`: the first slice of the local emulator (issue #121).** The real server on
  loopback, with a generated dev configuration and a guard that refuses to run anywhere it
  could be reached from outside the machine.

  - **The storage fork is settled by policy, not preference.** The issue asks for "embedded or
    lightweight storage requiring no external services", and two readings of that were already
    ruled out here. Embedding a database is FORBIDDEN: `docs/design/TENANCY.md` records that
    the only maintained pure-Rust embedded-Postgres crate pulls licences outside the permissive
    allowlist, which the supply-chain policy forbids and `cargo deny check licenses` enforces.
    A substitute dev store contradicts this issue's own requirement to boot "the real server
    binary (not a mock)": dev and CI would never exercise row-level security, so the emulator
    would be green on exactly the class of bug it exists to catch. A disposable cluster is what
    remains, and `scripts/with-test-db.sh` already proves the mechanism.

  - **The guard is the bind address, and that coupling is deliberate** (criterion 6). Dev
    mode's value comes from deterministic secrets and seeded identities, and those are exactly
    what make it catastrophic to expose. Gating on the bind means the unsafe combination cannot
    be assembled by setting one flag and forgetting another. A HOSTNAME is refused even when it
    would resolve to loopback: `localhost` resolves to `::1` on some hosts and `127.0.0.1` on
    others, and to whatever `/etc/hosts` says on a host somebody has edited, so a guard that
    trusts a name is one that can be talked out of its answer.

  - **It hands off to the SAME `serve` path production uses** rather than carrying a second
    boot sequence, which would drift, and drift invisibly, because dev is where nobody looks
    for a production difference.

  - **The throwaway cluster is now automated.** `ironauth dev` locates the Postgres binaries,
    runs `initdb`, starts a loopback-only server on an ephemeral port, and STOPS AND DELETES
    the whole thing on drop. An existing `DATABASE_URL` still wins, so a developer who has a
    database does not get a second one started underneath them.

  - **Two defects the real cluster test caught, neither of which a mock would have.**

    First, `pg_ctl start` launches a daemon that inherits whatever stdout and stderr it is
    given and holds them for its lifetime, so capturing them with `Command::output` blocks
    forever waiting for an EOF that arrives only when the database shuts down. It hung for ten
    minutes against a perfectly healthy running cluster. The server's output now goes to a log
    file via `pg_ctl -l`, this process's handles are closed, and the log is read back only on
    failure. This is precisely why `scripts/with-test-db.sh` redirects to `/dev/null` at that
    step.

    Second, the binary search claimed in its own doc comment to use "the same search order"
    as that script and did not: it omitted `~/.theseus/postgresql/*/bin`, which is where this
    project's own tooling installs Postgres, so it failed on a host where the shell script
    succeeds. The claim is now true rather than intended.

  - **Nothing in the module is dead.** A binary-search helper written ahead of the automation
    was REMOVED rather than kept behind an `allow(dead_code)`, which is the shape three
    modules on #120 had to be dug out of; it came back when the automation gave it a caller.


- **The RFC 8252 loopback flow, and the end of #120's dormancy.** `ironauth login` now selects
  between loopback and device, and every module this issue shipped has a caller.

  - **All three `allow(dead_code)` markers are GONE.** `device_login.rs`, `login_flow.rs`, and
    `loopback.rs` each shipped correct, tested, and callerless; their tests passed because they
    called those modules directly, which is exactly why they could not notice that nothing else
    did. The markers are removed, no dead code is reported, and
    `scripts/dormant-module-scan.sh` no longer allowlists any of them. The scan is an
    INDEPENDENT check: it would flag a module that was still unreachable, so its silence is
    evidence rather than assertion. `ironauth-store/token_exchange_decision` came off the same
    allowlist, where it should have gone when #826 gave it a caller.

  - **The fallback lives at the BIND, not at the heuristic.** `choose_flow` reads the host (a
    display, an SSH session, a platform that opens a browser implicitly), and none of that says
    whether a listener can actually bind: a locked-down host, a sandbox without loopback, or an
    exhausted ephemeral range all fail afterwards. So `prepare` returns a bind failure as a
    VALUE and the command falls back to the device flow, which is the criterion's wording.

  - **A registration that cannot support loopback is REPORTED, not downgraded.** `localhost`
    and `https://` redirects fail with the reason. Silently switching flows would hide a
    configuration error behind something that happens to work, leaving it undiagnosable.

  - **PKCE uses the SERVER's own transform.** The challenge comes from
    `ironauth_oidc::pkce::s256_challenge`, and the tests assert the generated verifier against
    `verify_s256` and `code_verifier_is_well_formed` rather than against strings written here.
    That is not stylistic: dropping the verifier below the RFC 7636 entropy floor is caught by
    the server's own rejection, and `s256_challenge`'s documentation records that two copies of
    this transform once existed in this workspace and AGREED, which is the dangerous state.

  - **The `state` is compared, and an error beats a code.** A redirect whose state differs
    belongs to a different authorization request, so its code is not ours to redeem. A response
    carrying both an error and a code is malformed, and reading the code would proceed with a
    grant the server just said it was refusing.

  - **The URL is printed before the browser is opened.** Opening a browser can fail silently on
    a host with no handler registered, and a user watching a terminal that only says "waiting"
    has no way to continue.


- **`ironauth login` drives the RFC 8628 device flow (issue #120).** The three modules that
  shipped earlier under this issue now have a caller.

  - **`device_login.rs` is no longer dormant.** It shipped with a module-level
    `allow(dead_code)` and zero call sites; its tests passed because they called it directly,
    which is exactly why they could not notice that nothing else did. The `allow` is now
    REMOVED and the module reports no dead code, which is the measurable form of "it is
    wired". `login_flow.rs` and `loopback.rs` remain dormant until the loopback flow lands,
    and still say so.

  - **The device flow first, because it is the one that works everywhere.** It needs no
    listener, no browser on this machine, and no open port, so it is the flow available on the
    headless boxes and over the SSH sessions where a CLI login most often happens.

  - **The transport is SHARED, not copied.** The HTTP goes through
    `ironauth_apply::client::post_form`, the same connect, TLS configuration, total deadline,
    and response size cap the control-plane client uses. `send` gained a content type and an
    optional Authorization header, which is the whole difference between a management-API call
    and an OAuth token request. A second copy of that logic in this crate would have been two
    things to keep in step, and the copy that drifts is the one nobody is looking at.

  - **Section 3.5, enforced through the command.** The client waits BEFORE its first poll
    (polling immediately guarantees an `authorization_pending` the user could not have
    avoided); an omitted `interval` means five seconds; `slow_down` raises the interval for
    this AND every subsequent request rather than once; and any error code other than the two
    pending ones stops polling, because a client cannot know an unrecognised one is transient
    and guessing that it is turns one server change into a fleet polling forever.

  - **A failed store fails the LOGIN.** Reporting success would tell the user they are signed
    in on a machine that has nothing stored, and the next command would fail for a reason that
    looks unrelated.

  - **Form values are percent-encoded.** A `client_id` is caller-supplied and opaque, so
    interpolating it raw would let a value containing `&` or `=` forge additional parameters;
    the test asserts exactly that case.


- **`ironauth logout`, and the keychain-backed credential store beneath it (issue #120).** The
  first piece of the CLI login story that a user can actually run.

  - **The keychain, and no file.** Credentials live in the macOS Keychain, the Windows
    Credential Manager, or the Secret Service on Linux, reached through one `keyring` API. The
    criterion asks for "no plaintext token files in default mode" and the reason is specific: a
    refresh token in a dotfile is readable by every process running as that user, survives into
    backups, and is the one credential that regenerates all the others.

  - **Removing an absent credential SUCCEEDS; a refusing keychain does NOT.** `logout` exists to
    put a machine into a known state, so failing because it was already in that state would
    report that something is still stored when nothing is. A keychain that refuses is the
    opposite case: the credential may still be there, and a logout that lies about a credential
    is the one failure this command cannot have.

  - **Only as large as its callers.** The store has exactly one operation, `delete`, because
    `logout` is the only caller today; the read and write halves land WITH `ironauth login`.
    That is a deliberate response to a measured problem in this milestone rather than
    minimalism: `device_login.rs`, `login_flow.rs`, and `loopback.rs` all shipped earlier under
    this same issue, are individually well tested, and have ZERO call sites, each carrying a
    module-level `allow(dead_code)` because of it. Their tests pass because they call those
    modules directly, which is exactly why they cannot notice that nothing else does. A
    `store`/`load` pair with no caller would have repeated that and needed the same `allow`.

  - **The seam is the store, not the keychain.** Every backend needs a real desktop session, so
    a test against the real one would fail on a CI runner or pass on a laptop and fail in CI for
    a reason resembling nothing in the change. `KeyringStore` is kept thin enough that what the
    tests leave unproved is a delegation rather than a decision; only running it on each
    platform proves the backend itself.


- **The boot path starts the outbox RETENTION sweeper (issue #104, PR 3).**
  `spawn_retention_sweeper` takes the store, the scopes and the observer as ARGUMENTS, for
  the reason `spawn_consumer_pools` does: it is what lets a test drive the real seam against
  a real database instead of asserting about a copy.

  - WHEN IT ACTUALLY RUNS, stated exactly, because an earlier draft of this entry said
    "unconditionally" and that was measured false. `serve` starts it independently of
    `backchannel_worker_inputs` and shuts it down alongside the logout pools, but THREE
    things stop it: `outbox.reap_enabled = false` (a deliberate operator choice, logged at
    warn); no control-plane DSN, which is the DEFAULT deployment, because
    `admin.control_database_url` is unset and `dev_mode` is off (logged at error); and a
    deployment whose consumers never run, where the sweeper starts and correctly removes
    nothing, because only a consumer makes a message reapable.
  - It does NOT share the consumer pools' gate. Those are the switches of ONE consumer of a
    generic queue; the next consumer to register will run behind a different one, and
    retention must not have to be re-wired per consumer.
    `retention_is_not_gated_on_the_back_channel_logout_switch` is what turns red if such a
    gate is added, and `tests/serve_retention_boot.rs` boots the real binary to pin that the
    `serve` call site exists at all: replacing it with a no-op used to leave the whole suite
    green.
  - `outbox_retention_settings` resolves the inverted sentinel at ONE seam:
    `dead_letter_retention_secs = 0` becomes `None` (never), not `Duration::ZERO` (always).
    All four config-to-settings mappings are now pinned at distinct values, because swapping
    the completed window with the interval, and replacing the batch with `i64::MAX`, were
    both undetected.
  - `TracingRetentionObserver` logs a SATURATED pass at warn, naming the two knobs that fix
    it; a failed pass at warn, naming the missing 0102 grant as the likely cause; and an
    IDLE pass at debug, so a healthy reaper with nothing to do and a dead one are not the
    same silence.
  - OPERATOR OBLIGATION: retention deletes as `ironauth_control`, the only role migration
    0102 grants DELETE on `outbox_messages`. With NO control-plane DSN there is NO REAPING
    AT ALL: the boot logs an error saying so, and `outbox_messages` grows without bound,
    because every ended session enqueues one message plus one per participating relying
    party and nothing else removes any of them. Set `admin.control_database_url` (or run in
    dev mode). `outbox.reap_enabled = false` disables the sweeper deliberately and logs a
    warning saying the same thing. See `docs/design/RETENTION.md` for what this reaper does
    and does not bound.

- **The boot path spawns the outbox consumer pools (issue #104, PR 2).** Back-channel logout
  delivery is no longer a hand-rolled worker: `spawn_backchannel_logout_pools` registers the
  two logout consumers, and `spawn_consumer_pools` turns that registry into one running
  worker pool each, all sweeping one `ControlPlaneScopes` and reporting to one
  `TracingOutboxObserver`. `outbox_worker_settings` is the single place the `[outbox]`
  section becomes a `WorkerSettings`.

  - **The FAN-OUT consumer gets an effectively unbounded attempts budget, and the delivery
    consumer keeps the shared cap.** Both pools were first given `outbox.max_attempts`, and
    that loses logouts. A `session_ended` message is an ENTIRE session's fan-out, held at a
    moment when no per-relying-party message exists yet, so dead-lettering it leaves every
    RP of that session permanently un-notified with nothing anywhere to replay from. Its
    handler makes no outbound call, so the only failure it can classify as retryable is a
    DATABASE fault, and at the shipped defaults five attempts on a ten second base is about
    150 seconds of database trouble to discard a session's logout forever. The bound cannot
    be doing the other job a bound does either: every input this handler cannot process is
    already `permanent` and dead-letters on its first attempt regardless. This also restores
    what the deleted worker did, which was to let the lease lapse and re-claim, forever;
    moving onto a generic substrate is what introduced a terminal state here. It is safe
    HERE specifically because a `session_ended` message's ordering key is the ended session
    id, so its group is a singleton and there is nothing behind it to block; a consumer
    whose producers share ordering keys must keep the finite bound.
  - **The pools' outcomes are LOGGED.** The migration deleted two `tracing::warn!` calls and
    replaced them with nothing, and the new pool loop discarded its results, so a
    dead-lettered logout, a drain pass failing on a persistence fault, and a scope sweep
    that never returned a scope were all silent. `TracingOutboxObserver` reports a
    dead-lettering pass at ERROR (naming the consumer, the scope and the count), and a
    failed pass or a failed sweep at WARN. A healthy pass is deliberately not logged: one
    line per pool per scope per poll interval would bury the three that matter.
  - **The wiring is MEASURED, in `src/outbox_wiring_tests.rs`.** PR 1 shipped a framework
    with zero call sites; the same defect one layer up is a wiring that runs and that nothing
    observes. Measured with `.take(1)` on the pool loop, so the binary spawns the fan-out
    pool and never the delivery pool: with this suite SKIPPED, all 17 remaining tests of the
    crate pass and `cargo clippy --workspace --all-targets --all-features -- -D warnings` is
    clean, so nothing but this suite can see it. The suite
    drives the REAL `spawn_consumer_pools` and `outbox_worker_settings` against a real
    database and asserts BEHAVIOUR: a message enqueued for every registered consumer must be
    handled, whichever subset a broken loop would have covered.

- **The `dev_mode` control-DSN fallback warning now names the consequence that actually
  bites** (issue #441). When `admin.control_database_url` is unset and `dev_mode` is on, the
  management plane connects on `database.url`. A development database is usually a
  full-privilege one, so a management route the least-privileged control role holds no
  privilege for answers perfectly there and fails on every deployment that sets the knob.
  That was measured rather than supposed: with the router on the owning role and the
  relevant grants reverted, all 143 published management operations pass. The warning listed
  the row-level-security backstop and the role separation and stopped there, which said
  nothing about a surface being invisibly dead.

- Inbound OIDC federation is now WIRED into the server boot path (issue #75, PR B,
  adversarial review MEDIUM-1). `build_oidc_router` reads the new `oidc.federation` config and,
  when `oidc.federation.enabled` is set, builds the `FederationRuntime` (its OWN SSRF-hardened
  outbound fetcher plus the configured discovery / JWKS cache TTLs) and installs it via
  `OidcState::with_federation`, so a stored connector's `/federation/*` login legs go live.
  OFF by default: with federation disabled the routes stay a uniform not-found, so an existing
  deployment is unaffected. A downstream resource server MUST key trust on the local token's
  `acr` (`urn:ironauth:acr:federated`), NOT on the passed-through `amr`, which reflects the
  UPSTREAM's own assertion.
- Guarded SMS OTP factor semantics hardening (issue #70, adversarial review): the SMS
  verify surface the server exposes now honors the no-silent-downgrade invariant on EVERY
  purpose. `POST .../otp/sms/verify` establishes a primary session only for `login`,
  `recovery`, and self-service `register` (each gated by the tenant downgrade opt-in on a
  passkey / TOTP-protected account); `mfa` and `verify_address` now return a possession
  proof (`{"verified":true,"purpose":...}`) with NO session cookie instead of a full
  authenticated `sms` session, closing a purpose-confusion factor-downgrade to account
  takeover. The SMS send surface stays uniform present-vs-absent even under hashing-pool
  back-pressure. No configuration or wiring change for the binary.
- Guarded SMS OTP (issue #70): the server binary now installs a `LoggingSmsSender` dev stub
  behind the SMS provider seam, so the guarded SMS-OTP factor delivers end to end without an
  SMS gateway (the code is emitted only at the `debug` trace level; a real provider adapter
  is a documented M11 seam a deployment installs in its place). SMS OTP stays off by default,
  so the stub is inert until a tenant explicitly enables SMS and configures a country
  allowlist.
- `ironauth credential-class-policy set|list|remove` CLI (issue #66, PR A): set, list, and
  remove the declarative per-scope minimum-credential-class ladder row for a subject
  (`--subject tenant|group|org`, `--subject-ref ID`, `--class any|mfa|passkey|attested_passkey`),
  each an audited write through the same acting repository the authentication path composes
  from with strictest-wins. Mirrors the `step-up-policy` CLI pattern; a hosted admin HTTP CRUD
  can layer on later.
- Magic-link cross-device UI reachability (issue #68, adversarial review): the served
  magic-link send acknowledgment page now renders a `short_code` entry form, so the
  cross-device fallback (open the link on one device, finish on the originating device that
  holds the binding cookie) is completable through the browser UI the binary serves, not
  only via a raw POST.
- Email OTP and scanner-safe magic links (issue #68): the server binary now installs a
  `LoggingVerificationSender` dev transport behind the #64 verification seam, so the email-
  OTP and magic-link factors deliver end to end without a mail server (the code / link are
  emitted only at the `debug` trace level; a real email provider is a documented M11 seam
  a deployment installs in its place).
- Breached-password screening and the NIST SP 800-63B-4 policy are wired at boot from the
  `[password_policy]` config (issue #63). The boot path resolves the policy (length floors,
  legacy composition/rotation overrides, fail-open/closed) and installs it on the OIDC data
  plane, and builds the screening provider: the online HIBP k-anonymity range provider over a
  fresh SSRF-hardened fetcher, or the offline corpus provider loaded from the operator
  dataset file. The shipped defaults are the modern 63B-4 posture with screening MANDATORY
  over the free HIBP provider (fail-open), so a default deployment screens passwords with no
  configuration. A provider whose input is unavailable (a fetcher-setup failure, an
  unreadable corpus) logs and leaves the state to apply the fail-open/closed policy.
- `step-up-policy set | list | remove` subcommands (RFC 9470 step-up, issue #72): set,
  list, and remove the declarative per-scope and per-client step-up authentication policy
  directly against the data-plane store, each an audited write through the SAME repositories
  the enforcement path reads, so an operator can enable a policy without hand-writing Rust or
  SQL. A short `--acr` alias (`pwd`/`mfa`/`phr`/`phrh`) is canonicalized to the value the
  enforcement path compares against. Closes the "declarative policy has no production
  reachability" gap; a hosted admin HTTP CRUD can layer on later.
- `ban` / `unban` / `bans` subcommands (issue #64): place, lift, and list durable
  credential-abuse bans directly against the data-plane store, each an audited write. An
  identifier subject is canonicalized through the login seam so a CLI ban matches the form
  the request path checks, and a `--path` scopes the ban to one authentication path
  (default `password`), so a CLI lockout never blocks the passkey or recovery path. The
  admin API offers the same operations over HTTP; both write through the SAME repository.
- Wire the Argon2id hashing pool (issue #62): when the OIDC provider is mounted, the boot
  path builds ONE `HashingPool` from `[password_hashing]` (worker count from
  `pool_threads`, or the host core count when 0; the configured Argon2id parameters and
  queue depth) sharing the SAME quota enforcer as the request path, so hashing admission
  is per-tenant fair-share, and installs it on the OIDC state. Adds the `ironauth
  hash-probe [--config PATH] [--json]` subcommand: a headless-install tuning helper that
  measures Argon2id on this host and recommends parameters meeting the configured latency
  target, printing projected logins/s per core (the same probe backs the in-admin tuning
  helper). Registers the pool metric descriptions. The probe's default per-hash memory
  budget now derives from TOTAL host RAM (Linux `MemTotal / 2`, or a 1 GiB fallback on
  hosts without a dependency-free total-RAM read) instead of the currently-configured
  memory cost, so the default probe can explore the full ladder and recommend stronger
  parameters than the host is presently configured for (issue #62 hardening); a new
  `--memory-budget KIB` flag overrides it explicitly.
- Wire the inbound lazy-migration hook (issue #56): when the OIDC provider is mounted and
  `[oidc.lazy_migration]` is enabled, the boot path builds ONE `LazyMigrationHook` (a
  dedicated SSRF-hardened fetcher with the configured per-call timeout, the resolved shared
  secret, and a circuit breaker on the env clock) and installs the SAME Arc on BOTH the OIDC
  data plane (arming the login path) and the management plane (so the migration-progress
  endpoint reports the node's breaker state). A disabled or misconfigured hook (unresolvable
  secret, TLS setup failure) is logged and simply not armed, leaving the login path
  unchanged.
- The management-plane control store is now built with the platform envelope master
  key attached (issue #52), so the admin user-management API can seal, blind-index,
  and open user PII (issue #48) exactly as the data plane does. Without the key those
  admin user paths fail closed (never plaintext); `resolve_master_key` logs when it
  is unset.
- The binary now dispatches the config-as-code subcommands `validate`, `plan`,
  `apply`, and `drift` (issue #51, CLI half) into the new `ironauth-apply` crate.
  They are a THIN client of the management API: `validate` checks a document
  against the snapshot format locally; `plan` and `apply --dry-run` render the
  server-computed promotion plan; `apply` applies transactionally (a re-apply of
  an unchanged target is a no-op, a target drifted from an expected revision
  exits nonzero and changes nothing); `drift` reports drift with CI-gate exit
  codes. Run `ironauth <subcommand> --help` for usage. The outbound HTTP the CLI
  needs lives entirely in `ironauth-apply`, so this binary crate stays free of an
  HTTP-client dependency (scripts/http-audit.sh). The Terraform-provider and
  dogfooding halves of issue #51 are deferred; the issue stays open.
- The boot path now spawns the OIDC Back-Channel Logout delivery worker (issue #34) when
  `oidc.enabled` AND `oidc.backchannel_logout_enabled` are set (off by default). The
  worker drains the durable session-ended outbox per scope, builds one signed Logout Token
  per participating relying party, and POSTs it through the SSRF-hardened outbound fetcher
  with bounded-backoff retries and a dead-letter state. Scope enumeration is a
  control-plane read (the data-plane role cannot see the non-RLS `environments` table), so
  the worker connects both a data-plane store (to drain and sign) and a control-plane store
  (to enumerate scopes); a missing control DSN or a connect/fetcher-setup failure is logged
  and the worker is simply not spawned, leaving the rest of the server unaffected (the
  queue is durable, so nothing is lost). Adds tokio's `time` feature to the binary.
- The boot path now runs the strict feature-maturity gate (issue #4/#36): it validates
  `[features]` against the built-in registry and REFUSES to boot on a violation (an
  unknown feature, or an enabled experimental feature without an exact-version ack), and
  it resolves the experimental Global Token Revocation receiver's mount from that ladder
  (feature enabled AND acked) rather than any plain `[oidc]` toggle, so the ack can never
  be bypassed. When enabled it mounts `POST /global-token-revocation` and logs the
  experimental-surface warning.
- Wire the OIDF conformance suite into CI as a merge gate (issue #37). New
  `deploy/conformance/` harness: a docker-compose stack pinned BY DIGEST via a
  committed `SUITE_VERSION` (the OIDF suite, MongoDB, an nginx TLS terminator
  fronting the OP as the `op` issuer host, and IronAuth), a
  certification-representative `ironauth.toml` that turns on the legacy/downgrade
  OP-profile toggles FOR THE CERT ENVIRONMENT ONLY (the shipped default stays
  hardened, proven by a config test), a reviewed `profile-matrix.yaml` (the four
  OP profiles on the merge gate, Implicit/Hybrid nightly, the four logout
  profiles deferred to #33/#34/#39 as explicitly not-yet-enabled), a strict
  results gate (`parse_results.py`) that fails on ANY non-PASS (finished-but-
  failed, unreviewed WARNING, REVIEW, SKIPPED, unfinished, or a vacuously empty
  run) with standard-library unit tests, and a one-command runner that FAILS
  CLOSED: it exits 0 only after actually driving at least one plan with every
  module passing, and exits non-zero on a missing OIDF runner, an empty profile
  selection, a crashed selector, or an unrenderable plan config. Each plan's
  runner config is GENERATED from the profile matrix (`gen-plan-config.py`), so
  the exact-string issuer the suite matches has exactly one definition (#194).
  The runner is bash 3.2 portable, so the one-command local reproduction works on
  stock macOS.

  CI gains an always-on static lane (`scripts/conformance-check.sh`, in the
  invariants job) which is what actually ENFORCES today: it is gated by no
  repository variable and it runs the results-gate unit tests, validates the
  matrix, renders every enabled profile's plan config, verifies every image
  reference anywhere under `deploy/conformance` is pinned by digest, asserts the
  harness cannot fail open, and re-checks downgrade confinement. The LIVE suite
  lane always runs but is explicitly ADVISORY and named so it cannot be mistaken
  for a gate: it has no job-level `if:`, because GitHub reports a skipped job to
  branch protection as SUCCESS, so a required check gated on a repository
  variable would turn silently green if that variable were unset or mistyped.
  While the suite is unprovisioned it prints a `NOT ENFORCING` banner rather than
  posing as a passing gate. Also a nightly full-matrix workflow with a
  least-privilege badge-publish job, which now FAILS THE RUN when the matrix does
  not pass (a failing nightly used to be a green run recorded only in a badge
  JSON, notifying nobody), and a secret-isolated track-suite-master workflow.

  Provisioning the OIDF runner, resolving the real image digests, validating the
  generated plan config against the live runner, demonstrating the seeded
  regression, and only then promoting the live check to required are owner
  actions; docs/conformance/RUNBOOK.md carries the complete list, and
  docs/conformance/README.md states plainly what enforces today versus what does
  not.
- Compose per-environment issuers, JWKS serving, and signing into the live data
  plane (issue #194). `build_oidc_router` now builds ONE store-backed
  `IssuerRegistry` (keys load lazily and RLS-scoped from the data-plane store on
  first use) and mounts all three surfaces on the public plane: the protocol
  router, discovery (both well-known forms), and the per-environment JWKS, all over
  that one registry. Discovery resolves each environment's signing policy from its
  loaded keys, so the advertised `id_token_signing_alg_values_supported`, the served
  JWKS, and the minted tokens cannot diverge, and an unprovisioned or cross-tenant
  scope returns 404 exactly like the JWKS surface. The JWKS/discovery
  `Cache-Control` max-age comes from `oidc.jwks_cache_max_age_secs`. The stale
  "mounted with NO signing keys" warning is gone; an environment without a
  provisioned key still fails closed (token endpoint `server_error`, JWKS/discovery
  404). Default boot is unchanged.
- Mount the OIDC provider (issue #12) on the PUBLIC plane when `oidc.enabled` is
  set, connecting the data-plane store with `database.url`. Per-environment
  signing-key provisioning is a later milestone: until an environment has a key,
  its token endpoint fails closed (a startup warning says so). Default boot is
  unchanged (unmounted, database-free).
- `ironauth serve [--config PATH]`: loads and strictly validates config,
  surfaces its warnings to the log, wires telemetry, and runs the dual-plane
  server until `SIGTERM`/`SIGINT`, draining within the configured grace period.
  The non-default `otlp` feature is forwarded to `ironauth-server`.
- Initial binary: `--version` and `--help` only. The server skeleton lands
  with the M1 server-skeleton issue.
