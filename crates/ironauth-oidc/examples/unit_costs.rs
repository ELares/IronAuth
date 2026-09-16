// SPDX-License-Identifier: MIT OR Apache-2.0

//! Measure the per-operation unit costs a sizing guide is built from (issue #152 criterion 4).
//!
//! ```text
//! cargo run --release -p ironauth-oidc --example unit_costs
//! ```
//!
//! # Why password hashing dominates, MEASURED rather than asserted
//!
//! A sizing guide answers "how many of these can one machine do", and that number is decided
//! by whichever operation dominates. This said the password hash dominates "by roughly three
//! orders of magnitude" and measured only the hash, so the claim that justified excluding
//! everything else was the one figure never taken.
//!
//! A review took it: 3.1 orders for `EdDSA`, 3.0 for `ES256`, and 1.5 for `RS256`, which is not
//! hypothetical, every fresh environment publishes an RS256 key from day one, and at 34x
//! rather than 1000x it is a visible line item in a capacity model rather than a row rounding
//! to zero. The token mint is measured here now, per algorithm, and the ratio is derived from
//! the two measurements rather than written down.
//!
//! # The parameters are printed with the numbers, because they ARE the number
//!
//! Argon2id cost is a configuration choice, not a property of the code. A unit cost quoted
//! without `m`, `t` and `p` is unreproducible and, worse, invites a reader to compare it
//! against a deployment tuned differently and conclude something about the software. The
//! memory cost dominates: halving `m` roughly halves the time and halves the security margin
//! with it, which is exactly the tradeoff a sizing guide must not let somebody make by
//! accident.

use ironauth_env::Env;
use ironauth_jose::{
    JwsAlgorithm, KeySet, SigningKey, SigningPolicy, generate_rsa_pkcs1_der, sign_detached,
};
use ironauth_oidc::{Argon2Params, hash_password_with, verify_password};

/// How many samples per measurement. Small because each one is deliberately expensive.
const SAMPLES: u32 = 10;

/// How many samples per SIGNATURE measurement. A mint is microseconds, so ten of them measure
/// timer resolution rather than the operation.
const SIGN_SAMPLES: u32 = 2_000;

/// Warm-up signatures discarded before timing, so the first-call cost of a lazily initialised
/// backend is not charged to the published figure.
const SIGN_WARMUP: u32 = 50;

/// How many samples per JWKS RENDER measurement. A render is microseconds like a mint, so it
/// needs the same sample count to measure the operation rather than the clock.
const RENDER_SAMPLES: u32 = 2_000;

/// The performance and efficiency core counts on a heterogeneous macOS CPU, or [`None`] when
/// the host does not report them (a homogeneous machine, or not macOS).
///
/// Printed because "per core" means two different things on such a machine, and the published
/// figure is whichever kind the scheduler happened to choose.
fn core_split() -> Option<(u32, u32)> {
    let read = |key: &str| -> Option<u32> {
        std::process::Command::new("sysctl")
            .args(["-n", key])
            .output()
            .ok()
            .filter(|out| out.status.success())
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .and_then(|text| text.trim().parse().ok())
    };
    let performance = read("hw.perflevel0.logicalcpu")?;
    let efficiency = read("hw.perflevel1.logicalcpu")?;
    Some((performance, efficiency))
}

/// The CPU this ran on, so the numbers carry their hardware.
fn cpu_brand() -> String {
    std::process::Command::new("sysctl")
        .args(["-n", "machdep.cpu.brand_string"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|brand| brand.trim().to_owned())
        .filter(|brand| !brand.is_empty())
        // Not macOS, or sysctl is absent. Saying so is better than printing nothing and
        // leaving a reader to assume the numbers came from their own hardware class.
        .unwrap_or_else(|| "unknown (sysctl unavailable on this host)".to_owned())
}

#[allow(clippy::too_many_lines)]
// One linear measurement script: the host banner, the hashing table, the mint table and the
// derived capacity line read top to bottom, and splitting them would scatter the order a
// reader follows.
fn main() {
    let env = Env::system();

    // The hardware class is printed WITH the numbers, never left for a reader to supply.
    // A unit cost quoted without the machine it was measured on is a number somebody will
    // compare against their own hardware and draw a conclusion from.
    println!("unit-costs: host");
    println!("  cpu      {}", cpu_brand());
    println!(
        "  cores    {}",
        std::thread::available_parallelism().map_or(0, std::num::NonZeroUsize::get)
    );
    println!(
        "  build    {}",
        if cfg!(debug_assertions) {
            "DEBUG -- these numbers are meaningless, use --release"
        } else {
            "release"
        }
    );
    println!("  samples  {SAMPLES}");
    // HETEROGENEOUS CPUs MAKE "PER CORE" AMBIGUOUS, and this ran unpinned. On an Apple
    // performance-versus-efficiency machine the same binary measured 11.0 ms per verify on a
    // P-core and 62 to 66 ms under background QoS on an E-core, a 5.7x spread, while the
    // "cores" line above counts them as interchangeable. A review found the published
    // per-core figure quoted without that caveat, which an operator would then multiply by
    // the full pool width.
    if let Some((performance, efficiency)) = core_split() {
        println!("  core mix {performance} performance + {efficiency} efficiency");
        println!(
            "           NOT PINNED: a per-core figure below is whichever kind the scheduler \
             chose"
        );
    }

    // Every parameter set worth publishing, so a reader can see the shape of the tradeoff
    // rather than one number with no context. The floor is what config load refuses to go
    // below; the default is what ships.
    let cases = [
        ("OWASP default (shipped)", Argon2Params::new(19_456, 2, 1)),
        // THE TRUE FLOOR, derived from the validator rather than guessed. This row said
        // "the weakest config load accepts" while using t=2, and config load only rejects
        // `iterations < 1`: a review loaded m=8192, t=1, p=1 successfully and measured it at
        // 2.24 ms, roughly half the figure published as the floor. The document exists to
        // show the shape of the tradeoff so nobody weakens hashing by accident, and it was
        // understating the cheap end by 2x, hiding exactly the configuration most tempting to
        // a reader chasing throughput.
        (
            "config floor (the weakest config load accepts)",
            Argon2Params::new(ironauth_config::PASSWORD_HASHING_MIN_MEMORY_KIB, 1, 1),
        ),
        (
            "config floor at the default iterations",
            Argon2Params::new(8_192, 2, 1),
        ),
        ("double iterations", Argon2Params::new(19_456, 4, 1)),
    ];

    println!("\nunit-costs: password hashing");
    println!(
        "  {:<64} {:>10} {:>10}",
        "parameters (m KiB, t, p)", "hash ms", "verify ms"
    );
    let mut shipped_verify_ms = 0.0_f64;
    for (label, params) in cases {
        let (m, t, p) = (
            params.memory_kib(),
            params.iterations(),
            params.parallelism(),
        );

        let mut hashed = String::new();
        let started = env.clock().monotonic();
        for _ in 0..SAMPLES {
            hashed =
                hash_password_with(&env, "correct horse battery staple", params).expect("hash");
        }
        let hash_ms = started.elapsed().as_secs_f64() * 1000.0 / f64::from(SAMPLES);

        // VERIFY IS MEASURED SEPARATELY, and it is the number that matters for capacity: a
        // login verifies, and only a password change hashes. They are close but not equal,
        // and quoting one for both is how a capacity estimate drifts.
        let started = env.clock().monotonic();
        for _ in 0..SAMPLES {
            assert!(
                verify_password("correct horse battery staple", &hashed),
                "the verify must actually succeed, or this measures a failure path"
            );
        }
        let verify_ms = started.elapsed().as_secs_f64() * 1000.0 / f64::from(SAMPLES);

        println!(
            "  {:<64} {:>10.1} {:>10.1}",
            format!("{label}: m={m}, t={t}, p={p}"),
            hash_ms,
            verify_ms
        );
        if m == 19_456 && t == 2 && p == 1 {
            shipped_verify_ms = verify_ms;
        }
    }

    // THE TOKEN MINT, so the "password hashing dominates" claim is derived rather than
    // asserted. A review measured it and found the claim true for EdDSA and ES256 and false
    // for RS256, which every fresh environment publishes from day one.
    println!("\nunit-costs: token mint (one detached signature over a 186-byte JWT payload)");
    println!(
        "  {:<40} {:>12} {:>18}",
        "algorithm", "mint us", "vs a verify"
    );
    let payload = vec![b'x'; 186];
    let mut signing_keys: Vec<(&str, SigningKey)> = Vec::new();
    if let Ok(key) = SigningKey::ed25519_from_seed(Some("ed".to_owned()), &[7_u8; 32]) {
        signing_keys.push(("EdDSA", key));
    }
    if let Ok(der) = generate_rsa_pkcs1_der(env.entropy()) {
        if let Ok(key) =
            SigningKey::rsa_from_pkcs1_der(Some("rs".to_owned()), JwsAlgorithm::Rs256, &der)
        {
            signing_keys.push(("RS256 (published day one)", key));
        }
    }
    for (label, key) in &signing_keys {
        for _ in 0..SIGN_WARMUP {
            let _ = sign_detached(key, &payload);
        }
        let started = env.clock().monotonic();
        for _ in 0..SIGN_SAMPLES {
            let _ = sign_detached(key, &payload);
        }
        let mint_us = started.elapsed().as_secs_f64() * 1_000_000.0 / f64::from(SIGN_SAMPLES);
        // THE RATIO IS DIVIDED, not stated. This is the whole point: "three orders of
        // magnitude" was a sentence, and one of the three algorithms is 34x.
        let ratio = if mint_us > 0.0 {
            shipped_verify_ms * 1000.0 / mint_us
        } else {
            0.0
        };
        println!(
            "  {label:<40} {mint_us:>12.1} {:>18}",
            format!("{ratio:.0}x cheaper")
        );
    }

    // THE JWKS RENDER, because it is the cost an accelerator in front of this document could
    // save and therefore the number that decides whether such an accelerator is worth a hop.
    //
    // `IssuerRegistry::jwks_json` consults its hot state AFTER `resolve_for_publication` has
    // already returned the entry, deliberately: everything deciding WHETHER to publish has to
    // run first, and `issuer.rs` says so at the call site. The consequence is that a hit saves
    // this render and nothing else. It cannot save a database read, because the read that
    // produced the entry has already happened.
    //
    // So a cache hop is worth taking only if the hop is cheaper than the figure below. Publish
    // it rather than reasoning about it: a reader can compare it against their own accelerator
    // round trip and decide, which is what a sizing guide is for.
    println!("\nunit-costs: JWKS render (the cost a hot-state hit in front of the document saves)");
    println!("  {:<40} {:>12}", "published keys", "render us");
    let now = env.clock().now_utc();
    // BUILT FRESH rather than reused from the mint loop: `SigningKey` is deliberately not
    // `Clone`, and a keyset takes ownership.
    let mut rendered_any = false;
    for (label, with_rsa) in [
        ("EdDSA only", false),
        ("EdDSA + RS256 (a fresh environment)", true),
    ] {
        let Ok(ed) = SigningKey::ed25519_from_seed(Some("ed".to_owned()), &[7_u8; 32]) else {
            continue;
        };
        let mut algorithms = vec![JwsAlgorithm::EdDsa];
        let mut keyset = KeySet::bootstrap(ed, now);
        if with_rsa {
            let Ok(der) = generate_rsa_pkcs1_der(env.entropy()) else {
                continue;
            };
            let Ok(rsa) =
                SigningKey::rsa_from_pkcs1_der(Some("rs".to_owned()), JwsAlgorithm::Rs256, &der)
            else {
                continue;
            };
            keyset.add(rsa, now);
            algorithms.push(JwsAlgorithm::Rs256);
        }
        let Ok(policy) = SigningPolicy::new(algorithms) else {
            continue;
        };
        // WARMED like the signature loop, so a lazily built projection is not charged here.
        for _ in 0..SIGN_WARMUP {
            let _ = keyset
                .published_jwks(now, &policy)
                .and_then(|jwks| jwks.to_json());
        }
        let started = env.clock().monotonic();
        for _ in 0..RENDER_SAMPLES {
            let _ = keyset
                .published_jwks(now, &policy)
                .and_then(|jwks| jwks.to_json());
        }
        let render_us = started.elapsed().as_secs_f64() * 1_000_000.0 / f64::from(RENDER_SAMPLES);
        println!("  {label:<40} {render_us:>12.1}");
        rendered_any = true;
    }
    if !rendered_any {
        println!("  (no signing key could be built on this host, so no render was measured)");
    }

    // DERIVED FROM THE MEASUREMENT, not written down. A capacity line is the sentence a
    // reader quotes, so it must move when the number under it moves.
    //
    // Deliberately a FLOOR rather than an estimate. It counts one verify per login and
    // nothing else, on one core, with no contention: a real login also reads a user, mints
    // tokens and writes an audit row, and the hashing pool bounds concurrency separately. So
    // this is the ceiling arithmetic alone allows, and a deployment will do less.
    if shipped_verify_ms > 0.0 {
        println!(
            "\nunit-costs: at the shipped parameters ONE CORE OF THIS KIND sustains at most \
             {:.0} password logins per second ({:.1} ms each), before anything else a login \
             does, and on a heterogeneous CPU the other kind of core is several times slower",
            1000.0 / shipped_verify_ms,
            shipped_verify_ms
        );
    }
}
