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
    JwsAlgorithm, KeySet, SigningKey, SigningPolicy, generate_ecdsa_p256_pkcs8_der,
    generate_rsa_pkcs1_der, sign_detached,
};
use ironauth_oidc::{Argon2Params, hash_password_with, verify_password};

/// Quote a label as a JSON string.
///
/// HAND-ROLLED, because this example depends on no JSON crate and should not start: the only
/// values it emits are its own labels and formatted floats. It escapes the two characters that
/// can break a JSON string, which is the whole of what these labels can contain.
fn json_string(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

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
/// How many cores `available_parallelism` reports, or 0 when it cannot say.
fn available_cores() -> usize {
    std::thread::available_parallelism().map_or(0, std::num::NonZeroUsize::get)
}

/// The core mix as the banner states it, or an empty string on a homogeneous machine.
///
/// SHARED WITH THE BANNER rather than reformatted, so the record and the printed table cannot
/// describe two different machines.
fn core_mix_description() -> String {
    core_split().map_or_else(String::new, |(performance, efficiency)| {
        format!("{performance} performance + {efficiency} efficiency")
    })
}

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
    println!("  cores    {}", available_cores());
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
    if core_split().is_some() {
        println!("  core mix {}", core_mix_description());
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
    // THE MACHINE-READABLE RECORD, accumulated as the human table is printed so the two cannot
    // disagree (issue #152 criterion 4). The sizing guide is generated from this rather than
    // transcribed from the table above it, which is how six of its ten published figures came to
    // sit outside their own ranges.
    let mut hashing_json: Vec<String> = Vec::new();
    let mut mint_json: Vec<String> = Vec::new();
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
            // pool-boundary-allow: this MEASURES the raw hasher, which is the one caller
            // that must not route through the pool -- going through
            // `OidcState::verify_password` would time the admission queue and the worker
            // hop as well, and the number this example publishes is the per-verify CPU
            // cost the pool is then sized against. An example is not a request path.
            assert!(
                verify_password("correct horse battery staple", &hashed), // pool-boundary-allow: measures the raw verify
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
        hashing_json.push(format!(
            "    {{\"label\": {}, \"m_kib\": {m}, \"t\": {t}, \"p\": {p}, \
             \"hash_ms\": {hash_ms:.2}, \"verify_ms\": {verify_ms:.2}}}",
            json_string(label)
        ));
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
        mint_json.push(format!(
            "    {{\"algorithm\": {}, \"mint_us\": {mint_us:.1}, \"vs_verify\": {ratio:.0}}}",
            json_string(label)
        ));
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
    // THE JWKS RENDER AND WHAT A CACHE HIT ACTUALLY COSTS, because the difference between them
    // is what an accelerator in front of this document would save, and that difference is the
    // number issue #146's wiring question turns on.
    //
    // `IssuerRegistry::jwks_json` consults its hot state AFTER `resolve_for_publication` has
    // returned the entry, deliberately: everything deciding WHETHER to publish runs first. So a
    // hit cannot save a database read. What it saves is the render.
    //
    // WHAT IT ADDS IS MEASURED HERE TOO, because the first version of this benchmark said a hit
    // "saves the render and nothing else" and that was wrong in the expensive direction. On a
    // hit the path runs `String::from_utf8` and then a full `serde_json` validation parse of the
    // returned document, which `issuer.rs` keeps deliberately: without it the endpoint served
    // any UTF-8 bytes under that key as the environment's JWK Set. A miss never pays it. So the
    // saving is the render MINUS that parse, not the render.
    println!("\nunit-costs: JWKS render against what a cache hit costs to accept");
    println!(
        "  {:<52} {:>10} {:>9} {:>12}",
        "published keys", "render us", "parse us", "net saved us"
    );
    let now = env.clock().now_utc();
    // A FRESH ENVIRONMENT PUBLISHES THREE ALGORITHMS, not two. `DayOneSigningKeys::generate`
    // mints EdDSA, ES256 and RS256 and marks all three published from the environment's creation
    // instant, and the derived policy retains every algorithm present. The first version of this
    // row measured two keys and labelled them "a fresh environment", which no environment is.
    // The six-key row is one rotation of each, whose predecessors stay published for a window.
    let mut rendered_any = false;
    for (label, algorithms, rotations) in [
        ("EdDSA only", &[JwsAlgorithm::EdDsa][..], 0_u32),
        (
            "EdDSA + ES256 + RS256 (a fresh environment)",
            &[
                JwsAlgorithm::EdDsa,
                JwsAlgorithm::Es256,
                JwsAlgorithm::Rs256,
            ][..],
            0,
        ),
        (
            "the same three, one rotation each (six published)",
            &[
                JwsAlgorithm::EdDsa,
                JwsAlgorithm::Es256,
                JwsAlgorithm::Rs256,
            ][..],
            1,
        ),
    ] {
        let mut keyset: Option<KeySet> = None;
        let mut built = Vec::new();
        // GENERATED PER SLOT so each key is distinct, as a real environment's are. Reusing one
        // key would understate the document: kid strings and moduli both land in the bytes.
        for round in 0..=rotations {
            for algorithm in algorithms {
                let kid = format!("k{round}{}", built.len());
                let key = match algorithm {
                    JwsAlgorithm::EdDsa => {
                        let mut seed = [0_u8; 32];
                        env.entropy().fill_bytes(&mut seed);
                        SigningKey::ed25519_from_seed(Some(kid.clone()), &seed).ok()
                    }
                    JwsAlgorithm::Es256 => generate_ecdsa_p256_pkcs8_der(env.entropy())
                        .ok()
                        .and_then(|der| {
                            SigningKey::ecdsa_p256_from_pkcs8(Some(kid.clone()), &der).ok()
                        }),
                    _ => generate_rsa_pkcs1_der(env.entropy()).ok().and_then(|der| {
                        SigningKey::rsa_from_pkcs1_der(Some(kid.clone()), JwsAlgorithm::Rs256, &der)
                            .ok()
                    }),
                };
                let Some(key) = key else { continue };
                built.push(*algorithm);
                match keyset.as_mut() {
                    None => keyset = Some(KeySet::bootstrap(key, now)),
                    Some(set) => set.add(key, now),
                }
            }
        }
        let (Some(keyset), Ok(policy)) = (keyset, SigningPolicy::new(built)) else {
            continue;
        };
        let render = || {
            keyset
                .published_jwks(now, &policy)
                .and_then(|jwks| jwks.to_json())
                .ok()
        };
        let Some(document) = render() else { continue };

        for _ in 0..SIGN_WARMUP {
            let _ = render();
        }
        let started = env.clock().monotonic();
        for _ in 0..RENDER_SAMPLES {
            let _ = render();
        }
        let render_us = started.elapsed().as_secs_f64() * 1_000_000.0 / f64::from(RENDER_SAMPLES);

        // EXACTLY WHAT THE HIT PATH RUNS on the bytes it got back, in the same order: the UTF-8
        // check, the parse, and the `keys` array test that decides whether to serve them.
        let bytes = document.clone().into_bytes();
        let accept = || {
            String::from_utf8(bytes.clone()).ok().and_then(|text| {
                serde_json::from_str::<serde_json::Value>(&text)
                    .ok()
                    .and_then(|value| value.get("keys").map(serde_json::Value::is_array))
            })
        };
        for _ in 0..SIGN_WARMUP {
            let _ = accept();
        }
        let started = env.clock().monotonic();
        for _ in 0..RENDER_SAMPLES {
            let _ = accept();
        }
        let parse_us = started.elapsed().as_secs_f64() * 1_000_000.0 / f64::from(RENDER_SAMPLES);

        // SUBTRACTED, NOT ASSERTED. A negative net means a hit costs more CPU than rendering
        // from the entry the caller already holds, before any hop is paid for at all.
        println!(
            "  {label:<52} {render_us:>10.2} {parse_us:>9.2} {:>12.2}",
            render_us - parse_us
        );
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
    // THE RECORD THE SIZING GUIDE IS GENERATED FROM (issue #152 criterion 4).
    //
    // WRITTEN ONLY WHEN ASKED, via UNIT_COSTS_JSON. The example's default behaviour is a human
    // table on stdout, which is what `scripts/bench.sh` archives and what a developer runs; a
    // file appearing in a working tree because a benchmark was run once would be a surprise.
    if let Ok(path) = std::env::var("UNIT_COSTS_JSON") {
        let document = format!(
            "{{\n  \"host\": {{\n    \"cpu\": {},\n    \"cores\": {},\n    \"core_mix\": {},\n\
             \"samples\": {SAMPLES},\n    \"sign_samples\": {SIGN_SAMPLES},\n\
             \"sign_warmup\": {SIGN_WARMUP}\n  }},\n  \"password_hashing\": [\n{}\n  ],\n\
             \"token_mint\": [\n{}\n  ],\n  \"shipped_verify_ms\": {shipped_verify_ms:.2}\n}}\n",
            json_string(&cpu_brand()),
            available_cores(),
            json_string(&core_mix_description()),
            hashing_json.join(",\n"),
            mint_json.join(",\n"),
        );
        match std::fs::write(&path, document) {
            Ok(()) => println!("\nunit-costs: measurement written to {path}"),
            Err(error) => {
                // LOUD, AND A FAILING EXIT. A generator reading a stale file because this one
                // could not be written would publish last run's numbers as this run's.
                eprintln!("unit-costs: cannot write {path}: {error}");
                std::process::exit(1);
            }
        }
    }

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
