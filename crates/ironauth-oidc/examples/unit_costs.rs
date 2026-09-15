// SPDX-License-Identifier: MIT OR Apache-2.0

//! Measure the per-operation unit costs a sizing guide is built from (issue #152 criterion 4).
//!
//! ```text
//! cargo run --release -p ironauth-oidc --example unit_costs
//! ```
//!
//! # Why password hashing is the only operation here
//!
//! A sizing guide answers "how many of these can one machine do", and that number is decided
//! by whichever operation dominates. For an identity provider under load that is the password
//! hash, by roughly three orders of magnitude: Argon2id at the OWASP defaults deliberately
//! costs 19 MiB and tens of milliseconds, while a token mint is a signature over a few
//! hundred bytes. Publishing a table where the interesting row is surrounded by rows that
//! round to zero would suggest they are comparable.
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
use ironauth_oidc::{Argon2Params, hash_password_with, verify_password};

/// How many samples per measurement. Small because each one is deliberately expensive.
const SAMPLES: u32 = 10;

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

    // Every parameter set worth publishing, so a reader can see the shape of the tradeoff
    // rather than one number with no context. The floor is what config load refuses to go
    // below; the default is what ships.
    let cases = [
        ("OWASP default (shipped)", Argon2Params::new(19_456, 2, 1)),
        (
            "config floor (8 MiB, the weakest config load accepts)",
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

    // DERIVED FROM THE MEASUREMENT, not written down. A capacity line is the sentence a
    // reader quotes, so it must move when the number under it moves.
    //
    // Deliberately a FLOOR rather than an estimate. It counts one verify per login and
    // nothing else, on one core, with no contention: a real login also reads a user, mints
    // tokens and writes an audit row, and the hashing pool bounds concurrency separately. So
    // this is the ceiling arithmetic alone allows, and a deployment will do less.
    if shipped_verify_ms > 0.0 {
        println!(
            "\nunit-costs: at the shipped parameters one core sustains at most {:.0} \
             password logins per second ({:.1} ms each), before anything else a login does",
            1000.0 / shipped_verify_ms,
            shipped_verify_ms
        );
    }
}
