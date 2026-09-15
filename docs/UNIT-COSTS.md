# Per-operation unit costs

Issue #152 criterion 4 asks for per-operation unit costs with the Argon2id parameters stated.
Measured, reproduced by one command:

```
cargo run --release -p ironauth-oidc --example unit_costs
```

## Password hashing

| parameters | hash | verify |
|---|---|---|
| **OWASP default (shipped)**: `m=19456 KiB, t=2, p=1` | 11.8 ms | 11.5 ms |
| config floor: `m=8192 KiB, t=2, p=1` | 4.5 ms | 4.5 ms |
| double iterations: `m=19456 KiB, t=4, p=1` | 23.5 ms | 23.5 ms |

Apple M4 Pro, 14 cores, release build, 10 samples. Reproduced twice within noise.

**At the shipped parameters one core sustains at most 87 password logins per second.**

## Why that number is a floor, not a capacity

It counts one Argon2id verify per login and nothing else: no user read, no token mint, no
audit write, one core, no contention. A deployment will do less. Quoting it as a capacity
figure would be the most flattering possible reading of a single measurement.

## Why the parameters are printed with the numbers

Argon2id cost is a configuration choice, not a property of the code. A unit cost quoted
without `m`, `t` and `p` is unreproducible, and worse, invites a reader to compare it against
a deployment tuned differently and conclude something about the software.

The table shows the shape of the tradeoff deliberately. Dropping to the config floor roughly
halves the time AND halves the security margin with it; that is the trade a sizing guide must
not let somebody make by accident while reading it for capacity numbers. The floor is what
config load refuses to go below, not a recommendation.

## Why only password hashing

A sizing guide answers "how many can one machine do", and that is decided by whichever
operation dominates. For an identity provider under load it is the password hash, by roughly
three orders of magnitude: Argon2id at the OWASP defaults deliberately costs 19 MiB and tens
of milliseconds, while a token mint is a signature over a few hundred bytes. A table where
the interesting row is surrounded by rows rounding to zero would suggest they are comparable.

## Verify is measured separately from hash

A login VERIFIES; only a password change HASHES. They are close but not equal, and quoting
one for both is how a capacity estimate drifts. The capacity line above uses verify, because
that is the operation a login performs.

## What this does not cover

Criterion 4 also asks that the sizing guide be GENERATED from CI benchmark output and
regenerate on release, which needs a release pipeline. And the hardware here is a development
machine: a published sizing guide should be measured on the instance classes it recommends,
so these are a floor rather than a capacity statement. See `docs/PERFORMANCE.md` for the same
caveat on startup and RSS.
