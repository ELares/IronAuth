// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * Verify-latency benchmark (issue #118).
 *
 * Issue #118 wants published verify numbers that "reproduce from the repo by one documented
 * command", with the methodology published alongside. This is that command:
 *
 *     npm run bench
 *
 * ## What is measured, and what is deliberately not
 *
 * ONLY the verification itself: decode, algorithm check, key lookup against an ALREADY WARM
 * cache, signature verification, and claim validation. That is the number the "verify a token
 * anywhere in under a millisecond" claim is about.
 *
 * The JWKS fetch is excluded, and saying so matters more than the number. A verifier fetches
 * keys once per cache lifetime and verifies on every request, so folding a network round trip
 * into a per-request figure would report a number no production request pays. The first fetch
 * is performed during warmup, outside the timed region, exactly as a real process does it.
 *
 * Key IMPORT is inside the timed region, because the implementation imports per verification.
 * That is a real cost of this design and hiding it would flatter the result.
 *
 * ## Why a distribution and not a mean
 *
 * A mean hides exactly what an edge operator cares about. A p50 of 0.2 ms with a p99 of 40 ms
 * is a bad verifier wearing a good average. So p50, p95, p99 and max are all reported, and the
 * raw iteration count with them, because a percentile over too few samples is decoration.
 *
 * ## Honesty about what these numbers are
 *
 * They are one machine, one runtime, one moment. They are reproducible on THAT machine and are
 * not a claim about anyone else's. The output prints the runtime and platform for exactly that
 * reason, so a pasted table cannot lose its context.
 */

import { readFileSync } from 'node:fs';

import { JwksCache, verifyToken } from '../dist/verify.js';

/** How many timed iterations per algorithm. */
const ITERATIONS = 2000;

/** Untimed iterations first, so the JIT and the key cache are warm. */
const WARMUP = 200;

const corpus = JSON.parse(
  readFileSync(new URL('../vectors/verify-vectors.json', import.meta.url), 'utf8'),
);

/** A key cache serving the corpus JWKS with no network. */
function corpusKeys() {
  const send = async () =>
    new Response(JSON.stringify(corpus.jwks), {
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'max-age=300' },
    });
  return new JwksCache({
    uri: 'https://issuer.example/jwks',
    fetch: send,
    now: () => corpus.now,
  });
}

const options = {
  issuer: corpus.issuer,
  audience: corpus.audience,
  algorithms: corpus.algorithms,
  now: () => corpus.now,
  skewSeconds: 0,
};

/** The percentile of a SORTED array, by nearest-rank. */
function percentile(sorted, fraction) {
  const rank = Math.max(0, Math.ceil(fraction * sorted.length) - 1);
  return sorted[rank];
}

/** Time `iterations` verifications of `token`, returning millisecond timings. */
async function measure(token, keys) {
  // Warmup is NOT timed, and it is what makes the timed region measure steady state rather
  // than first-call compilation and the initial JWKS fetch.
  for (let index = 0; index < WARMUP; index += 1) {
    await verifyToken(token, keys, options);
  }
  const timings = new Array(ITERATIONS);
  for (let index = 0; index < ITERATIONS; index += 1) {
    const started = performance.now();
    await verifyToken(token, keys, options);
    timings[index] = performance.now() - started;
  }
  return timings.sort((left, right) => left - right);
}

/**
 * One accepted vector per ALGORITHM.
 *
 * Only accepted tokens are timed, since a refusal exits early and is not the case anyone
 * deploys for. Grouping by algorithm matters: the corpus holds five accepted vectors across
 * three distinct algorithms, so two of the five share one. Timing all five would print
 * near-identical rows and imply the table measured more than it did, which is the kind of
 * padding that makes a benchmark look thorough while telling you less.
 *
 * The grouping is DERIVED from the corpus rather than listed here, so this comment is the only
 * thing that can go stale when the corpus grows. It already had: it said four and two while the
 * corpus carried five and three.
 */
function subjects() {
  const byAlgorithm = new Map();
  for (const entry of corpus.cases) {
    if (entry.expect !== 'accept') continue;
    const header = JSON.parse(
      atob(entry.token.split('.')[0].replace(/-/g, '+').replace(/_/g, '/')),
    );
    if (!byAlgorithm.has(header.alg)) {
      byAlgorithm.set(header.alg, { name: header.alg, token: entry.token });
    }
  }
  return [...byAlgorithm.values()];
}

async function main() {
  const rows = [];
  for (const subject of subjects()) {
    // A FRESH cache per algorithm, warmed inside `measure`, so one subject cannot inherit
    // another's warm state and look faster for the wrong reason.
    const sorted = await measure(subject.token, corpusKeys());
    rows.push({
      subject: subject.name,
      p50: percentile(sorted, 0.5),
      p95: percentile(sorted, 0.95),
      p99: percentile(sorted, 0.99),
      max: sorted[sorted.length - 1],
      opsPerSecond: 1000 / (sorted.reduce((sum, value) => sum + value, 0) / sorted.length),
    });
  }

  const format = (value) => value.toFixed(3).padStart(8);
  process.stdout.write(
    `\nIronAuth verify latency (issue #118)\n` +
      `runtime: ${process.version} on ${process.platform}/${process.arch}\n` +
      `${ITERATIONS} timed iterations after ${WARMUP} warmup, JWKS cache warm, ` +
      `key import inside the timed region\n\n` +
      `algorithm        p50 (ms)  p95 (ms)  p99 (ms)  max (ms)      ops/s\n` +
      `${'-'.repeat(66)}\n`,
  );
  for (const row of rows) {
    process.stdout.write(
      `${row.subject.padEnd(16)}${format(row.p50)}  ${format(row.p95)}  ` +
        `${format(row.p99)}  ${format(row.max)}  ${Math.round(row.opsPerSecond)
          .toString()
          .padStart(9)}\n`,
    );
  }
  process.stdout.write(
    `\nThese are one machine, one runtime, one moment. They reproduce on THIS machine and are\n` +
      `not a claim about yours. The JWKS fetch is excluded because it happens once per cache\n` +
      `lifetime, not per request; including it would report a cost no production request pays.\n\n`,
  );

  // Emit machine-readable output too, so a CI job can publish the table as an artifact
  // without re-parsing the human one.
  if (process.env.BENCH_JSON === '1') {
    process.stdout.write(
      `${JSON.stringify(
        {
          runtime: process.version,
          platform: `${process.platform}/${process.arch}`,
          iterations: ITERATIONS,
          warmup: WARMUP,
          jwksFetchExcluded: true,
          rows,
        },
        null,
        2,
      )}\n`,
    );
  }
}

await main();
