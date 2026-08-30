-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Precompiled artifacts for deployed WASM, issue #114 criterion 4.
--
--   "AOT cold start p95 is below 1 ms and warm invocation p95 below 100 microseconds"
--
-- Before this, a cache miss COMPILED: roughly 34 ms of cranelift for the shipped Rust guest and
-- far more for a large one. The gate honestly enforced 250 ms because that is what the dispatch
-- did. These columns hold what `Engine::precompile_component` produced at DEPLOY time, so a miss
-- deserializes machine code instead of generating it.
--
-- # The artifact is MACHINE CODE, and the key is what decides whether it runs
--
-- `Component::deserialize` checks a header, and the safety note on `load_precompiled` states
-- plainly what that is worth: an `Ok` is not evidence the artifact was trustworthy. So the
-- decision is made BEFORE deserialization by comparing `aot_engine_key`, and a mismatch never
-- reaches the unsafe call -- it falls back to compiling, which is exactly today's behaviour.
--
-- The key is a SHA-256 over wasmtime's own `precompile_compatibility_hash` plus the wasmtime
-- version. Its contract is the one needed: engines whose hashes match are guaranteed to
-- deserialize each other's binaries. An engine upgrade always produces a NEW key, so every
-- deployed component recompiles on first use after one -- a needless recompile is the safe
-- direction, and a wrong load is not.
--
-- # Nullable, and null is not a degraded state
--
-- A row with no artifact compiles, which is what every row did before this migration. That makes
-- the change EXPAND-safe in both directions: an old binary ignores these columns, and a new
-- binary reading a row an old one wrote simply compiles it. Nothing needs backfilling and no
-- deploy is blocked on one.
--
-- BOTH OR NEITHER. An artifact with no key cannot be checked, and a key with no artifact
-- describes nothing. Either alone is a row a reader has to invent a rule for, so the CHECK
-- refuses both shapes.
--
-- # Why 80 MiB, measured rather than guessed
--
-- A precompiled artifact is several times its source. MEASURED on the artifacts this repository
-- ships, with this wasmtime and this config:
--
--   * `good` (Rust)         45,615 bytes -> 220,624 bytes   (4.8x)
--   * `wordmark` (Rust)     65,411 bytes -> 257,504 bytes   (3.9x)
--   * `token-customize` (TypeScript) 11,125,985 -> 34,009,760 bytes   (3.1x)
--
-- The component columns cap at 16 MiB (0166, raised for exactly the TypeScript case). Five times
-- that is 80 MiB, which covers the worst ratio observed with room above it, and leaves the
-- shipped TypeScript artifact -- the largest thing this repository actually produces -- at 2.3x
-- headroom.
--
-- A bound at all because this column is READ ON THE LOGIN PATH. It is larger than the component
-- it replaces, and that is the trade this criterion asks for: a bigger read on a cache miss in
-- exchange for not running a compiler on one.

ALTER TABLE token_hooks
    ADD COLUMN aot_artifact bytea,
    ADD COLUMN aot_engine_key text;

ALTER TABLE token_hooks
    ADD CONSTRAINT token_hooks_aot_artifact_bounded
        CHECK (aot_artifact IS NULL OR octet_length(aot_artifact) <= 83886080);

ALTER TABLE token_hooks
    ADD CONSTRAINT token_hooks_aot_both_or_neither
        CHECK ((aot_artifact IS NULL) = (aot_engine_key IS NULL));

ALTER TABLE token_hooks
    ADD CONSTRAINT token_hooks_aot_key_shaped
        CHECK (aot_engine_key IS NULL OR aot_engine_key ~ '^[0-9a-f]{64}$');

ALTER TABLE challenge_components
    ADD COLUMN aot_artifact bytea,
    ADD COLUMN aot_engine_key text;

ALTER TABLE challenge_components
    ADD CONSTRAINT challenge_components_aot_artifact_bounded
        CHECK (aot_artifact IS NULL OR octet_length(aot_artifact) <= 83886080);

ALTER TABLE challenge_components
    ADD CONSTRAINT challenge_components_aot_both_or_neither
        CHECK ((aot_artifact IS NULL) = (aot_engine_key IS NULL));

-- THE KEY'S SHAPE IS CHECKED, and this is not decoration. The key gates an UNSAFE load, and the
-- comparison is a string equality: a column that could hold an empty string, or NULL-ish text, or
-- a truncated digest, would make "the keys matched" a weaker statement than it reads as. Sixty-
-- four lowercase hex characters is exactly what `HookEngine::compatibility_key` produces.
ALTER TABLE challenge_components
    ADD CONSTRAINT challenge_components_aot_key_shaped
        CHECK (aot_engine_key IS NULL OR aot_engine_key ~ '^[0-9a-f]{64}$');
