-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- A precompiled artifact beside the component, keyed on the engine that produced it
-- (issue #114 criterion 4).
--
-- # This supersedes the reasoning in 0162, which was right about the hazard and wrong about
-- # the remedy
--
-- 0162's header says a precompiled artifact in a shared database "is a portability hazard with
-- a memory-safety failure mode: a replica on a different CPU, or one wasmtime version ahead,
-- deserializes machine code built for something else." That is true, and it is why the artifact
-- was left out. A shipped migration cannot be edited -- its whole file is checksummed -- so the
-- correction lives here.
--
-- The remedy was available in wasmtime the whole time.
-- `Engine::precompile_compatibility_hash` is documented as: "If this Hash matches between two
-- Engines then binaries from one are guaranteed to deserialize in the other." So the artifact
-- travels WITH the key of the engine that produced it, and a reader deserializes only on an
-- exact match. A replica on a different CPU, or a node one wasmtime version ahead, computes a
-- different key, does not match, and compiles from `component` exactly as it does today.
--
-- The failure mode is therefore a slower first request, not undefined behaviour, and it is the
-- runtime's own guarantee doing the work rather than a version string somebody remembered to
-- bump.
--
-- # Why criterion 4 needs it
--
-- "AOT cold start p95 is below 1 ms." Compiling is ~93 ms on the pinned runner, so a dispatch
-- that compiles cannot meet that at any cache hit rate: the FIRST request in each process pays
-- it. Deserializing is ~200 to 440 us on the same runner, which does.
--
-- # Both columns or neither
--
-- An artifact without its key cannot be safely loaded, and a key without an artifact describes
-- nothing. The CHECK makes the pair the unit, so no reader has to handle a half-written row --
-- and a row written before this migration has NULL for both, which is the "compile from source"
-- case that already works.
ALTER TABLE token_hooks
    ADD COLUMN precompiled bytea,
    ADD COLUMN engine_key  bytea;

ALTER TABLE token_hooks
    ADD CONSTRAINT token_hooks_precompiled_is_keyed
    CHECK ((precompiled IS NULL) = (engine_key IS NULL));

-- A SHA-256 digest, so exactly 32 bytes. A key of another length is not a key this deployment
-- produced, and the artifact beside it is not one this deployment can vouch for.
ALTER TABLE token_hooks
    ADD CONSTRAINT token_hooks_engine_key_is_a_digest
    CHECK (engine_key IS NULL OR octet_length(engine_key) = 32);

-- A precompiled artifact is machine code and larger than the component it came from. The
-- component is bounded at 8 MiB by 0162; this is bounded too, and more generously, because
-- cranelift output for a large component legitimately exceeds its source. An unbounded column
-- is a way to fill the tenant's disk through the admin surface.
ALTER TABLE token_hooks
    ADD CONSTRAINT token_hooks_precompiled_bounded
    CHECK (precompiled IS NULL OR (octet_length(precompiled) > 0 AND octet_length(precompiled) <= 67108864));
