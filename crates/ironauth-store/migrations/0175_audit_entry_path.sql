-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- How a management call ARRIVED, on the audit row. Issue #123 criterion 5.
--
-- > Every admin MCP mutation appears in the audit stream attributed to the machine identity with
-- > the MCP entry path marked.
--
-- The attribution half already worked: `actor_kind` and `actor_id` name the machine identity,
-- and an MCP server authenticating with a scoped API key is that identity. What nothing recorded
-- is the ENTRY PATH -- whether the same identity made the call directly or through an agent
-- tool. An operator investigating "why did this key delete a client at 3am" needs to tell those
-- apart, and they are indistinguishable without this column.
--
-- # NULL is the direct API, and that is why the column is nullable
--
-- Every call made before this migration, and every call made directly afterwards, has no entry
-- path to record. A `DEFAULT 'direct'` would be a claim about rows nobody measured -- it would
-- state that a hundred thousand historical rows arrived directly, which happens to be true and
-- is still not something this migration knows. NULL says "not recorded", which is the fact.
--
-- # WHAT THIS COLUMN IS WORTH, said plainly, because it is easy to over-read
--
-- It is SELF-DECLARED PROVENANCE, not an authenticated fact. The value arrives in a request
-- header the caller sets, so a caller can omit it on an MCP call or supply it on a direct one.
--
-- That is not a hole, because it is not a privilege: the caller is already authenticated and
-- already authorized for the operation, and lying about their own entry path changes nothing
-- they can DO. What it costs is that an operator must read `entry_path` as "the caller said
-- this" rather than "the platform observed this" -- which is exactly how a `User-Agent` is read,
-- and is useful for the same reasons.
--
-- Making it authenticated would mean binding the entry path to the CREDENTIAL rather than the
-- request: a key issued for MCP use that cannot be used any other way. That is a real design and
-- it belongs with the machine-identity work rather than here, where it would be a second
-- credential model bolted onto an audit column.
--
-- The value is CONSTRAINED to a closed set even so. An unconstrained column would let a caller
-- write a paragraph, or a value that reads like another system's, into every operator's audit
-- stream and every SIEM export -- and the cost of that is not authorization, it is that the
-- column stops being groupable, which is the only thing it is for.
--
-- Migration safety obligation: audit_log is an existing table and this is one NULLABLE column
-- with no default, so the old binary neither reads nor writes it and a rollback leaves it inert.
-- An EXPAND.

ALTER TABLE audit_log
    ADD COLUMN entry_path text;

-- A CLOSED SET. See the header: the column exists to be grouped by, and a free-text one is not.
-- `mcp` is the only member today; adding one is a migration, which is the point -- an entry path
-- nobody declared cannot appear in an export.
ALTER TABLE audit_log
    ADD CONSTRAINT audit_log_entry_path_known
    CHECK (entry_path IS NULL OR entry_path IN ('mcp'));
