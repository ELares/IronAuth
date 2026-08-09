-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Audited impersonation: the session half (issue #101).
--
-- A session becomes an impersonation session by carrying five columns together: who is
-- impersonating, why in a typed code, why in the operator's own words, when the impersonation
-- started, and when it must stop. An ordinary session carries none of them.
--
-- EXPAND only. Every existing row keeps every value it had, and `impersonator` staying NULL is
-- what says the session is ordinary, so no row is rewritten and the old binary reads the table
-- unchanged.
ALTER TABLE sessions ADD COLUMN impersonator text;
ALTER TABLE sessions ADD COLUMN impersonation_reason_code text;
ALTER TABLE sessions ADD COLUMN impersonation_reason_text text;
ALTER TABLE sessions ADD COLUMN impersonation_started_at timestamptz;
ALTER TABLE sessions ADD COLUMN impersonation_expires_at timestamptz;

-- All five or none. A session with an impersonator and no justification is the row the
-- criterion "starting impersonation without a typed justification is rejected" exists to
-- prevent, and rejecting it in a handler leaves the row representable for anything that writes
-- around the handler. Here it is not representable at all.
--
-- `impersonation_reason_text` is deliberately part of the arc rather than optional. A typed
-- code alone reads as a category; the criterion asks for "structured reason plus free text",
-- and an operator who must write a sentence writes a different sentence for each incident.
ALTER TABLE sessions ADD CONSTRAINT sessions_impersonation_arc
    CHECK (
        (impersonator IS NULL
            AND impersonation_reason_code IS NULL
            AND impersonation_reason_text IS NULL
            AND impersonation_started_at IS NULL
            AND impersonation_expires_at IS NULL)
     OR (impersonator IS NOT NULL
            AND impersonation_reason_code IS NOT NULL
            AND impersonation_reason_text IS NOT NULL
            AND impersonation_started_at IS NOT NULL
            AND impersonation_expires_at IS NOT NULL)
    );

-- Neither justification field may be blank. Without this the arc above is satisfied by an
-- empty string, which is a justification in the schema and nothing to a human reading the
-- audit stream.
--
-- The character set on `btrim` is explicit and not decorative. One-argument `btrim` strips
-- SPACES only, so a justification of a tab and a newline trims to itself, is non-empty, and
-- passes. A test wrote exactly that and it was admitted.
ALTER TABLE sessions ADD CONSTRAINT sessions_impersonation_reason_nonempty
    CHECK (
        impersonator IS NULL
     OR (btrim(impersonation_reason_code, E' \t\r\n\f\v') <> ''
         AND btrim(impersonation_reason_text, E' \t\r\n\f\v') <> '')
    );

-- THE HARD CAP, as a schema invariant rather than an application rule (issue #101).
--
-- The criterion says the 60-minute bound "is a hard bound, not configurable upward". Written
-- as a check in the start handler, that is one `if` away from being configurable by whoever
-- edits the handler next, and it says nothing at all about a row written by a migration, a
-- fixture, or a future extension path. Written here, an impersonation session lasting 61
-- minutes cannot be stored, so "extension or refresh past the cap fails" is true of every
-- writer that will ever exist rather than of the two that exist today.
--
-- Anchored on `impersonation_started_at`, which the writer sets from the SAME clock as the
-- expiry, and NOT on `created_at` or `now()`.
--
-- `created_at` defaults to the database's `now()` while every time the application writes
-- comes from its injected clock seam, so anchoring there would compare two clocks that are
-- only incidentally the same and would reject legitimate rows wherever they diverge. `now()`
-- would be worse in a different way: a CHECK is re-evaluated on UPDATE, so a session could be
-- extended sixty minutes from each update, forever, which is the cap bypass this constraint
-- exists to make unrepresentable.
--
-- Re-evaluation on UPDATE is the point. An extension writes a new expiry against the ORIGINAL
-- start, so the bound is measured from when the impersonation began, which is what a cap
-- means.
ALTER TABLE sessions ADD CONSTRAINT sessions_impersonation_hard_cap
    CHECK (
        impersonation_expires_at IS NULL
     OR (impersonation_expires_at > impersonation_started_at
         AND impersonation_expires_at <= impersonation_started_at + INTERVAL '60 minutes')
    );

-- The fleet listing filters impersonation sessions, so it gets the partial index rather than
-- scanning every session of a scope to find the few that are flagged.
CREATE INDEX sessions_impersonation_idx
    ON sessions (tenant_id, environment_id, created_at, id)
    WHERE impersonator IS NOT NULL;

-- The app plane WRITES an impersonation session at start (it owns session INSERT) and the
-- control plane READS the flag for the fleet listing, which its existing table-wide SELECT
-- already covers. Neither plane may UPDATE the justification or the impersonator: a
-- justification that can be edited after the fact is not an audit record. The cap column is
-- writable by neither for the same reason, and the CHECK above bounds it regardless.
GRANT UPDATE (impersonation_expires_at) ON sessions TO ironauth_app;
