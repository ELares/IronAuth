-- Group bindings record which SCIM connection pushed them (issue #136, criterion 6).
--
-- WHAT THIS IS FOR.
--
-- Criterion 6 asks that deleting a provisioning connection "tears down all assignments derived
-- from it". Today nothing can answer which bindings those are. `org_group_members` records the
-- group and the membership and nothing about who created the row, so a revoked connection
-- leaves every person it ever pushed holding every role their groups confer, indefinitely, and
-- an operator revoking a compromised identity provider has disarmed the credential without
-- undoing anything it did.
--
-- A binding is where a role actually comes from on this path. The data plane holds NOTHING on
-- `org_group_roles` (0185 says so and means it), so a provisioning connection cannot attach a
-- role to a group; all it can do is put people into groups an operator has already given
-- roles. The derived assignment IS the binding, and this column is what makes it attributable.
--
-- NULLABLE, AND NULL MEANS OPERATOR.
--
-- Every binding written before this migration, and every binding an operator writes through the
-- management API afterwards, carries NULL. That is the correct value rather than a gap to be
-- backfilled: those bindings were not derived from any connection and the teardown must never
-- touch them. Criterion 5's "directly granted roles survive" is this column being NULL, and the
-- teardown's predicate is `source_scim_connection_id = $1`, which no NULL row can satisfy --
-- in SQL a NULL comparison is never true, so the survival property is a consequence of the type
-- rather than of remembering to write the exclusion.
--
-- WHY NOT ON `org_groups` TOO.
--
-- A group a connection created is not an assignment and tearing it down is a larger act than
-- the criterion asks for: an operator may have attached roles to it, other connections may push
-- into it, and a group that vanished when one identity provider was revoked would take those
-- with it. Revoking a connection un-does what it PUT people into, and leaves the structure an
-- operator can still see and reuse.
--
-- NO NEW GRANTS ARE NEEDED, and that is worth stating because it is easy to assume otherwise.
-- 0185 grants the data plane `INSERT ON org_group_members` at TABLE level rather than by
-- column, so a new column is insertable by the same grant. 0088 grants the control plane
-- `UPDATE (updated_at, deleted_at)`, which is exactly what the teardown writes: it soft-deletes
-- the bindings and never repoints them. This column is therefore write-once at insert and
-- readable by both planes, which is the containment property 0087 and 0088 established.

ALTER TABLE org_group_members
    ADD COLUMN source_scim_connection_id text
    REFERENCES scim_connections (id);

-- The teardown's own access path. It answers "every live binding this connection pushed",
-- which is one scan per revoke and would otherwise be a sequential scan of every binding in
-- the deployment. PARTIAL on the two conditions the teardown always carries: a NULL source is
-- an operator's binding and is not in the index at all, so the index is sized by what
-- provisioning actually pushed rather than by the whole table.
CREATE INDEX org_group_members_by_source_connection
    ON org_group_members (tenant_id, environment_id, source_scim_connection_id)
    WHERE source_scim_connection_id IS NOT NULL AND deleted_at IS NULL;

COMMENT ON COLUMN org_group_members.source_scim_connection_id IS
    'Issue #136: the SCIM connection that pushed this binding, or NULL when an operator made '
    'it directly. Written once at insert and never updated: 0088 grants UPDATE on updated_at '
    'and deleted_at only, so a binding cannot be re-attributed after the fact.';
