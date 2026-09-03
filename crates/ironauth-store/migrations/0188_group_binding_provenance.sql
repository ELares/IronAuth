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
-- A binding is where a role actually comes from on this path. The data plane holds SELECT on
-- `org_group_roles` and nothing else -- 0089 grants exactly that, under its own words "the DATA
-- plane needs SELECT and NOTHING ELSE", because that table is what token issuance reads -- so a
-- provisioning connection can see what a group confers and can never change it. All it can do
-- is put people into groups an operator has already given roles. The derived assignment IS the
-- binding, and this column is what makes it attributable.
--
-- (0185 says only that IT grants nothing there, which is a statement about that migration
-- rather than about the plane's holdings. An earlier draft of this paragraph restated it as
-- the latter and was wrong twice over: the data plane does hold SELECT, and 0185 never claimed
-- otherwise. Migration text is checksummed whole-file, so a sentence that ships here can never
-- be corrected in place, which is exactly what 0185 says about 0087 and 0088.)
--
-- ONE ROW PER (GROUP, MEMBERSHIP), SO PROVENANCE IS FIRST-WRITER-WINS, and that is a real
-- limitation rather than an oversight. 0088's live-unique index makes a person a member of a
-- group at most once, so this column records who bound them FIRST and there is nowhere to
-- record a second asserter.
--
-- What follows with TWO CONNECTIONS PROVISIONING ONE ORGANIZATION, which is the sharpest edge
-- of the design and is what `two_connections_on_one_organization_share_one_binding` drives:
--
--   * the second connection's push of a person the first already bound is accepted and writes
--     nothing, so the binding stays attributed to the first;
--   * revoking the FIRST removes a binding the second still asserts. The second rewrites it on
--     its next full-membership sync (a PUT or a replace-PATCH names the whole set), and an
--     incremental client that sends only changes does not, so the person loses that group's
--     roles until somebody notices;
--   * and the second connection's ORDINARY full-membership PUT deletes the FIRST connection's
--     binding whenever it does not name that person, because a replace reconciles against every
--     existing binding regardless of who wrote it. That is the case that needs no revoke at
--     all, and it is the reason two connections should not push into one group.
--
-- The same asymmetry runs the other way: an operator cannot ADD a binding a connection already
-- made, because the insert is refused as a conflict. They can CONVERT one, with two calls the
-- management surface already exposes -- remove the binding, then add it back with no source --
-- and after that a revoke of the connection leaves it alone. So "an operator's binding survives
-- a teardown" is true of the bindings an operator wrote or re-wrote, and the operator has a way
-- to make it true of any binding they choose. It is not automatic and nothing prompts them.
--
-- Fixing either needs a second table recording every asserter of a binding, which is a
-- different schema and a different issue. This column answers the question criterion 6 asks --
-- which bindings did THIS credential create -- and not "which credentials would still assert
-- this binding".
--
-- NULLABLE, AND NULL MEANS OPERATOR.
--
-- Every binding written before this migration, and every binding an operator writes through the
-- management API afterwards, carries NULL. That is the correct value rather than a gap to be
-- backfilled: those bindings were not derived from any connection and the teardown must never
-- touch them. Criterion 5's "directly granted roles survive" is this column being NULL, and the
-- teardown's predicate is `source_scim_connection_id = $4`, which no NULL row can satisfy --
-- in SQL a NULL comparison is never true, so the survival property is a consequence of the type
-- rather than of remembering to write the exclusion. It holds for the bindings an operator
-- wrote FIRST; see the note above for what that leaves out.
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
