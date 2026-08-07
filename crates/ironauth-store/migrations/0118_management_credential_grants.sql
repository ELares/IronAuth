-- Scoped grants on a management credential (issue #102, delegated administration).
--
-- Migration 0003 gave `management_credentials` an id, a scope, a key hash, a display name and
-- a revocation instant. It gave it nothing that could restrict what the credential may DO, so
-- every management key is full power within its `(tenant, environment)` and `Principal` has no
-- shape for a restricted admin. That is the reason every acceptance criterion on #102 is
-- unimplemented: there was no subject to attach a restriction to.
--
-- This adds the subject. It is the FOUNDATION only: the personas, the project grants and the
-- per-route enforcement are separate changes that build on this column.
--
-- NULL means UNRESTRICTED, and that is what makes this expand-only. Every credential that
-- exists when this migration runs keeps exactly the authority it had, because a restriction
-- nobody has written cannot take any away. A default of "no permissions" would revoke every
-- key in every deployment at upgrade, which is an outage rather than a security improvement,
-- and the same argument 0117 made for grandfathering domain rules applies here.
--
-- The vocabulary is deliberately its OWN, not the organization RBAC vocabulary from issue #98.
-- Those govern different universes: #98's permissions are in-product authorization over a
-- tenant's own resources, and these govern MANAGEMENT-PLANE operations over the tenant itself.
-- Conflating them would make a product permission grantable to a management key, and a slug
-- that means one thing in one table and another thing here is the shape that rots. What the
-- two share is the slug GRAMMAR and the counted-pin discipline, not the values.
--
-- An empty array is refused rather than read as "no authority". A credential that may do
-- nothing is indistinguishable from a revoked one, and there is already a revocation
-- (`deleted_at`). Forcing the distinction keeps "revoked" the single way to say it.
--
-- Expand-only and safe for the old binary: one nullable added column and a CHECK that
-- constrains only rows a pre-migration binary never writes. A binary that predates this
-- migration reads and writes `management_credentials` exactly as before, and because NULL is
-- unrestricted it also behaves exactly as before.

ALTER TABLE management_credentials
    ADD COLUMN permissions text[];

ALTER TABLE management_credentials
    ADD CONSTRAINT management_credentials_permissions_nonempty
        CHECK (permissions IS NULL OR cardinality(permissions) >= 1);

-- The control plane owns the credential lifecycle, so it owns the grant. Column scoped per
-- the #31 lesson, never a table-wide UPDATE. `updated_at` is not in the list because 0003's
-- table does not carry one; adding a column the statement does not set would be noise.
GRANT UPDATE (permissions) ON management_credentials TO ironauth_control;
