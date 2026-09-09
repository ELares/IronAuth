-- A directory connector may sync users and no groups (issue #142).
--
-- 0212 required `group_base_dn` and `group_filter` to be non-empty. That made a users-only
-- connector unrepresentable, which is not a rare configuration: a directory whose groups mean
-- nothing to IronAuth, or a first rollout that adds group-to-role mapping later, has no group
-- base to give and would have to invent one. Inventing one is worse than leaving it out -- a DN
-- with nothing under it reads as a group with no members, and the sync then finds NOBODY, which
-- is the empty-directory shape the diff exists to refuse.
--
-- The reader already handles the empty value: `ldap_boot::inputs_for` maps a blank group base to
-- NO group roots rather than to one empty root, and a sync with no roots scopes on the user base
-- alone. So this relaxation arms no reader; it makes a branch that was already written reachable.
--
-- Expand-only: it widens what an existing column accepts and changes no existing row. An older
-- binary reading a blank value takes the same no-roots branch, because that branch predates this
-- migration.
--
-- The length ceilings are unchanged, and the USER base stays required: a connector with no user
-- base has nothing to read at all.

ALTER TABLE ldap_connectors
    DROP CONSTRAINT ldap_connectors_base_dns_shaped;

ALTER TABLE ldap_connectors
    ADD CONSTRAINT ldap_connectors_base_dns_shaped
        CHECK (user_base_dn <> '' AND octet_length(user_base_dn) <= 1024
               AND octet_length(group_base_dn) <= 1024);

ALTER TABLE ldap_connectors
    DROP CONSTRAINT ldap_connectors_filters_shaped;

-- The group filter follows the group base: with no group base there is nothing to filter, and a
-- filter required alongside an absent base would be a value with no meaning.
ALTER TABLE ldap_connectors
    ADD CONSTRAINT ldap_connectors_filters_shaped
        CHECK (user_filter <> '' AND octet_length(user_filter) <= 4096
               AND octet_length(group_filter) <= 4096
               AND (group_base_dn = '' OR group_filter <> ''));
