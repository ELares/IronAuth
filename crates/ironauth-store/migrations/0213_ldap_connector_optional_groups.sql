-- A directory connector may sync users and no groups (issue #142).
--
-- 0212 required `group_base_dn` and `group_filter` to be non-empty. That made a users-only
-- connector unrepresentable, which is not a rare configuration: a directory whose groups mean
-- nothing to IronAuth, or a first rollout that adds group-to-role mapping later, has no group
-- base to give and would have to invent one. Inventing one is worse than leaving it out -- a DN
-- with nothing under it reads as a group with no members, and the sync then finds NOBODY, which
-- is the empty-directory shape the diff exists to refuse.
--
-- BLANK MEANS BLANK AFTER TRIMMING, because that is what the reader means. 0212 keyed on
-- `group_base_dn <> ''` while `ldap_boot::inputs_for` keys on `group_base_dn.trim().is_empty()`,
-- and the two disagree on whitespace: a single space was storable under 0212 and the sweep read
-- it as no group scoping at all, while the database went on demanding the group filter that
-- pairs with a base. So the operator who typed a space rather than clearing the field was forced
-- to supply a filter nothing then read. Both checks below use `btrim`, so one value means one
-- thing to the schema and to the sweep.
--
-- The reader needs no change: it already maps a blank group base to NO group roots rather than to
-- one empty root. This relaxation makes that arm reachable by a row an operator would
-- deliberately write, rather than only by the whitespace accident.
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
        CHECK (btrim(user_base_dn) <> '' AND octet_length(user_base_dn) <= 1024
               AND octet_length(group_base_dn) <= 1024);

ALTER TABLE ldap_connectors
    DROP CONSTRAINT ldap_connectors_filters_shaped;

-- The group filter follows the group base: with no group base there is nothing to filter, and a
-- filter required alongside an absent base would be a value with no meaning.
ALTER TABLE ldap_connectors
    ADD CONSTRAINT ldap_connectors_filters_shaped
        CHECK (btrim(user_filter) <> '' AND octet_length(user_filter) <= 4096
               AND octet_length(group_filter) <= 4096
               AND (btrim(group_base_dn) = '' OR btrim(group_filter) <> ''));
