-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Per-endpoint event-type subscription (issue #106).
--
-- #106 requires that "an endpoint subscribes to a set of event types; non-matching events
-- are excluded before a delivery attempt is ever created". Until #569 nothing emitted an
-- event at all, so there was nothing to filter and the column would have been inert. Now
-- that `user.created` flows end to end, the filter is the difference between an integrator
-- receiving what it asked for and receiving everything the platform ever emits.
--
-- ## NULL means every type, and that is the whole compatibility story
--
-- The column is nullable and defaults to NULL, which means "no filter": the endpoint
-- receives every event, which is exactly what every endpoint registered before this
-- migration already did. An empty ARRAY is deliberately a different thing from NULL and is
-- refused by the CHECK below, because "subscribed to nothing" is far more likely to be a
-- client that serialized an empty list by accident than an operator asking for an endpoint
-- that can never receive anything.
--
-- ## Exact match, not a wildcard grammar
--
-- Entries are matched exactly. A grammar like `user.*` is what Svix offers and it is
-- deliberately not here yet: without the typed catalogue (#108) there is nothing to
-- validate a pattern against, so a filter with a typo would match nothing and look exactly
-- like a filter that was working. Exact strings fail the same way but are trivially
-- checkable against the catalogue when it lands, and widening to patterns later is additive.
ALTER TABLE webhook_endpoints
    ADD COLUMN event_types text[];

-- A subscription that is present must name at least one type. NULL (no filter) stays the
-- way to receive everything.
ALTER TABLE webhook_endpoints
    ADD CONSTRAINT webhook_endpoints_event_types_non_empty
    CHECK (event_types IS NULL OR array_length(event_types, 1) >= 1);

-- The control plane manages the subscription, exactly as it manages the url and the
-- description: it is operator configuration, not something the delivery path decides.
GRANT UPDATE (event_types) ON webhook_endpoints TO ironauth_control;
