-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Per-client CIBA delivery registration (issue #131 criteria 2 and 6).
--
-- CIBA Core makes the delivery mode a REGISTERED client property, not a per-request
-- choice. Until now the backchannel endpoint inferred it from whether a request
-- carried a client_notification_token, which is a reasonable stopgap and the wrong
-- contract: a client that registered for ping should get ping whether or not any
-- individual request remembers to say so, and a client that registered for poll
-- must not be able to talk the server into calling a URL by adding a parameter.
--
-- Two columns, both additive and both defaulting to the pre-#131 behaviour, so the
-- old binary keeps working:
--
--   backchannel_delivery_mode: 'poll' or 'ping'. NOT NULL, defaults to 'poll'.
--                              'push' is absent from the vocabulary rather than
--                              rejected in application code -- see
--                              docs/WILL-NOT-IMPLEMENT.md, which records that push
--                              has the weakest security properties of the three
--                              modes and is forbidden by the FAPI-CIBA profile.
--                              A CHECK is the enforcement that survives a writer who
--                              has not read that document, which is what makes
--                              criterion 6 structural rather than a promise.
--
--   backchannel_client_notification_endpoint:
--                              where a ping is sent. NULL for poll clients.
--
-- The pairing is enforced by a CHECK in BOTH directions. Ping without an endpoint is
-- a client that asked to be notified and never can be, so it would wait forever. Poll
-- WITH an endpoint is the more interesting refusal: the row would carry a URL that
-- nothing consults today, and the first future reader that consults the column before
-- checking the mode turns a poll registration into a server-side request to an
-- arbitrary URL. An unused URL on a row is exactly the kind of latent capability that
-- becomes an SSRF the day someone wires it up.
--
-- The endpoint's SCHEME is deliberately NOT constrained here. The fetcher refuses
-- plaintext and private-range targets at call time (the same SSRF-hardened path the
-- webhook and enrichment surfaces use), and duplicating that policy in a CHECK would
-- give it two homes that drift -- while being weaker than the real one, since a CHECK
-- cannot resolve DNS.

ALTER TABLE clients
    ADD COLUMN backchannel_delivery_mode text NOT NULL DEFAULT 'poll',
    ADD COLUMN backchannel_client_notification_endpoint text;

ALTER TABLE clients
    ADD CONSTRAINT clients_backchannel_delivery_mode_known
        CHECK (backchannel_delivery_mode IN ('poll', 'ping')),
    ADD CONSTRAINT clients_backchannel_ping_has_endpoint
        CHECK (
            (backchannel_delivery_mode = 'ping'
                AND backchannel_client_notification_endpoint IS NOT NULL)
            OR
            (backchannel_delivery_mode = 'poll'
                AND backchannel_client_notification_endpoint IS NULL)
        );

-- Migration 0018 revoked the table-wide UPDATE on clients from ironauth_app and
-- re-granted a COLUMN-SCOPED UPDATE over exactly the data-plane-owned columns, so a
-- new clients column is app-unwritable until deliberately granted (the whole point of
-- that narrowing). Dynamic client registration is a data-plane write, so both columns
-- are added to the data plane's column-scoped UPDATE. This is additive; Postgres
-- unions column privileges, so it does not touch the 0018 grant, and the
-- control-plane-only quarantine columns stay unwritable to the data plane.
GRANT UPDATE (
    backchannel_delivery_mode,
    backchannel_client_notification_endpoint
) ON clients TO ironauth_app;
