-- Shared Signals: the columns a stream configuration update writes (issue #143).
--
-- 0216 withheld these deliberately and said why: "The configuration update SSF 1.0 also defines
-- is a later slice, and its columns are granted with the statement that writes them rather than
-- ahead of it." This is that slice, and this is that grant. 0212 states the rule both follow: a
-- privilege for a write nothing performs is one nobody can account for later.
--
-- WHAT SSF 1.0 LETS A RECEIVER CHANGE is exactly three properties of its own stream:
-- `events_requested`, `delivery` and `description`. Everything else in the stream configuration
-- object is Transmitter-Supplied and read-only, and the surface refuses a request that tries to
-- change one. So the grant is SIX COLUMNS: the three behind `delivery` (the method and the two
-- push fields), the two behind the event negotiation, and the description. `updated_at` is not
-- among them because 0216 granted it already for `set_status`, and this statement writes it too.
--
-- `events_delivered` IS IN THE LIST AND IS NOT RECEIVER-SUPPLIED. It is the transmitter's answer
-- to `events_requested` -- the intersection with what this build emits -- so it is recomputed
-- and written by the same statement rather than accepted from the request. A grant it did not
-- have would make every update fail at RUNTIME with 42501 the moment a receiver renegotiated.
--
-- `client_id` STAYS WITHHELD, which is the half of 0216's sentence that does not change. It
-- decides WHOSE stream this is, and no update this build performs writes it.
--
-- 0216's other worry was re-pointing: "no update can re-point a stream at another receiver's
-- endpoint." That property is preserved, but it is now carried by the STATEMENT rather than by
-- the absence of a privilege. `update_configuration` takes the receiver as a SQL conjunct, so a
-- receiver can re-point its OWN stream -- which is what SSF makes `delivery` receiver-supplied
-- for -- and matches no row for anybody else's. The grant is a coarser fence than it was; the
-- conjunct is the fence that matters, and it is the same one every other write here uses.
GRANT UPDATE (
    delivery_method,
    push_endpoint_url,
    push_secret_name,
    events_requested,
    events_delivered,
    description
) ON ssf_streams TO ironauth_app;
