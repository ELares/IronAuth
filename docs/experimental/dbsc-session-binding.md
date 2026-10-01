# DBSC session binding (DESIGN NOTE)

**Status:** design note only. No prototype ships.
**Pinned revision:** the Device-Bound Session Credentials (DBSC) spec as shipped in Chrome 146 GA (April 2026).
**Feature flag:** none (no prototype).
**Trigger condition:** DBSC support spreads beyond Chromium-on-Windows (the second browser + a non-Windows OS), OR a concrete enterprise engagement names it.
**Graduation criteria:** a Chromium-only prototype binding the hosted-pages OP session cookie to a device-bound credential, with the documented graceful fallback (a standard session cookie) everywhere else, behind the experimental ack gate.

## The bet

- No OSS IdP ships DBSC-bound OP session cookies; a first-mover here is a real differentiator for the hosted-pages tier.
- The session layer (the opaque server-side session row + hardened cookie from issue #20) is the seam: the cookie already carries only an identifier; a DBSC arm adds the device-bound assertion at the session's establishment and refresh.
- The fallback is structural: a browser without DBSC gets the current cookie semantics, so the prototype can never brick a session.
- Google Workspace defaulting DBSC on (May 2026) is the demand-side signal.

## What must NOT happen

- Binding anything but the session cookie: DBSC on the API/token surfaces would be a different product change with its own attack surface.
