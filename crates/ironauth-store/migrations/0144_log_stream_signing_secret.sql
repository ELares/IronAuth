-- The per-stream signing secret for the signed security-event stream (issue #110
-- criterion 5).
--
-- # Why a second secret name rather than reusing the credential
--
-- `credential_secret_name` authenticates IronAuth TO the sink: it is the Splunk HEC
-- token, the Datadog API key, the AWS secret. `signing_secret_name` is the opposite
-- direction -- it lets a CONSUMER establish that a batch came from this deployment
-- and arrived in order.
--
-- Reusing one secret for both would mean every party that can receive a batch also
-- holds the key that proves batches are genuine, so a compromised forwarder could
-- mint batches the SIEM behind it would verify. Separating them means the sink
-- credential can be rotated on the sink's schedule and the signing secret on the
-- consumer's, which are rarely the same schedule and are never the same threat.
--
-- # Never the value
--
-- As with `credential_secret_name`, this column NAMES an environment-scoped secret
-- (issue #45) and the shipper resolves it at delivery time. The comment at the head
-- of 0137 applies unchanged: the surest way to guarantee this table never leaks a
-- credential through a config read, an export, or a log is for it never to hold one.
--
-- # Nullable, deliberately
--
-- A stream with no signing secret ships UNSIGNED, exactly as every stream does today.
-- Making it NOT NULL would break every existing stream on deploy, and defaulting it to
-- a generated value would silently start signing with a key no consumer has -- which a
-- consumer would experience as every batch failing verification, the single worst
-- failure mode this feature has.

ALTER TABLE log_streams
    ADD COLUMN signing_secret_name text;

-- The app role SHIPS, so it reads the name in order to resolve the secret. It must not
-- be able to change which key its batches are signed with: that is a control-plane act,
-- and an app role that could rewrite it could sign with a key it chose.
GRANT SELECT (signing_secret_name) ON log_streams TO ironauth_app;
