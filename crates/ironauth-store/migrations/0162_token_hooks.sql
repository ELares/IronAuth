-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Deployed WASM token hooks (issue #114, and issue #113's criterion 1 transport).
--
-- One row per (scope, client) holding the hook that shapes that client's tokens: the WASM
-- COMPONENT bytes, and the payload version its guest was built against.
--
-- # Why the component and not a precompiled artifact
--
-- `HookEngine::compile` produces machine code for the exact engine, wasmtime version, CPU
-- features and flags that produced it, and `load_precompiled` is `unsafe` precisely because
-- nothing checks that. A precompiled artifact in a shared database is therefore a portability
-- hazard with a memory-safety failure mode: a replica on a different CPU, or one wasmtime
-- version ahead, deserializes machine code built for something else.
--
-- So the durable form is the PORTABLE one and each process compiles what it loads. Compiling is
-- ~33 ms, which is not something to pay per login, so the dispatch holds the loaded component in
-- a per-process cache keyed on (scope, client, component digest). That is what "AOT
-- precompilation at deploy time" amounts to when the deployment is more than one machine: the
-- cost is paid once per process per artifact, not once per issuance.
--
-- # Why the bytes and not a URL
--
-- A hook runs inside the token mint. Fetching it at issuance would put a network call on the
-- login path, and fetching it at deploy time from a URL that can change afterwards means the
-- thing that ran is not the thing that was reviewed. The bytes are the artifact.
CREATE TABLE token_hooks (
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    -- The OAuth client whose tokens this hook shapes. Not a foreign key to `clients`, and the
    -- reason is NOT the one `claims_mappings` gives -- no config snapshot carries this table, so
    -- the import-ordering argument does not apply here and citing it would be borrowing a reason
    -- that is not this table's.
    --
    -- The reason is that a hook is deployed against a client id an operator names, and the
    -- window between deploying a hook and creating the client it shapes is one an operator may
    -- legitimately want in either order. The hook is inert until a client of that id issues a
    -- token, so an early deploy costs nothing and a foreign key would only force an ordering.
    client_id       text        NOT NULL,
    -- The WASM component, as bytes.
    component       bytea       NOT NULL,
    -- The payload version the guest was built against (issue #113 criterion 6). Stored rather
    -- than inferred: a hook compiled against version 1 and invoked with a version 2 payload
    -- reads fields that moved, and the only way to refuse that is to know what it expected.
    payload_version integer     NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, environment_id, client_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),

    CONSTRAINT token_hooks_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT token_hooks_client_nonempty
        CHECK (client_id <> ''),
    -- A BOUND ON THE BYTES, in the database rather than only in the admin path.
    --
    -- Eight megabytes. A claim-shaping component is tens of kilobytes; the shipped fixtures are
    -- under a hundred. The bound is here because this column is read on the ISSUANCE path: an
    -- unbounded one is an unbounded read on every login for that client, and a row nobody can
    -- load is a client nobody can issue a token for.
    --
    -- Non-empty as well as bounded, because zero bytes is not a component and the failure it
    -- produces is a compile error at issuance rather than at the write that caused it.
    CONSTRAINT token_hooks_component_bounded
        CHECK (octet_length(component) > 0 AND octet_length(component) <= 8388608),
    -- The payload versions this server knows. A row naming any other version is one no
    -- invocation could honour, so it is refused at the write rather than discovered at a login.
    CONSTRAINT token_hooks_payload_version_known
        CHECK (payload_version = 1)
);

ALTER TABLE token_hooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE token_hooks FORCE ROW LEVEL SECURITY;

CREATE POLICY token_hooks_scope ON token_hooks
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The CONTROL plane owns the lifecycle: deploying a hook is deploying CODE that runs inside the
-- token mint, which is the most privileged thing an operator can install here.
--
-- No DELETE yet, for the reason 0159 gave and 0161 then satisfied: the operation does not exist
-- in this change, and a privilege held by nobody is one an attacker inherits for free. It
-- arrives with the admin surface that removes a hook.
GRANT SELECT, INSERT, UPDATE ON token_hooks TO ironauth_control;

-- And the DATA plane reads it, because the issuance path is what runs the hook. SELECT and
-- nothing more: the plane that mints tokens must not be able to change the code that shapes
-- them. That is the same split `claims_mappings` draws one migration earlier, and here it is
-- the difference between a data-plane compromise reading a hook and one INSTALLING one.
GRANT SELECT ON token_hooks TO ironauth_app;
