# ironauth-apply changelog

All notable changes to the `ironauth-apply` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- Initial config-as-code CLI (issue #51, CLI half): the `validate`, `plan`,
  `apply`, and `drift` subcommands the `ironauth` binary dispatches into. Every
  subcommand is a THIN client over a server-side primitive; the CLI performs no
  client-side diffing or planning, so it can never drift from server behavior.
  - **validate `<document>`** reuses the snapshot validator (issue #43,
    `ironauth_store::validate_document`) on a local document and touches no
    network. It reuses the server's validator rather than reimplementing it, so
    a document the CLI accepts is exactly a document the server accepts. Exits 0
    when valid, nonzero with the violation paths and messages when invalid; a
    rejected inline secret value is never echoed (only the offending key is).
  - **plan `<document>` --target T/E** POSTs the document to the promotion PLAN
    endpoint (issue #44) and renders the SERVER-computed plan verbatim: the same
    plan id, base and result revisions, resolved references, and diff the server
    returns.
  - **apply `<document>` --target T/E** applies through the transactional
    promotion APPLY endpoint. `--dry-run` renders the same plan `plan` would and
    applies nothing (dry-run parity: same plan id and content). `--expect-revision`
    gates the apply on a reviewed plan's base revision (a CI gate): a target that
    drifted since then fails with exit code 2 and changes nothing. A re-apply of
    an unchanged target is a no-op and exits 0. An unresolved reference is a
    plan-time failure (exit nonzero); the server fails closed.
  - **drift `<document>` --target T/E** reports whether the live target matches
    the document via the plan endpoint, with CI-gate exit codes: 0 in sync, 2 on
    drift.
  - **Exit-code contract:** 0 success/in-sync/no-op/applied/valid; 1 a failure a
    gate should stop on (invalid document, unresolved reference, server or
    transport error); 2 drift; 64 a usage error.
  - **Write-only secrets.** A promotion document is secret-free by construction
    (a secret is a `${secret:NAME}` reference, never an inline value); the CLI
    never prints the source document back, never prints the operator credential
    (which redacts on `Debug`), and renders only server-returned, secret-free
    fields, so a secret-scan over its stdout and logs finds no secret value.
  - **Auth.** The management bearer credential comes from `--token` or
    `IRONAUTH_TOKEN` (the environment variable is preferred; a `--token` value is
    visible in the process table) and is never logged. The endpoint comes from
    `--api-url` or `IRONAUTH_API_URL`.
  - **HTTP.** The CLI is a client of the operator's OWN control plane, which by
    design runs on a loopback or private address, so it carries its own minimal
    HTTP/1.1 client over the same vetted hyper + tokio-rustls stack the server
    uses (no new crate enters the lock). It deliberately does NOT reuse
    `ironauth-fetch`: that crate's SSRF deny policy refuses loopback and private
    destinations by design and so cannot reach a control plane. The
    outbound-HTTP dependency is confined to this CLI-client crate (with the
    `http-audit-allow` markers `scripts/http-audit.sh` requires), keeping the
    server-wiring binary free of an HTTP-client dependency.
  - Deferred to a follow-up (owner/infra-gated, tracked separately): the Go
    Terraform provider half of issue #51 (a separate toolchain, its compose-stack
    acceptance CI, and the Terraform Registry publish) and the dogfooding work
    (shipping IronAuth's own defaults as declarative artifacts). Issue #51 stays
    OPEN.
