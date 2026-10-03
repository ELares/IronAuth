# Python management SDK changelog

## Unreleased

- Generate recipient-index preview and bounded preparation methods from the public
  management contract (issue #1475). Preparation uses an explicit idempotency key.

- Add `with_idempotency_key` to copy a client with a caller-supplied operation key.
  Generated backup requests can now send the required header and reuse the same
  key on explicit retries without changing the original client. Existing
  generated method signatures and raw response handling are unchanged.
