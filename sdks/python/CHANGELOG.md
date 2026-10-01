# Python management SDK changelog

## Unreleased

- Add `with_idempotency_key` to copy a client with a caller-supplied operation key.
  Generated backup requests can now send the required header and reuse the same
  key on explicit retries without changing the original client. Existing
  generated method signatures and raw response handling are unchanged.
