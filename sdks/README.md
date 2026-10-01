# Generated management clients

The Go and Python clients are generated from
[`docs/openapi/management.json`](../docs/openapi/management.json). Update
`scripts/gen-management-sdks.py` and regenerate with
`python3 scripts/gen-management-sdks.py`; do not edit generated clients.

## Idempotent operations

For an operation requiring `Idempotency-Key`, make a client copy with your
operation's key before calling the existing generated method:

```go
client := management.New(managementURL, operatorToken)
operation := client.WithIdempotencyKey(savedOperationKey)
response, err := operation.TriggerBackup(tenantID, environmentID, nil)
```

```python
client = Client(management_url, operator_token)
operation = client.with_idempotency_key(saved_operation_key)
status, body = operation.trigger_backup(tenant_id, environment_id)
```

Retain the key for the logical operation. When retrying after an uncertain
response, reuse that key with the same endpoint and input. Choose a different
key for a new operation. The copy sends the supplied key on every request;
the SDK does not generate keys or automatically retry. These builders leave
the original client unchanged. An empty key omits the header, as the original
client does, and endpoints requiring it will reject the request.

Go copies preserve the configured HTTP client. Both clients retain their
existing raw response behavior: Go returns `*http.Response` for HTTP errors,
and Python returns `(status, body)` for HTTP errors. Transport failures remain
errors. A backup `202` acknowledges a queued request, not a completed backup.

Run the offline request-capture regressions with:

```sh
(cd sdks/go && go test ./...)
python3 -B -m unittest discover -s sdks/python/tests
python3 scripts/gen-management-sdks.py --check
```

Release notes: [Go](go/CHANGELOG.md), [Python](python/CHANGELOG.md).
