# SPDX-License-Identifier: MIT OR Apache-2.0
"""Capture generated requests at the standard-library transport boundary, offline."""

import io
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ironauth_management.client_gen import Client


class Response(io.BytesIO):
    def __init__(self, status, body):
        super().__init__(body)
        self.status = status


class ClientTests(unittest.TestCase):
    def test_backup_key_survives_explicit_retries_and_http_failures(self):
        statuses = [503, 202, 422, 401]
        bodies = [b'{"error":"temporarily_unavailable"}', b'{"request_id":"saved"}',
                  b'{"error":"idempotency_key_conflict"}', b'{"error":"unauthorized"}']
        key = "Backup-Operation.A_17:retry"
        calls = []

        def capture(request):
            index = len(calls)
            calls.append(request)
            self.assertEqual(request.method, "POST")
            self.assertEqual(request.full_url, "https://management.example/v1/tenants/tenant/environments/environment/backups")
            self.assertIsNone(request.data)
            self.assertEqual(request.get_header("Idempotency-key"), key)
            self.assertEqual(request.get_header("Authorization"), "Bearer operator-token")
            if statuses[index] >= 400:
                raise urllib.error.HTTPError(request.full_url, statuses[index], "error", {}, io.BytesIO(bodies[index]))
            return Response(statuses[index], bodies[index])

        operation = Client("https://management.example/", "operator-token").with_idempotency_key(key)
        with patch("urllib.request.urlopen", side_effect=capture):
            for index, expected in enumerate(zip(statuses, bodies)):
                self.assertEqual(operation.trigger_backup("tenant", "environment"), expected)
                self.assertEqual(len(calls), index + 1, "no automatic retry")

    def test_keyed_clients_are_independent_and_original_unchanged(self):
        client = Client("https://management.example", "operator-token")
        original = vars(client).copy()
        first = client.with_idempotency_key("first")
        second = first.with_idempotency_key("second")
        cleared = first.with_idempotency_key("")
        other = Client(client.base_url, client.token)
        other_operation = other.with_idempotency_key("other")
        keys = []

        def capture(request):
            keys.append(request.get_header("Idempotency-key"))
            return Response(202, b"accepted")

        with patch("urllib.request.urlopen", side_effect=capture):
            for operation in [first, second, client, other_operation, first, cleared, second, other]:
                self.assertEqual(operation.trigger_backup("tenant", "environment"), (202, b"accepted"))
        self.assertEqual(keys, ["first", "second", None, "other", "first", None, "second", None])
        self.assertEqual(vars(client), original)
        self.assertIsNot(first, client)
        self.assertIsNot(first, second)

    def test_transport_error_is_preserved_without_automatic_retry(self):
        failure = urllib.error.URLError("connection interrupted")
        calls = []

        def capture(request):
            calls.append(request)
            self.assertEqual(request.get_header("Idempotency-key"), "persisted-operation-key")
            raise failure

        operation = Client("https://management.example", "operator-token").with_idempotency_key("persisted-operation-key")
        with patch("urllib.request.urlopen", side_effect=capture):
            for count in [1, 2]:
                with self.assertRaises(urllib.error.URLError) as raised:
                    operation.trigger_backup("tenant", "environment")
                self.assertIs(raised.exception, failure)
                self.assertEqual(len(calls), count)


if __name__ == "__main__":
    unittest.main()
