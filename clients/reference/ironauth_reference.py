#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""A from-scratch reference client for the IronAuth management API (issue #122, criterion 2).

Criterion 2 asks that "a third-party SDK (or a from-scratch reference client written without
reading official SDK source) passes the published conformance suite against the emulator".

This is that client, and the parenthetical is a constraint on HOW it may be written, not a
formality. It was built from two published artifacts and nothing else:

  * `docs/openapi/management.json`, the published spec;
  * `docs/SDK-CONTRACT.md`, the published contract.

`sdks/go` and `sdks/python` were deliberately not opened while writing it. That is the whole
value of the exercise: a client derived from the generated SDKs would prove those SDKs are
self-consistent, which is not in question. What IS in question is whether the PUBLISHED
artifacts are sufficient to build a working client from -- and the only way to find out is to
try to build one using nothing else.

What that turned up is recorded in the conformance suite beside each assertion it forced.

This client is deliberately small. It is not a competitor to the generated SDKs and should
never grow into one: it implements the cross-cutting mechanics an SDK must get right
(authorization, the error envelope, idempotency, pagination) and drives operations generically
off the spec rather than exposing 162 hand-written methods.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any


class ApiError(Exception):
    """A non-2xx answer, decoded through the documented error envelope.

    The status is kept alongside the decoded body because the two carry different
    information: the status is the protocol's answer and the `error` code is the
    application's, and a client that collapses them cannot tell "the server refused this
    request" from "the server could not be reached".
    """

    def __init__(self, status: int, code: str | None, message: str | None, raw: bytes) -> None:
        super().__init__(f"{status} {code}: {message}")
        self.status = status
        self.code = code
        self.message = message
        self.raw = raw


@dataclass
class Response:
    """One decoded answer."""

    status: int
    headers: dict[str, str]
    body: Any


@dataclass
class ReferenceClient:
    """A minimal management-API client.

    `base_url` is the MANAGEMENT plane's origin, which is a different listener from the OIDC
    plane. Discovering that they are separate was the first thing the spec alone did not tell
    me: the spec describes paths, not which of the server's two listeners serves them.
    """

    base_url: str
    token: str
    timeout_secs: float = 20.0
    #: Every request made, for tests that assert on the wire rather than the return value.
    sent: list[tuple[str, str]] = field(default_factory=list)

    def request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        query: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        token: str | None = ...,  # type: ignore[assignment]
    ) -> Response:
        """One request, with the bearer credential the spec's `bearer` security scheme names.

        `token` defaults to the client's own; pass `None` to send NO credential (the suite
        needs that to prove the API refuses an unauthenticated call) or a string to send a
        different one. A sentinel default rather than `None` because "send nothing" and "use
        mine" are both meaningful and a plain `None` default could not express both.
        """
        url = self.base_url.rstrip("/") + path
        if query:
            # Skip absent values rather than sending `?limit=None`, which the server would
            # read as a malformed integer rather than an omitted parameter.
            pairs = {k: v for k, v in query.items() if v is not None}
            if pairs:
                url = f"{url}?{urllib.parse.urlencode(pairs)}"

        data = None
        headers = {"accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode()
            headers["content-type"] = "application/json"

        effective = self.token if token is ... else token
        if effective is not None:
            headers["authorization"] = f"Bearer {effective}"
        if idempotency_key is not None:
            headers["idempotency-key"] = idempotency_key

        self.sent.append((method, path))
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_secs) as answer:
                return Response(
                    status=answer.status,
                    headers={k.lower(): v for k, v in answer.headers.items()},
                    body=_decode(answer.read()),
                )
        except urllib.error.HTTPError as error:
            raw = error.read()
            decoded = _decode(raw)
            code = decoded.get("error") if isinstance(decoded, dict) else None
            message = decoded.get("message") if isinstance(decoded, dict) else None
            raise ApiError(error.code, code, message, raw) from None

    # --- The handful of typed helpers the suite drives ----------------------------------

    def list_operators(self) -> Response:
        return self.request("GET", "/v1/operators")

    def list_tenants(self, *, limit: int | None = None, cursor: str | None = None) -> Response:
        return self.request("GET", "/v1/tenants", query={"limit": limit, "cursor": cursor})

    def create_tenant(self, display_name: str, *, idempotency_key: str) -> Response:
        """Create a tenant.

        `Idempotency-Key` is REQUIRED by the spec on this operation, so it is a required
        argument here rather than an option. A client that made it optional would compile and
        then fail at runtime on every create, which is a worse place to learn it.
        """
        return self.request(
            "POST",
            "/v1/tenants",
            body={"display_name": display_name},
            idempotency_key=idempotency_key,
        )

    def get_tenant(self, tenant_id: str) -> Response:
        return self.request("GET", f"/v1/tenants/{urllib.parse.quote(tenant_id, safe='')}")


def _decode(raw: bytes) -> Any:
    """Decode a body, tolerating an empty one.

    An empty body is not an error: several operations answer 204. Returning `None` for it
    keeps the caller from having to distinguish "no body" from "unparseable body", which the
    exception path already covers.
    """
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw.decode("utf-8", "replace")
