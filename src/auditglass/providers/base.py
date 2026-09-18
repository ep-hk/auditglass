"""Shared machinery for backend connectors.

A connector's whole job is: turn a :class:`RenderedQuery` into one outbound request,
send it through the constrained client, and normalise the response into a list of
flat records. It never constructs a query string — that has already happened in the
template engine — and it never talks to the network directly.

See ``docs/writing-a-connector.md``.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from ..config import EndpointPolicy
from ..errors import ProviderError
from ..models import OutboundRequest, RenderedQuery
from ..policy.http import ConstrainedHTTPClient
from ..policy.templates import query_params_of


def ensure_success(body: Any, backend: str) -> dict[str, Any]:
    """Validate the response envelope and return its ``data`` object.

    Both Loki and Prometheus can answer HTTP 200 with ``{"status": "error", ...}``.
    Parsing such a body would yield an empty record list — indistinguishable from
    "nothing matched". In a tool whose entire value rests on being honest about what
    it could and could not see, a failed query that reads as "no errors found" is the
    worst possible failure mode, so it is raised instead. The run loop turns it into a
    recorded evidence gap, which is what the reader should see.
    """
    if not isinstance(body, dict):
        raise ProviderError(
            f"{backend} returned {type(body).__name__}, not a JSON object"
        )
    status = body.get("status")
    # A missing status is tolerated: gateways and proxies sometimes strip the
    # envelope. A status that is present and not "success" never is.
    if status is not None and status != "success":
        detail = body.get("error") or body.get("errorType") or status
        raise ProviderError(f"{backend} returned an error response: {detail}")
    data = body.get("data")
    return data if isinstance(data, dict) else {}


def build_request(query: RenderedQuery, endpoint: EndpointPolicy) -> OutboundRequest:
    return OutboundRequest(
        method=query.method,
        scheme=endpoint.scheme,
        host=endpoint.host,
        port=endpoint.effective_port(),
        path=query.path,
        query_params=query_params_of(query),
        backend=query.backend,
        template_id=query.template_id,
        statement=query.statement,
        params=dict(query.params),
    )


class HTTPBackedProvider:
    """Base class for providers that reach a backend over HTTP."""

    backend: str = ""

    def __init__(
        self,
        client: ConstrainedHTTPClient,
        endpoint: EndpointPolicy,
        max_records: int = 5000,
    ) -> None:
        self._client = client
        self._endpoint = endpoint
        self._max_records = max_records

    def fetch(self, query: RenderedQuery) -> tuple[list[dict[str, Any]], bool]:
        response = self._client.send(build_request(query, self._endpoint))
        records = self.parse(response.json_body)
        truncated = len(records) > self._max_records
        return records[: self._max_records], truncated

    def parse(self, body: Any) -> list[dict[str, Any]]:  # pragma: no cover
        raise NotImplementedError


def endpoint_from_url(name: str, backend: str, url: str, paths: list[str], methods: list[str]):
    """Convenience for tests and for building an endpoint from a plain URL."""
    parts = urlsplit(url)
    return EndpointPolicy(
        name=name,
        backend=backend,
        scheme=parts.scheme or "https",
        host=parts.hostname or "",
        port=parts.port,
        paths=paths,
        methods=methods,
    )
