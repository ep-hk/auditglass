"""The only module in this package permitted to speak HTTP.

``tests/ci/test_no_unmediated_http.py`` walks the source tree and fails the build if
any other module imports an HTTP client, a socket, or a subprocess. That test is
layer L3 of the read-only model: it makes "there is no other way out of this
process" a property the build checks rather than a claim in a document.

Two controls here are easy to miss and both matter:

* **Redirects are never followed.** A 302 from an allowlisted host to somewhere else
  would otherwise carry credentials past a guard that already said yes.
* **Credentials are attached here and nowhere else**, read from the environment at
  call time, so they cannot reach a log line, an audit record, or a report by
  travelling inside a request object.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any

import httpx

from ..errors import PolicyViolation, ProviderError
from ..models import OutboundRequest
from .guard import PolicyGuard


class RateLimiter:
    """Minimum-interval limiter.

    During an incident the backends are often already degraded — frequently because
    of the incident. A diagnosis tool that floods them makes the outage worse.
    """

    def __init__(self, per_second: float) -> None:
        self._interval = 1.0 / per_second if per_second > 0 else 0.0
        self._last = 0.0

    def wait(self) -> None:
        if self._interval <= 0:
            return
        elapsed = time.monotonic() - self._last
        if elapsed < self._interval:
            time.sleep(self._interval - elapsed)
        self._last = time.monotonic()


@dataclass
class HTTPResponse:
    status_code: int
    json_body: Any
    elapsed_ms: int


class ConstrainedHTTPClient:
    def __init__(
        self,
        guard: PolicyGuard,
        timeout_seconds: float = 20.0,
        rate_limit_per_second: float = 4.0,
        credential_env: dict[str, str] | None = None,
    ) -> None:
        self._guard = guard
        self._timeout = timeout_seconds
        self._limiter = RateLimiter(rate_limit_per_second)
        # Maps host -> environment variable holding a bearer token.
        self._credential_env = credential_env or {}
        self._client = httpx.Client(
            timeout=timeout_seconds,
            follow_redirects=False,
            headers={"User-Agent": "auditglass/0.1 (+https://github.com/ep-hk/auditglass)"},
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> ConstrainedHTTPClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ #

    def send(self, request: OutboundRequest) -> HTTPResponse:
        decision = self._guard.authorize(request)
        if not decision.allowed:
            raise PolicyViolation(decision.reason, decision.rule)

        headers = self._auth_headers(request.host)
        self._limiter.wait()
        started = time.monotonic()
        try:
            if request.method.upper() == "GET":
                response = self._client.get(
                    request.url, params=request.query_params, headers=headers
                )
            else:
                response = self._client.post(
                    request.url,
                    params=request.query_params,
                    json=request.body,
                    headers=headers,
                )
        except httpx.TimeoutException as exc:
            raise ProviderError(f"timed out after {self._timeout:.0f}s") from exc
        except httpx.HTTPError as exc:
            raise ProviderError(f"transport error: {type(exc).__name__}") from exc

        elapsed_ms = int((time.monotonic() - started) * 1000)

        if response.is_redirect:
            raise ProviderError(
                f"backend returned a redirect ({response.status_code}); redirects are "
                f"never followed because the destination has not been through policy"
            )
        if response.status_code >= 400:
            raise ProviderError(f"backend returned HTTP {response.status_code}")

        try:
            body = response.json()
        except ValueError as exc:
            raise ProviderError("backend response was not JSON") from exc

        return HTTPResponse(response.status_code, body, elapsed_ms)

    # ------------------------------------------------------------------ #

    def _auth_headers(self, host: str) -> dict[str, str]:
        env_name = self._credential_env.get(host)
        if not env_name:
            return {}
        token = os.environ.get(env_name)
        if not token:
            raise ProviderError(
                f"credential for {host} is configured to come from ${env_name}, "
                f"which is not set"
            )
        return {"Authorization": f"Bearer {token}"}
