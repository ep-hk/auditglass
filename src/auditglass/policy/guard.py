"""PolicyGuard — egress mediation, default deny.

This is layer L2 of the read-only model described in ``docs/readonly-guarantee.md``.
It is explicitly *not* the primary control: that is the read-only service account
the deploying organisation issues (L1). This layer exists so that a bug in L1's
configuration, or a mistake in a connector, does not become a write.

Ordering of checks matters and is deliberate. The destination is settled before
anything about the query is considered, so an unknown host is rejected without the
query ever being examined.

The check that does the real work is :meth:`_verify_statement`. Rather than scanning
the outgoing query for dangerous keywords — a denylist, which loses — the guard
re-renders the statement from the template id and the validated parameters and
requires an exact match. A statement that was tampered with anywhere between
rendering and dispatch fails this comparison regardless of what it contains.
"""

from __future__ import annotations

from collections.abc import Callable

from ..config import PolicyConfig
from ..errors import ParamValidationError
from ..models import Decision, OutboundRequest
from .templates import RenderContext, TemplateRegistry

DenialHook = Callable[[OutboundRequest, Decision], None]

#: Methods this tool is capable of emitting at all. Anything else is rejected
#: before policy is consulted, because no template can produce it.
SUPPORTED_METHODS = frozenset({"GET", "POST"})


class PolicyGuard:
    def __init__(
        self,
        policy: PolicyConfig,
        registry: TemplateRegistry,
        context: RenderContext,
        on_denial: DenialHook | None = None,
    ) -> None:
        self._policy = policy
        self._registry = registry
        self._context = context
        self._on_denial = on_denial

    def bind_context(self, context: RenderContext) -> None:
        """Adopt the render context of the run now in progress.

        The guard must re-render against exactly the same context the run used,
        including the incident window. Verifying against a different context would
        reject every legitimate query — and, more to the point, would mean the guard
        was not actually checking what the run was doing.
        """
        self._context = context

    @property
    def context(self) -> RenderContext:
        return self._context

    # ------------------------------------------------------------------ #

    def authorize(self, request: OutboundRequest) -> Decision:
        decision = self._evaluate(request)
        if not decision.allowed and self._on_denial is not None:
            self._on_denial(request, decision)
        return decision

    def _evaluate(self, request: OutboundRequest) -> Decision:
        method = request.method.upper()
        if method not in SUPPORTED_METHODS:
            return Decision.deny(
                f"method {method} is not one this tool emits", rule="method-unsupported"
            )

        at_destination = self._endpoints_at(request)
        if not at_destination:
            return Decision.deny(
                f"{request.scheme}://{request.host}:{request.port} is not a declared "
                f"endpoint",
                rule="host-not-allowlisted",
            )

        serving = [e for e in at_destination if request.path in e.paths]
        if not serving:
            permitted = sorted({p for e in at_destination for p in e.paths})
            names = sorted(e.name for e in at_destination)
            return Decision.deny(
                f"path {request.path!r} is not permitted at "
                f"{request.scheme}://{request.host}:{request.port} "
                f"(endpoint(s) {names}); permitted paths are {permitted}",
                rule="path-not-allowlisted",
            )

        if request.backend:
            matching = [e for e in serving if e.backend == request.backend]
            if not matching:
                return Decision.deny(
                    f"backend {request.backend!r} does not match any endpoint serving "
                    f"{request.path!r}; that path is served by "
                    f"{sorted({e.backend for e in serving})}",
                    rule="backend-mismatch",
                )
            endpoint = matching[0]
        else:
            endpoint = serving[0]

        if method not in endpoint.methods:
            return Decision.deny(
                f"method {method} is not permitted on endpoint {endpoint.name!r}; "
                f"permitted methods are {sorted(endpoint.methods)}",
                rule="method-not-allowlisted",
            )

        verdict = self._verify_statement(request)
        if verdict is not None:
            return verdict

        verdict = self._scan_forbidden(request)
        if verdict is not None:
            return verdict

        return Decision.allow(rule=f"endpoint:{endpoint.name}")

    # ------------------------------------------------------------------ #

    def _endpoints_at(self, request: OutboundRequest):
        """Every declared endpoint sharing this request's destination.

        More than one is normal rather than exotic: an observability gateway commonly
        fronts Loki at ``/loki/*`` and Prometheus at ``/api/v1/*`` on one host and
        port. Matching only the first endpoint at a destination would permanently deny
        the second backend, and blame the wrong endpoint in the message while doing it.
        """
        return [
            endpoint
            for endpoint in self._policy.endpoints
            if endpoint.scheme == request.scheme
            and endpoint.host == request.host
            and endpoint.effective_port() == request.port
        ]

    def _verify_statement(self, request: OutboundRequest) -> Decision | None:
        """Re-derive the statement and require an exact match.

        A request that carries a statement must name the template it came from.
        Anything else is a statement of unknown provenance, and the whole design
        rests on that not being possible.
        """
        if not request.statement and not request.template_id:
            return None

        if request.statement and not request.template_id:
            return Decision.deny(
                "request carries a query statement but names no template; statements "
                "of unknown provenance are never dispatched",
                rule="statement-without-template",
            )

        if request.template_id not in self._registry:
            return Decision.deny(
                f"template {request.template_id!r} is not in the loaded template set",
                rule="unknown-template",
            )

        template = self._registry.get(request.template_id)
        try:
            expected = template.render(dict(request.params), self._context)
        except ParamValidationError as exc:
            return Decision.deny(
                f"parameters do not satisfy template {request.template_id!r}: {exc}",
                rule="param-validation",
            )

        if expected.statement != request.statement:
            return Decision.deny(
                "statement does not match what template "
                f"{request.template_id!r} renders for these parameters",
                rule="statement-mismatch",
            )
        if expected.path != request.path or expected.method != request.method.upper():
            return Decision.deny(
                f"route {request.method} {request.path} does not match the template's "
                f"declared route {expected.method} {expected.path}",
                rule="route-mismatch",
            )
        return None

    def _scan_forbidden(self, request: OutboundRequest) -> Decision | None:
        """Defence in depth against a badly authored template.

        This is a denylist and is understood to be incomplete. It is not what makes
        the guard sound; it exists to catch an operator mistake early and loudly.
        """
        haystacks = [request.statement or ""]
        haystacks.extend(str(v) for v in request.query_params.values())
        if request.body:
            haystacks.append(str(request.body))
        blob = " ".join(haystacks).lower()
        for needle in self._policy.forbidden_substrings:
            if needle.lower() in blob:
                return Decision.deny(
                    f"request contains forbidden construct {needle!r}",
                    rule="forbidden-substring",
                )
        return None
