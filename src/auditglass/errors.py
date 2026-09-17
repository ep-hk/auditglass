"""Exception hierarchy.

Errors are split by who needs to act on them. ``ConfigError`` and ``TemplateError``
are operator problems and carry a config locator. ``PolicyViolation`` and
``RedactionFailure`` are security-relevant and always reach the audit trail.
"""

from __future__ import annotations


class AuditglassError(Exception):
    """Base class for every error this package raises."""


class ConfigError(AuditglassError):
    """Configuration is invalid or internally inconsistent."""

    def __init__(self, message: str, locator: str = "") -> None:
        self.locator = locator
        super().__init__(f"{message} (at: {locator})" if locator else message)


class TemplateError(ConfigError):
    """A query template is malformed."""


class ParamValidationError(AuditglassError):
    """A planner supplied parameters a template will not accept.

    This is the expected outcome when injected content attempts to widen scope,
    so it is a normal control-flow event, not a crash.
    """


class PolicyViolation(AuditglassError):
    """PolicyGuard refused an outbound request. Always audited."""

    def __init__(self, reason: str, rule: str = "default-deny") -> None:
        self.reason = reason
        self.rule = rule
        super().__init__(f"denied by {rule}: {reason}")


class RedactionFailure(AuditglassError):
    """Redaction could not complete. The run aborts rather than degrading."""


class BudgetExhausted(AuditglassError):
    """A configured budget ceiling was reached."""


class ProviderError(AuditglassError):
    """A backend failed to answer. Recorded as an evidence gap, not fatal."""


class ReasonerError(AuditglassError):
    """The reasoner failed or returned output that did not satisfy the schema."""
