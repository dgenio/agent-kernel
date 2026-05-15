"""Custom exception hierarchy for agent-kernel."""


class AgentKernelError(Exception):
    """Base class for all agent-kernel errors."""


# ── Token errors ──────────────────────────────────────────────────────────────


class TokenExpired(AgentKernelError):
    """Raised when a token's ``expires_at`` is in the past."""


class TokenInvalid(AgentKernelError):
    """Raised when a token's HMAC signature does not verify."""


class TokenScopeError(AgentKernelError):
    """Raised when a token is used by the wrong principal or for the wrong capability."""


class TokenRevoked(AgentKernelError):
    """Raised when a revoked token is presented for verification."""


# ── Policy errors ─────────────────────────────────────────────────────────────


class PolicyDenied(AgentKernelError):
    """Raised when the policy engine rejects a capability request."""


class PolicyConfigError(AgentKernelError):
    """Raised when a declarative policy file is malformed or unreadable."""


# ── Driver errors ─────────────────────────────────────────────────────────────


class DriverError(AgentKernelError):
    """Raised when a driver fails to execute a capability."""


# ── Firewall errors ───────────────────────────────────────────────────────────


class FirewallError(AgentKernelError):
    """Raised when the context firewall cannot transform a raw result."""


class BudgetExhausted(AgentKernelError):
    """Raised when a :class:`~agent_kernel.firewall.budgets.BudgetManager` has
    no remaining cross-invocation context budget.

    Distinct from :class:`FirewallError`: this error fires *before* the
    firewall transforms data, signalling that the caller has consumed the
    entire session-level context budget. The current invocation never runs
    the driver.
    """


class BudgetConfigError(AgentKernelError):
    """Raised when a :class:`~agent_kernel.firewall.budgets.BudgetManager` is
    constructed with invalid parameters, or asked to allocate/record/release
    a negative amount.

    Used in place of bare :class:`ValueError` so callers can catch budget
    configuration mistakes without swallowing unrelated stdlib errors.
    """


# ── Adapter errors ────────────────────────────────────────────────────────────


class AdapterParseError(AgentKernelError):
    """Raised when an LLM tool-format adapter cannot parse vendor input.

    Covers two adapter-side failure modes:

    - Malformed tool-call shapes: missing fields, non-JSON ``arguments``, wrong
      types (e.g. ``arguments`` is an int).
    - Capability-ID validation: e.g. capability IDs that contain the OpenAI
      namespace separator (``__``) cannot be round-tripped unambiguously and
      are rejected at tool-emit time.

    Callers can catch this to distinguish adapter parse / validation failures
    from kernel-side errors (:class:`PolicyDenied`, :class:`DriverError`).
    """


# ── Registry / lookup errors ──────────────────────────────────────────────────


class CapabilityAlreadyRegistered(AgentKernelError):
    """Raised when a capability with the same ID is already registered."""


class CapabilityNotFound(AgentKernelError):
    """Raised when a capability ID is not found in the registry."""


# ── Handle errors ─────────────────────────────────────────────────────────────


class HandleNotFound(AgentKernelError):
    """Raised when a handle ID is not found in the handle store."""


class HandleExpired(AgentKernelError):
    """Raised when a handle's TTL has elapsed."""
