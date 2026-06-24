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
    """Raised when the policy engine rejects a capability request.

    Carries an optional ``reason_code`` attribute holding a stable
    :class:`~weaver_kernel.policy_reasons.DenialReason` value so callers can
    branch on it without matching the human-readable message:

    .. code-block:: python

        try:
            kernel.grant_capability(request, principal, justification="...")
        except PolicyDenied as exc:
            if exc.reason_code == DenialReason.MISSING_ROLE:
                ...
    """

    def __init__(self, message: str, *, reason_code: str | None = None) -> None:
        super().__init__(message)
        self.reason_code: str | None = reason_code


class PolicyConfigError(AgentKernelError):
    """Raised when a declarative policy file is malformed or unreadable."""


# ── Driver errors ─────────────────────────────────────────────────────────────


class DriverError(AgentKernelError):
    """Raised when a driver fails to execute a capability."""


# ── Firewall errors ───────────────────────────────────────────────────────────


class FirewallError(AgentKernelError):
    """Raised when the context firewall cannot transform a raw result."""


class BudgetExhausted(AgentKernelError):
    """Raised when a :class:`~weaver_kernel.firewall.budget_manager.BudgetManager` has
    no remaining cross-invocation context budget.

    Distinct from :class:`FirewallError`: this error fires *before* the
    firewall transforms data, signalling that the caller has consumed the
    entire session-level context budget. The current invocation never runs
    the driver.
    """


class BudgetConfigError(AgentKernelError):
    """Raised when a budget is constructed with invalid parameters.

    Covers the :class:`~weaver_kernel.firewall.budget_manager.BudgetManager`
    (non-positive ``total_budget``/``default_request``, or a negative
    allocate/record/release amount) and the
    :class:`~weaver_kernel.handles.HandleStore` byte budgets (non-positive
    ``max_total_bytes``/``max_entry_bytes``).

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


class HandleTooLarge(AgentKernelError):
    """Raised when a single handle payload exceeds the store's byte ceiling.

    Fires from :meth:`~weaver_kernel.handles.HandleStore.store` when a byte
    budget is configured and the estimated size of the data exceeds the binding
    per-store ceiling — ``max_entry_bytes``, or ``max_total_bytes`` (a single
    entry larger than the whole budget can never fit). The data is *not*
    retained — rejecting an over-cap payload outright (rather than silently
    truncating it) keeps handle expansion faithful to the original dataset and
    bounds resident raw data.
    """


class HandleConstraintViolation(AgentKernelError):
    """Raised when a handle expansion request violates the grant's constraints.

    Handles persist the constraints attached to the original
    :class:`~weaver_kernel.models.PolicyDecision` (e.g. ``max_rows``,
    ``allowed_fields``). :meth:`HandleStore.expand` rechecks the requested
    query against those constraints; expansions that would exceed the row
    cap, request disallowed fields, or violate scope raise this error so
    callers can branch on ``reason_code`` rather than parse the message.

    Carries the same ``reason_code`` shape as :class:`PolicyDenied` so
    metrics and UI mapping use one denial vocabulary across the kernel.
    """

    def __init__(self, message: str, *, reason_code: str | None = None) -> None:
        super().__init__(message)
        self.reason_code: str | None = reason_code


# ── Registry / namespace errors ───────────────────────────────────────────────


class NamespaceNotFound(AgentKernelError):
    """Raised when a namespace prefix is not known to the registry."""


# ── Federation errors ─────────────────────────────────────────────────────────


class FederationError(AgentKernelError):
    """Base class for federation / capability marketplace failures."""


class TrustPolicyError(FederationError):
    """Raised when a federation request violates the configured trust policy.

    Examples include an unknown trust policy name, a remote manifest from an
    untrusted endpoint, or a token that originated outside the importing
    kernel's HMAC scope.
    """


class ManifestError(FederationError):
    """Raised when a :class:`~weaver_kernel.models.CapabilityManifest` cannot be
    serialised, parsed, or imported (e.g. missing fields, invalid version,
    duplicate capability IDs).
    """


class ManifestSignatureError(FederationError):
    """Raised when a signed manifest fails HMAC verification.

    A signature mismatch indicates either tampering, a wrong shared
    secret, or a bug in the publisher's signing code. Either way the
    manifest must not be imported — the importer should reject the
    payload outright.
    """


class DiscoveryError(FederationError):
    """Raised when peer/registry discovery fails (network error, malformed
    response, or rate-limit hit).
    """
