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


# ── Policy errors ─────────────────────────────────────────────────────────────


class PolicyDenied(AgentKernelError):
    """Raised when the policy engine rejects a capability request."""


# ── Driver errors ─────────────────────────────────────────────────────────────


class DriverError(AgentKernelError):
    """Raised when a driver fails to execute a capability."""


# ── Firewall errors ───────────────────────────────────────────────────────────


class FirewallError(AgentKernelError):
    """Raised when the context firewall cannot transform a raw result."""


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
