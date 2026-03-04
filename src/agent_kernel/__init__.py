"""agent-kernel: capability-based security kernel for AI agents.

Public API
----------

Core classes::

    from agent_kernel import Kernel, CapabilityRegistry
    from agent_kernel import Capability, Principal
    from agent_kernel import SafetyClass, SensitivityTag

Token management::

    from agent_kernel import HMACTokenProvider, CapabilityToken

Policy::

    from agent_kernel import DefaultPolicyEngine

Firewall::

    from agent_kernel import Firewall, Budgets

Handles & traces::

    from agent_kernel import HandleStore, TraceStore

Errors::

    from agent_kernel import (
        AgentKernelError,
        TokenExpired, TokenInvalid, TokenScopeError,
        PolicyDenied, DriverError, FirewallError,
        CapabilityNotFound, HandleNotFound, HandleExpired,
    )
"""

from .drivers.base import Driver, ExecutionContext
from .drivers.http import HTTPDriver
from .drivers.memory import InMemoryDriver, make_billing_driver
from .enums import SafetyClass, SensitivityTag
from .errors import (
    AgentKernelError,
    CapabilityAlreadyRegistered,
    CapabilityNotFound,
    DriverError,
    FirewallError,
    HandleExpired,
    HandleNotFound,
    PolicyDenied,
    TokenExpired,
    TokenInvalid,
    TokenScopeError,
)
from .firewall.budgets import Budgets
from .firewall.transform import Firewall
from .handles import HandleStore
from .kernel import Kernel
from .models import (
    ActionTrace,
    Capability,
    CapabilityGrant,
    CapabilityRequest,
    Frame,
    Handle,
    ImplementationRef,
    PolicyDecision,
    Principal,
    Provenance,
    RawResult,
    ResponseMode,
    RoutePlan,
)
from .policy import DefaultPolicyEngine
from .registry import CapabilityRegistry
from .router import StaticRouter
from .tokens import CapabilityToken, HMACTokenProvider
from .trace import TraceStore

__version__ = "0.1.0"

__all__ = [
    # version
    "__version__",
    # kernel
    "Kernel",
    # registry
    "CapabilityRegistry",
    # models
    "Capability",
    "CapabilityGrant",
    "CapabilityRequest",
    "CapabilityToken",
    "Frame",
    "Handle",
    "ImplementationRef",
    "PolicyDecision",
    "Principal",
    "Provenance",
    "RawResult",
    "ResponseMode",
    "RoutePlan",
    "ActionTrace",
    # enums
    "SafetyClass",
    "SensitivityTag",
    # errors
    "AgentKernelError",
    "CapabilityAlreadyRegistered",
    "CapabilityNotFound",
    "DriverError",
    "FirewallError",
    "HandleExpired",
    "HandleNotFound",
    "PolicyDenied",
    "TokenExpired",
    "TokenInvalid",
    "TokenScopeError",
    # policy
    "DefaultPolicyEngine",
    # tokens
    "HMACTokenProvider",
    # router
    "StaticRouter",
    # drivers
    "Driver",
    "ExecutionContext",
    "InMemoryDriver",
    "HTTPDriver",
    "make_billing_driver",
    # firewall
    "Firewall",
    "Budgets",
    # stores
    "HandleStore",
    "TraceStore",
]
