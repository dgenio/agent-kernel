"""agent-kernel: capability-based security kernel for AI agents.

Public API
----------

Core classes::

    from weaver_kernel import Kernel, CapabilityRegistry
    from weaver_kernel import Capability, Principal
    from weaver_kernel import SafetyClass, SensitivityTag

Token management::

    from weaver_kernel import HMACTokenProvider, CapabilityToken

Policy::

    from weaver_kernel import DefaultPolicyEngine, DeclarativePolicyEngine
    from weaver_kernel import PolicyDecisionTrace, PolicyTraceStep
    from weaver_kernel import DenialReason, AllowReason

Firewall::

    from weaver_kernel import Firewall, Budgets, BudgetManager

Handles & traces::

    from weaver_kernel import HandleStore, TraceStore

LLM tool-format adapters::

    from weaver_kernel import OpenAIMiddleware, AnthropicMiddleware

Federation (capability marketplace)::

    from weaver_kernel import CapabilityManifest, CapabilityDescriptor
    from weaver_kernel import build_manifest, import_manifest, TrustPolicy

Errors::

    from weaver_kernel import (
        AgentKernelError,
        TokenExpired, TokenInvalid, TokenScopeError, TokenRevoked,
        PolicyDenied, PolicyConfigError,
        DriverError, FirewallError, AdapterParseError,
        BudgetExhausted, BudgetConfigError,
        CapabilityNotFound, CapabilityAlreadyRegistered,
        HandleNotFound, HandleExpired, HandleConstraintViolation,
        NamespaceNotFound, FederationError, ManifestError, ManifestSignatureError,
        TrustPolicyError, DiscoveryError,
    )
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

from .adapters import AnthropicMiddleware, OpenAIMiddleware
from .drivers.base import Driver, ExecutionContext
from .drivers.http import HTTPDriver
from .drivers.mcp import MCPDriver
from .drivers.memory import InMemoryDriver, make_billing_driver
from .enums import SafetyClass, SensitivityTag
from .errors import (  # noqa: I001 - keep group ordering stable
    AdapterParseError,
    AgentKernelError,
    BudgetConfigError,
    BudgetExhausted,
    CapabilityAlreadyRegistered,
    CapabilityNotFound,
    DiscoveryError,
    DriverError,
    FederationError,
    FirewallError,
    HandleConstraintViolation,
    HandleExpired,
    HandleNotFound,
    ManifestError,
    ManifestSignatureError,
    NamespaceNotFound,
    PolicyConfigError,
    PolicyDenied,
    TokenExpired,
    TokenInvalid,
    TokenRevoked,
    TokenScopeError,
    TrustPolicyError,
)
from .federation import (
    MANIFEST_VERSION,
    TrustPolicy,
    build_manifest,
    import_manifest,
    merge_sensitivity,
)
from .federation_discovery import (
    DiscoveryRateLimiter,
    discover_peers,
    serve_manifest_payload,
    sign_manifest,
    verify_manifest,
)
from .firewall.budget_manager import BudgetManager
from .firewall.budgets import Budgets
from .firewall.token_counting import TokenCounter, default_token_counter
from .firewall.transform import Firewall
from .handles import HandleStore
from .kernel import (
    Kernel,
    StreamingDriver,  # re-export for backwards-compatible imports
)
from .models import (
    ActionTrace,
    Capability,
    CapabilityDescriptor,
    CapabilityGrant,
    CapabilityManifest,
    CapabilityRequest,
    DenialExplanation,
    DryRunResult,
    FailedCondition,
    Frame,
    Handle,
    ImplementationRef,
    NamespaceMetadata,
    PolicyDecision,
    PolicyDecisionTrace,
    PolicyTraceStep,
    Principal,
    Provenance,
    RawResult,
    ResponseMode,
    RoutePlan,
    ToolHints,
    TrustLevel,
)
from .otel import OTEL_AVAILABLE, instrument_kernel
from .policy import DefaultPolicyEngine, ExplainingPolicyEngine, PolicyEngine
from .policy_dsl import DeclarativePolicyEngine, PolicyMatch, PolicyRule
from .policy_reasons import AllowReason, DenialReason
from .registry import CapabilityRegistry
from .router import StaticRouter
from .tokens import CapabilityToken, HMACTokenProvider
from .trace import TraceStore

# Single source of truth: read the version from the installed distribution
# metadata (the PyPI dist name is ``weaver-kernel``, distinct from the import
# name ``weaver_kernel``) so it never drifts from ``pyproject.toml``.
try:
    __version__ = _pkg_version("weaver-kernel")
except PackageNotFoundError:  # pragma: no cover - source tree without dist metadata
    __version__ = "0.0.0+local"

__all__ = [
    # version
    "__version__",
    # kernel
    "Kernel",
    # registry
    "CapabilityRegistry",
    # models
    "Capability",
    "CapabilityDescriptor",
    "CapabilityGrant",
    "CapabilityManifest",
    "CapabilityRequest",
    "CapabilityToken",
    "DenialExplanation",
    "DryRunResult",
    "FailedCondition",
    "Frame",
    "Handle",
    "ImplementationRef",
    "NamespaceMetadata",
    "PolicyDecision",
    "PolicyDecisionTrace",
    "PolicyTraceStep",
    "Principal",
    "Provenance",
    "RawResult",
    "ResponseMode",
    "RoutePlan",
    "ActionTrace",
    "ToolHints",
    "TrustLevel",
    # enums
    "SafetyClass",
    "SensitivityTag",
    # errors
    "AdapterParseError",
    "AgentKernelError",
    "BudgetConfigError",
    "BudgetExhausted",
    "CapabilityAlreadyRegistered",
    "CapabilityNotFound",
    "DiscoveryError",
    "DriverError",
    "FederationError",
    "FirewallError",
    "HandleConstraintViolation",
    "HandleExpired",
    "HandleNotFound",
    "ManifestError",
    "ManifestSignatureError",
    "NamespaceNotFound",
    "PolicyConfigError",
    "PolicyDenied",
    "TokenExpired",
    "TokenInvalid",
    "TokenRevoked",
    "TokenScopeError",
    "TrustPolicyError",
    # federation
    "MANIFEST_VERSION",
    "TrustPolicy",
    "build_manifest",
    "import_manifest",
    "merge_sensitivity",
    # federation discovery (issue #51)
    "DiscoveryRateLimiter",
    "discover_peers",
    "serve_manifest_payload",
    "sign_manifest",
    "verify_manifest",
    # policy
    "AllowReason",
    "DefaultPolicyEngine",
    "DeclarativePolicyEngine",
    "DenialReason",
    "ExplainingPolicyEngine",
    "PolicyEngine",
    "PolicyMatch",
    "PolicyRule",
    # tokens
    "HMACTokenProvider",
    # router
    "StaticRouter",
    # drivers
    "Driver",
    "ExecutionContext",
    "InMemoryDriver",
    "HTTPDriver",
    "MCPDriver",
    "make_billing_driver",
    # firewall
    "BudgetManager",
    "Budgets",
    "Firewall",
    "TokenCounter",
    "default_token_counter",
    # stores
    "HandleStore",
    "TraceStore",
    # adapters
    "AnthropicMiddleware",
    "OpenAIMiddleware",
    # observability
    "OTEL_AVAILABLE",
    "instrument_kernel",
    # streaming
    "StreamingDriver",
]
