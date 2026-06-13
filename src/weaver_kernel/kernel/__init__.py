"""The :class:`Kernel` — the main entry point for agent-kernel.

The class lives in this package's ``__init__.py`` so existing imports
(``from weaver_kernel.kernel import Kernel``) continue to work after the
split from a single-file module into a sub-package. Heavy
implementation is delegated to sibling modules (:mod:`._invoke`,
:mod:`._dry_run`) to honour AGENTS.md's ≤ 300-line module budget.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncIterator
from typing import Any, Literal, overload

from ..drivers.base import Driver, StreamingDriver
from ..errors import AgentKernelError
from ..federation import TrustPolicy
from ..firewall.budget_manager import BudgetManager
from ..firewall.transform import Firewall
from ..handles import HandleStore
from ..models import (
    ActionTrace,
    Capability,
    CapabilityGrant,
    CapabilityManifest,
    CapabilityRequest,
    DenialExplanation,
    DryRunResult,
    Frame,
    Handle,
    Principal,
    ResponseMode,
    RoutePlan,
)
from ..policy import DefaultPolicyEngine, PolicyEngine
from ..registry import CapabilityRegistry
from ..router import Router, StaticRouter
from ..tokens import CapabilityToken, HMACTokenProvider, TokenProvider
from ..trace import TraceStore
from ._dry_run import build_dry_run_result
from ._federation import (
    perform_advertise,
    perform_discover_peers,
    perform_import_remote,
)
from ._invoke import perform_invoke
from ._stream import invoke_stream_impl

logger = logging.getLogger(__name__)


class Kernel:
    """The central orchestrator for capability-based AI agent security.

    The Kernel wires together the registry, policy engine, token provider,
    router, firewall, handle store, and trace store into a single coherent
    interface.

    Example::

        registry = CapabilityRegistry()
        registry.register(Capability(...))
        kernel = Kernel(registry)

        requests = kernel.request_capabilities("list invoices")
        grant = kernel.grant_capability(requests[0], principal, justification="...")
        frame = await kernel.invoke(
            grant.token, principal=principal, args={"operation": "list_invoices"}
        )
    """

    def __init__(
        self,
        registry: CapabilityRegistry,
        policy: PolicyEngine | None = None,
        token_provider: TokenProvider | None = None,
        router: Router | None = None,
        firewall: Firewall | None = None,
        handle_store: HandleStore | None = None,
        trace_store: TraceStore | None = None,
        budget_manager: BudgetManager | None = None,
        kernel_id: str = "agent-kernel",
    ) -> None:
        self._registry = registry
        self._policy: PolicyEngine = policy or DefaultPolicyEngine()
        self._token_provider: TokenProvider = token_provider or HMACTokenProvider()
        self._router: Router = router or StaticRouter()
        self._firewall = firewall or Firewall()
        self._handle_store = handle_store or HandleStore()
        self._trace_store = trace_store or TraceStore()
        self._budget_manager = budget_manager
        self._drivers: dict[str, Driver] = {}
        self._kernel_id = kernel_id

    @property
    def kernel_id(self) -> str:
        """Stable identifier used when this kernel advertises its capabilities."""
        return self._kernel_id

    @property
    def budget(self) -> BudgetManager | None:
        """The cross-invocation :class:`BudgetManager`, or ``None`` if none is configured."""
        return self._budget_manager

    def register_driver(self, driver: Driver) -> None:
        """Register a driver with the kernel."""
        self._drivers[driver.driver_id] = driver

    def list_capabilities(self) -> list[Capability]:
        """Return every capability registered with the kernel."""
        return self._registry.list_all()

    def request_capabilities(
        self,
        goal: str,
        *,
        context_tags: dict[str, str] | None = None,
    ) -> list[CapabilityRequest]:
        """Discover capabilities that match a natural-language goal."""
        results = self._registry.search(goal)
        logger.debug(
            "request_capabilities",
            extra={"goal": goal, "matches": len(results)},
        )
        return results

    def grant_capability(
        self,
        request: CapabilityRequest,
        principal: Principal,
        *,
        justification: str,
    ) -> CapabilityGrant:
        """Evaluate the policy and, if approved, issue a signed token."""
        capability = self._registry.get(request.capability_id)
        decision = self._policy.evaluate(
            request, capability, principal, justification=justification
        )
        audit_id = str(uuid.uuid4())
        token = self._token_provider.issue(
            capability.capability_id,
            principal.principal_id,
            constraints=decision.constraints,
            audit_id=audit_id,
        )
        logger.info(
            "grant_capability",
            extra={
                "principal_id": principal.principal_id,
                "capability_id": capability.capability_id,
                "safety_class": capability.safety_class.value,
                "audit_id": audit_id,
                "token_id": token.token_id,
            },
        )
        return CapabilityGrant(
            request=request,
            principal=principal,
            decision=decision,
            token=token,
            audit_id=audit_id,
        )

    def get_token(
        self,
        request: CapabilityRequest,
        principal: Principal,
        *,
        justification: str,
    ) -> CapabilityToken:
        """Like :meth:`grant_capability` but returns the token directly."""
        return self.grant_capability(request, principal, justification=justification).token

    @overload
    async def invoke(
        self,
        token: CapabilityToken,
        *,
        principal: Principal,
        args: dict[str, Any],
        response_mode: ResponseMode = ...,
        dry_run: Literal[True],
    ) -> DryRunResult: ...

    @overload
    async def invoke(
        self,
        token: CapabilityToken,
        *,
        principal: Principal,
        args: dict[str, Any],
        response_mode: ResponseMode = ...,
        dry_run: Literal[False] = ...,
    ) -> Frame: ...

    async def invoke(
        self,
        token: CapabilityToken,
        *,
        principal: Principal,
        args: dict[str, Any],
        response_mode: ResponseMode = "summary",
        dry_run: bool = False,
    ) -> Frame | DryRunResult:
        """Execute a capability using a signed token.

        When ``dry_run=True`` the full pipeline runs (token verification,
        capability lookup, route resolution) but the driver is never called;
        a :class:`DryRunResult` is returned instead of a :class:`Frame`.
        """
        self._token_provider.verify(
            token,
            expected_principal_id=principal.principal_id,
            expected_capability_id=token.capability_id,
        )
        capability = self._registry.get(token.capability_id)
        plan: RoutePlan = self._router.route(token.capability_id)
        if dry_run:
            return build_dry_run_result(
                token=token,
                principal=principal,
                capability=capability,
                plan=plan,
                args=args,
                response_mode=response_mode,
                budget_manager=self._budget_manager,
            )
        return await perform_invoke(
            self,
            token=token,
            principal=principal,
            args=args,
            response_mode=response_mode,
            plan=plan,
            capability=capability,
        )

    async def invoke_stream(
        self,
        token: CapabilityToken,
        *,
        principal: Principal,
        args: dict[str, Any],
        response_mode: ResponseMode = "summary",
    ) -> AsyncIterator[Frame]:
        """Stream a capability invocation.

        Yields :class:`Frame` chunks as they arrive from the driver. The last
        yielded frame has ``is_final=True``. Falls back to wrapping a
        single-shot :meth:`Driver.execute` when the resolved driver does not
        implement :class:`~weaver_kernel.drivers.base.StreamingDriver`.

        The same security pipeline applies as in :meth:`invoke`: token
        verification, admin-mode gate, budget escalation, firewall
        redaction on *every* chunk, and one :class:`ActionTrace` for the
        whole stream.

        Args:
            token: A signed token authorising the invocation.
            principal: The invoking principal (must match the token).
            args: Driver arguments.
            response_mode: Initial response mode. May be escalated mid-stream
                if a :class:`BudgetManager` is attached and runs low on budget.

        Yields:
            :class:`Frame` chunks. Consumers should look at ``is_final`` to
            detect end-of-stream.
        """
        self._token_provider.verify(
            token,
            expected_principal_id=principal.principal_id,
            expected_capability_id=token.capability_id,
        )
        capability = self._registry.get(token.capability_id)
        plan: RoutePlan = self._router.route(token.capability_id)
        async for frame in invoke_stream_impl(
            kernel=self,
            token=token,
            principal=principal,
            capability=capability,
            plan=plan,
            args=args,
            response_mode=response_mode,
        ):
            yield frame

    def expand(
        self,
        handle: Handle,
        *,
        query: dict[str, Any],
        principal: Principal | None = None,
    ) -> Frame:
        """Expand a handle with pagination, field selection, or filtering.

        Args:
            handle: The :class:`Handle` to expand.
            query: Query parameters (``offset``, ``limit``, ``fields``, ``filter``).
            principal: The principal performing the expansion. **Required**
                when the handle was created with a non-empty ``principal_id``:
                an omitted principal is treated as a mismatch and raises
                :class:`HandleConstraintViolation` (handle IDs are not bearer
                credentials). Optional for handles that were not principal-bound.

        Raises:
            HandleNotFound: If the handle is unknown.
            HandleExpired: If the handle has expired.
            HandleConstraintViolation: If the requested expansion exceeds the
                grant's persisted constraints (``max_rows``, ``allowed_fields``,
                ``scope``) or is requested by a different principal.
        """
        logger.info(
            "expand",
            extra={
                "handle_id": handle.handle_id,
                "capability_id": handle.capability_id,
                "principal_id": principal.principal_id if principal else "",
            },
        )
        return self._handle_store.expand(
            handle,
            query=query,
            principal_id=principal.principal_id if principal else "",
        )

    def explain(self, action_id: str) -> ActionTrace:
        """Retrieve the audit trace for a past invocation."""
        logger.info("explain", extra={"action_id": action_id})
        return self._trace_store.get(action_id)

    def list_traces(self) -> list[ActionTrace]:
        """Return every recorded :class:`ActionTrace` in insertion order.

        Public entry point for the trace export contract
        (:func:`~weaver_kernel.export_action_traces`): downstream tools can
        serialise the audit trail without reaching into kernel internals. See
        ``docs/trace_export.md``.
        """
        return self._trace_store.list_all()

    def explain_denial(
        self,
        request: CapabilityRequest,
        principal: Principal,
        *,
        justification: str = "",
    ) -> DenialExplanation:
        """Explain why *principal*'s *request* would be denied (or allowed).

        Delegates to the configured policy engine's ``explain()`` method.
        Rate-limit state is not reflected here.

        Raises:
            CapabilityNotFound: If the capability is not registered.
            AgentKernelError: If the configured policy engine does not
                implement ``explain()``.
        """
        capability = self._registry.get(request.capability_id)
        explain_fn = getattr(self._policy, "explain", None)
        if explain_fn is None:
            raise AgentKernelError(
                f"Policy engine {type(self._policy).__name__!r} does not implement "
                f"explain(); structured denial explanations are unavailable. "
                f"Use DefaultPolicyEngine or DeclarativePolicyEngine, or add an "
                f"explain() method to your engine."
            )
        result = explain_fn(request, capability, principal, justification=justification)
        assert isinstance(result, DenialExplanation)
        return result

    def advertise(
        self,
        *,
        endpoint: str,
        trust_level: Literal["verified", "unverified"] = "unverified",
    ) -> CapabilityManifest:
        """Build a public-facing :class:`CapabilityManifest` for this kernel.

        Internal implementation details (driver IDs, operation names,
        ``parameters_model`` Python references) are stripped — only fields
        safe to share over the wire are emitted.
        """
        return perform_advertise(self, endpoint=endpoint, trust_level=trust_level)

    async def discover_peers(
        self,
        *,
        peer_urls: list[str] | None = None,
        registry_url: str | None = None,
        secret: str | None = None,
    ) -> list[CapabilityManifest]:
        """Fetch capability manifests from peer kernels or a registry URL.

        Either *peer_urls* (direct manifest endpoints) or *registry_url*
        (URL that returns a JSON list of peer manifest URLs) must be
        provided. Pass *secret* when peers serve signed envelopes; the
        importer will *refuse* unsigned manifests when a secret is
        provided, and refuse signed manifests when one is not.

        Discovered manifests still flow through :meth:`import_remote` —
        no capability is ever registered as a side effect of discovery.
        """
        return await perform_discover_peers(
            self,
            peer_urls=peer_urls,
            registry_url=registry_url,
            secret=secret,
            rate_limiter=None,
            client=None,
        )

    def import_remote(
        self,
        manifest: CapabilityManifest,
        *,
        driver: Driver,
        trust_policy: TrustPolicy = "most_restrictive",
    ) -> list[Capability]:
        """Register a remote manifest's capabilities into this kernel.

        Imported capabilities flow through the *local* policy → token →
        firewall pipeline; the remote endpoint is never trusted to
        authorise on our behalf.

        Raises:
            FederationError: If the configured router cannot accept new routes
                (no ``add_route``), so imported capabilities could not be made
                invokable. The registry is left untouched.
            TrustPolicyError: If *trust_policy* is unknown.
            ManifestError: If the manifest is malformed.
            CapabilityAlreadyRegistered: If any imported capability ID is
                already registered locally.
        """
        return perform_import_remote(self, manifest, driver=driver, trust_policy=trust_policy)

    # Helpers in sibling modules use these short-alias properties to reach
    # internal state without circular-import gymnastics.
    @property
    def _driver_map(self) -> dict[str, Driver]:
        return self._drivers

    @property
    def _fw(self) -> Firewall:
        return self._firewall

    @property
    def _handles(self) -> HandleStore:
        return self._handle_store

    @property
    def _traces(self) -> TraceStore:
        return self._trace_store


__all__ = ["Kernel", "TrustPolicy", "StreamingDriver"]
