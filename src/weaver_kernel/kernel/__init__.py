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
from collections.abc import AsyncIterator, Callable
from typing import Any, Literal, overload

from ..drivers.base import Driver, StreamingDriver
from ..enums import SafetyClass
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
from ..rate_limit import RateLimiter
from ..registry import CapabilityRegistry
from ..router import Router, StaticRouter
from ..stats import KernelStats, StatsSnapshot
from ..stores import TraceStoreProtocol
from ..tokens import CapabilityToken, HMACTokenProvider, TokenProvider
from ..trace import TraceStore
from ..trace_query import TraceQuery
from ._audit import record_expansion_trace
from ._constraints import run_pre_invoke_checks, validate_invoke_rate_limits
from ._dry_run import build_dry_run_result
from ._federation import (
    perform_advertise,
    perform_discover_peers,
    perform_import_remote,
)
from ._grant import perform_grant
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
        trace_store: TraceStoreProtocol | None = None,
        budget_manager: BudgetManager | None = None,
        kernel_id: str = "agent-kernel",
        invoke_rate_limits: dict[SafetyClass, tuple[int, float]] | None = None,
        invoke_rate_clock: Callable[[], float] | None = None,
    ) -> None:
        # invoke_rate_limits (#170): optional invoke-time limits, default off.
        validate_invoke_rate_limits(invoke_rate_limits)
        self._registry = registry
        self._policy: PolicyEngine = policy or DefaultPolicyEngine()
        self._token_provider: TokenProvider = token_provider or HMACTokenProvider()
        self._router: Router = router or StaticRouter()
        self._firewall = firewall or Firewall()
        self._handle_store = handle_store or HandleStore()
        self._trace_store: TraceStoreProtocol = trace_store or TraceStore()
        self._budget_manager = budget_manager
        self._drivers: dict[str, Driver] = {}
        self._kernel_id = kernel_id
        self._stats = KernelStats()
        self._invoke_rate_limits: dict[SafetyClass, tuple[int, float]] = invoke_rate_limits or {}
        self._invoke_limiter = RateLimiter(clock=invoke_rate_clock)

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
        ttl_s: int | None = None,
    ) -> CapabilityGrant:
        """Evaluate the policy and, if approved, issue a signed token.

        On a :class:`~weaver_kernel.PolicyDenied` rejection, a ``"deny"`` audit
        record (carrying the stable reason code) is written to the trace store
        (best-effort) before the exception propagates, so the audit trail answers
        "who was refused what, and why" (#175). A trace-store write failure is
        logged but never masks the denial. Denials are also counted in
        :attr:`stats`.

        Args:
            request: The capability request being granted.
            principal: The principal the grant is issued to.
            justification: Free-text justification forwarded to the policy engine.
            ttl_s: Optional per-grant token time-to-live in seconds (#203).
                ``None`` uses the token provider's default. A non-positive value,
                or one exceeding the policy's ``max_ttl_s``, is denied (never
                silently clamped).
        """
        return perform_grant(self, request, principal, justification=justification, ttl_s=ttl_s)

    def get_token(
        self,
        request: CapabilityRequest,
        principal: Principal,
        *,
        justification: str,
        ttl_s: int | None = None,
    ) -> CapabilityToken:
        """Like :meth:`grant_capability` but returns the token directly.

        Args:
            request: The capability request being granted.
            principal: The principal the grant is issued to.
            justification: Free-text justification forwarded to the policy engine.
            ttl_s: Optional per-grant token time-to-live in seconds (#203).
        """
        return self.grant_capability(
            request, principal, justification=justification, ttl_s=ttl_s
        ).token

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
        # Invoke-time enforcement (#183 arg constraints, #170 rate limits).
        run_pre_invoke_checks(
            self,
            token=token,
            capability=capability,
            principal=principal,
            args=args,
            response_mode=response_mode,
            dry_run=dry_run,
        )
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
        # Same invoke-time enforcement as the single-shot path (#183, #170).
        run_pre_invoke_checks(
            self,
            token=token,
            capability=capability,
            principal=principal,
            args=args,
            response_mode=response_mode,
            dry_run=False,
        )
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
        principal_id = principal.principal_id if principal else ""
        action_id = str(uuid.uuid4())
        logger.info(
            "expand",
            extra={
                "handle_id": handle.handle_id,
                "capability_id": handle.capability_id,
                "principal_id": principal_id,
                "action_id": action_id,
            },
        )
        frame = self._handle_store.expand(
            handle,
            query=query,
            action_id=action_id,
            principal_id=principal_id,
            max_depth=self._firewall.budgets.max_depth,
        )
        # A successful expansion is an authorized data-access event — record it
        # in the audit trail (I-02) and count it (#175, #179). Unlike the
        # best-effort denial trace (a denial is already authoritative and fails
        # closed), this record is *not* wrapped: an audit-write failure here
        # propagates so a served expansion is never left unaudited (I-02).
        record_expansion_trace(
            action_id=action_id,
            capability_id=handle.capability_id,
            principal_id=principal_id,
            handle_id=handle.handle_id,
            query=query,
            frame=frame,
            trace_store=self._trace_store,
        )
        self._stats.on_expansion()
        return frame

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

    def query_traces(self, query: TraceQuery) -> list[ActionTrace]:
        """Return audit records matching *query*, ordered and paginated (#177).

        Operator-facing entry point over the configured trace store's
        :meth:`~weaver_kernel.stores.TraceStoreProtocol.query`. Answers
        questions like "what did principal X do in the last hour?" or "which
        capabilities were denied today?" without iterating store internals.
        """
        return self._trace_store.query(query)

    @property
    def stats(self) -> StatsSnapshot:
        """An immutable snapshot of the kernel's aggregate counters (#179).

        Cheap operational telemetry (grants, denials by reason, invocations,
        fallback activations, redaction events, budget downgrades, handle
        stores/expansions) that needs no trace export and no optional extra.
        """
        return self._stats.snapshot()

    def reset_stats(self) -> None:
        """Zero every counter returned by :attr:`stats`."""
        self._stats.reset()

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
    def _traces(self) -> TraceStoreProtocol:
        return self._trace_store


__all__ = ["Kernel", "TrustPolicy", "StreamingDriver"]
