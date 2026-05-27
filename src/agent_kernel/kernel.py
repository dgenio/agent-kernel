"""The Kernel: the main entry point for agent-kernel."""

from __future__ import annotations

import datetime
import logging
import uuid
from typing import Any, Literal, overload

from .drivers.base import Driver, ExecutionContext
from .enums import SafetyClass
from .errors import AgentKernelError, DriverError, FederationError
from .federation import TrustPolicy, build_manifest, import_manifest
from .firewall.budget_manager import BudgetManager
from .firewall.transform import Firewall
from .handles import HandleStore
from .models import (
    ActionTrace,
    Capability,
    CapabilityGrant,
    CapabilityManifest,
    CapabilityRequest,
    DenialExplanation,
    DryRunResult,
    Frame,
    Handle,
    PolicyDecision,
    PolicyDecisionTrace,
    PolicyTraceStep,
    Principal,
    ResponseMode,
    RoutePlan,
)
from .policy import DefaultPolicyEngine, PolicyEngine
from .policy_reasons import AllowReason
from .registry import CapabilityRegistry
from .router import Router, StaticRouter
from .tokens import CapabilityToken, HMACTokenProvider, TokenProvider
from .trace import TraceStore

logger = logging.getLogger(__name__)


_MEMORY_CAPABILITY_PREFIX = "memory."
_MEMORY_SENSITIVE_ARG_KEYS: frozenset[str] = frozenset(
    {"payload", "content", "value", "memory", "text", "body"}
)


def _redact_args_for_trace(capability_id: str, args: dict[str, Any]) -> dict[str, Any]:
    """Strip raw memory payloads from :class:`ActionTrace.args`.

    Memory capabilities (``capability_id`` starting with ``"memory."``) may
    carry durable text the principal is committing to or fetching from
    long-term memory. Tracing the raw payload would defeat the I-01 boundary
    that the :class:`Firewall` enforces for outputs — so we apply an
    equivalent input-side redaction at trace-record time.

    The resulting dict preserves keys (so audit can confirm a payload was
    provided) and replaces sensitive values with ``"[REDACTED]"``. Non-memory
    capabilities are returned unchanged.
    """
    if not capability_id.startswith(_MEMORY_CAPABILITY_PREFIX):
        return args
    redacted: dict[str, Any] = {}
    for k, v in args.items():
        if k.lower() in _MEMORY_SENSITIVE_ARG_KEYS:
            redacted[k] = "[REDACTED]"
        else:
            redacted[k] = v
    return redacted


def _frame_payload(frame: Frame) -> Any:
    """Return the LLM-facing payload from a :class:`Frame` for token counting.

    Only the data the LLM actually sees is counted — facts, table rows,
    or raw data. Provenance metadata, action IDs, and handle IDs are
    skipped because they are kernel bookkeeping rather than context.
    """
    if frame.response_mode == "raw":
        return frame.raw_data
    if frame.response_mode == "table":
        return frame.table_preview
    if frame.response_mode == "handle_only":
        return None
    return frame.facts


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
        frame = await kernel.invoke(grant.token, principal=principal, args={"operation": "list_invoices"})
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
        """Stable identifier used when this kernel advertises its capabilities.

        Defaults to ``"agent-kernel"`` — override at construction time when
        running multiple kernels in the same process or across hosts so that
        manifests carry a meaningful publisher identity.
        """
        return self._kernel_id

    # ── Budget accessor ────────────────────────────────────────────────────────

    @property
    def budget(self) -> BudgetManager | None:
        """The cross-invocation :class:`BudgetManager`, or ``None`` if none is configured."""
        return self._budget_manager

    # ── Driver registration ────────────────────────────────────────────────────

    def register_driver(self, driver: Driver) -> None:
        """Register a driver with the kernel.

        Args:
            driver: Any object implementing the :class:`~agent_kernel.drivers.base.Driver` protocol.
        """
        self._drivers[driver.driver_id] = driver

    # ── Public API ─────────────────────────────────────────────────────────────

    def list_capabilities(self) -> list[Capability]:
        """Return every capability registered with the kernel.

        Convenience accessor used by LLM adapters that need to enumerate the
        full registry (e.g. ``OpenAIMiddleware.get_tools()``) without reaching
        into private state. Capabilities are returned in registration order.
        """
        return self._registry.list_all()

    def request_capabilities(
        self,
        goal: str,
        *,
        context_tags: dict[str, str] | None = None,
    ) -> list[CapabilityRequest]:
        """Discover capabilities that match a natural-language goal.

        Args:
            goal: Free-text description of the agent's intent.
            context_tags: Optional metadata to narrow the search (currently unused).

        Returns:
            An ordered list of :class:`CapabilityRequest` objects (best match first).
        """
        results = self._registry.search(goal)
        logger.debug(
            "request_capabilities",
            extra={
                "goal": goal,
                "matches": len(results),
            },
        )
        return results

    def grant_capability(
        self,
        request: CapabilityRequest,
        principal: Principal,
        *,
        justification: str,
    ) -> CapabilityGrant:
        """Evaluate the policy and, if approved, issue a signed token.

        Args:
            request: The capability request to evaluate.
            principal: The principal requesting access.
            justification: Free-text justification for the request.

        Returns:
            A :class:`CapabilityGrant` containing the signed token.

        Raises:
            PolicyDenied: If the policy engine rejects the request.
            CapabilityNotFound: If the requested capability is not registered.
        """
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
        """Like :meth:`grant_capability` but returns the token directly.

        Convenience wrapper for callers that don't need the full
        :class:`CapabilityGrant`.  Delegates entirely to
        :meth:`grant_capability`; see its docstring for parameter and
        exception details.
        """
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
        """Execute a capability using a signed token and return a Frame.

        When ``dry_run=True`` the full pipeline runs (token verification,
        capability lookup, route resolution) but the driver is never called.
        A :class:`DryRunResult` is returned instead of a :class:`Frame`.

        Args:
            token: A signed :class:`CapabilityToken` authorising the invocation.
            principal: The principal invoking the capability (must match token).
            args: Arguments passed to the driver.
            response_mode: How to present the result (``summary``, ``table``,
                ``handle_only``, or ``raw``).
            dry_run: When ``True``, skip driver execution and return a
                :class:`DryRunResult` describing what would happen.

        Returns:
            A bounded :class:`Frame`, or :class:`DryRunResult` when
            ``dry_run=True``.

        Raises:
            TokenRevoked: If the token has been revoked.
            TokenExpired: If the token has expired.
            TokenInvalid: If the token signature does not verify.
            TokenScopeError: If the token belongs to a different principal or capability.
            CapabilityNotFound: If the capability is not registered.
            DriverError: If all drivers fail (not raised in dry-run mode).
        """
        # ── Verify token ──────────────────────────────────────────────────────
        self._token_provider.verify(
            token,
            expected_principal_id=principal.principal_id,
            expected_capability_id=token.capability_id,
        )

        capability = self._registry.get(token.capability_id)
        plan: RoutePlan = self._router.route(token.capability_id)

        # ── Dry-run short-circuit ─────────────────────────────────────────────
        if dry_run:
            driver_id = plan.driver_ids[0] if plan.driver_ids else ""
            # Mirror driver operation resolution exactly (see InMemoryDriver,
            # HTTPDriver, MCPDriver — all read ``args.get("operation", capability_id)``).
            # Using ``capability.impl.operation`` here would diverge from what the
            # driver actually executes at real-invoke time.
            operation = str(args.get("operation", token.capability_id))
            # Mirror Firewall's admin-only gate for ``raw`` mode
            # (see firewall/transform.py:108 and docs/agent-context/invariants.md).
            # Dry-run must not let non-admin principals probe raw-mode availability.
            effective_response_mode: ResponseMode = response_mode
            if response_mode == "raw" and "admin" not in principal.roles:
                effective_response_mode = "summary"
            # Mirror the BudgetManager escalation an actual invoke would apply,
            # so dry-run reports the mode the caller would really see.
            if self._budget_manager is not None:
                effective_response_mode = self._budget_manager.suggested_mode(
                    effective_response_mode
                )
            _cost_map: dict[SafetyClass, Literal["low", "medium", "high"]] = {
                SafetyClass.READ: "low",
                SafetyClass.WRITE: "medium",
                SafetyClass.DESTRUCTIVE: "high",
            }
            dry_run_trace = PolicyDecisionTrace(
                engine="Kernel.invoke[dry_run]",
                capability_id=token.capability_id,
                principal_id=principal.principal_id,
                intent=None,
                scope_keys=[],
                steps=[
                    PolicyTraceStep(
                        name="token_verified",
                        outcome="allowed",
                        detail="Token verified; original policy decision was at grant time.",
                        reason_code=str(AllowReason.TOKEN_VERIFIED),
                    )
                ],
                final_outcome="allowed",
                final_reason_code=str(AllowReason.TOKEN_VERIFIED),
            )
            return DryRunResult(
                capability_id=token.capability_id,
                principal_id=principal.principal_id,
                policy_decision=PolicyDecision(
                    allowed=True,
                    reason="Token verified. Policy was evaluated at grant time.",
                    constraints=dict(token.constraints),
                    reason_code=str(AllowReason.TOKEN_VERIFIED),
                    trace=dry_run_trace,
                ),
                driver_id=driver_id,
                operation=operation,
                resolved_args=args,
                response_mode=effective_response_mode,
                budget_remaining=(
                    self._budget_manager.remaining if self._budget_manager is not None else None
                ),
                estimated_cost=_cost_map[capability.safety_class],
            )

        action_id = str(uuid.uuid4())

        # ── Mirror Firewall's admin-only ``raw`` gate ─────────────────────────
        # The Firewall downgrades raw → summary for non-admin principals
        # (see firewall/transform.py and docs/agent-context/invariants.md).
        # We must mirror that downgrade *before* deciding whether to store a
        # handle and before consulting the budget manager, otherwise a
        # non-admin asking for raw would get a summary frame *without* a
        # handle (because the kernel skipped handle creation thinking the
        # mode was still raw).
        effective_mode: ResponseMode = response_mode
        if response_mode == "raw" and "admin" not in principal.roles:
            effective_mode = "summary"

        # ── Cross-invocation budget allocation & mode escalation ──────────────
        # When a BudgetManager is attached, reserve a slice of the cumulative
        # session budget before driver execution. The manager raises
        # BudgetExhausted if no budget remains. The requested response_mode is
        # escalated to a more aggressive tier as the remaining budget shrinks
        # (see BudgetManager.suggested_mode). This change is invisible to
        # callers without a BudgetManager — the original mode flows through.
        reserved_tokens: int | None = None
        if self._budget_manager is not None:
            reserved_tokens = await self._budget_manager.allocate()
            effective_mode = self._budget_manager.suggested_mode(effective_mode)

        _log_ctx = {
            "action_id": action_id,
            "principal_id": principal.principal_id,
            "capability_id": token.capability_id,
        }
        logger.info(
            "invoke_start",
            extra={
                **_log_ctx,
                "token_id": token.token_id,
                "response_mode": response_mode,
                "effective_mode": effective_mode,
            },
        )

        # ── Execute with fallback ─────────────────────────────────────────────
        raw_result = None
        used_driver_id = ""
        last_error: Exception | None = None

        for driver_id in plan.driver_ids:
            driver = self._drivers.get(driver_id)
            if driver is None:
                continue
            ctx = ExecutionContext(
                capability_id=token.capability_id,
                principal_id=principal.principal_id,
                args=args,
                constraints=token.constraints,
                action_id=action_id,
            )
            try:
                raw_result = await driver.execute(ctx)
                used_driver_id = driver_id
                logger.debug("driver_success", extra={**_log_ctx, "driver_id": driver_id})
                break
            except DriverError as exc:
                logger.warning(
                    "driver_failure",
                    extra={**_log_ctx, "driver_id": driver_id, "error": str(exc)},
                )
                last_error = exc
                continue

        if raw_result is None:
            # Release any reservation — no tokens were spent by the firewall.
            if self._budget_manager is not None and reserved_tokens is not None:
                await self._budget_manager.release(reserved_tokens)
            err_msg = str(last_error) if last_error else "No drivers available."
            logger.warning("invoke_failure", extra={**_log_ctx, "error": err_msg})
            trace = ActionTrace(
                action_id=action_id,
                capability_id=token.capability_id,
                principal_id=principal.principal_id,
                token_id=token.token_id,
                invoked_at=datetime.datetime.now(tz=datetime.timezone.utc),
                args=_redact_args_for_trace(token.capability_id, args),
                response_mode=response_mode,
                driver_id="",
                error=err_msg,
            )
            self._trace_store.record(trace)
            raise DriverError(
                f"All drivers failed for capability '{token.capability_id}'. Last error: {err_msg}"
            )

        # ── Store handle ──────────────────────────────────────────────────────
        handle: Handle | None = None
        if effective_mode != "raw":
            handle = self._handle_store.store(
                capability_id=token.capability_id,
                data=raw_result.data,
                principal_id=principal.principal_id,
                constraints=token.constraints,
            )

        # ── Firewall transform + budget reconciliation ────────────────────────
        # Both steps run inside a try/finally so a Firewall exception (e.g.
        # malformed constraint inputs) still releases any outstanding budget
        # reservation. record_usage replaces the reservation with committed
        # usage; the finally branch only fires if we never got there.
        reservation_consumed = False
        try:
            frame = self._firewall.transform(
                raw_result,
                action_id=action_id,
                principal_id=principal.principal_id,
                principal_roles=list(principal.roles),
                response_mode=effective_mode,
                constraints=token.constraints,
                handle=handle,
            )
            if self._budget_manager is not None and reserved_tokens is not None:
                actual_tokens = self._budget_manager.count_tokens(_frame_payload(frame))
                await self._budget_manager.record_usage(actual_tokens, reserved=reserved_tokens)
            reservation_consumed = True
        finally:
            if (
                not reservation_consumed
                and self._budget_manager is not None
                and reserved_tokens is not None
            ):
                await self._budget_manager.release(reserved_tokens)

        # ── Record trace ──────────────────────────────────────────────────────
        trace = ActionTrace(
            action_id=action_id,
            capability_id=token.capability_id,
            principal_id=principal.principal_id,
            token_id=token.token_id,
            invoked_at=datetime.datetime.now(tz=datetime.timezone.utc),
            args=_redact_args_for_trace(token.capability_id, args),
            response_mode=frame.response_mode,
            driver_id=used_driver_id,
            handle_id=handle.handle_id if handle else None,
        )
        self._trace_store.record(trace)

        logger.info(
            "invoke_success",
            extra={**_log_ctx, "response_mode": frame.response_mode, "driver_id": used_driver_id},
        )
        return frame

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

        Returns:
            A :class:`Frame` with the requested slice of data.

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
        """Retrieve the audit trace for a past invocation.

        Args:
            action_id: The unique action identifier returned in a :class:`Frame`.

        Returns:
            The :class:`ActionTrace` for that action.

        Raises:
            AgentKernelError: If no trace exists for that action ID.
        """
        logger.info(
            "explain",
            extra={
                "action_id": action_id,
            },
        )
        return self._trace_store.get(action_id)

    def explain_denial(
        self,
        request: CapabilityRequest,
        principal: Principal,
        *,
        justification: str = "",
    ) -> DenialExplanation:
        """Explain why *principal*'s *request* would be denied (or allowed).

        Delegates to the configured policy engine's ``explain()`` method.
        Unlike :meth:`grant_capability`, this does not raise
        :class:`PolicyDenied` when the policy fails — it returns a
        :class:`DenialExplanation` instead.

        Note: Rate-limit state is not reflected here. A request denied due to
        rate limits shows as ``denied=False`` in the explanation.

        Args:
            request: The capability request to explain.
            principal: The principal to evaluate the request for.
            justification: Free-text justification (used in policy checks).

        Returns:
            :class:`DenialExplanation` with ``denied=False`` if the request
            would succeed.

        Raises:
            CapabilityNotFound: If the capability is not registered.
            AgentKernelError: If the configured policy engine does not
                implement ``explain()``. Use :class:`DefaultPolicyEngine` or
                :class:`DeclarativePolicyEngine` for structured explanations,
                or add an ``explain()`` method to your engine.
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

    # ── Federation (capability marketplace, part 1) ───────────────────────────

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

        Args:
            endpoint: Transport endpoint at which this kernel can be reached
                (e.g. ``"https://agent-a.example/kernel"``). Format is
                transport-specific; importing kernels use it to construct a
                local driver — the endpoint is never invoked by federation
                itself.
            trust_level: Publisher-declared hint. The importing kernel still
                applies its configured trust policy regardless.

        Returns:
            A :class:`CapabilityManifest` ready to be serialised with
            :meth:`CapabilityManifest.to_dict`.
        """
        manifest = build_manifest(
            kernel_id=self._kernel_id,
            registry=self._registry,
            endpoint=endpoint,
            trust_level=trust_level,
        )
        logger.info(
            "advertise",
            extra={
                "kernel_id": self._kernel_id,
                "endpoint": endpoint,
                "capability_count": len(manifest.capabilities),
            },
        )
        return manifest

    def import_remote(
        self,
        manifest: CapabilityManifest,
        *,
        driver: Driver,
        trust_policy: TrustPolicy = "most_restrictive",
    ) -> list[Capability]:
        """Register a remote manifest's capabilities into this kernel.

        Imported capabilities are routed to *driver* — typically an
        :class:`~agent_kernel.drivers.http.HTTPDriver` or
        :class:`~agent_kernel.drivers.mcp.MCPDriver` configured against the
        manifest's endpoint. Invocation still flows through this kernel's
        local policy → token → firewall pipeline; the remote endpoint is
        never trusted to authorise on our behalf.

        Tokens are kernel-scoped: imported capabilities are signed by *this*
        kernel's :class:`HMACTokenProvider`, so a token issued by another
        kernel cannot be replayed against this one.

        Args:
            manifest: The remote :class:`CapabilityManifest` to import.
            driver: A driver that will execute imported capabilities. The
                driver is registered on this kernel automatically; its
                ``driver_id`` is recorded on each imported
                :class:`Capability` so the router can find it.
            trust_policy: How the importer weighs the manifest's sensitivity
                metadata. See
                :data:`~agent_kernel.federation.TrustPolicy`.

        Returns:
            The list of imported :class:`Capability` objects, in manifest order.

        Raises:
            FederationError: If the configured router cannot accept new routes
                (no ``add_route``), so imported capabilities could not be made
                invokable.
            TrustPolicyError: If *trust_policy* is unknown.
            ManifestError: If the manifest is malformed or contains a
                capability ID that conflicts with an existing local one.
            CapabilityAlreadyRegistered: If any imported capability ID is
                already registered locally.
        """
        # Imported capabilities must be routable. Require a mutable router up
        # front so we fail clean instead of registering capabilities that can
        # never be invoked.
        router_add = getattr(self._router, "add_route", None)
        if router_add is None:
            raise FederationError(
                "import_remote() requires a router that supports add_route(); "
                f"the configured {type(self._router).__name__} does not, so "
                "imported capabilities would be unroutable. Use a mutable router "
                "(e.g. StaticRouter) or pre-configure routes for the imported IDs."
            )
        self.register_driver(driver)
        imported = import_manifest(
            manifest=manifest,
            registry=self._registry,
            driver_id=driver.driver_id,
            trust_policy=trust_policy,
        )
        # Route each imported capability to its driver so existing
        # ``Kernel.invoke`` works unchanged.
        for cap in imported:
            router_add(cap.capability_id, [driver.driver_id])
        logger.info(
            "import_remote",
            extra={
                "kernel_id": self._kernel_id,
                "remote_kernel_id": manifest.kernel_id,
                "endpoint": manifest.endpoint,
                "capability_count": len(imported),
                "trust_policy": trust_policy,
                "driver_id": driver.driver_id,
            },
        )
        return imported
