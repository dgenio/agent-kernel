"""The Kernel: the main entry point for agent-kernel."""

from __future__ import annotations

import datetime
import uuid
from typing import Any

from .drivers.base import Driver, ExecutionContext
from .errors import DriverError
from .firewall.transform import Firewall
from .handles import HandleStore
from .models import (
    ActionTrace,
    CapabilityGrant,
    CapabilityRequest,
    Frame,
    Handle,
    Principal,
    ResponseMode,
    RoutePlan,
)
from .policy import DefaultPolicyEngine, PolicyEngine
from .registry import CapabilityRegistry
from .router import Router, StaticRouter
from .tokens import CapabilityToken, HMACTokenProvider, TokenProvider
from .trace import TraceStore


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
    ) -> None:
        self._registry = registry
        self._policy: PolicyEngine = policy or DefaultPolicyEngine()
        self._token_provider: TokenProvider = token_provider or HMACTokenProvider()
        self._router: Router = router or StaticRouter()
        self._firewall = firewall or Firewall()
        self._handle_store = handle_store or HandleStore()
        self._trace_store = trace_store or TraceStore()
        self._drivers: dict[str, Driver] = {}

    # ── Driver registration ────────────────────────────────────────────────────

    def register_driver(self, driver: Driver) -> None:
        """Register a driver with the kernel.

        Args:
            driver: Any object implementing the :class:`~agent_kernel.drivers.base.Driver` protocol.
        """
        self._drivers[driver.driver_id] = driver

    # ── Public API ─────────────────────────────────────────────────────────────

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
        return self._registry.search(goal)

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
        return self.grant_capability(
            request, principal, justification=justification
        ).token

    async def invoke(
        self,
        token: CapabilityToken,
        *,
        principal: Principal,
        args: dict[str, Any],
        response_mode: ResponseMode = "summary",
    ) -> Frame:
        """Execute a capability using a signed token and return a Frame.

        Args:
            token: A signed :class:`CapabilityToken` authorising the invocation.
            principal: The principal invoking the capability (must match token).
            args: Arguments passed to the driver.
            response_mode: How to present the result (``summary``, ``table``,
                ``handle_only``, or ``raw``).

        Returns:
            A bounded :class:`Frame` (never raw driver output).

        Raises:
            TokenExpired: If the token has expired.
            TokenInvalid: If the token signature does not verify.
            TokenScopeError: If the token belongs to a different principal or capability.
            CapabilityNotFound: If the capability is not registered.
            DriverError: If all drivers fail.
        """
        # ── Verify token ──────────────────────────────────────────────────────
        self._token_provider.verify(
            token,
            expected_principal_id=principal.principal_id,
            expected_capability_id=token.capability_id,
        )

        action_id = str(uuid.uuid4())
        self._registry.get(token.capability_id)  # validate capability exists
        plan: RoutePlan = self._router.route(token.capability_id)

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
                break
            except DriverError as exc:
                last_error = exc
                continue

        if raw_result is None:
            err_msg = str(last_error) if last_error else "No drivers available."
            trace = ActionTrace(
                action_id=action_id,
                capability_id=token.capability_id,
                principal_id=principal.principal_id,
                token_id=token.token_id,
                invoked_at=datetime.datetime.now(tz=datetime.timezone.utc),
                args=args,
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
        if response_mode != "raw":
            handle = self._handle_store.store(
                capability_id=token.capability_id,
                data=raw_result.data,
            )

        # ── Firewall transform ────────────────────────────────────────────────
        frame = self._firewall.transform(
            raw_result,
            action_id=action_id,
            principal_id=principal.principal_id,
            principal_roles=list(principal.roles),
            response_mode=response_mode,
            constraints=token.constraints,
            handle=handle,
        )

        # ── Record trace ──────────────────────────────────────────────────────
        trace = ActionTrace(
            action_id=action_id,
            capability_id=token.capability_id,
            principal_id=principal.principal_id,
            token_id=token.token_id,
            invoked_at=datetime.datetime.now(tz=datetime.timezone.utc),
            args=args,
            response_mode=frame.response_mode,
            driver_id=used_driver_id,
            handle_id=handle.handle_id if handle else None,
        )
        self._trace_store.record(trace)

        return frame

    def expand(self, handle: Handle, *, query: dict[str, Any]) -> Frame:
        """Expand a handle with pagination, field selection, or filtering.

        Args:
            handle: The :class:`Handle` to expand.
            query: Query parameters (``offset``, ``limit``, ``fields``, ``filter``).

        Returns:
            A :class:`Frame` with the requested slice of data.

        Raises:
            HandleNotFound: If the handle is unknown.
            HandleExpired: If the handle has expired.
        """
        return self._handle_store.expand(handle, query=query)

    def explain(self, action_id: str) -> ActionTrace:
        """Retrieve the audit trace for a past invocation.

        Args:
            action_id: The unique action identifier returned in a :class:`Frame`.

        Returns:
            The :class:`ActionTrace` for that action.

        Raises:
            AgentKernelError: If no trace exists for that action ID.
        """
        return self._trace_store.get(action_id)
