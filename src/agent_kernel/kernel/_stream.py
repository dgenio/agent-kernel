"""Streaming invocation pipeline (:meth:`Kernel.invoke_stream`).

Yields :class:`Frame` chunks as the driver produces them. The same
security pipeline as :meth:`Kernel.invoke` is applied per chunk —
firewall transformation on every chunk, budget escalation as the
remaining budget drains, and a single :class:`ActionTrace` covering the
whole stream.

When the resolved driver does not implement
:class:`~agent_kernel.drivers.base.StreamingDriver`, this helper falls
back to a single :meth:`Driver.execute` call and yields one ``Frame``
with ``is_final=True``. The fallback preserves the same firewall +
trace guarantees as the streaming path.
"""

from __future__ import annotations

import datetime
import logging
import uuid
from collections.abc import AsyncIterator
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from ..drivers.base import ExecutionContext, StreamingDriver
from ..errors import DriverError
from ..models import (
    ActionTrace,
    Capability,
    Frame,
    Handle,
    Principal,
    RawResult,
    ResponseMode,
    RoutePlan,
)
from ..tokens import CapabilityToken
from ._invoke import resolve_effective_mode

if TYPE_CHECKING:  # pragma: no cover
    from . import Kernel

logger = logging.getLogger("agent_kernel.kernel")


async def invoke_stream_impl(
    *,
    kernel: Kernel,
    token: CapabilityToken,
    principal: Principal,
    capability: Capability,
    plan: RoutePlan,
    args: dict[str, Any],
    response_mode: ResponseMode,
) -> AsyncIterator[Frame]:
    """Stream Frames for one capability invocation."""
    del capability  # currently unused; kept in signature for future hooks.
    action_id = str(uuid.uuid4())
    initial_mode = resolve_effective_mode(
        response_mode=response_mode,
        principal=principal,
        budget_manager=kernel.budget,
    )
    log_ctx = {
        "action_id": action_id,
        "principal_id": principal.principal_id,
        "capability_id": token.capability_id,
    }
    logger.info(
        "invoke_stream_start",
        extra={
            **log_ctx,
            "token_id": token.token_id,
            "response_mode": response_mode,
            "initial_mode": initial_mode,
        },
    )

    ctx = ExecutionContext(
        capability_id=token.capability_id,
        principal_id=principal.principal_id,
        args=args,
        constraints=token.constraints,
        action_id=action_id,
    )

    # Resolve a streaming-capable driver, else fall back to one-shot execute.
    streaming_driver: StreamingDriver | None = None
    fallback_driver_id = ""
    for driver_id in plan.driver_ids:
        candidate = kernel._driver_map.get(driver_id)
        if candidate is None:
            continue
        if isinstance(candidate, StreamingDriver):
            streaming_driver = candidate
            fallback_driver_id = driver_id
            break
        fallback_driver_id = driver_id  # last non-streaming candidate

    yielded_any = False
    handle: Handle | None = None
    last_frame: Frame | None = None
    try:
        if streaming_driver is not None:
            async for frame in _stream_chunks(
                kernel=kernel,
                driver=streaming_driver,
                ctx=ctx,
                token=token,
                principal=principal,
                response_mode=initial_mode,
                action_id=action_id,
            ):
                yielded_any = True
                last_frame = frame
                yield frame
        else:
            # Non-streaming fallback — wrap a single execute() call.
            fallback_driver = kernel._driver_map.get(fallback_driver_id)
            if fallback_driver is None:
                raise DriverError(f"No driver available for capability '{token.capability_id}'.")
            raw = await fallback_driver.execute(ctx)
            if initial_mode != "raw":
                handle = kernel._handles.store(
                    capability_id=token.capability_id,
                    data=raw.data,
                )
            frame = kernel._fw.transform(
                raw,
                action_id=action_id,
                principal_id=principal.principal_id,
                principal_roles=list(principal.roles),
                response_mode=initial_mode,
                constraints=token.constraints,
                handle=handle,
            )
            frame = replace(frame, is_final=True)
            yielded_any = True
            last_frame = frame
            yield frame
    finally:
        kernel._traces.record(
            ActionTrace(
                action_id=action_id,
                capability_id=token.capability_id,
                principal_id=principal.principal_id,
                token_id=token.token_id,
                invoked_at=datetime.datetime.now(tz=datetime.timezone.utc),
                args=args,
                response_mode=(last_frame.response_mode if last_frame else initial_mode),
                driver_id=fallback_driver_id,
                handle_id=handle.handle_id if handle else None,
                error=None if yielded_any else "stream produced no chunks",
            )
        )
        logger.info(
            "invoke_stream_end",
            extra={
                **log_ctx,
                "yielded_any": yielded_any,
                "driver_id": fallback_driver_id,
            },
        )


async def _stream_chunks(
    *,
    kernel: Kernel,
    driver: StreamingDriver,
    ctx: ExecutionContext,
    token: CapabilityToken,
    principal: Principal,
    response_mode: ResponseMode,
    action_id: str,
) -> AsyncIterator[Frame]:
    """Yield firewalled frames for each chunk the driver produces.

    Each chunk is wrapped in a synthetic :class:`RawResult` and passed
    through :meth:`Firewall.transform` so PII redaction applies to
    every chunk. Mode escalation happens before each chunk when a
    :class:`BudgetManager` is attached.
    """
    final_marker_seen = False
    async for chunk in driver.execute_stream(ctx):
        is_final = bool(chunk.get("__is_final__", False))
        # Strip the synthetic marker before passing to the firewall.
        payload = {k: v for k, v in chunk.items() if k != "__is_final__"}
        synthetic_raw = RawResult(
            capability_id=token.capability_id,
            data=payload,
            metadata={"action_id": action_id, "streaming": True},
        )
        effective_mode = resolve_effective_mode(
            response_mode=response_mode,
            principal=principal,
            budget_manager=kernel.budget,
        )
        frame = kernel._fw.transform(
            synthetic_raw,
            action_id=action_id,
            principal_id=principal.principal_id,
            principal_roles=list(principal.roles),
            response_mode=effective_mode,
            constraints=token.constraints,
        )
        if is_final:
            final_marker_seen = True
            frame = replace(frame, is_final=True)
        yield frame
    if not final_marker_seen:
        # Driver ended without an explicit final marker — emit a final
        # sentinel frame so consumers can detect end-of-stream uniformly.
        yield replace(
            kernel._fw.transform(
                RawResult(
                    capability_id=token.capability_id,
                    data={},
                    metadata={
                        "action_id": action_id,
                        "streaming": True,
                        "sentinel": True,
                    },
                ),
                action_id=action_id,
                principal_id=principal.principal_id,
                principal_roles=list(principal.roles),
                response_mode=response_mode,
                constraints=token.constraints,
            ),
            is_final=True,
        )


__all__ = ["invoke_stream_impl"]
