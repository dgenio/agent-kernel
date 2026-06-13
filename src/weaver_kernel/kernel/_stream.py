"""Streaming invocation pipeline (:meth:`Kernel.invoke_stream`).

Yields :class:`Frame` chunks as the driver produces them. The same
security pipeline as :meth:`Kernel.invoke` is applied per chunk —
firewall transformation on every chunk, budget escalation as the
remaining budget drains, and a single :class:`ActionTrace` covering the
whole stream.

When the resolved driver does not implement
:class:`~weaver_kernel.drivers.base.StreamingDriver`, this helper falls
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
    ResponseMode,
    RoutePlan,
)
from ..tokens import CapabilityToken
from ._invoke import _frame_result_summary, _redact_args_for_trace, resolve_effective_mode

if TYPE_CHECKING:  # pragma: no cover
    from . import Kernel

logger = logging.getLogger("weaver_kernel.kernel")


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
                    principal_id=principal.principal_id,
                    constraints=token.constraints,
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
                args=_redact_args_for_trace(token.capability_id, args),
                response_mode=(last_frame.response_mode if last_frame else initial_mode),
                driver_id=fallback_driver_id,
                sensitivity=capability.sensitivity,
                handle_id=handle.handle_id if handle else None,
                result_summary=(_frame_result_summary(last_frame) if last_frame else None),
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

    Delegates per-chunk redaction to :meth:`Firewall.apply_stream`, so the
    streaming path shares a single firewall implementation with the
    single-shot path (no second copy of the wrap-and-redact loop to drift).
    The effective response mode is resolved once up front — no budget is
    consumed mid-stream, so it is stable across chunks — and passed through,
    honouring ``apply_stream``'s stateless contract. If the driver ends
    without an explicit ``__is_final__`` marker, a final sentinel chunk is
    injected so consumers can detect end-of-stream uniformly.
    """
    effective_mode = resolve_effective_mode(
        response_mode=response_mode,
        principal=principal,
        budget_manager=kernel.budget,
    )

    async def _raw_chunks() -> AsyncIterator[dict[str, Any]]:
        saw_final = False
        async for chunk in driver.execute_stream(ctx):
            if chunk.get("__is_final__"):
                saw_final = True
            yield chunk
        if not saw_final:
            yield {"__is_final__": True}

    async for frame in kernel._fw.apply_stream(
        _raw_chunks(),
        action_id=action_id,
        capability_id=token.capability_id,
        principal_id=principal.principal_id,
        principal_roles=list(principal.roles),
        response_mode=effective_mode,
        constraints=token.constraints,
    ):
        yield frame


__all__ = ["invoke_stream_impl"]
