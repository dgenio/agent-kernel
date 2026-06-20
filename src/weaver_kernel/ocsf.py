"""Map :class:`ActionTrace` records to OCSF API Activity events (#176).

Security teams consume agent activity through SIEMs, and the Open Cybersecurity
Schema Framework (OCSF) is the cross-vendor schema those pipelines speak. This
module renders each audit record as an **OCSF API Activity** event (``class_uid``
6003), enriched per the OWASP Agent Observability Standard (AOS), which extends
OCSF for agent traces. It complements — does not replace — the OpenTelemetry
export (:mod:`weaver_kernel.otel`, #125): OTel feeds the *observability*
pipeline, OCSF feeds the *security-operations* pipeline.

The mapping is a **pure, dependency-free** dict construction — no new runtime
dependency, deterministic for identical input. Output is built only from
already-redaction-safe :class:`ActionTrace` fields, so exporting cannot widen the
I-01 firewall boundary.

Field mapping (kernel → OCSF API Activity 6003)
-----------------------------------------------

==========================  =====================================================
OCSF field                  Source
==========================  =====================================================
``class_uid`` / ``class_name``  Constant ``6003`` / ``"API Activity"``
``category_uid`` / name     Constant ``6`` / ``"Application Activity"``
``activity_id`` / name      ``event_type`` maps invoke→Other(99),
                            expand→Read(2), deny→Other(99)
``type_uid``                ``class_uid * 100 + activity_id``
``status_id`` / ``status``  ``2``/``Failure`` when ``error`` is set else ``1``/``Success``
``status_detail``           ``error`` (already redacted)
``severity_id`` / name      deny maps to Medium(3) else Informational(1)
``time``                    ``invoked_at`` as epoch milliseconds (UTC)
``actor.user.uid``          ``principal_id``
``api.operation``           ``capability_id``
``api.service.name``        ``driver_id`` (or ``"weaver-kernel"`` when empty)
``metadata``                product + OCSF version + AOS extension marker
``unmapped``                kernel-specific enrichment (see below)
==========================  =====================================================

Kernel specifics that have no native OCSF home — ``action_id``, ``token_id``,
``event_type``, ``response_mode``, ``sensitivity``, ``reason_code``,
``handle_id``, ``result_summary`` — are carried under ``unmapped`` so no audit
detail is lost while the top-level shape stays OCSF-valid.
"""

from __future__ import annotations

from collections.abc import Iterable

from .models import ActionTrace

OCSF_VERSION = "1.3.0"
"""OCSF schema version this mapping targets (carried in ``metadata.version``)."""

AOS_EXTENSION = "aos"
"""OWASP Agent Observability Standard extension marker (``metadata.extensions``)."""

_CLASS_UID = 6003
_CATEGORY_UID = 6

# event_type → (activity_id, activity_name) per the table in the module docstring.
_ACTIVITY: dict[str, tuple[int, str]] = {
    "invoke": (99, "Other"),
    "expand": (2, "Read"),
    "deny": (99, "Other"),
}


def trace_to_ocsf(trace: ActionTrace) -> dict[str, object]:
    """Render *trace* as a single OCSF API Activity (6003) event.

    Args:
        trace: A recorded :class:`ActionTrace` (any ``event_type``).

    Returns:
        A JSON-serialisable dict in OCSF API Activity shape, AOS-enriched. The
        result is deterministic: identical traces produce identical output.
    """
    activity_id, activity_name = _ACTIVITY.get(trace.event_type, (99, "Other"))
    failed = trace.error is not None
    epoch_ms = int(trace.invoked_at.timestamp() * 1000)
    severity_id, severity = (3, "Medium") if trace.event_type == "deny" else (1, "Informational")

    return {
        "activity_id": activity_id,
        "activity_name": activity_name,
        "category_uid": _CATEGORY_UID,
        "category_name": "Application Activity",
        "class_uid": _CLASS_UID,
        "class_name": "API Activity",
        "type_uid": _CLASS_UID * 100 + activity_id,
        "severity_id": severity_id,
        "severity": severity,
        "status_id": 2 if failed else 1,
        "status": "Failure" if failed else "Success",
        "status_detail": trace.error,
        "time": epoch_ms,
        "metadata": {
            "version": OCSF_VERSION,
            "product": {"name": "weaver-kernel", "vendor_name": "Weaver"},
            "extensions": [{"name": AOS_EXTENSION, "uid": "aos", "version": "draft"}],
        },
        "actor": {"user": {"uid": trace.principal_id}},
        "api": {
            "operation": trace.capability_id,
            "service": {"name": trace.driver_id or "weaver-kernel"},
        },
        "unmapped": {
            "action_id": trace.action_id,
            "token_id": trace.token_id,
            "event_type": trace.event_type,
            "response_mode": trace.response_mode,
            "sensitivity": trace.sensitivity.value,
            "reason_code": trace.reason_code,
            "handle_id": trace.handle_id,
            "result_summary": trace.result_summary,
        },
    }


def traces_to_ocsf(traces: Iterable[ActionTrace]) -> list[dict[str, object]]:
    """Map an iterable of traces to a list of OCSF API Activity events.

    Order is preserved from *traces* (typically ``Kernel.list_traces()`` /
    ``Kernel.query_traces(...)``), so the caller controls ordering.
    """
    return [trace_to_ocsf(trace) for trace in traces]


__all__ = ["AOS_EXTENSION", "OCSF_VERSION", "trace_to_ocsf", "traces_to_ocsf"]
