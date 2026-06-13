"""``weaver-kernel audit`` — inspect, filter, and verify action traces (issue #147).

Operates on a persisted trace store (:class:`SQLiteTraceStore` or
:class:`JsonlTraceStore`). Output is redaction-safe by construction: the CLI
renders only what an :class:`~weaver_kernel.models.ActionTrace` already holds —
no flag surfaces raw driver output.

Note:
    Traces describe **authorised** invocations only: a denied request never
    produces an :class:`ActionTrace` (policy gates before invocation, per I-02).
    Filtering is therefore by ``--status succeeded|failed``, not by an
    allow/deny/ask decision, which the trace store does not record.
"""

from __future__ import annotations

import argparse
import datetime
import json
from pathlib import Path
from typing import Protocol

from ..errors import AgentKernelError
from ..models import ActionTrace
from ..stores import TraceStoreProtocol
from ..stores._trace_codec import encode_trace
from ..stores.audit_chain import ChainVerificationResult, TraceRecord
from ..stores.jsonl import JsonlTraceStore
from ..stores.sqlite import SQLiteTraceStore


class _VerifiableTraceStore(TraceStoreProtocol, Protocol):
    """A persisted trace store that also exposes the audit chain."""

    def list_records(self) -> list[TraceRecord]: ...

    def verify_chain(self) -> ChainVerificationResult: ...


def open_trace_store(
    path: str, fmt: str | None, *, secret: str | None = None
) -> _VerifiableTraceStore:
    """Open a persisted trace store, inferring the format from the path suffix.

    Raises:
        AgentKernelError: If *path* does not exist. Opening would otherwise
            create an empty store and make ``audit verify`` falsely report OK on
            a mistyped path, hiding the misconfiguration.
    """
    if path != ":memory:" and not Path(path).exists():
        raise AgentKernelError(
            f"Trace store '{path}' does not exist. Check the --store path "
            "(the audit commands read an existing store; they do not create one)."
        )
    resolved = fmt or ("jsonl" if path.endswith(".jsonl") else "sqlite")
    if resolved == "jsonl":
        return JsonlTraceStore(path, secret=secret)
    return SQLiteTraceStore(path, secret=secret)


def _parse_dt(value: str) -> datetime.datetime:
    dt = datetime.datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def _matches(
    trace: ActionTrace,
    *,
    principal: str | None,
    capability: str | None,
    status: str | None,
    since: datetime.datetime | None,
    until: datetime.datetime | None,
) -> bool:
    if principal is not None and trace.principal_id != principal:
        return False
    if capability is not None and trace.capability_id != capability:
        return False
    if status is not None:
        trace_status = "failed" if trace.error is not None else "succeeded"
        if trace_status != status:
            return False
    if since is not None and trace.invoked_at < since:
        return False
    return not (until is not None and trace.invoked_at >= until)


def _filter_traces(store: TraceStoreProtocol, args: argparse.Namespace) -> list[ActionTrace]:
    since = _parse_dt(args.since) if args.since else None
    until = _parse_dt(args.until) if args.until else None
    traces = [
        t
        for t in store.list_all()
        if _matches(
            t,
            principal=args.principal,
            capability=args.capability,
            status=args.status,
            since=since,
            until=until,
        )
    ]
    if args.limit is not None:
        traces = traces[: args.limit]
    return traces


def cmd_list(args: argparse.Namespace) -> int:
    """Handle ``audit list``."""
    store = open_trace_store(args.store, args.format, secret=args.secret)
    traces = _filter_traces(store, args)
    if args.json:
        print(json.dumps([encode_trace(t) for t in traces], indent=2))
        return 0
    if not traces:
        print("No traces matched.")
        return 0
    header = f"{'ACTION_ID':<38} {'CAPABILITY':<28} {'PRINCIPAL':<18} {'STATUS':<9} INVOKED_AT"
    print(header)
    print("-" * len(header))
    for t in traces:
        status = "failed" if t.error is not None else "succeeded"
        print(
            f"{t.action_id:<38} {t.capability_id:<28} {t.principal_id:<18} "
            f"{status:<9} {t.invoked_at.isoformat()}"
        )
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    """Handle ``audit show ACTION_ID``."""
    store = open_trace_store(args.store, args.format, secret=args.secret)
    trace = store.get(args.action_id)  # raises AgentKernelError if unknown
    print(json.dumps(encode_trace(trace), indent=2))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Handle ``audit verify``. Exit non-zero if the chain does not verify."""
    store = open_trace_store(args.store, args.format, secret=args.secret)
    result = store.verify_chain()
    if args.json:
        print(
            json.dumps(
                {
                    "ok": result.ok,
                    "records_checked": result.records_checked,
                    "first_bad_seq": result.first_bad_seq,
                    "detail": result.detail,
                }
            )
        )
    else:
        print(("OK: " if result.ok else "TAMPER DETECTED: ") + result.detail)
    return 0 if result.ok else 1


def cmd_export(args: argparse.Namespace) -> int:
    """Handle ``audit export`` — emit filtered traces as JSONL (one per line)."""
    store = open_trace_store(args.store, args.format, secret=args.secret)
    traces = _filter_traces(store, args)
    lines = [json.dumps(encode_trace(t)) for t in traces]
    payload = "\n".join(lines)
    if args.out:
        Path(args.out).write_text(payload + ("\n" if payload else ""), encoding="utf-8")
        print(f"Wrote {len(traces)} trace(s) to {args.out}")
    else:
        print(payload)
    return 0


def add_common_store_arguments(parser: argparse.ArgumentParser) -> None:
    """Attach the store-selection flags shared by every audit subcommand."""
    parser.add_argument(
        "--store", required=True, help="Path to the trace store (SQLite or .jsonl)."
    )
    parser.add_argument(
        "--format",
        choices=["sqlite", "jsonl"],
        help="Store format (default: inferred from the path suffix).",
    )
    parser.add_argument(
        "--secret",
        help="HMAC secret for chain verification (default: WEAVER_KERNEL_SECRET).",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")


def add_filter_arguments(parser: argparse.ArgumentParser) -> None:
    """Attach the shared list/export filter flags to *parser*."""
    parser.add_argument("--principal", help="Filter by principal id.")
    parser.add_argument("--capability", help="Filter by capability id.")
    parser.add_argument(
        "--status",
        choices=["succeeded", "failed"],
        help="Filter by outcome (denials are not traced; see --help).",
    )
    parser.add_argument("--since", help="Only traces at/after this ISO-8601 timestamp.")
    parser.add_argument("--until", help="Only traces strictly before this ISO-8601 timestamp.")
    parser.add_argument("--limit", type=int, help="Cap the number of traces returned.")


def build_audit_parser(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """Register the ``audit`` subcommand tree on *subparsers*."""
    audit = subparsers.add_parser("audit", help="Inspect and verify persisted action traces.")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)

    p_list = audit_sub.add_parser("list", help="List/filter traces as a table.")
    add_common_store_arguments(p_list)
    add_filter_arguments(p_list)
    p_list.set_defaults(handler=cmd_list)

    p_show = audit_sub.add_parser("show", help="Show one trace in full.")
    add_common_store_arguments(p_show)
    p_show.add_argument("action_id", help="The action id to display.")
    p_show.set_defaults(handler=cmd_show)

    p_verify = audit_sub.add_parser("verify", help="Verify the hash chain integrity.")
    add_common_store_arguments(p_verify)
    p_verify.set_defaults(handler=cmd_verify)

    p_export = audit_sub.add_parser("export", help="Export filtered traces as JSONL.")
    add_common_store_arguments(p_export)
    add_filter_arguments(p_export)
    p_export.add_argument("--out", help="Write to this file instead of stdout.")
    p_export.set_defaults(handler=cmd_export)
