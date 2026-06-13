"""``weaver-kernel`` command-line entry point.

Subcommands:

* ``audit`` — inspect, filter, verify, and export persisted action traces (#147).
* ``doctor`` — preflight-check the local environment and self-test vectors (#124).

Both are stdlib-only (argparse); see ``docs/cli.md``.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from ..errors import AgentKernelError
from ._audit import build_audit_parser
from ._doctor import build_doctor_parser


def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level ``weaver-kernel`` argument parser."""
    parser = argparse.ArgumentParser(
        prog="weaver-kernel",
        description="Capability-based security kernel — operator CLI.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    build_audit_parser(subparsers)
    build_doctor_parser(subparsers)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns a process exit code.

    Kernel errors (e.g. an unknown action id) are reported on stderr with a
    non-zero exit, never as an uncaught traceback.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = args.handler(args)
        return int(result)
    except AgentKernelError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
