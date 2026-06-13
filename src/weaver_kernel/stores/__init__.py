"""Pluggable persistence backends for the kernel's stateful stores (issue #126).

The in-memory stores remain the defaults. Import a durable backend and inject it
via constructor:

.. code-block:: python

    from weaver_kernel import Kernel, HMACTokenProvider
    from weaver_kernel.stores import SQLiteTraceStore, SQLiteRevocationStore

    traces = SQLiteTraceStore("audit.db")
    tokens = HMACTokenProvider(revocation_store=SQLiteRevocationStore("revoked.db"))
    kernel = Kernel(registry, token_provider=tokens, trace_store=traces)

See ``docs/architecture.md`` for backend selection and durability trade-offs.
"""

from __future__ import annotations

from ._protocols import (
    HandleStoreProtocol,
    RevocationStoreProtocol,
    TraceStoreProtocol,
)
from ._trace_codec import decode_trace, encode_trace
from .audit_chain import (
    CHAIN_VERSION,
    GENESIS_HASH,
    ChainVerificationResult,
    TraceRecord,
    build_record,
    compute_record_hash,
    verify_chain,
)
from .jsonl import JsonlTraceStore
from .memory import InMemoryRevocationStore
from .sqlite import SQLiteRevocationStore, SQLiteTraceStore

__all__ = [
    # protocols
    "TraceStoreProtocol",
    "RevocationStoreProtocol",
    "HandleStoreProtocol",
    # audit chain (issue #127)
    "CHAIN_VERSION",
    "GENESIS_HASH",
    "ChainVerificationResult",
    "TraceRecord",
    "build_record",
    "compute_record_hash",
    "verify_chain",
    "decode_trace",
    "encode_trace",
    # backends
    "InMemoryRevocationStore",
    "JsonlTraceStore",
    "SQLiteTraceStore",
    "SQLiteRevocationStore",
]
