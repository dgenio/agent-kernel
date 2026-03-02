"""Core dataclasses for agent-kernel.

All types use ``dataclasses.dataclass`` with ``slots=True`` where supported
(Python ≥ 3.10) for minimal memory footprint and fast attribute access.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Any, Literal

from .enums import SafetyClass, SensitivityTag

ResponseMode = Literal["summary", "table", "handle_only", "raw"]


# ── Capability ────────────────────────────────────────────────────────────────


@dataclass(slots=True)
class ImplementationRef:
    """Points a capability at a concrete driver + operation."""

    driver_id: str
    """Identifier of the driver that handles this capability (e.g. ``"memory"``)."""

    operation: str
    """Operation name understood by the driver (e.g. ``"list_invoices"``)."""


@dataclass(slots=True)
class Capability:
    """A task-shaped unit of work that can be authorized and executed."""

    capability_id: str
    """Stable, human-readable identifier (e.g. ``"billing.list_invoices"``)."""

    name: str
    """Short human-readable name."""

    description: str
    """What the capability does."""

    safety_class: SafetyClass
    """READ / WRITE / DESTRUCTIVE."""

    sensitivity: SensitivityTag = SensitivityTag.NONE
    """Optional sensitivity tag."""

    allowed_fields: list[str] = field(default_factory=list)
    """If non-empty, only these fields are returned unless the caller has ``pii_reader``."""

    tags: list[str] = field(default_factory=list)
    """Arbitrary keyword tags used for capability matching."""

    impl: ImplementationRef | None = None
    """Optional pointer to the implementation."""


# ── Request / Grant ───────────────────────────────────────────────────────────


@dataclass(slots=True)
class CapabilityRequest:
    """A request for authorization to use a capability."""

    capability_id: str
    """The capability being requested."""

    goal: str
    """Free-text description of why this capability is needed."""

    constraints: dict[str, Any] = field(default_factory=dict)
    """Optional execution constraints (e.g. ``{"max_rows": 10}``)."""


@dataclass(slots=True)
class Principal:
    """Represents the entity (agent, user, service) making a request."""

    principal_id: str
    """Unique identifier (UUID or slug)."""

    roles: list[str] = field(default_factory=list)
    """Role strings, e.g. ``["reader", "admin"]``."""

    attributes: dict[str, str] = field(default_factory=dict)
    """Arbitrary attributes, e.g. ``{"tenant": "acme"}``."""


@dataclass(slots=True)
class PolicyDecision:
    """Result of a policy engine evaluation."""

    allowed: bool
    """``True`` if the request is permitted."""

    reason: str
    """Human-readable explanation."""

    constraints: dict[str, Any] = field(default_factory=dict)
    """Any additional constraints imposed by the policy (e.g. ``max_rows``)."""


@dataclass(slots=True)
class CapabilityGrant:
    """A signed authorization binding a principal to a capability."""

    request: CapabilityRequest
    """The original request."""

    principal: Principal
    """The principal this grant is issued to."""

    decision: PolicyDecision
    """The policy decision that led to this grant."""

    token_id: str
    """The token's unique identifier."""


# ── Routing ───────────────────────────────────────────────────────────────────


@dataclass(slots=True)
class RoutePlan:
    """Maps a capability to an ordered list of driver IDs to try."""

    capability_id: str
    driver_ids: list[str]
    """Ordered list; first that succeeds wins."""


# ── Raw results & Frames ──────────────────────────────────────────────────────


@dataclass(slots=True)
class RawResult:
    """Unfiltered output from a driver execution."""

    capability_id: str
    data: Any
    """Arbitrary data returned by the driver."""

    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Handle:
    """An opaque reference to a full dataset stored in the HandleStore."""

    handle_id: str
    capability_id: str
    created_at: datetime.datetime
    expires_at: datetime.datetime
    total_rows: int = 0


@dataclass(slots=True)
class Provenance:
    """Tracks the origin of information in a Frame."""

    capability_id: str
    principal_id: str
    invoked_at: datetime.datetime
    action_id: str


@dataclass(slots=True)
class Budgets:
    """Budget constraints for the context firewall."""

    max_rows: int = 50
    max_fields: int = 20
    max_chars: int = 4000
    max_depth: int = 3


@dataclass(slots=True)
class FieldSpec:
    """Describes a single field in a structured result."""

    name: str
    value_type: str


@dataclass(slots=True)
class Frame:
    """Bounded, LLM-safe representation of a capability result.

    The firewall always returns a Frame; raw data is never passed to the LLM.
    """

    action_id: str
    capability_id: str
    response_mode: ResponseMode

    facts: list[str] = field(default_factory=list)
    """Key facts extracted from the result (≤ 20 items)."""

    table_preview: list[dict[str, Any]] = field(default_factory=list)
    """Tabular preview (≤ max_rows rows)."""

    handle: Handle | None = None
    """Opaque reference to the full dataset for later expansion."""

    warnings: list[str] = field(default_factory=list)
    """Non-fatal warnings (e.g. redacted fields)."""

    provenance: Provenance | None = None
    """Audit provenance of this frame."""

    raw_data: Any = None
    """Only populated in ``raw`` response mode for admin principals."""


# ── Audit trace ───────────────────────────────────────────────────────────────


@dataclass(slots=True)
class ActionTrace:
    """Complete audit record for a single kernel invocation."""

    action_id: str
    capability_id: str
    principal_id: str
    token_id: str
    invoked_at: datetime.datetime
    args: dict[str, Any]
    response_mode: ResponseMode
    driver_id: str
    handle_id: str | None = None
    error: str | None = None
