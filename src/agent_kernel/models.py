"""Core dataclasses for agent-kernel.

All types use ``dataclasses.dataclass`` with ``slots=True`` where supported
(Python ≥ 3.10) for minimal memory footprint and fast attribute access.
"""

from __future__ import annotations

import datetime
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

from .enums import SafetyClass, SensitivityTag
from .errors import ManifestError

if TYPE_CHECKING:
    from pydantic import BaseModel

    from .tokens import CapabilityToken

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
class ToolHints:
    """Vendor-specific tool-definition hints for LLM adapters.

    Consumed by ``agent_kernel.adapters`` when emitting tool schemas.
    Engines that don't recognise a hint silently ignore it; setting a hint
    never changes how the kernel itself behaves.
    """

    cache_control: dict[str, Any] | None = None
    """Anthropic prompt-cache control block (e.g. ``{"type": "ephemeral"}``).

    Forwarded verbatim to the Anthropic tool definition. Ignored by other adapters.
    """

    strict: bool = False
    """When ``True``, OpenAI tool definitions are emitted with ``strict: true``.

    The capability's ``parameters_model`` (or ``parameters_schema``) must produce a
    JSON Schema that satisfies OpenAI's strict-mode rules (every property required,
    ``additionalProperties: false`` on all objects). The adapter normalises objects
    where possible and falls back to non-strict with a warning if normalisation fails.
    Ignored by other adapters.
    """


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
    """If non-empty, only these fields are returned unless the caller has ``pii_reader``.

    Note: this is an **output redaction** control consumed by the firewall — it does
    not describe the capability's input parameters. For input schemas use
    :attr:`parameters_model` or :attr:`parameters_schema`.
    """

    tags: list[str] = field(default_factory=list)
    """Arbitrary keyword tags used for capability matching."""

    impl: ImplementationRef | None = None
    """Optional pointer to the implementation."""

    parameters_model: type[BaseModel] | None = None
    """Optional pydantic model describing the capability's input parameters.

    When present, LLM adapters generate the tool's JSON Schema from
    ``parameters_model.model_json_schema()`` and validate incoming tool-call
    arguments against the model before invocation. Takes precedence over
    :attr:`parameters_schema`.
    """

    parameters_schema: dict[str, Any] | None = None
    """Optional raw JSON Schema for the capability's input parameters.

    Used by LLM adapters as a fallback schema source when no
    :attr:`parameters_model` is supplied. Forwarded to the vendor tool definition
    verbatim; the adapter does not validate incoming arguments against it (use
    :attr:`parameters_model` for validation).
    """

    tool_hints: ToolHints | None = None
    """Vendor-specific hints consumed by LLM adapters (e.g. Anthropic
    ``cache_control``, OpenAI ``strict`` mode). Has no effect on kernel routing
    or policy. See :class:`ToolHints`.
    """


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

    intent: str | None = None
    """Structured intent label (e.g. ``"customer_support_lookup"``).

    Free-text :attr:`goal` is still required for human-readable audit; ``intent``
    is the machine-readable counterpart that declarative policies can match
    on directly without parsing the goal. See :class:`PolicyMatch.intent`.
    """

    scope: dict[str, Any] = field(default_factory=dict)
    """Structured scope metadata describing what the request narrows to.

    Examples: ``{"region": "eu-west"}``, ``{"customer_id": "C-42"}``. Policies
    can deny a capability invocation that is technically allowed but unsafe
    for a particular scope. See :class:`PolicyMatch.scope`.
    """


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
class PolicyTraceStep:
    """A single step recorded while a policy engine evaluated a request.

    Steps describe what the engine considered, in order — which rule it
    examined, whether it matched, what condition (if any) failed, and what
    constraint (if any) was applied. Steps never contain raw argument values
    from the caller; they reference fields and IDs only.
    """

    name: str
    """Short label for the step (e.g. ``"safety_class:WRITE"`` or rule name)."""

    outcome: Literal["matched", "skipped", "denied", "allowed", "constraint_applied"]
    """What happened at this step.

    - ``"matched"``: a rule's match clause matched and evaluation continues.
    - ``"skipped"``: the step did not apply (e.g. wildcard, wrong safety class).
    - ``"denied"``: this step produced the final denial.
    - ``"allowed"``: this step produced the final allow.
    - ``"constraint_applied"``: the step merged a constraint into the decision.
    """

    detail: str = ""
    """Human-readable detail, e.g. ``"role 'writer' required, principal had ['reader']"``."""

    reason_code: str | None = None
    """For ``"denied"`` steps, the :class:`~agent_kernel.policy_reasons.DenialReason`.
    For ``"allowed"`` steps, the :class:`~agent_kernel.policy_reasons.AllowReason`.
    ``None`` for ``"matched"``, ``"skipped"``, and ``"constraint_applied"`` steps.
    """


@dataclass(slots=True)
class PolicyDecisionTrace:
    """Structured trace of how a :class:`PolicyDecision` was reached.

    The trace lists every step the policy engine took, in order, so callers
    can audit which rule matched, which conditions failed, and which
    constraints were applied. The trace must not contain raw argument
    values — only field names, role names, attribute names, rule names, and
    safe IDs — so it is safe to serialize and log.
    """

    engine: str
    """Engine identifier (e.g. ``"DefaultPolicyEngine"``)."""

    capability_id: str
    """The capability that was being evaluated."""

    principal_id: str
    """The principal the decision was made for."""

    intent: str | None
    """Echoed :attr:`CapabilityRequest.intent` (may be ``None``)."""

    scope_keys: list[str] = field(default_factory=list)
    """Scope dimension names present on the request (values redacted for safety)."""

    steps: list[PolicyTraceStep] = field(default_factory=list)
    """Ordered list of evaluation steps."""

    final_outcome: Literal["allowed", "denied"] = "denied"
    """The decision the engine reached."""

    final_reason_code: str | None = None
    """The :class:`~agent_kernel.policy_reasons.AllowReason` or
    :class:`~agent_kernel.policy_reasons.DenialReason` for the final outcome.
    """


@dataclass(slots=True)
class PolicyDecision:
    """Result of a policy engine evaluation."""

    allowed: bool
    """``True`` if the request is permitted."""

    reason: str
    """Human-readable explanation. Wording may evolve; assert on
    :attr:`reason_code` for stable behavior."""

    constraints: dict[str, Any] = field(default_factory=dict)
    """Any additional constraints imposed by the policy (e.g. ``max_rows``)."""

    reason_code: str | None = None
    """Stable machine-readable code (typically a :class:`~agent_kernel.policy_reasons.AllowReason`
    or :class:`~agent_kernel.policy_reasons.DenialReason` value).

    Use this for assertions, metrics, and UI mapping. ``None`` only when an
    out-of-tree policy engine has not populated it.
    """

    trace: PolicyDecisionTrace | None = None
    """Structured trace of how this decision was reached.

    Populated by both built-in engines on allow and deny paths. ``None`` for
    third-party engines that don't produce a trace.
    """


@dataclass(slots=True)
class CapabilityGrant:
    """A signed authorization binding a principal to a capability."""

    request: CapabilityRequest
    """The original request."""

    principal: Principal
    """The principal this grant is issued to."""

    decision: PolicyDecision
    """The policy decision that led to this grant."""

    token: CapabilityToken
    """The signed capability token issued for this grant."""

    audit_id: str
    """Unique audit identifier embedded in the token for traceability."""


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
    """An opaque reference to a full dataset stored in the HandleStore.

    Handles carry the grant constraints persisted at creation time. The
    :class:`HandleStore` rechecks those constraints when the handle is
    expanded, so an over-broad expand query is denied with a stable
    :class:`~agent_kernel.errors.HandleConstraintViolation` rather than
    silently returning data the original grant never authorised.
    """

    handle_id: str
    capability_id: str
    created_at: datetime.datetime
    expires_at: datetime.datetime
    total_rows: int = 0

    principal_id: str = ""
    """Principal the original grant was issued to. ``expand`` rejects use by
    other principals so handle references cannot be shared as a back-door."""

    constraints: dict[str, Any] = field(default_factory=dict)
    """Grant constraints copied from :attr:`PolicyDecision.constraints` at
    handle creation time. ``expand`` rechecks ``max_rows``, ``allowed_fields``,
    and any ``scope`` filter against these values.
    """


@dataclass(slots=True)
class Provenance:
    """Tracks the origin of information in a Frame."""

    capability_id: str
    principal_id: str
    invoked_at: datetime.datetime
    action_id: str


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

    is_final: bool = False
    """``True`` when this Frame is the last chunk of a stream.

    Non-streaming :meth:`~agent_kernel.Kernel.invoke` always returns a Frame
    with ``is_final=True``. For :meth:`~agent_kernel.Kernel.invoke_stream`, only
    the terminal Frame has it set; intermediate chunks have ``is_final=False``.
    """


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
    result_summary: dict[str, Any] | None = None
    """Redaction-safe summary of the firewalled :class:`Frame` this invocation
    produced (``None`` for failed runs, which have no Frame).

    Derived **only** from the post-Firewall Frame — counts and flags, never raw
    driver data — so recording it cannot widen the I-01 boundary or leak
    sensitive payloads into the audit trail. It lets a reviewer reconstruct an
    invocation's outcome directly from :meth:`~agent_kernel.Kernel.explain`; for
    example, a repository safety check passed iff ``result_summary["row_count"]
    == 0``.
    """


# ── Policy explanation ────────────────────────────────────────────────────────


@dataclass(slots=True)
class FailedCondition:
    """A single policy condition that was not met."""

    condition: str
    """Name of the condition (e.g. ``"roles"``, ``"min_justification"``)."""

    required: Any
    """What the policy requires."""

    actual: Any
    """What the principal or request actually has."""

    suggestion: str
    """Actionable remediation hint."""

    reason_code: str | None = None
    """Stable machine-readable code (a :class:`~agent_kernel.policy_reasons.DenialReason` value).
    Use this for assertions instead of matching the human-readable
    :attr:`suggestion` string.
    """


@dataclass(slots=True)
class DenialExplanation:
    """Structured explanation of a policy evaluation result."""

    denied: bool
    """``True`` if the request would be denied."""

    rule_name: str
    """Name of the rule (or rule category) that caused the denial."""

    failed_conditions: list[FailedCondition]
    """All conditions that were not satisfied."""

    remediation: list[str]
    """Ordered list of actionable steps to satisfy the policy."""

    narrative: str
    """Human-readable single-sentence summary."""

    reason_code: str | None = None
    """Primary :class:`~agent_kernel.policy_reasons.DenialReason` for the denial
    (typically the code of the first :class:`FailedCondition`). ``None`` on the
    allow path (``denied=False``).
    """


# ── Dry-run ───────────────────────────────────────────────────────────────────


# ── Namespaces & federation ───────────────────────────────────────────────────


@dataclass(slots=True)
class NamespaceMetadata:
    """Describes a capability namespace.

    Namespaces are dot-notation prefixes (``"billing"``, ``"billing.invoices"``)
    inferred from registered :attr:`Capability.capability_id` values. A
    :class:`NamespaceMetadata` entry can optionally carry a description and a
    deferred *loader* — a zero-argument callable that registers additional
    capabilities the first time the namespace is searched or listed.
    """

    prefix: str
    """Dot-notation namespace prefix (e.g. ``"billing"`` or ``"billing.invoices"``)."""

    description: str = ""
    """Optional human-readable description of the namespace. Not surfaced by
    ``CapabilityRegistry.list_namespaces`` (which returns prefixes only)."""

    loader: Callable[[], list[Capability]] | None = None
    """Optional zero-arg loader invoked at most once on first access.

    The loader must return capabilities whose ``capability_id`` starts with
    :attr:`prefix` (followed by ``.`` or matching the prefix exactly). The
    registry stores the returned capabilities and marks the namespace as
    loaded — subsequent searches or list calls will not re-invoke it.
    """

    loaded: bool = False
    """``True`` once the deferred loader has been invoked (or no loader exists)."""


@dataclass(slots=True)
class CapabilityDescriptor:
    """Public-facing capability description for cross-kernel advertising.

    A descriptor is the slice of a :class:`Capability` that is safe to share
    over the wire: no driver IDs, no operation names, no Python-level
    references. JSON-serialisable via :meth:`to_dict`.
    """

    capability_id: str
    """Stable, namespaced identifier (e.g. ``"billing.invoices.list"``)."""

    name: str
    """Short human-readable name."""

    description: str
    """What the capability does."""

    safety_class: SafetyClass
    """READ / WRITE / DESTRUCTIVE — preserved verbatim from the source capability."""

    sensitivity: SensitivityTag = SensitivityTag.NONE
    """Optional sensitivity tag — preserved verbatim."""

    tags: list[str] = field(default_factory=list)
    """Search/keyword tags from the source capability."""

    parameters_schema: dict[str, Any] | None = None
    """JSON Schema describing the capability's input parameters, if available."""

    def to_dict(self) -> dict[str, Any]:
        """Serialise the descriptor to a JSON-compatible dict."""
        return {
            "capability_id": self.capability_id,
            "name": self.name,
            "description": self.description,
            "safety_class": self.safety_class.value,
            "sensitivity": self.sensitivity.value,
            "tags": list(self.tags),
            "parameters_schema": self.parameters_schema,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CapabilityDescriptor:
        """Reconstruct a descriptor from a dict produced by :meth:`to_dict`.

        Raises:
            ManifestError: If a required field is missing or ``safety_class`` /
                ``sensitivity`` carries an unrecognised value.
        """
        try:
            capability_id = data["capability_id"]
            name = data["name"]
            description = data["description"]
            safety_class_raw = data["safety_class"]
        except KeyError as exc:
            raise ManifestError(f"Capability descriptor is missing required field {exc}.") from exc
        try:
            safety_class = SafetyClass(safety_class_raw)
        except ValueError as exc:
            raise ManifestError(
                f"Capability descriptor field 'safety_class' has invalid value "
                f"{safety_class_raw!r}."
            ) from exc
        sensitivity_raw = data.get("sensitivity", SensitivityTag.NONE.value)
        try:
            sensitivity = SensitivityTag(sensitivity_raw)
        except ValueError as exc:
            raise ManifestError(
                f"Capability descriptor field 'sensitivity' has invalid value {sensitivity_raw!r}."
            ) from exc
        return cls(
            capability_id=capability_id,
            name=name,
            description=description,
            safety_class=safety_class,
            sensitivity=sensitivity,
            tags=list(data.get("tags", [])),
            parameters_schema=data.get("parameters_schema"),
        )


TrustLevel = Literal["verified", "unverified"]


@dataclass(slots=True)
class CapabilityManifest:
    """Serialisable advertisement of a kernel's capabilities.

    A manifest is what one kernel publishes for another to consume. It
    intentionally omits internal driver IDs, operation names, and any
    Python references — only the public-facing :class:`CapabilityDescriptor`
    list, the advertising kernel's identity, and a transport endpoint.

    Manifests are weaver-spec contract artifacts (I-02): the importing kernel
    must still run the full local pipeline (policy → token → firewall) on every
    imported capability invocation.
    """

    kernel_id: str
    """Stable identifier of the advertising kernel (e.g. ``"agent-a"``)."""

    version: str
    """Schema version of this manifest payload (e.g. ``"1"``)."""

    capabilities: list[CapabilityDescriptor]
    """Public-facing descriptors. Ordered by registration on the advertising side."""

    endpoint: str
    """Transport endpoint at which the advertising kernel can be reached.

    Format is transport-specific (e.g. ``"https://agent-a.example/kernel"``
    or ``"mcp://stdio:python -m mcp_server"``). The importing kernel uses it
    purely to construct a local driver — the endpoint is never invoked by
    federation itself.
    """

    trust_level: TrustLevel = "unverified"
    """Trust hint declared by the publisher. ``"verified"`` indicates the
    publisher claims independent verification (e.g. a signed manifest); the
    importing kernel still applies its configured trust policy regardless.
    """

    def to_dict(self) -> dict[str, Any]:
        """Serialise the manifest to a JSON-compatible dict."""
        return {
            "kernel_id": self.kernel_id,
            "version": self.version,
            "endpoint": self.endpoint,
            "trust_level": self.trust_level,
            "capabilities": [cap.to_dict() for cap in self.capabilities],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CapabilityManifest:
        """Reconstruct a manifest from a dict produced by :meth:`to_dict`.

        Raises:
            ManifestError: If a required field is missing, ``capabilities`` is
                not a list, or ``trust_level`` is not ``"verified"`` /
                ``"unverified"``.
        """
        try:
            kernel_id = data["kernel_id"]
            version = data["version"]
            endpoint = data["endpoint"]
            raw_capabilities = data["capabilities"]
        except KeyError as exc:
            raise ManifestError(f"Manifest is missing required field {exc}.") from exc
        if not isinstance(raw_capabilities, list):
            raise ManifestError(
                "Manifest field 'capabilities' must be a list, got "
                f"{type(raw_capabilities).__name__}."
            )
        trust_level = data.get("trust_level", "unverified")
        if trust_level not in ("verified", "unverified"):
            raise ManifestError(
                f"Manifest field 'trust_level' has invalid value {trust_level!r}; "
                "expected 'verified' or 'unverified'."
            )
        return cls(
            kernel_id=kernel_id,
            version=version,
            endpoint=endpoint,
            trust_level=trust_level,
            capabilities=[CapabilityDescriptor.from_dict(c) for c in raw_capabilities],
        )


@dataclass(slots=True)
class DryRunResult:
    """Result of a dry-run invocation — driver is never called.

    Returned by :meth:`~agent_kernel.Kernel.invoke` when ``dry_run=True``.
    """

    capability_id: str
    principal_id: str
    policy_decision: PolicyDecision
    """The policy decision encoded in the verified token."""

    driver_id: str
    """Driver that would handle the invocation (first in route plan)."""

    operation: str
    """Operation name that would be passed to the driver."""

    resolved_args: dict[str, Any]
    """Arguments that would be forwarded to the driver."""

    response_mode: ResponseMode
    budget_remaining: int | None
    """Reserved for a future cross-invocation budget mechanism; always
    ``None`` in v0.5 (no such budget is tracked today)."""

    estimated_cost: Literal["low", "medium", "high"]
    """Rough cost estimate based on the capability's safety class."""
