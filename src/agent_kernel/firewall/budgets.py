"""Per-invocation firewall budget caps.

Defines :class:`Budgets`, the dataclass enforced by the
:class:`~agent_kernel.firewall.transform.Firewall` when shaping a single
:class:`~agent_kernel.models.Frame`. Cross-invocation cumulative tracking
lives in :mod:`agent_kernel.firewall.budget_manager`.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class Budgets:
    """Budget constraints enforced by the context firewall.

    Attributes:
        max_rows: Maximum number of rows to include in a table preview.
        max_fields: Maximum number of fields per row.
        max_chars: Maximum total characters in the frame output.
        max_depth: Maximum nesting depth when traversing dict/list values.
    """

    max_rows: int = 50
    max_fields: int = 20
    max_chars: int = 4000
    max_depth: int = 3
