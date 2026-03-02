"""TraceStore: in-memory audit trail for kernel invocations."""

from __future__ import annotations

from .errors import AgentKernelError
from .models import ActionTrace


class TraceStore:
    """Stores :class:`ActionTrace` records indexed by ``action_id``.

    All invocations recorded by the :class:`~agent_kernel.kernel.Kernel` are
    retrievable here for audit and explainability purposes.
    """

    def __init__(self) -> None:
        self._traces: dict[str, ActionTrace] = {}

    def record(self, trace: ActionTrace) -> None:
        """Store an action trace.

        Args:
            trace: The :class:`ActionTrace` to record.
        """
        self._traces[trace.action_id] = trace

    def get(self, action_id: str) -> ActionTrace:
        """Retrieve an action trace by its ID.

        Args:
            action_id: The unique action identifier.

        Returns:
            The :class:`ActionTrace` for that action.

        Raises:
            AgentKernelError: If no trace with that ID exists.
        """
        try:
            return self._traces[action_id]
        except KeyError:
            raise AgentKernelError(f"No action trace found for action_id='{action_id}'.") from None

    def list_all(self) -> list[ActionTrace]:
        """Return all recorded traces in insertion order."""
        return list(self._traces.values())
