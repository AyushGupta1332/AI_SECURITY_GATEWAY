"""
Policy Engine
=============
Thin coordinator that delegates to a pluggable PolicyProvider.
Manages provider lifecycle, mode switching, and exposes
a unified interface for the execution controller.
"""

from typing import Any

from gateway.identity import RequestIdentityContext
from gateway.policy_provider import (
    PolicyDecision,
    PolicyProvider,
    DefaultPolicyProvider,
    get_provider,
)


class PolicyEngine:
    """
    Coordinates policy evaluation through a pluggable provider.
    Supports runtime mode switching (e.g. default → healthcare).
    """

    def __init__(self, provider: PolicyProvider | None = None) -> None:
        self._provider = provider or DefaultPolicyProvider()

    @property
    def mode(self) -> str:
        return self._provider.get_mode_name()

    def switch_mode(self, mode: str) -> dict[str, str]:
        """Swap the active policy provider at runtime."""
        self._provider = get_provider(mode)
        return {"status": "ok", "message": f"Switched to '{mode}' mode", "mode": mode}

    def reload(self) -> None:
        """Reload the active provider's config from disk."""
        self._provider.load_config()

    # ── Identity-aware evaluation ─────────────────────────────

    def evaluate_identity(self, ctx: RequestIdentityContext, tool: str) -> PolicyDecision:
        """Delegate identity-level checks to the active provider."""
        return self._provider.evaluate_identity(ctx, tool)

    def get_risk_modifiers(self, ctx: RequestIdentityContext, tool: str) -> dict[str, int]:
        """Get identity-driven risk adjustments from the active provider."""
        return self._provider.get_risk_modifiers(ctx, tool)

    # ── Agent / tool checks (backward compatible) ─────────────

    def agent_exists(self, agent_id: str) -> bool:
        return self._provider.agent_exists(agent_id)

    def is_tool_allowed(self, agent_id: str, tool_name: str) -> bool:
        return self._provider.is_tool_allowed(agent_id, tool_name)

    def get_tool_constraints(self, agent_id: str, tool_name: str) -> dict[str, Any]:
        return self._provider.get_tool_constraints(agent_id, tool_name)

    def get_user_config(self, user_id: str) -> dict[str, Any]:
        return self._provider.get_user_config(user_id)

    # ── Risk config ───────────────────────────────────────────

    @property
    def risk_threshold(self) -> int:
        return self._provider.get_risk_threshold()

    @property
    def sensitive_tools(self) -> list[str]:
        return self._provider.get_sensitive_tools()

    @property
    def risk_weights(self) -> dict[str, int]:
        return self._provider.get_risk_weights()
