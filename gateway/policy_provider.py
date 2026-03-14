"""
Policy Provider
===============
Abstract policy provider interface and concrete implementations.
Supports swappable "industry modes" without changing core gateway logic.

Each provider loads its own config and knows how to evaluate access
based on identity context, tool name, and parameters.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from gateway.identity import RequestIdentityContext


CONFIG_DIR = Path(__file__).parent.parent / "config"


# ── Policy Decision ───────────────────────────────────────────

class PolicyDecision:
    """Result of a policy evaluation."""

    def __init__(
        self,
        allowed: bool,
        reason: str,
        flags: list[str] | None = None,
        extra_constraints: dict[str, Any] | None = None,
    ) -> None:
        self.allowed = allowed
        self.reason = reason
        self.flags = flags or []
        self.extra_constraints = extra_constraints or {}


# ── Abstract Provider ─────────────────────────────────────────

class PolicyProvider(ABC):
    """
    Base class for all policy providers.
    Subclass this to create an industry-specific policy mode.
    """

    @abstractmethod
    def get_mode_name(self) -> str:
        """Return the human-readable name of this policy mode."""
        ...

    @abstractmethod
    def load_config(self) -> None:
        """Load or reload the underlying configuration."""
        ...

    @abstractmethod
    def agent_exists(self, agent_id: str) -> bool:
        """Check if the agent is registered."""
        ...

    @abstractmethod
    def is_tool_allowed(self, agent_id: str, tool_name: str) -> bool:
        """Check if the agent can use this tool."""
        ...

    @abstractmethod
    def get_tool_constraints(self, agent_id: str, tool_name: str) -> dict[str, Any]:
        """Get parameter constraints for a tool/agent pair."""
        ...

    @abstractmethod
    def evaluate_identity(self, ctx: RequestIdentityContext, tool: str) -> PolicyDecision:
        """
        Evaluate identity-level access (ABAC, delegation, purpose).
        Called before parameter validation and injection scanning.
        """
        ...

    @abstractmethod
    def get_risk_modifiers(self, ctx: RequestIdentityContext, tool: str) -> dict[str, int]:
        """
        Return extra risk point adjustments based on identity context.
        Keys are risk factor names, values are points to add.
        """
        ...

    # Shared config properties — subclasses read from their own config dict

    @abstractmethod
    def get_risk_threshold(self) -> int:
        ...

    @abstractmethod
    def get_sensitive_tools(self) -> list[str]:
        ...

    @abstractmethod
    def get_risk_weights(self) -> dict[str, int]:
        ...

    @abstractmethod
    def get_user_config(self, user_id: str) -> dict[str, Any]:
        """Get user attributes from policy config."""
        ...


# ── Default Provider ──────────────────────────────────────────

class DefaultPolicyProvider(PolicyProvider):
    """
    Standard policy provider — loads config/policy.json.
    This is the refactored version of the original PolicyEngine behavior,
    extended with identity awareness.
    """

    def __init__(self, config_path: Path | None = None) -> None:
        self._config_path = config_path or (CONFIG_DIR / "policy.json")
        self._config: dict[str, Any] = {}
        self.load_config()

    def get_mode_name(self) -> str:
        return self._config.get("mode", "default")

    def load_config(self) -> None:
        with open(self._config_path, "r", encoding="utf-8") as f:
            self._config = json.load(f)

    def agent_exists(self, agent_id: str) -> bool:
        return agent_id in self._config.get("agents", {})

    def is_tool_allowed(self, agent_id: str, tool_name: str) -> bool:
        agent = self._config.get("agents", {}).get(agent_id, {})
        return tool_name in agent.get("allowed_tools", {})

    def get_tool_constraints(self, agent_id: str, tool_name: str) -> dict[str, Any]:
        agent = self._config.get("agents", {}).get(agent_id, {})
        tool = agent.get("allowed_tools", {}).get(tool_name, {})
        return tool.get("constraints", {})

    def get_risk_threshold(self) -> int:
        return int(self._config.get("risk_threshold", 70))

    def get_sensitive_tools(self) -> list[str]:
        return self._config.get("sensitive_tools", [])

    def get_risk_weights(self) -> dict[str, int]:
        return self._config.get("risk_weights", {
            "sensitive_tool": 20,
            "suspicious_prompt": 30,
            "parameter_violation": 40,
            "unknown_agent": 50,
        })

    def get_user_config(self, user_id: str) -> dict[str, Any]:
        return self._config.get("users", {}).get(user_id, {})

    def evaluate_identity(self, ctx: RequestIdentityContext, tool: str) -> PolicyDecision:
        """
        Default mode identity evaluation:
        - Check delegation depth
        - Check tenant isolation (if enabled)
        - Check clearance level (if tool requires it)
        """
        identity_rules = self._config.get("identity_rules", {})
        abac = self._config.get("abac", {})
        flags: list[str] = []

        # Delegation depth check
        max_depth = identity_rules.get("max_delegation_depth", 5)
        if ctx.delegation.depth > max_depth:
            return PolicyDecision(
                allowed=False,
                reason=f"Delegation chain depth ({ctx.delegation.depth}) exceeds maximum ({max_depth})",
                flags=["delegation_depth_exceeded"],
            )

        # Tenant isolation
        if abac.get("tenant_isolation", False) and ctx.user.tenant != "default":
            # Check if user's tenant matches any allowed tenant for the agent
            agent_config = self._config.get("agents", {}).get(ctx.agent.agent_id, {})
            allowed_tenants = agent_config.get("allowed_tenants", [])
            if allowed_tenants and ctx.user.tenant not in allowed_tenants:
                return PolicyDecision(
                    allowed=False,
                    reason=f"Tenant '{ctx.user.tenant}' not allowed for agent '{ctx.agent.agent_id}'",
                    flags=["tenant_violation"],
                )

        # Clearance level check
        clearance_levels = abac.get("clearance_levels", ["public", "standard", "confidential", "admin"])
        tool_clearance = self._get_tool_clearance(tool)
        if tool_clearance:
            user_level = clearance_levels.index(ctx.user.clearance) if ctx.user.clearance in clearance_levels else 0
            required_level = clearance_levels.index(tool_clearance) if tool_clearance in clearance_levels else 0
            if user_level < required_level:
                return PolicyDecision(
                    allowed=False,
                    reason=f"Clearance '{ctx.user.clearance}' insufficient — tool requires '{tool_clearance}'",
                    flags=["clearance_mismatch"],
                )

        return PolicyDecision(allowed=True, reason="Identity checks passed", flags=flags)

    def get_risk_modifiers(self, ctx: RequestIdentityContext, tool: str) -> dict[str, int]:
        """Add risk points based on identity signals."""
        modifiers: dict[str, int] = {}
        identity_rules = self._config.get("identity_rules", {})

        # Missing purpose
        if identity_rules.get("require_purpose", False) and not ctx.purpose.purpose:
            modifiers["missing_purpose"] = 10

        # Long delegation chain
        if ctx.delegation.depth > 2:
            modifiers["long_delegation_chain"] = 15

        return modifiers

    def _get_tool_clearance(self, tool: str) -> str:
        """Look up the minimum clearance level required for a tool."""
        tool_clearances = self._config.get("tool_clearances", {})
        return tool_clearances.get(tool, "")


# ── Healthcare Provider ───────────────────────────────────────

class HealthcarePolicyProvider(DefaultPolicyProvider):
    """
    Healthcare industry mode — extends default with stricter rules:
    - Purpose is always required
    - Tenant isolation is always enforced
    - PHI-related tools have higher clearance requirements
    - Longer audit reasons
    """

    def __init__(self) -> None:
        super().__init__(config_path=CONFIG_DIR / "policy_healthcare.json")

    def get_mode_name(self) -> str:
        return "healthcare"

    def evaluate_identity(self, ctx: RequestIdentityContext, tool: str) -> PolicyDecision:
        """Healthcare mode always requires purpose binding."""
        # Purpose is mandatory in healthcare
        if not ctx.purpose.purpose:
            return PolicyDecision(
                allowed=False,
                reason="Healthcare mode requires a declared purpose for all tool executions",
                flags=["missing_purpose_healthcare"],
            )

        # Check purpose against allowed purposes for this tool
        allowed_purposes = self._config.get("allowed_purposes", {}).get(tool, [])
        if allowed_purposes and ctx.purpose.purpose not in allowed_purposes:
            return PolicyDecision(
                allowed=False,
                reason=f"Purpose '{ctx.purpose.purpose}' not approved for tool '{tool}' under healthcare policy",
                flags=["purpose_not_approved"],
            )

        # Run the rest of the standard identity checks
        return super().evaluate_identity(ctx, tool)

    def get_risk_modifiers(self, ctx: RequestIdentityContext, tool: str) -> dict[str, int]:
        """Healthcare adds stricter risk for missing justification."""
        modifiers = super().get_risk_modifiers(ctx, tool)

        # In healthcare, missing justification is riskier
        if not ctx.purpose.justification:
            modifiers["missing_justification"] = 15

        # PHI tools get extra scrutiny
        phi_tools = self._config.get("phi_tools", [])
        if tool in phi_tools:
            modifiers["phi_tool_access"] = 10

        return modifiers


# ── Provider Registry ─────────────────────────────────────────

PROVIDER_REGISTRY: dict[str, type[PolicyProvider]] = {
    "default": DefaultPolicyProvider,
    "healthcare": HealthcarePolicyProvider,
}


def get_provider(mode: str = "default") -> PolicyProvider:
    """Instantiate a policy provider by mode name."""
    provider_class = PROVIDER_REGISTRY.get(mode)
    if not provider_class:
        raise ValueError(f"Unknown policy mode: '{mode}'. Available: {list(PROVIDER_REGISTRY.keys())}")
    return provider_class()
