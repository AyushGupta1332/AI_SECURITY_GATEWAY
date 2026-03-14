"""
Execution Controller
====================
Central orchestrator for the AI Security Gateway.
All tool execution requests flow through this controller.

Pipeline:
1. Resolve identity context
2. Check if tool exists
3. Validate agent identity
4. Evaluate identity-level access (ABAC, delegation, purpose)
5. Validate tool permission
6. Validate parameters
7. Run injection detection
7.5 Semantic intent analysis (LLM)
8. Calculate risk score (including identity + intent modifiers)
9. Make allow/deny decision
10. Generate LLM policy reasoning
11. Log structured decision
12. If allowed → execute tool
"""

import time
from typing import Any

from gateway.identity import RequestIdentityContext, build_identity_context
from gateway.policy_engine import PolicyEngine
from gateway.parameter_validator import ParameterValidator
from gateway.injection_detector import InjectionDetector
from gateway.risk_engine import RiskEngine
from gateway.logger import log_decision
from gateway.llm_intelligence import get_intent_analyzer, get_policy_reasoner
from tools.email_tool import send_email
from tools.file_tool import read_file, write_file
from tools.db_tool import query_database


# Registry of available tool functions
TOOL_REGISTRY: dict[str, Any] = {
    "read_file": read_file,
    "write_file": write_file,
    "send_email": send_email,
    "query_database": query_database,
}


class ExecutionController:
    """
    Central orchestrator that evaluates every tool execution request
    through a multi-stage security pipeline before allowing or denying it.
    Now identity-aware with pluggable policy providers.
    """

    def __init__(self, policy_engine: PolicyEngine | None = None) -> None:
        self._policy = policy_engine or PolicyEngine()
        self._validator = ParameterValidator()
        self._detector = InjectionDetector()
        self._risk_engine = RiskEngine(self._policy.risk_weights)
        self._intent_analyzer = get_intent_analyzer()
        self._policy_reasoner = get_policy_reasoner()

    @property
    def current_mode(self) -> str:
        return self._policy.mode

    def reload_policy(self) -> dict[str, str]:
        """Reload the policy configuration from disk without restart."""
        self._policy.reload()
        self._risk_engine = RiskEngine(self._policy.risk_weights)
        return {"status": "success", "message": "Policy reloaded successfully"}

    def switch_mode(self, mode: str) -> dict[str, str]:
        """Switch the active policy mode (e.g. default → healthcare)."""
        result = self._policy.switch_mode(mode)
        self._risk_engine = RiskEngine(self._policy.risk_weights)
        return result

    def execute(
        self,
        agent_id: str,
        tool: str,
        parameters: dict[str, Any],
        original_prompt: str = "",
        dry_run: bool = False,
        # New identity fields (all optional for backward compatibility)
        user_id: str | None = None,
        tenant: str | None = None,
        clearance: str | None = None,
        department: str | None = None,
        session_id: str | None = None,
        purpose: str | None = None,
        justification: str | None = None,
        delegation_chain: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """
        Process a tool execution request through the security pipeline.

        Accepts optional identity fields alongside the required agent_id/tool/params.
        If no identity fields are provided, defaults are used (backward compatible).
        """
        flags: list[str] = []
        denial_reasons: list[str] = []
        _start = time.time()

        # ── Step 1: Build identity context ────────────────────────
        identity = build_identity_context(
            agent_id=agent_id,
            user_id=user_id,
            tenant=tenant,
            clearance=clearance,
            department=department,
            session_id=session_id,
            purpose=purpose,
            justification=justification,
            delegation_chain=delegation_chain,
        )

        # ── Step 2: Check if tool exists ──────────────────────────
        if tool not in TOOL_REGISTRY:
            return self._build_denied_response(
                identity=identity,
                tool=tool,
                risk_score=0,
                flags=["unknown_tool"],
                reason=f"Tool '{tool}' is not registered in the gateway",
                parameters=parameters,
                duration_ms=(time.time() - _start) * 1000,
            )

        # ── Step 3: Validate agent identity ───────────────────────
        unknown_agent = not self._policy.agent_exists(agent_id)
        if unknown_agent:
            flags.append("unknown_agent")
            denial_reasons.append(f"Agent '{agent_id}' is not recognized in the policy")

        # ── Step 4: Identity-level evaluation (ABAC, delegation, purpose) ──
        identity_denied = False
        if not unknown_agent:
            identity_decision = self._policy.evaluate_identity(identity, tool)
            if not identity_decision.allowed:
                identity_denied = True
                flags.extend(identity_decision.flags)
                denial_reasons.append(identity_decision.reason)
            else:
                flags.extend(identity_decision.flags)

        # ── Step 5: Validate tool permission ──────────────────────
        tool_denied = False
        if not unknown_agent and not identity_denied:
            if not self._policy.is_tool_allowed(agent_id, tool):
                flags.append("tool_not_permitted")
                denial_reasons.append(
                    f"Tool '{tool}' is not permitted for agent '{agent_id}'"
                )
                tool_denied = True

        # ── Step 6: Validate parameters ───────────────────────────
        parameter_violation = False
        param_reason = ""
        if not unknown_agent and not tool_denied and not identity_denied:
            constraints = self._policy.get_tool_constraints(agent_id, tool)
            is_valid, param_reason = self._validator.validate(
                tool, parameters, constraints
            )
            if not is_valid:
                parameter_violation = True
                flags.append("parameter_violation")
                denial_reasons.append(param_reason)

        # ── Step 7: Injection detection (heuristic + LLM) ─────────
        injection_detected, matched_patterns = self._detector.scan(
            prompt=original_prompt,
            tool=tool,
            parameters=parameters,
        )
        if injection_detected:
            flags.append("prompt_injection_detected")
            flags.extend([f"pattern:{p}" for p in matched_patterns])

        # ── Step 7.5: Semantic intent analysis (LLM) ──────────────
        intent_result = None
        intent_risk_adj = 0
        try:
            intent_result = self._intent_analyzer.analyze(
                prompt=original_prompt,
                tool=tool,
                parameters=parameters,
                agent_id=agent_id,
                purpose=purpose or "",
            )
            if intent_result:
                if not intent_result.get("intent_aligned", True):
                    flags.append("intent_mismatch")
                    mismatch = intent_result.get("mismatch_type", "unknown")
                    flags.append(f"mismatch_type:{mismatch}")
                intent_risk_adj = int(intent_result.get("risk_adjustment", 0))
                intent_risk_adj = max(-10, min(30, intent_risk_adj))  # clamp
        except Exception:
            pass  # never block pipeline

        # ── Step 8: Risk scoring ──────────────────────────────────
        is_sensitive = tool in self._policy.sensitive_tools
        if is_sensitive:
            flags.append("sensitive_tool")

        risk_score, risk_factors = self._risk_engine.evaluate(
            is_sensitive_tool=is_sensitive,
            injection_detected=injection_detected,
            parameter_violation=parameter_violation,
            unknown_agent=unknown_agent,
        )

        # Add identity-driven risk modifiers
        identity_modifiers = self._policy.get_risk_modifiers(identity, tool)
        for factor_name, points in identity_modifiers.items():
            risk_score += points
            risk_factors.append(f"{factor_name} (+{points})")
            flags.append(factor_name)

        # Add intent analysis risk adjustment
        if intent_risk_adj != 0:
            risk_score += intent_risk_adj
            risk_factors.append(f"intent_analysis ({'+' if intent_risk_adj > 0 else ''}{intent_risk_adj})")
        risk_score = max(0, min(100, risk_score))  # clamp 0-100

        # ── Step 9: Make decision ─────────────────────────────────
        should_deny = (
            unknown_agent
            or identity_denied
            or tool_denied
            or parameter_violation
            or self._risk_engine.is_above_threshold(
                risk_score, self._policy.risk_threshold
            )
        )

        if should_deny:
            reason = "; ".join(denial_reasons) if denial_reasons else (
                f"Risk score {risk_score} exceeds threshold {self._policy.risk_threshold}"
            )
            # Generate LLM reasoning for denial
            llm_reasoning = self._generate_reasoning(
                decision="DENIED", risk_score=risk_score, agent_id=agent_id,
                tool=tool, flags=flags, risk_factors=risk_factors,
                reason=reason, identity=identity,
            )
            return self._build_denied_response(
                identity=identity,
                tool=tool,
                risk_score=risk_score,
                flags=flags,
                reason=reason,
                parameters=parameters,
                risk_factors=risk_factors,
                duration_ms=(time.time() - _start) * 1000,
                intent_analysis=intent_result,
                llm_reasoning=llm_reasoning,
            )

        # ── Step 10: Build reason string for allowed ──────────────
        reason = param_reason if param_reason else "All checks passed"
        if injection_detected:
            reason += " (WARNING: prompt injection patterns detected but risk within threshold)"

        # ── Step 11: Execute tool (or dry-run) ────────────────────
        # Generate LLM reasoning for allowed request
        llm_reasoning = self._generate_reasoning(
            decision="ALLOWED", risk_score=risk_score, agent_id=agent_id,
            tool=tool, flags=flags, risk_factors=risk_factors,
            reason=reason, identity=identity,
        )

        if dry_run:
            flags.append("dry_run")
            log_decision(
                agent_id=agent_id,
                tool=tool,
                decision="ALLOWED (DRY RUN)",
                risk_score=risk_score,
                flags=flags,
                reason=reason,
                parameters=parameters,
                identity_context=identity.to_dict(),
                mode=self.current_mode,
                duration_ms=(time.time() - _start) * 1000,
            )
            return {
                "decision": "ALLOWED (DRY RUN)",
                "risk_score": risk_score,
                "risk_factors": risk_factors,
                "flags": flags,
                "reason": reason,
                "result": None,
                "identity": identity.to_dict(),
                "mode": self.current_mode,
                "intent_analysis": intent_result,
                "llm_reasoning": llm_reasoning,
            }

        # Execute the tool
        tool_fn = TOOL_REGISTRY[tool]
        tool_result = tool_fn(**parameters)

        # ── Step 12: Log and return ───────────────────────────────
        log_decision(
            agent_id=agent_id,
            tool=tool,
            decision="ALLOWED",
            risk_score=risk_score,
            flags=flags,
            reason=reason,
            parameters=parameters,
            identity_context=identity.to_dict(),
            mode=self.current_mode,
            duration_ms=(time.time() - _start) * 1000,
        )

        return {
            "decision": "ALLOWED",
            "risk_score": risk_score,
            "risk_factors": risk_factors,
            "flags": flags,
            "reason": reason,
            "result": tool_result,
            "identity": identity.to_dict(),
            "mode": self.current_mode,
            "intent_analysis": intent_result,
            "llm_reasoning": llm_reasoning,
        }

    def _generate_reasoning(
        self,
        decision: str,
        risk_score: int,
        agent_id: str,
        tool: str,
        flags: list[str],
        risk_factors: list[str],
        reason: str,
        identity: RequestIdentityContext,
    ) -> dict[str, Any] | None:
        """Generate LLM policy reasoning (non-blocking)."""
        try:
            return self._policy_reasoner.explain(
                decision=decision,
                risk_score=risk_score,
                threshold=self._policy.risk_threshold,
                agent_id=agent_id,
                tool=tool,
                flags=flags,
                risk_factors=risk_factors,
                reason=reason,
                mode=self.current_mode,
                identity=identity.to_dict(),
            )
        except Exception:
            return None

    def _build_denied_response(
        self,
        identity: RequestIdentityContext,
        tool: str,
        risk_score: int,
        flags: list[str],
        reason: str,
        parameters: dict[str, Any],
        risk_factors: list[str] | None = None,
        duration_ms: float = 0,
        intent_analysis: dict[str, Any] | None = None,
        llm_reasoning: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build and log a DENIED response."""
        log_decision(
            agent_id=identity.agent_id,
            tool=tool,
            decision="DENIED",
            risk_score=risk_score,
            flags=flags,
            reason=reason,
            parameters=parameters,
            identity_context=identity.to_dict(),
            mode=self.current_mode,
            duration_ms=duration_ms,
        )

        return {
            "decision": "DENIED",
            "risk_score": risk_score,
            "risk_factors": risk_factors or [],
            "flags": flags,
            "reason": reason,
            "result": None,
            "identity": identity.to_dict(),
            "mode": self.current_mode,
            "intent_analysis": intent_analysis,
            "llm_reasoning": llm_reasoning,
        }
