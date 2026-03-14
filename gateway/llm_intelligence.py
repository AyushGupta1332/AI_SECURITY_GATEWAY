"""
LLM Intelligence Layer
=======================
LLM-powered analysis modules for the AI Security Gateway:

  1. Intent Analyzer   — Does the stated intent match the tool action?
  2. Policy Reasoner   — Natural language explanation of allow/deny decisions
  3. Audit Intelligence — Trend analysis and anomaly detection on audit logs

All modules use Groq (llama-3.3-70b-versatile) and degrade gracefully
if the API is unavailable — they NEVER block the pipeline.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

logger = logging.getLogger("ai_security_gateway")

# ── Shared Groq client ───────────────────────────────────────

_groq_client = None


def _get_groq():
    """Lazy-init Groq client singleton."""
    global _groq_client
    if _groq_client is not None:
        return _groq_client

    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        return None

    try:
        from groq import Groq
        _groq_client = Groq(api_key=api_key)
        return _groq_client
    except ImportError:
        logger.warning("groq package not installed — LLM intelligence disabled")
        return None


GROQ_MODEL = "llama-3.3-70b-versatile"


def _llm_call(system: str, user: str, max_tokens: int = 400) -> str | None:
    """Make a Groq LLM call. Returns raw text or None on failure."""
    client = _get_groq()
    if not client:
        return None
    try:
        response = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=0.1,
            max_tokens=max_tokens,
            timeout=8.0,
        )
        raw = response.choices[0].message.content.strip()
        # Strip markdown code fences if present
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
        return raw
    except Exception as e:
        logger.warning("LLM call failed: %s", str(e))
        return None


# ══════════════════════════════════════════════════════════════
# 1. SEMANTIC INTENT ANALYZER
# ══════════════════════════════════════════════════════════════

INTENT_SYSTEM = """You are a security intent analyzer for an AI execution gateway.
Your job is to determine if a user's stated intent MATCHES the tool action being performed.

Intent mismatch is a red flag — it could indicate:
- Prompt injection (user says one thing, action does another)
- Confused agent behavior
- Social engineering (distraction in prompt, real goal in parameters)

You must respond ONLY with valid JSON (no markdown)."""

INTENT_USER = """Analyze whether the stated intent aligns with the tool action:

STATED INTENT (original prompt):
{prompt}

ACTUAL ACTION:
- Tool: {tool}
- Parameters: {parameters}
- Agent: {agent_id}
- Declared purpose: {purpose}

Respond with JSON:
{{
  "intent_aligned": true/false,
  "alignment_score": 0.0-1.0 (1.0 = perfectly aligned),
  "stated_intent": "brief summary of what user wants",
  "actual_effect": "brief summary of what tool will do",
  "mismatch_type": "none" | "scope_escalation" | "target_mismatch" | "action_mismatch" | "data_exfiltration" | "distraction",
  "risk_adjustment": -10 to +30 (how much to adjust risk score),
  "explanation": "1-2 sentence explanation"
}}"""


class IntentAnalyzer:
    """
    Semantic intent analysis — checks if what the user says matches
    what the tool actually does. Catches sophisticated mismatches
    that heuristics can't detect.
    """

    def analyze(
        self,
        prompt: str,
        tool: str,
        parameters: dict[str, Any],
        agent_id: str = "",
        purpose: str = "",
    ) -> dict[str, Any] | None:
        """
        Analyze intent alignment. Returns analysis dict or None if LLM unavailable.
        """
        if not prompt or len(prompt.strip()) < 15:
            return None

        start = time.time()

        user_msg = INTENT_USER.format(
            prompt=prompt[:1500],
            tool=tool,
            parameters=json.dumps(parameters, default=str)[:500],
            agent_id=agent_id or "unknown",
            purpose=purpose or "not declared",
        )

        raw = _llm_call(INTENT_SYSTEM, user_msg, max_tokens=300)
        if not raw:
            return None

        elapsed = (time.time() - start) * 1000

        try:
            result = json.loads(raw)
            result["analysis_time_ms"] = round(elapsed, 1)
            logger.info(
                "Intent analysis: aligned=%s score=%.2f mismatch=%s time=%.0fms",
                result.get("intent_aligned"), result.get("alignment_score", 0),
                result.get("mismatch_type", "none"), elapsed,
            )
            return result
        except json.JSONDecodeError:
            logger.warning("Intent analysis returned invalid JSON")
            return None


# ══════════════════════════════════════════════════════════════
# 2. POLICY REASONER
# ══════════════════════════════════════════════════════════════

REASONER_SYSTEM = """You are a security policy reasoning engine for an AI execution gateway.
Your job is to generate clear, human-readable explanations of security decisions.

You explain WHY a request was allowed or denied in plain English, referencing the
specific policy rules, risk factors, and identity checks that led to the decision.

Your explanations should be:
- Clear and concise (2-4 sentences)
- Reference specific security factors
- Helpful for security auditors reviewing logs
- Professional and precise

Respond ONLY with valid JSON (no markdown)."""

REASONER_USER = """Generate a human-readable explanation for this security decision:

DECISION: {decision}
RISK SCORE: {risk_score}/{threshold} (threshold)
AGENT: {agent_id}
TOOL: {tool}
MODE: {mode}

FLAGS RAISED: {flags}
RISK FACTORS: {risk_factors}
TECHNICAL REASON: {reason}

IDENTITY:
- User: {user_id} | Tenant: {tenant} | Clearance: {clearance}
- Purpose: {purpose}

Respond with JSON:
{{
  "summary": "1-sentence executive summary",
  "explanation": "2-4 sentence detailed explanation for auditors",
  "severity": "info" | "warning" | "critical",
  "recommendations": ["list of 1-3 actionable recommendations"],
  "policy_references": ["list of specific policy rules that applied"]
}}"""


class PolicyReasoner:
    """
    Generates natural language explanations of security decisions.
    Makes audit logs human-readable and actionable.
    """

    def explain(
        self,
        decision: str,
        risk_score: int,
        threshold: int,
        agent_id: str,
        tool: str,
        flags: list[str],
        risk_factors: list[str],
        reason: str,
        mode: str = "default",
        identity: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """
        Generate a natural language explanation. Returns dict or None if unavailable.
        """
        id_ctx = identity or {}
        user_info = id_ctx.get("user", {})

        user_msg = REASONER_USER.format(
            decision=decision,
            risk_score=risk_score,
            threshold=threshold,
            agent_id=agent_id,
            tool=tool,
            mode=mode,
            flags=", ".join(flags) if flags else "none",
            risk_factors=", ".join(risk_factors) if risk_factors else "none",
            reason=reason[:500],
            user_id=user_info.get("user_id", "anonymous"),
            tenant=user_info.get("tenant", "default"),
            clearance=user_info.get("clearance", "public"),
            purpose=id_ctx.get("purpose", {}).get("purpose", "not declared"),
        )

        start = time.time()
        raw = _llm_call(REASONER_SYSTEM, user_msg, max_tokens=400)
        elapsed = (time.time() - start) * 1000

        if not raw:
            return None

        try:
            result = json.loads(raw)
            result["reasoning_time_ms"] = round(elapsed, 1)
            logger.info(
                "Policy reasoning: severity=%s time=%.0fms",
                result.get("severity", "unknown"), elapsed,
            )
            return result
        except json.JSONDecodeError:
            logger.warning("Policy reasoner returned invalid JSON")
            return None


# ══════════════════════════════════════════════════════════════
# 3. AUDIT INTELLIGENCE
# ══════════════════════════════════════════════════════════════

AUDIT_SYSTEM = """You are a security analytics engine for an AI execution gateway.
Your job is to analyze audit event data and produce insightful security summaries.

You identify:
- Patterns and trends (increasing/decreasing risk, new attack vectors)
- Anomalies (unusual agents, tools, or timing patterns)
- Security posture assessment (overall health of the system)
- Actionable recommendations for security improvements

Be specific and quantitative where possible. Reference actual data.
Respond ONLY with valid JSON (no markdown)."""

AUDIT_USER = """Analyze these audit statistics and recent events, then produce a security intelligence briefing:

STATISTICS:
- Total events: {total_events}
- Allowed: {allowed} | Denied: {denied}
- Average risk score: {avg_risk}
- Last 24h events: {last_24h}
- Injection attempts: {injections}
- Top agents: {top_agents}
- Top denial reasons: {top_denials}

RECENT EVENTS (last {event_count}):
{recent_events}

Respond with JSON:
{{
  "executive_summary": "2-3 sentence overview for leadership",
  "threat_level": "low" | "moderate" | "elevated" | "high" | "critical",
  "key_findings": ["list of 3-5 specific findings with data"],
  "anomalies": ["list of unusual patterns detected"],
  "trends": {{
    "risk_trend": "increasing" | "stable" | "decreasing",
    "volume_trend": "increasing" | "stable" | "decreasing",
    "description": "1-2 sentence trend summary"
  }},
  "recommendations": ["list of 3-5 prioritized security recommendations"],
  "posture_score": 0-100 (overall security health: 100=excellent)
}}"""


class AuditIntelligence:
    """
    LLM-powered audit intelligence — analyzes event data and produces
    security briefings, anomaly detection, and trend analysis.
    """

    def generate_briefing(
        self,
        stats: dict[str, Any],
        recent_events: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        """
        Generate a security intelligence briefing.
        """
        # Format recent events for the LLM
        events_text = ""
        for e in recent_events[:15]:  # Limit to 15 events
            flags_str = ", ".join(e.get("flags", [])[:5])
            events_text += (
                f"  [{e.get('timestamp', '?')[:19]}] "
                f"{e.get('decision', '?'):8s} "
                f"agent={e.get('agent_id', '?')} "
                f"tool={e.get('tool', '?')} "
                f"risk={e.get('risk_score', 0)} "
                f"flags=[{flags_str}]\n"
            )

        if not events_text:
            events_text = "  (no recent events)"

        user_msg = AUDIT_USER.format(
            total_events=stats.get("total_events", 0),
            allowed=stats.get("allowed", 0),
            denied=stats.get("denied", 0),
            avg_risk=stats.get("avg_risk_score", 0),
            last_24h=stats.get("last_24h", 0),
            injections=stats.get("injection_attempts", 0),
            top_agents=json.dumps(stats.get("top_agents", []))[:300],
            top_denials=json.dumps(stats.get("top_denials", []))[:300],
            event_count=len(recent_events),
            recent_events=events_text,
        )

        start = time.time()
        raw = _llm_call(AUDIT_SYSTEM, user_msg, max_tokens=600)
        elapsed = (time.time() - start) * 1000

        if not raw:
            return None

        try:
            result = json.loads(raw)
            result["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            result["analysis_time_ms"] = round(elapsed, 1)
            logger.info(
                "Audit intelligence: threat=%s posture=%s time=%.0fms",
                result.get("threat_level", "unknown"),
                result.get("posture_score", "?"),
                elapsed,
            )
            return result
        except json.JSONDecodeError:
            logger.warning("Audit intelligence returned invalid JSON")
            return None


# ── Module-level singletons ──────────────────────────────────

_intent_analyzer: IntentAnalyzer | None = None
_policy_reasoner: PolicyReasoner | None = None
_audit_intel: AuditIntelligence | None = None


def get_intent_analyzer() -> IntentAnalyzer:
    global _intent_analyzer
    if _intent_analyzer is None:
        _intent_analyzer = IntentAnalyzer()
    return _intent_analyzer


def get_policy_reasoner() -> PolicyReasoner:
    global _policy_reasoner
    if _policy_reasoner is None:
        _policy_reasoner = PolicyReasoner()
    return _policy_reasoner


def get_audit_intelligence() -> AuditIntelligence:
    global _audit_intel
    if _audit_intel is None:
        _audit_intel = AuditIntelligence()
    return _audit_intel
