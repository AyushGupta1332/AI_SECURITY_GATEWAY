"""
Risk Scoring Engine
===================
Modular risk calculation based on configurable weights.
Risk score accumulates from multiple factors during evaluation.
Separate from policy logic — receives weights as configuration.
"""

from typing import Any


class RiskEngine:
    """
    Calculates cumulative risk score for a tool execution request
    based on configurable risk weights and detected risk factors.
    """

    def __init__(self, risk_weights: dict[str, int]) -> None:
        """
        Initialize the RiskEngine.

        Args:
            risk_weights: Dict mapping risk factor names to their point values.
                Expected keys: sensitive_tool, suspicious_prompt,
                parameter_violation, unknown_agent.
        """
        self._weights = risk_weights

    def evaluate(
        self,
        is_sensitive_tool: bool,
        injection_detected: bool,
        parameter_violation: bool,
        unknown_agent: bool,
    ) -> tuple[int, list[str]]:
        """
        Evaluate risk for a single request.

        Args:
            is_sensitive_tool: Whether the requested tool is classified as sensitive.
            injection_detected: Whether prompt injection was detected.
            parameter_violation: Whether parameter validation failed.
            unknown_agent: Whether the agent is not recognized in the policy.

        Returns:
            A tuple of (total_risk_score, list_of_contributing_factors).
        """
        risk_score: int = 0
        risk_factors: list[str] = []

        if unknown_agent:
            points = self._weights.get("unknown_agent", 50)
            risk_score += points
            risk_factors.append(f"unknown_agent (+{points})")

        if is_sensitive_tool:
            points = self._weights.get("sensitive_tool", 20)
            risk_score += points
            risk_factors.append(f"sensitive_tool (+{points})")

        if injection_detected:
            points = self._weights.get("suspicious_prompt", 30)
            risk_score += points
            risk_factors.append(f"suspicious_prompt (+{points})")

        if parameter_violation:
            points = self._weights.get("parameter_violation", 40)
            risk_score += points
            risk_factors.append(f"parameter_violation (+{points})")

        return risk_score, risk_factors

    def is_above_threshold(self, risk_score: int, threshold: int) -> bool:
        """
        Check if the risk score exceeds the configured threshold.

        Args:
            risk_score: The computed risk score.
            threshold: The maximum acceptable risk score from policy.

        Returns:
            True if the score exceeds the threshold.
        """
        return risk_score > threshold
