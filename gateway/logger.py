"""
Structured Logging Module
=========================
Provides structured JSON logging for all gateway decisions.
Dual output: console/file (human monitoring) + SQLite (queryable persistence).
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from gateway.audit_database import get_audit_db


# Configure audit log file path
AUDIT_LOG_PATH = Path(__file__).parent.parent / "audit.log"


class StructuredFormatter(logging.Formatter):
    """Custom formatter that outputs structured JSON log entries."""

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record as a JSON string."""
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
        }

        # Merge structured data if present
        if hasattr(record, "structured_data"):
            log_entry.update(record.structured_data)
        else:
            log_entry["message"] = record.getMessage()

        return json.dumps(log_entry, indent=2)


def _setup_logger() -> logging.Logger:
    """Initialize and configure the gateway logger."""
    logger = logging.getLogger("ai_security_gateway")
    logger.setLevel(logging.INFO)

    # Prevent duplicate handlers on re-import
    if logger.handlers:
        return logger

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(StructuredFormatter())
    logger.addHandler(console_handler)

    # File handler for audit persistence
    file_handler = logging.FileHandler(AUDIT_LOG_PATH, mode="a", encoding="utf-8")
    file_handler.setFormatter(StructuredFormatter())
    logger.addHandler(file_handler)

    return logger


# Module-level logger instance
gateway_logger = _setup_logger()


def log_decision(
    agent_id: str,
    tool: str,
    decision: str,
    risk_score: int,
    flags: list[str],
    reason: str,
    parameters: dict[str, Any] | None = None,
    identity_context: dict[str, Any] | None = None,
    mode: str = "default",
    api_key: str = "",
    ip_address: str = "",
    duration_ms: float = 0,
) -> dict[str, Any]:
    """
    Log a structured gateway decision to both file and database.

    Returns:
        The structured log entry dict (includes the event_id from DB).
    """
    log_entry: dict[str, Any] = {
        "agent_id": agent_id,
        "tool": tool,
        "decision": decision,
        "risk_score": risk_score,
        "flags": flags,
        "reason": reason,
    }

    if parameters:
        log_entry["parameters"] = parameters

    if identity_context:
        log_entry["identity"] = identity_context

    # Write to file/console via logging
    record = logging.LogRecord(
        name="ai_security_gateway",
        level=logging.INFO if decision.startswith("ALLOWED") else logging.WARNING,
        pathname=__file__,
        lineno=0,
        msg="",
        args=(),
        exc_info=None,
    )
    record.structured_data = log_entry  # type: ignore[attr-defined]
    gateway_logger.handle(record)

    # Write to SQLite database
    try:
        db = get_audit_db()
        event_id = db.log_event(
            agent_id=agent_id,
            tool=tool,
            decision=decision,
            risk_score=risk_score,
            flags=flags,
            reason=reason,
            parameters=parameters,
            identity=identity_context,
            mode=mode,
            api_key=api_key,
            ip_address=ip_address,
            duration_ms=duration_ms,
        )
        log_entry["event_id"] = event_id
    except Exception as e:
        gateway_logger.warning("Failed to write to audit DB: %s", str(e))

    return log_entry
