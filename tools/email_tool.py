"""
Simulated Email Tool
====================
Mock implementation of an email sending tool.
Does NOT perform any real email operations.
"""

from typing import Any


def send_email(to: str, subject: str, body: str) -> dict[str, Any]:
    """
    Simulate sending an email.

    Args:
        to: Recipient email address.
        subject: Email subject line.
        body: Email body content.

    Returns:
        A simulated success response.
    """
    return {
        "status": "success",
        "message": f"Email sent to {to}",
        "details": {
            "to": to,
            "subject": subject,
            "body_length": len(body),
        },
    }
