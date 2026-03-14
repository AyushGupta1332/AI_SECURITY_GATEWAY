"""
Identity Model
==============
Dataclasses representing the full identity context of a gateway request.
Covers user, agent, session, delegation chain, purpose binding,
and attribute-based access control (ABAC) fields.

All fields are optional at the API boundary for backward compatibility.
The gateway constructs a RequestIdentityContext from whatever is provided.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class UserIdentity:
    """The human (or service account) behind the request."""

    user_id: str = "anonymous"
    tenant: str = "default"
    clearance: str = "public"
    department: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentIdentity:
    """The AI agent making the tool call."""

    agent_id: str = ""
    agent_type: str = "generic"      # e.g. "research", "orchestrator", "admin"
    model: str = ""                   # e.g. "gpt-4", "claude-3"
    version: str = "1.0"


@dataclass
class DelegationLink:
    """One hop in a delegation chain."""

    principal_type: str              # "user" or "agent"
    principal_id: str
    delegated_permissions: list[str] = field(default_factory=list)


@dataclass
class DelegationChain:
    """Ordered delegation path from the original principal to the acting agent."""

    chain: list[DelegationLink] = field(default_factory=list)

    @property
    def depth(self) -> int:
        return len(self.chain)

    @property
    def origin(self) -> str:
        """Who originally initiated the chain."""
        if self.chain:
            return self.chain[0].principal_id
        return "unknown"

    @property
    def actor(self) -> str:
        """Who is actually performing the action (last in chain)."""
        if self.chain:
            return self.chain[-1].principal_id
        return "unknown"


@dataclass
class SessionContext:
    """Per-session metadata."""

    session_id: str = ""
    started_at: str = ""
    request_count: int = 0


@dataclass
class PurposeBinding:
    """Declared intent for the action."""

    purpose: str = ""
    justification: str = ""


@dataclass
class RequestIdentityContext:
    """
    Wraps the full identity context for a single gateway request.
    This is the object that flows through the entire pipeline.
    """

    user: UserIdentity = field(default_factory=UserIdentity)
    agent: AgentIdentity = field(default_factory=AgentIdentity)
    session: SessionContext = field(default_factory=SessionContext)
    delegation: DelegationChain = field(default_factory=DelegationChain)
    purpose: PurposeBinding = field(default_factory=PurposeBinding)

    @property
    def agent_id(self) -> str:
        """Shortcut — keeps backward compatibility with existing pipeline code."""
        return self.agent.agent_id

    def to_dict(self) -> dict[str, Any]:
        """Serialize the full identity context for logging."""
        return {
            "user": {
                "user_id": self.user.user_id,
                "tenant": self.user.tenant,
                "clearance": self.user.clearance,
                "department": self.user.department,
                "attributes": self.user.attributes,
            },
            "agent": {
                "agent_id": self.agent.agent_id,
                "agent_type": self.agent.agent_type,
                "model": self.agent.model,
                "version": self.agent.version,
            },
            "session": {
                "session_id": self.session.session_id,
                "started_at": self.session.started_at,
                "request_count": self.session.request_count,
            },
            "delegation": {
                "depth": self.delegation.depth,
                "origin": self.delegation.origin,
                "actor": self.delegation.actor,
                "chain": [
                    {
                        "principal_type": link.principal_type,
                        "principal_id": link.principal_id,
                        "delegated_permissions": link.delegated_permissions,
                    }
                    for link in self.delegation.chain
                ],
            },
            "purpose": {
                "purpose": self.purpose.purpose,
                "justification": self.purpose.justification,
            },
        }


def build_identity_context(
    agent_id: str,
    user_id: str | None = None,
    tenant: str | None = None,
    clearance: str | None = None,
    department: str | None = None,
    session_id: str | None = None,
    purpose: str | None = None,
    justification: str | None = None,
    delegation_chain: list[dict[str, Any]] | None = None,
) -> RequestIdentityContext:
    """
    Build a RequestIdentityContext from flat API request fields.
    Handles missing/optional fields gracefully for backward compatibility.
    """
    user = UserIdentity(
        user_id=user_id or "anonymous",
        tenant=tenant or "default",
        clearance=clearance or "public",
        department=department or "",
    )

    agent = AgentIdentity(agent_id=agent_id)

    session = SessionContext(session_id=session_id or "")

    purpose_binding = PurposeBinding(
        purpose=purpose or "",
        justification=justification or "",
    )

    # Build delegation chain from list of dicts
    chain_links: list[DelegationLink] = []
    if delegation_chain:
        for link_data in delegation_chain:
            chain_links.append(
                DelegationLink(
                    principal_type=link_data.get("type", "agent"),
                    principal_id=link_data.get("id", ""),
                    delegated_permissions=link_data.get("permissions", []),
                )
            )

    delegation = DelegationChain(chain=chain_links)

    return RequestIdentityContext(
        user=user,
        agent=agent,
        session=session,
        delegation=delegation,
        purpose=purpose_binding,
    )
