"""
AI Security Gateway — Main Application
=======================================
FastAPI application exposing the security gateway endpoint.
All tool executions must pass through this API layer.
"""

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from gateway.execution_controller import ExecutionController
from gateway.security_middleware import install_security_middleware
from gateway.audit_database import get_audit_db

# Path to static files
STATIC_DIR = Path(__file__).parent / "static"


# ── Pydantic Models ───────────────────────────────────────────

class ToolExecutionRequest(BaseModel):
    """Request model for tool execution."""
    agent_id: str = Field(
        ...,
        description="Identifier of the AI agent making the request",
        examples=["research_agent"],
    )
    tool: str = Field(
        ...,
        description="Name of the tool to execute",
        examples=["send_email"],
    )
    parameters: dict[str, Any] = Field(
        ...,
        description="Parameters to pass to the tool",
        examples=[{"to": "user@company.com", "subject": "Hello", "body": "Test"}],
    )
    original_prompt: str = Field(
        default="",
        description="Original prompt text for injection scanning",
    )
    dry_run: bool = Field(
        default=False,
        description="If true, evaluate without executing the tool",
    )
    # Identity fields (all optional for backward compatibility)
    user_id: str | None = Field(default=None, description="Human user behind the request")
    tenant: str | None = Field(default=None, description="Tenant / organization")
    clearance: str | None = Field(default=None, description="Clearance level (public, standard, confidential, admin)")
    department: str | None = Field(default=None, description="User department")
    session_id: str | None = Field(default=None, description="Session identifier")
    purpose: str | None = Field(default=None, description="Declared intent for this action")
    justification: str | None = Field(default=None, description="Justification for the action")
    delegation_chain: list[dict[str, Any]] | None = Field(
        default=None,
        description="Delegation chain — list of {type, id, permissions}",
    )


class ToolExecutionResponse(BaseModel):
    """Response model for tool execution."""
    decision: str = Field(..., description="ALLOWED or DENIED")
    risk_score: int = Field(..., description="Computed risk score")
    risk_factors: list[str] = Field(default_factory=list, description="Contributing risk factors")
    flags: list[str] = Field(default_factory=list, description="Flags raised during evaluation")
    reason: str = Field(..., description="Human-readable decision reason")
    result: Any = Field(default=None, description="Tool execution result (if allowed)")
    identity: dict[str, Any] | None = Field(default=None, description="Resolved identity context")
    mode: str | None = Field(default=None, description="Active policy mode")
    intent_analysis: dict[str, Any] | None = Field(default=None, description="LLM semantic intent analysis")
    llm_reasoning: dict[str, Any] | None = Field(default=None, description="LLM policy reasoning explanation")


class HealthResponse(BaseModel):
    """Response model for health check."""
    status: str
    service: str
    version: str
    mode: str
    llm_injection_detection: bool
    auth_enabled: bool


class PolicyReloadResponse(BaseModel):
    """Response model for policy reload."""
    status: str
    message: str


class ModeSwitchRequest(BaseModel):
    """Request model for mode switching."""
    mode: str = Field(..., description="Policy mode to switch to (e.g. 'default', 'healthcare')")


class ModeSwitchResponse(BaseModel):
    """Response model for mode switching."""
    status: str
    message: str
    mode: str


# ── Application Setup ─────────────────────────────────────────

app = FastAPI(
    title="AI Security Gateway",
    description=(
        "Policy-driven execution boundary security for agentic AI. "
        "All tool executions pass through this gateway for identity validation, "
        "parameter checking, injection detection, and risk scoring."
    ),
    version="3.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Initialize the execution controller
controller = ExecutionController()

# Install security middleware (auth, rate limiting, headers, error handling)
security = install_security_middleware(app)

# CORS must be added AFTER security middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ── API Endpoints ─────────────────────────────────────────────

@app.get("/", include_in_schema=False)
async def serve_dashboard():
    """Serve the web dashboard."""
    return FileResponse(STATIC_DIR / "index.html")

@app.get("/audit", include_in_schema=False)
async def serve_audit_dashboard():
    """Serve the audit dashboard."""
    return FileResponse(STATIC_DIR / "audit.html")

@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check() -> HealthResponse:
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        service="AI Security Gateway",
        version="3.0.0",
        mode=controller.current_mode,
        llm_injection_detection=controller._detector.llm_available,
        auth_enabled=security["auth"].is_enabled,
    )


@app.post(
    "/execute_tool",
    response_model=ToolExecutionResponse,
    tags=["Gateway"],
    summary="Execute a tool through the security gateway",
    description=(
        "All tool calls must go through this endpoint. "
        "The gateway evaluates identity, permissions, parameters, "
        "injection risk, and cumulative risk score before allowing execution."
    ),
)
async def execute_tool(request: ToolExecutionRequest) -> ToolExecutionResponse:
    """Process a tool execution request through the security pipeline."""
    result = controller.execute(
        agent_id=request.agent_id,
        tool=request.tool,
        parameters=request.parameters,
        original_prompt=request.original_prompt,
        dry_run=request.dry_run,
        user_id=request.user_id,
        tenant=request.tenant,
        clearance=request.clearance,
        department=request.department,
        session_id=request.session_id,
        purpose=request.purpose,
        justification=request.justification,
        delegation_chain=request.delegation_chain,
    )
    return ToolExecutionResponse(**result)


@app.post(
    "/reload_policy",
    response_model=PolicyReloadResponse,
    tags=["System"],
    summary="Reload policy configuration",
    description="Hot-reload the active policy config without restarting the server.",
)
async def reload_policy() -> PolicyReloadResponse:
    """Reload the policy configuration from disk."""
    result = controller.reload_policy()
    return PolicyReloadResponse(**result)


@app.post(
    "/switch_mode",
    response_model=ModeSwitchResponse,
    tags=["System"],
    summary="Switch policy mode",
    description="Switch the active policy provider (e.g. 'default' → 'healthcare').",
)
async def switch_mode(request: ModeSwitchRequest) -> ModeSwitchResponse:
    """Switch the active policy mode at runtime."""
    try:
        result = controller.switch_mode(request.mode)
        return ModeSwitchResponse(**result)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

# ── Audit API Endpoints ───────────────────────────────────────

@app.get("/audit/events", tags=["Audit"], summary="Query audit events")
async def get_audit_events(
    agent_id: str | None = None,
    tool: str | None = None,
    decision: str | None = None,
    search: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = 50,
    offset: int = 0,
):
    """Query audit events with filters, search, and pagination."""
    db = get_audit_db()
    return db.query_events(
        agent_id=agent_id, tool=tool, decision=decision,
        search=search, since=since, until=until,
        limit=min(limit, 200), offset=offset,
    )


@app.get("/audit/events/{event_id}", tags=["Audit"], summary="Get single audit event")
async def get_audit_event(event_id: str):
    """Get a single audit event by ID."""
    db = get_audit_db()
    event = db.get_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@app.get("/audit/stats", tags=["Audit"], summary="Get audit statistics")
async def get_audit_stats():
    """Get aggregate audit statistics for the dashboard."""
    db = get_audit_db()
    return db.get_stats()


@app.get("/audit/export", tags=["Audit"], summary="Export audit events")
async def export_audit(
    format: str = "json",
    limit: int = 1000,
    agent_id: str | None = None,
    decision: str | None = None,
):
    """Export audit events as JSON or CSV."""
    from fastapi.responses import PlainTextResponse
    db = get_audit_db()
    data = db.export_events(
        format=format, limit=min(limit, 5000),
        agent_id=agent_id, decision=decision,
    )
    media = "text/csv" if format == "csv" else "application/json"
    return PlainTextResponse(content=data, media_type=media)


@app.get("/audit/intelligence", tags=["Audit"], summary="AI security intelligence briefing")
async def get_audit_intelligence():
    """Generate an LLM-powered security intelligence briefing from audit data."""
    from gateway.llm_intelligence import get_audit_intelligence
    db = get_audit_db()
    stats = db.get_stats()
    events_data = db.query_events(limit=20)
    intel = get_audit_intelligence()
    briefing = intel.generate_briefing(stats, events_data.get("events", []))
    if not briefing:
        raise HTTPException(status_code=503, detail="LLM intelligence unavailable")
    return briefing


# ── Session API Endpoints ─────────────────────────────────────

class SessionCreateRequest(BaseModel):
    user_id: str
    agent_id: str
    tenant: str = "default"
    ttl_minutes: int = 60


@app.post("/sessions", tags=["Sessions"], summary="Create a session")
async def create_session(request: SessionCreateRequest):
    """Create a new tracked session."""
    db = get_audit_db()
    return db.create_session(
        user_id=request.user_id,
        agent_id=request.agent_id,
        tenant=request.tenant,
        ttl_minutes=request.ttl_minutes,
    )


@app.get("/sessions/{session_id}", tags=["Sessions"], summary="Validate session")
async def validate_session(session_id: str):
    """Validate and refresh a session."""
    db = get_audit_db()
    session = db.validate_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found or expired")
    return session


@app.delete("/sessions/{session_id}", tags=["Sessions"], summary="Invalidate session")
async def invalidate_session(session_id: str):
    """Invalidate (end) a session."""
    db = get_audit_db()
    found = db.invalidate_session(session_id)
    if not found:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"status": "ok", "message": "Session invalidated"}


@app.get("/sessions", tags=["Sessions"], summary="List active sessions")
async def list_sessions(user_id: str | None = None):
    """List all active sessions, optionally filtered by user_id."""
    db = get_audit_db()
    return db.get_active_sessions(user_id=user_id)


# ── Run Server ────────────────────────────────────────────────

if __name__ == "__main__":
    import webbrowser
    import threading
    import uvicorn

    def open_browser():
        """Open the dashboard in the default browser after a short delay."""
        import time
        time.sleep(1.5)
        webbrowser.open("http://127.0.0.1:8000")

    # Launch browser in a background thread
    threading.Thread(target=open_browser, daemon=True).start()

    print("\n🛡️  AI Security Gateway v3.0 — PRODUCTION MODE")
    print("📍 Dashboard:  http://127.0.0.1:8000")
    print("📚 API Docs:   http://127.0.0.1:8000/docs")
    print(f"🔐 Auth:       {'ENABLED' if security['auth'].is_enabled else 'DISABLED'}")
    print(f"🤖 LLM Detect: {'ENABLED' if controller._detector.llm_available else 'DISABLED'}")
    print(f"📋 Dev Key:    sg-dev-key-2026")
    print("Press Ctrl+C to stop\n")

    uvicorn.run(app, host="127.0.0.1", port=8000)
