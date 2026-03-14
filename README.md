# 🛡️ AI Security Gateway

## Policy-Driven Execution Boundary Security for Agentic AI

A production-grade security gateway that sits between AI agents and MCP-style tools, enforcing **identity-aware permissions**, **attribute-based access control (ABAC)**, **parameter-level validation**, **dual-layer prompt injection detection** (heuristic + LLM), **LLM-powered semantic intent analysis**, **cumulative risk scoring**, **structured audit logging with SQLite**, **natural language policy reasoning**, and **AI-driven security intelligence** — all driven by JSON policy configuration.

---

## 🏗️ Architecture

```
User → Agent → AI Security Gateway → MCP Tool → External System
                    │
                    ├── Security Middleware    (API key auth, rate limiting, CORS)
                    ├── Identity & ABAC       (user/tenant/clearance/delegation)
                    ├── Policy Engine         (permission checks, multi-mode policies)
                    ├── Parameter Validator   (constraint enforcement)
                    ├── Injection Detector    (heuristic + LLM dual-layer)
                    ├── Intent Analyzer       (LLM semantic intent matching)
                    ├── Risk Engine           (cumulative risk scoring)
                    ├── Policy Reasoner       (LLM natural language explanations)
                    ├── Execution Controller  (central pipeline orchestrator)
                    ├── Audit Database        (SQLite with WAL mode)
                    ├── Audit Intelligence    (LLM-powered security briefings)
                    └── Structured Logger     (JSON console + file + database)
```

The **AI Security Gateway** is the **trust boundary**. All tool executions must pass through this layer — no direct tool access is allowed.

### Zero Trust Design

Every request is treated as untrusted by default:

- **No implicit trust** — Agents must be explicitly defined in policy
- **Least privilege** — Each agent is granted access only to specific tools with specific constraints
- **Defense in depth** — Multiple independent checks (identity → ABAC → permission → parameters → injection → intent → risk)
- **Fail-closed** — Unknown agents, tools, or constraint violations are denied by default
- **Graceful degradation** — LLM features degrade silently; pipeline never blocks

---

## 📁 Project Structure

```
ai_security_gateway/
│
├── main.py                              # FastAPI app, API endpoints, dashboard routes
├── requirements.txt                     # Python dependencies
│
├── gateway/
│   ├── security_middleware.py           # API key auth, rate limiting, CORS, headers
│   ├── identity.py                      # Identity model (user, agent, session, delegation)
│   ├── policy_engine.py                 # JSON policy loading & permission checks
│   ├── policy_provider.py              # Multi-mode policies, ABAC evaluation, risk modifiers
│   ├── parameter_validator.py           # Per-tool parameter constraint validation
│   ├── injection_detector.py            # Dual-layer injection detection (heuristic + LLM)
│   ├── llm_intelligence.py              # Intent analyzer, policy reasoner, audit intelligence
│   ├── risk_engine.py                   # Configurable risk scoring engine
│   ├── execution_controller.py          # Central 12-step pipeline orchestrator
│   ├── audit_database.py                # Thread-safe SQLite audit database (WAL mode)
│   └── logger.py                        # Structured JSON logging (console + file + DB)
│
├── tools/
│   ├── email_tool.py                    # Simulated email sending
│   ├── file_tool.py                     # Simulated file read/write
│   └── db_tool.py                       # Simulated database queries
│
├── config/
│   ├── policy.json                      # Default policy rules & risk configuration
│   ├── policy_healthcare.json           # Healthcare mode policy (stricter HIPAA-style)
│   └── api_keys.json                    # API key store (SHA-256 hashed)
│
├── static/
│   ├── index.html                       # Main interactive dashboard
│   └── audit.html                       # Audit log dashboard with AI intelligence
│
├── data/
│   └── audit.db                         # SQLite audit database (auto-created)
│
└── README.md
```

---

## 🔒 Security Pipeline (12 Steps)

Every request flows through a 12-step security pipeline:

| Step | Name | Description |
|------|------|-------------|
| 1 | **Identity Resolution** | Build identity context (user, agent, session, delegation, purpose) |
| 2 | **Tool Existence** | Verify the requested tool exists in the registry |
| 3 | **Agent Validation** | Check if the agent is registered in policy |
| 4 | **ABAC Evaluation** | Attribute-based access control (tenant, clearance, delegation depth) |
| 5 | **Permission Check** | Verify the agent is allowed to use this specific tool |
| 6 | **Parameter Validation** | Enforce per-tool constraints (domains, paths, SQL keywords) |
| 7 | **Injection Detection** | Dual-layer scan: heuristic pattern matching + LLM semantic analysis |
| 7.5 | **Intent Analysis** | LLM cross-references stated intent vs actual tool action |
| 8 | **Risk Scoring** | Cumulative score from all factors + identity modifiers + intent adjustment |
| 9 | **Decision** | Allow or deny based on threshold and policy rules |
| 10 | **Policy Reasoning** | LLM generates natural language explanation of the decision |
| 11 | **Execution** | If allowed, execute the tool (or dry-run) |
| 12 | **Audit Logging + Return** | Log decision to console/file/SQLite and return response |

---

## 🔐 Policy-Driven Enforcement

All access decisions are driven by JSON policy files. **No permissions are hardcoded in source code.**

### Policy Structure

```json
{
  "agents": {
    "research_agent": {
      "allowed_tools": {
        "read_file": { "constraints": { "path_prefix": "/data/research/" } },
        "send_email": { "constraints": { "allowed_domains": ["company.com"] } },
        "query_database": { "constraints": { "read_only": true } }
      }
    }
  },
  "risk_threshold": 70,
  "sensitive_tools": ["write_file", "send_email", "query_database"],
  "risk_weights": {
    "sensitive_tool": 20,
    "suspicious_prompt": 30,
    "parameter_violation": 40,
    "unknown_agent": 50
  }
}
```

### What the Policy Controls

| Feature | Description |
|---|---|
| **Agent Identity** | Only agents defined in `agents` are recognized |
| **Tool Permissions** | Each agent has an explicit allowlist of tools |
| **Parameter Constraints** | Per-tool constraints (path prefixes, email domains, SQL restrictions) |
| **Risk Threshold** | Maximum acceptable risk score before blocking |
| **Sensitive Tools** | Tools that add risk points simply by being invoked |
| **Risk Weights** | Configurable point values for each risk factor |
| **Multi-Mode Policies** | Switch between Default and Healthcare (HIPAA-style) modes |
| **ABAC Rules** | Tenant restrictions, clearance levels, delegation depth limits |

---

## 🧠 LLM Intelligence Layer

The gateway integrates three LLM-powered modules (Groq `llama-3.3-70b-versatile`) that enhance security without blocking the pipeline:

### 1. Dual-Layer Injection Detection
- **Heuristic layer**: Fast pattern matching against known injection phrases
- **LLM layer**: Semantic analysis — understands context, catches sophisticated attacks that string matching misses
- Combined result feeds into risk scoring

### 2. Semantic Intent Analyzer
Cross-references what the user **says** they want vs what the tool **actually does**:
- Catches scope escalation, target mismatch, data exfiltration, distraction attacks
- Returns alignment score (0-100%), mismatch type, and risk adjustment (-10 to +30)
- Example: Prompt says "read documentation" but tool is `send_email` to an external address → **MISMATCH** flagged

### 3. LLM Policy Reasoner
Generates natural language explanations for every security decision:
- Executive summary for quick review
- Detailed explanation referencing specific policy rules
- Severity classification (info / warning / critical)
- Actionable recommendations for security auditors

### 4. Audit Intelligence
LLM-powered security briefings from audit data:
- Threat level assessment (low → critical)
- Security posture score (0-100)
- Key findings with quantitative data
- Anomaly detection in agent/tool usage patterns
- Trend analysis (risk and volume)
- Prioritized recommendations

> All LLM features **degrade gracefully** — if the API is unavailable, the pipeline continues with rule-based checks only.

---

## ⚖️ Risk Scoring

The Risk Engine accumulates points from multiple independent factors:

| Risk Factor | Default Points | Trigger |
|---|---|---|
| Sensitive Tool | +20 | Tool is in the `sensitive_tools` list |
| Suspicious Prompt | +30 | Prompt injection pattern detected |
| Parameter Violation | +40 | Parameter fails constraint validation |
| Unknown Agent | +50 | Agent ID not found in policy |
| Tenant Violation | +20 | Cross-tenant access attempt |
| Clearance Mismatch | +15 | Insufficient clearance level |
| Deep Delegation | +10 | Delegation chain exceeds allowed depth |
| Intent Mismatch | -10 to +30 | LLM intent analysis risk adjustment |

If the cumulative risk score **exceeds** the `risk_threshold` (default: 70), the request is **blocked**.

---

## 🔑 Security Middleware

| Feature | Description |
|---|---|
| **API Key Authentication** | SHA-256 hashed keys stored in `config/api_keys.json` |
| **Rate Limiting** | Built-in in-memory sliding window limiter (default: 60 req/min per API key or IP) |
| **CORS** | Currently permissive (`allow_origins=["*"]`, `allow_methods=["*"]`, `allow_headers=["*"]`) |
| **Security Headers** | X-Content-Type-Options, X-Frame-Options, CSP, etc. |
| **Input Validation** | Request body size, prompt length, field length, and nesting-depth checks |

---

## 👤 Identity & Access Control

### Identity Context
Every request carries a full identity context:
- **User**: user_id, tenant, clearance (public/standard/confidential/admin), department
- **Agent**: agent_id, agent_type, model, version
- **Session**: session_id, TTL-based validation, request counting
- **Delegation**: depth, origin, actor, chain tracking
- **Purpose**: declared purpose and justification

### ABAC (Attribute-Based Access Control)
- Tenant isolation — agents can only access data within their tenant
- Clearance-level enforcement — tools require minimum clearance
- Delegation depth limits — prevents infinite delegation chains
- Purpose validation — optional justification requirements

---

## 📊 Audit System

### SQLite Database (WAL Mode)
- Thread-safe concurrent read/write access
- Connection-per-thread pattern
- Indexed tables for efficient querying
- Stores: agent, tool, decision, risk score, flags, parameters, identity, mode, duration
- Schema includes API key and IP fields, but they are not currently populated from request context in the execution flow

### Audit Dashboard
- Real-time statistics cards (total, allowed, denied, avg risk, 24h, injections)
- Searchable and filterable event table with pagination
- Detailed event view modal
- CSV and JSON export
- Auto-refreshing statistics

### AI Intelligence Briefing
- On-demand LLM-generated security briefing
- Threat level badge and posture score meter
- Key findings, anomalies, trends, recommendations

### API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/execute_tool` | POST | Execute a tool through the security pipeline |
| `/health` | GET | Health check with system status |
| `/reload_policy` | POST | Hot-reload policy without restart |
| `/switch_mode` | POST | Switch policy mode (body: `{ "mode": "default" \| "healthcare" }`) |
| `/audit/stats` | GET | Audit statistics summary |
| `/audit/events` | GET | Query audit events (search, filter, paginate) |
| `/audit/export` | GET | Export audit data (JSON/CSV) |
| `/audit/intelligence` | GET | AI-generated security intelligence briefing |
| `/sessions` | POST | Create a new session |
| `/sessions/{session_id}` | GET | Validate and refresh a session |
| `/sessions/{session_id}` | DELETE | End a session |
| `/sessions` | GET | List active sessions (optional `user_id` filter) |

---

## 🚀 Getting Started

### Prerequisites

- Python 3.11+
- Groq API key (for LLM features — optional, gateway works without it)

### Installation

```bash
cd ai_security_gateway
pip install -r requirements.txt
```

### Environment Variables

```bash
set GROQ_API_KEY=your_groq_api_key_here
```

### Running the Server

```bash
python main.py
```

The dashboard opens automatically at `http://127.0.0.1:8000`

- **Dashboard**: `http://127.0.0.1:8000`
- **Audit Dashboard**: `http://127.0.0.1:8000/audit`
- **API Docs**: `http://127.0.0.1:8000/docs`
- **ReDoc**: `http://127.0.0.1:8000/redoc`

### API Authentication

Protected endpoints require `X-API-Key`. Public paths include `/`, `/health`, `/docs`, `/redoc`, `/openapi.json`, `/audit`, and `/static/*`.

Example for a protected endpoint:

```bash
curl -X POST http://127.0.0.1:8000/reload_policy -H "X-API-Key: sg-dev-key-2026"
```

---

## 📡 Example Request & Response

### ✅ Valid Email Request (ALLOWED)

```bash
curl -X POST http://127.0.0.1:8000/execute_tool \
  -H "Content-Type: application/json" \
  -H "X-API-Key: sg-dev-key-2026" \
  -d '{
    "agent_id": "research_agent",
    "tool": "send_email",
    "parameters": {
      "to": "user@company.com",
      "subject": "Research Report",
      "body": "Please find the attached report."
    },
    "original_prompt": "Send an email to user@company.com with the report",
    "purpose": "sending quarterly report"
  }'
```

**Response:**
```json
{
  "decision": "ALLOWED",
  "risk_score": 20,
  "risk_factors": ["sensitive_tool (+20)"],
  "flags": ["sensitive_tool"],
  "reason": "Domain validated successfully",
  "result": {
    "status": "success",
    "message": "Email sent to user@company.com"
  },
  "identity": { "user": { "user_id": "anonymous", "tenant": "default" }, "..." },
  "mode": "default",
  "intent_analysis": {
    "intent_aligned": true,
    "alignment_score": 0.9,
    "stated_intent": "Send quarterly report to team",
    "actual_effect": "Send email to user@company.com with report",
    "mismatch_type": "none",
    "risk_adjustment": 0
  },
  "llm_reasoning": {
    "summary": "Request allowed — intent aligns with tool action",
    "severity": "info",
    "explanation": "The request was evaluated and found to have a risk score of 20...",
    "recommendations": ["Monitor usage of sensitive tools"],
    "policy_references": ["Sensitive Tool Usage, Domain Validation"]
  }
}
```

---

## 🔧 Extensibility

| Extension | How |
|---|---|
| **New tools** | Add a tool module in `tools/`, register in `TOOL_REGISTRY` |
| **New agents** | Add agent entries to `config/policy.json` |
| **New constraints** | Add validation logic in `parameter_validator.py` |
| **New injection patterns** | Extend patterns in `injection_detector.py` |
| **Custom risk factors** | Add new dimensions in `risk_engine.py` |
| **New policy modes** | Create `config/policy_<mode>.json` and register |
| **Real MCP integration** | Replace simulated tools with actual MCP client calls |

---

## 📜 License

This is an architectural implementation. Use and extend freely.
