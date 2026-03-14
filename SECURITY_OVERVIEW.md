# 🛡️ AI Security Gateway — Security Overview

## What is the AI Security Gateway?

The AI Security Gateway is a **security enforcement layer** that sits between AI agents and the tools they use — like sending emails, reading files, or querying databases. Every action an AI agent tries to perform must pass through this gateway, which inspects and evaluates the request before deciding whether to allow or block it.

The core idea is simple: **AI agents should never have unchecked access to tools.** Just like employees need badges and approvals, AI agents need a checkpoint that verifies who they are, what they're doing, and whether it's safe.

---

## How does it work?

When an AI agent wants to perform an action, the request flows through a **multi-step security pipeline**. Each step evaluates a different aspect of the request:

### Step 1 — Identity Verification

The gateway checks who is making the request. Every request carries identity information:

- **Which agent** is making the request (and is it a known, registered agent?)
- **Which user** initiated it (user ID, department, clearance level)
- **Which tenant** they belong to (for multi-tenant isolation)
- **Delegation tracking** — if an agent is acting on behalf of another agent, the full chain is recorded

If the agent isn't registered in the system, the request is immediately rejected.

### Step 2 — Access Control (ABAC)

Beyond simple "is this agent registered?", the gateway evaluates **attribute-based access control** rules:

- **Tenant isolation** — An agent from `tenant_A` cannot access resources belonging to `tenant_B`
- **Clearance levels** — Certain tools require minimum clearance (public, internal, confidential, restricted)
- **Delegation depth** — If agents delegate tasks to sub-agents, the depth is limited to prevent abuse

### Step 3 — Permission Check

Each agent has a specific list of tools it's allowed to use. This is defined in a policy file, not hardcoded. A research agent might be able to read files and send emails, but not write files or run database queries.

### Step 4 — Parameter Validation

This is where it gets granular. It's not just "can this agent send email?" but "can this agent send email **to this specific domain**?" For example:

- Emails to `@company.com` → Allowed
- Emails to `@gmail.com` → Blocked
- Database queries with `SELECT` → Allowed
- Database queries with `DROP` or `DELETE` → Blocked
- File access within `/data/research/` → Allowed
- File access outside that path → Blocked

### Step 5 — Prompt Injection Detection (Dual Layer)

This is a two-layer defense against prompt injection attacks:

1. **Heuristic layer** — Fast pattern matching that catches known injection phrases like "ignore previous instructions", "bypass security", or "reveal all secrets"

2. **LLM layer** — An AI model (Groq LLM) semantically analyzes the prompt in context. This catches sophisticated attacks that simple string matching would miss — like paraphrased instructions, social engineering, or context manipulation

### Step 6 — Semantic Intent Analysis (LLM)

This is one of the most valuable security features. The gateway uses an LLM to **cross-reference what the user says they want** versus **what the tool will actually do**.

For example:
- User says: *"Just read the documentation for me"*
- Tool action: `send_email` to `external@attacker.com` with customer data

The intent analyzer catches this **mismatch** and flags it. It can detect:
- **Scope escalation** — Requesting more access than stated
- **Target mismatch** — Saying one thing, doing another
- **Data exfiltration** — Using legitimate tools to extract data
- **Distraction** — Benign-sounding prompt hiding a harmful action

### Step 7 — Risk Scoring

Every check contributes points to a cumulative risk score:

| Factor | Points |
|---|---|
| Using a sensitive tool | +20 |
| Suspicious prompt detected | +30 |
| Parameter violation | +40 |
| Unregistered agent | +50 |
| Tenant violation | +20 |
| Clearance mismatch | +15 |
| Intent mismatch | up to +30 |

If the total exceeds the threshold (default: 70), the request is **blocked** — even if individual checks didn't fail on their own.

### Step 8 — Decision & AI Explanation

The gateway makes its final allow/deny decision. Then, an LLM generates a **natural language explanation** of why. This explanation includes:

- A clear summary of the decision
- Severity classification (info / warning / critical)
- Which specific policy rules were triggered
- Actionable recommendations for the security team

This makes audit logs **human-readable** — security auditors don't need to parse raw JSON to understand what happened and why.

---

## The Dashboard

The main gateway dashboard provides a visual interface for testing and monitoring the security pipeline in real-time.

![AI Security Gateway — Main Dashboard (Allowed Request)](../Screenshot/Dashboard_1.jpeg)

*The dashboard showing a successful request. The security pipeline visualizes all 8 steps, and the Intent Analysis (ALIGNED) and Policy Reasoning (INFO) panels provide LLM-generated context.*

---

When a request is denied, the dashboard clearly shows which checks failed and why:

![AI Security Gateway — Main Dashboard (Denied Request)](../Screenshot/Dashboard_2.jpeg)

*A denied request due to domain violation and prompt injection. Risk score hits 100/70. The Policy Reasoning panel (CRITICAL) provides a detailed explanation with recommendations.*

---

The system also supports advanced identity features — tenant isolation, clearance levels, and delegation tracking:

![AI Security Gateway — Identity & ABAC Controls](../Screenshot/Screenshot_3.jpeg)

*A cross-tenant access attempt blocked by ABAC rules. The identity context shows the external user and tenant, while the Policy Reasoning explains the denial with references to specific policies.*

---

## Audit Dashboard & AI Intelligence

Every security decision is logged to a SQLite database. The Audit Dashboard provides:

- **Real-time statistics** — Total events, allowed/denied counts, average risk, injection attempts
- **Searchable event log** — Filter by agent, tool, decision, with pagination
- **Event detail view** — Click any event to see the full JSON record
- **Data export** — Download audit data as CSV or JSON

The AI Intelligence feature generates an **LLM-powered security briefing** with:

- Threat level assessment and security posture score
- Key findings based on actual audit data
- Anomaly detection (unusual agents, tools, or patterns)
- Trend analysis (is risk increasing or decreasing?)
- Prioritized recommendations for security improvements

![Audit Dashboard with AI Intelligence Briefing](../Screenshot/Audit_Dashboard.jpeg)

*The Audit Dashboard showing 5 events with an AI-generated security briefing. Threat level: ELEVATED (60/100). The briefing identifies injection attempts, anomalies, and provides actionable recommendations.*

---

## Key Security Features Summary

| Feature | Description |
|---|---|
| **API Key Authentication** | All API requests require a valid key (SHA-256 hashed storage) |
| **Rate Limiting** | Prevents abuse with configurable per-endpoint limits |
| **Identity & ABAC** | User, agent, tenant, clearance, delegation tracking |
| **Policy-Driven** | All rules in JSON config files — no hardcoded permissions |
| **Multi-Mode Policies** | Switch between Default and Healthcare (HIPAA-style) modes |
| **Parameter Validation** | Domain restrictions, path prefixes, SQL keyword blocking |
| **Dual-Layer Injection Detection** | Heuristic patterns + LLM semantic analysis |
| **Intent Analysis** | LLM verifies stated intent matches actual action |
| **Cumulative Risk Scoring** | Multiple factors combine; threshold-based blocking |
| **Natural Language Reasoning** | LLM explains every decision in plain English |
| **SQLite Audit Database** | Thread-safe, indexed, exportable audit trail |
| **AI Security Briefings** | LLM-generated threat assessment and recommendations |
| **Graceful Degradation** | LLM features fail silently; pipeline always works |

---

## Technology Stack

| Component | Technology |
|---|---|
| Backend API | Python, FastAPI, Uvicorn |
| LLM Integration | Groq API (Llama 3.3 70B) |
| Audit Storage | SQLite (WAL mode, thread-safe) |
| Authentication | SHA-256 hashed API keys, SlowAPI rate limiting |
| Dashboard | HTML, CSS, JavaScript |
| Logging | Structured JSON (console + file + database) |

---

## How to Run

```
pip install -r requirements.txt
set GROQ_API_KEY=your_key_here
python main.py
```

The server starts and opens the dashboard automatically at `http://127.0.0.1:8000`. The Audit Dashboard is at `http://127.0.0.1:8000/audit`.

---

## Why This Matters

As AI agents become more capable and start interacting with real systems — sending emails, modifying files, running database queries — there needs to be a security layer ensuring they only do what they're authorized to do.

This gateway provides that layer:

- **Rule-based foundation** for predictable, auditable security decisions
- **AI-enhanced detection** that catches sophisticated attacks heuristics would miss
- **Natural language explanations** that make security decisions understandable
- **Comprehensive audit trail** for compliance and forensic analysis
- **Configurable policies** that adapt to different organizational needs

The architecture is designed to be extended — new tools, new agents, new policy modes, and new detection methods can all be added without changing the core pipeline.
