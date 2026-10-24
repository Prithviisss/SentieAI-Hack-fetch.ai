# SentinelFlow 🛡️
### Autonomous SecOps Incident Investigation & Verified Response Agent
**Built for the ASI:One Agent Challenge ("From Intent to Action")**  
**Hackathon:** Fetch-A-Thon 3.0 (October 24, 2026)  
**Team F-ups:**  
- **Meer Mohammed Shoaib (Team Lead):** Architecture, AI Reasoning, Security Policies, Threat Modeling  
- **Mohammed Maaz:** Agent Platform, Agentverse Registration, ACP Protocol, Deployment  
- **Prithvi S:** Tools, Synthetic Telemetry Data, Reliability Gauntlet Testing, Submission Documentation  

**Live Agentverse Agent Profile:**  
👉 [https://agentverse.ai/agents/details/agent1qwstka0f7sjyd0ux69zfv9pu66testhc807cdhx8yvav3u0eml7nwptkdfy](https://agentverse.ai/agents/details/agent1qwstka0f7sjyd0ux69zfv9pu66testhc807cdhx8yvav3u0eml7nwptkdfy)  

**Public GitHub Repository:**  
👉 [https://github.com/allanmaaz/sentinal.git](https://github.com/allanmaaz/sentinal.git)

---

## 🌟 Overview
Most AI security solutions stop at conversation—generating theoretical advice that an analyst must still manually investigate and execute.

**SentinelFlow** turns natural-language security intent into **autonomous, evidence-backed actions**:
1. **Dual-Protocol Access (ACP + MCP)**:
   - **ACP (Agent Chat Protocol)**: Powers Fetch.ai ASI:One conversational experiences with rich, interactive UI cards (`MetadataContent`).
   - **MCP (Model Context Protocol)**: Exposes SecOps tools over standard JSON-RPC 2.0 stdio for external LLM clients (Claude Desktop, Cursor, FastMCP).
2. **Dual-Persona Experience**:
   - **Real-World Consumer Mode**: Empathetic, zero-jargon plain English for everyday users ("Someone hacked my account alex@gmail.com"), 1-tap emergency rescue with 0.1 FET, and Personal Safety Certificate.
   - **Enterprise SOC Analyst Mode**: Tier-3 SOC reports, MITRE ATT&CK correlation, and SIEM telemetry.
3. **Deterministically searches SIEM and authentication logs** without fabricating records.
4. **Applies explainable MITRE ATT&CK risk-scoring rules** (Brute Force, Impossible Travel, Privilege Escalation).
5. **Surfaces Dynamic Interactive Cards Suite** in ASI:One (Risk Assessment, Response Approval, Verification Receipt, Forensics, Onboarding).
6. **Enforces a strict Human-in-the-Loop (HITL) Policy Gate** requiring explicit approval for high-impact actions.
7. **Executes safe, simulated containment** (e.g., revoking compromised sessions, blocking attacker IPs).
8. **Settles containment via Fetch.ai Payment Protocol** (`0.1 FET` SECaaS micro-transaction).
9. **Verifies the actual post-action system state** and outputs **Tamper-Evident Cryptographic SHA-256 Audit Receipt** directly inside ASI:One!

---

## 🔌 Dual-Protocol Architecture: ACP + MCP

SentinelFlow bridges the decentralized Fetch.ai ecosystem with the broader AI tooling standard:

```
                      ┌──────────────────────────────────────────────┐
                      │            SentinelFlow Core Engine          │
                      │  (Controller, SIEM Search, MITRE Evaluator,  │
                      │   HITL Policy Gate, Closed-Loop Verifier)    │
                      └───────────────┬──────────────┬───────────────┘
                                      │              │
                   Agent Chat Protocol│              │Model Context Protocol
                         (ACP)        │              │       (MCP)
                                      ▼              ▼
                     ┌───────────────────┐        ┌────────────────────┐
                     │ ASI:One / Chat UI │        │ Claude / Cursor /  │
                     │  Interactive Cards│        │ IDE Tool Calling   │
                     │  (MetadataContent)│        │   (JSON-RPC 2.0)   │
                     └───────────────────┘        └────────────────────┘
```

- **Agent Chat Protocol (ACP)**: Connects to Fetch.ai's decentralized agent network and ASI:One chat UI via Agentverse Mailbox. Delivers conversational replies and interactive UI cards (`agent.py`, `chat_proto.py`, `cards.py`).
- **Model Context Protocol (MCP)**: Exposes `investigate_security_logins`, `emergency_account_lockdown`, and `verify_containment_proof` as standardized MCP tools for Claude Desktop, Cursor, or IDE agents (`mcp_server.py`).

---

## 🎴 ASI:One Interactive Dynamic Cards Suite

SentinelFlow natively integrates with the ASI:One interactive card specification using `MetadataContent` in the Agent Chat Protocol (ACP):

| Card | Kind | Description | Interactive Capabilities |
| :--- | :--- | :--- | :--- |
| **Card A: Risk Assessment** | `custom` | High-visibility threat briefing, risk severity score (`85/100`), suspicious login evidence, account details, and MITRE ATT&CK tags. | Visual threat intelligence chips, geolocation anomaly breakdown, and next steps. |
| **Card B: Response Approval** | `review` | Human-in-the-Loop policy authorization gate reviewing action scope, impact analysis, and SECaaS escrow fee (`0.1 FET`). | 4 Clickable Action Buttons: `[Approve Session Revocation (0.1 FET)]`, `[Reject the Action]`, `[Request More Information]`, `[Block Attacker IP (0.1 FET)]`. |
| **Card C: Verification Receipt** | `custom` | Post-remediation closed-loop state proof with SHA-256 audit hash and Fetch.ai payment confirmation. | Cryptographic state receipt, audit ID, and immutable ledger record. |
| **Card D: Forensic Telemetry** | `detail` | Triggered when analyst selects *"Request More Information"*. Surfaces raw timestamped SIEM audit events. | Deep-dive log viewer with direct approval actions. |
| **Card E: Welcome & Onboarding** | `custom` | Triggered when any new user says *"hi"*, *"help"*, or *"start"*. Explains capabilities and provides one-click demo launches. | One-click launch buttons: `[Investigate demo-user-104]`, `[Investigate sarah-dev-92]`. |

### Two-Way Card Response Handling
When an analyst interacts with a card in ASI:One, SentinelFlow parses **both formats**:
1. **Structured JSON Action Selection**: Triggered when tapping buttons on interactive cards (`{"action": "approve_containment", "target": "demo-user-104", ...}`).
2. **Natural Language Analyst Chat**: Typed naturally in the chat window (e.g., *"Approve session revocation"*, *"Reject the action"*, *"Request more information"*, *"Block IP"*).

---

## 🚀 Technical Architecture

```
User Intent (ASI:One / Agentverse)
       │
       ▼
Agentverse Mailbox ────► SentinelFlow SecOps Agent (uAgents + ACP)
                                │
               ┌────────────────┴────────────────┐
               ▼                                 ▼
   Input & Injection Sanitizer       ASI:One Interactive Cards
               │                          │
               ▼                          ├─► Card A (Risk Assessment)
      Controller Engine                   ├─► Card B (Response Approval)
         │          │                     ├─► Card C (Verification Receipt)
         ▼          ▼                     ├─► Card D (Forensics)
   Log Search    MITRE Risk Engine        └─► Card E (Welcome & Onboarding)
   (Deterministic)  (Score 0-100)
         │          │
         └────┬─────┘
              ▼
      Policy & Approval Gate
              │ [Approved by Analyst via Card or Chat]
              ▼
   Multi-Agent Remediation (A2A)
              │
              ├─► Fetch.ai Payment Protocol (0.1 FET SECaaS Settlement)
              ▼
      Simulated Containment (Session Revocation / IP Block)
              │
              ▼
      Closed-Loop Verifier (Deterministic SHA-256 State Proof)
```

---

## 🛠️ Quickstart Guide

### 1. Prerequisites
- Python 3.10+ (Recommended: Python 3.12)
- Git

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/allanmaaz/sentinal.git
cd sentinal

# Create and activate virtual environment
python3.12 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configuration
Copy the sample environment file:
```bash
cp .env.example .env
```
Default settings in `.env`:
```env
AGENT_NAME="SentinelFlow SecOps Agent"
AGENT_SEED_PHRASE="sentinelflow-cyber-incident-agent-seed-2026"
AGENT_PORT=8000
AGENT_MAILBOX=True
ASI1_API_KEY="sk_fa69009adcea471ba1b9006d979c0f8953d0da9df14947589ef1a56124192d9c"
```

### 4. Running the Agent with Agentverse Mailbox
Start the agent locally:
```bash
python agent.py
```
On startup, `uAgents` will output:
```
============================================================
🛡️  SentinelFlow Agent Initialized: SentinelFlow SecOps Agent
📍 Agent Address: agent1qwstka0f7sjyd0ux69zfv9pu66testhc807cdhx8yvav3u0eml7nwptkdfy
🌐 Protocol: Agent Chat Protocol (ACP) Published
📬 Mailbox Enabled: True
============================================================
Ready to receive cybersecurity investigation tasks via ASI:One.
```

---

## 🧪 Running the F-ups Reliability Gauntlet (18/18 Tests)

SentinelFlow includes a comprehensive automated test suite verifying every critical edge case across ACP, MCP, payment, security, and consumer protection:

```bash
pytest -v
```

### Gauntlet Results:
- `T01. Normal investigation (demo-user-104)`: **PASSED** (Finds logs, correlates events, scores risk)
- `T02. Known suspicious pattern`: **PASSED** (Detects brute-force + travel anomaly + privilege probe)
- `T03. No matching records (unknown-user-999)`: **PASSED** (Returns `insufficient_data`, zero hallucinations)
- `T04. Malformed request validation`: **PASSED** (Rejects empty targets and shell injection attempts)
- `T05. Prompt injection in logs`: **PASSED** (Neutralizes adversarial User-Agent payloads)
- `T06. Unauthorized containment action`: **PASSED** (Blocks execution without valid approval token)
- `T07. Tool/API failure resilience`: **PASSED** (Degrades safely on SIEM timeouts without claiming success)
- `T08. Verification mismatch detection`: **PASSED** (Flags when state fails to transition to revoked)
- `T09. Idempotency & duplicate prevention`: **PASSED** (Prevents duplicate actions, preserves audit ledger)
- `T10. ASI:One Dynamic Cards & Selection Parsing`: **PASSED** (Validates Cards A, B, C, D, E & button parsing)
- `T11. Fetch.ai Payment Protocol Spec`: **PASSED** (Verifies Funds schema and seller role)
- `T12. Multi-Agent A2A Collaboration`: **PASSED** (Verifies ContainmentTask and ContainmentResult schemas)
- `T13. Real-World Consumer Emergency Lockdown`: **PASSED** (Natural language hack reports, 1-tap lock, and Safety Certificate)
- `T14. MCP Server Handshake & Ping`: **PASSED** (Validates MCP 2024-11-05 initialize protocol)
- `T15. MCP Tool Enumeration`: **PASSED** (Lists investigate, lockdown, and verify tools with JSON schemas)
- `T16. MCP Investigation Execution`: **PASSED** (Runs telemetry investigation via JSON-RPC 2.0 stdio)
- `T17. MCP Containment & Proof Verification`: **PASSED** (Executes lockdown and verifies SHA-256 state hash)
- `T18. MCP Error Handling`: **PASSED** (Safely handles unknown methods and malformed tool calls)

---

## 💬 Demonstration Scenarios in ASI:One

### Scenario 1: Autonomous Triage & Dual Interactive Cards
**User in ASI:One:**
> *"Investigate suspicious login events on account demo-user-104"*

**SentinelFlow Response:**
1. Acknowledges message immediately via ACP.
2. Correlates authentication logs for `demo-user-104`.
3. Detects 5 rapid failed logins from Lagos, Nigeria, followed by impossible travel from San Francisco, and multiple MFA fatigue prompts.
4. Generates an executive AI briefing via `asi1-mini`.
5. Renders **Card A (Risk Assessment)**:
   - Threat Level: `CRITICAL RISK` (Score: 85/100)
   - MITRE ATT&CK: `T1110.001 (Password Spraying)`, `T1078 (Valid Accounts)`, `T1556 (Modify Auth Process)`
   - Account & event breakdown.
6. Renders **Card B (Response Approval)**:
   - Action & Impact Analysis: Invalidate 3 active sessions, quarantine ingress IP `198.51.100.42`.
   - SECaaS Fee: `0.1 FET`.
   - 4 Action Buttons: `[Approve Session Revocation (0.1 FET)]`, `[Reject the Action]`, `[Request More Information]`, `[Block Attacker IP (0.1 FET)]`.
7. Analyst clicks **`[Approve Session Revocation (0.1 FET)]`** (or types *"Approve session revocation"*).
8. SentinelFlow validates authorization, revokes active sessions, settles 0.1 FET, verifies state (`sessions_revoked`), and renders **Card C (Verification Receipt)** with cryptographic SHA-256 audit proof!

### Scenario 2: Deep-Dive Forensic Inspection
**User clicks:** `[Request More Information]` (or types *"Request more info"*).  
**SentinelFlow Response:** Renders **Card D (Forensic Telemetry)** displaying raw, timestamped SIEM audit events and re-offering the decision buttons.

### Scenario 3: Onboarding & Discovery for Anyone
**User in ASI:One:** *"Hello"* or *"Help"*  
**SentinelFlow Response:** Renders **Card E (Welcome & Discovery)** with an introduction, key capabilities, and one-click launch buttons to explore demo scenarios.

---

## 📄 License
MIT License. Built for the Fetch.ai ASI:One Agent Challenge 2026 by Team F-ups.
