# SentinelFlow 🛡️
### Autonomous SecOps Incident Investigation & Verified Response Agent
**Built for the ASI:One Agent Challenge ("From Intent to Action")**  
**Hackathon:** Fetch-A-Thon 3.0 (October 24, 2026)  
**Team F-ups:**  
- **Meer Mohammed Shoaib (Team Lead):** Architecture, AI Reasoning, Security Policies, Threat Modeling  
- **Mohammed Maaz:** Agent Platform, Agentverse Registration, ACP Protocol, Deployment  
- **Prithvi S:** Tools, Synthetic Telemetry Data, Reliability Gauntlet Testing, Submission Documentation  

---

## 🌟 Overview
Most AI security solutions stop at conversation—generating theoretical advice that an analyst must still manually investigate and execute.

**SentinelFlow** turns natural-language security intent into **autonomous, evidence-backed actions**:
1. **Intakes intent** via ASI:One natural conversation or dynamic UI cards.
2. **Deterministically searches SIEM and authentication logs** without fabricating records.
3. **Applies explainable MITRE ATT&CK risk-scoring rules** (Brute Force, Impossible Travel, Privilege Escalation).
4. **Enforces a strict Human-in-the-Loop (HITL) Policy Gate** requiring explicit approval for high-impact actions.
5. **Executes safe, simulated containment** (e.g., revoking compromised sessions, blocking attacker IPs).
6. **Verifies the actual post-action system state** and outputs a tamper-evident cryptographic SHA-256 audit receipt directly inside ASI:One!

---

## 🚀 Key Features

| Capability | Description |
| :--- | :--- |
| **Agent Chat Protocol (ACP)** | Native implementation of `uagents_core.contrib.protocols.chat` with immediate message acknowledgments. |
| **ASI:One Interactive Cards** | Dynamic, guided element-tree UI cards with threat level badges, MITRE tactic chips, and one-tap action buttons. |
| **Multi-Agent Collaboration** | Decentralized A2A delegation between Triage Agent (Agent 1) and Remediation/Escrow Agent (Agent 2). |
| **Payment Protocol (0.1 FET)** | Monetization via Fetch.ai Payment Protocol (`payment_protocol_spec`, seller role) charging 0.1 FET for verified containment. |
| **Zero-Hallucination SIEM Engine** | Deterministic log querying ensuring that findings reference verified, immutable log event IDs. |
| **Indirect Prompt Injection Defense** | Sanitizes user inputs and raw ingested log fields (e.g. malicious User-Agent strings) to prevent prompt hijacking. |
| **Closed-Loop State Verification** | Never claims containment succeeded without independently inspecting the resulting system state. |
| **12/12 Reliability Gauntlet** | Full automated pytest suite proving resilience against tool timeouts, state mismatches, payments, and unauthorized actions. |

---

## 📐 Architecture

```
User Query (ASI:One)
       │
       ▼
Agentverse Mailbox ────► SentinelFlow Agent (uAgents + ACP)
                                │
               ┌────────────────┴────────────────┐
               ▼                                 ▼
   Input & Injection Sanitizer       ASI:One Interactive Cards
               │
               ▼
      Controller Engine
         │          │
         ▼          ▼
   Log Search    MITRE Risk Engine
   (Deterministic)  (Score 0-100)
         │          │
         └────┬─────┘
              ▼
      Policy & Approval Gate
              │ [Approved by Analyst]
              ▼
      Simulated Containment
              │
              ▼
      Closed-Loop Verifier (SHA-256 Audit Receipt)
```

---

## 🛠️ Quickstart Guide

### 1. Prerequisites
- Python 3.10+ (Recommended: Python 3.12)
- Git

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/your-username/sentinelflow.git
cd sentinelflow

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
AGENT_NAME="SentinelFlow Incident Response Agent"
AGENT_SEED_PHRASE="sentinelflow-cyber-incident-agent-seed-2026"
AGENT_PORT=8000
AGENT_MAILBOX=True
```

### 4. Running the Agent with Agentverse Mailbox
Start the agent locally:
```bash
python agent.py
```
On startup, `uAgents` will output:
```
============================================================
🛡️  SentinelFlow Agent Initialized: SentinelFlow Incident Response Agent
📍 Agent Address: agent1q...
🌐 Protocol: Agent Chat Protocol (ACP) Published
📬 Mailbox Enabled: True
============================================================
```
1. Click the Agentverse inspector registration URL printed in your terminal to link your agent to your Agentverse account.
2. Once registered, your agent is automatically discovered on [ASI:One](https://asi1.ai)!

---

## 🧪 Running the F-ups Reliability Gauntlet (10/10 Tests)

SentinelFlow includes an automated test suite verifying every critical edge case:

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
- `T10. ASI:One Dynamic Cards & Selection Parsing`: **PASSED** (Validates element-tree schema & button clicks)

---

## 💬 Demonstration Scenarios in ASI:One

### Scenario 1: Autonomous Triage & Containment Approval
**User in ASI:One:**
> *"Investigate suspicious login events on account demo-user-104"*

**SentinelFlow Response:**
1. Acknowledges message via ACP.
2. Searches authentication logs for `demo-user-104`.
3. Detects 7 failed logins from Bucharest, followed by a successful login and an MFA bypass probe.
4. Renders the **ASI:One Interactive Risk Assessment Card**:
   - Threat Level: `CRITICAL` (Score: 100/100)
   - MITRE Tactics: `T1110 (Brute Force)`, `T1078 (Valid Accounts)`, `T1068 (Privilege Escalation)`
   - Action Button: **`[Approve Session Revocation]`**
5. Analyst clicks **`[Approve Session Revocation]`**.
6. SentinelFlow validates authorization, revokes active sessions, verifies the resulting state, and renders the **Verification Receipt Card** with a cryptographic SHA-256 audit hash!

### Scenario 2: Benign Activity Check
**User in ASI:One:**
> *"Check security status for sarah-dev-202"*

**SentinelFlow Response:**
> Returns clean assessment: Risk `LOW` (Score: 0/100). All logins match normal corporate location baselines. No containment proposed.

### Scenario 3: Zero-Data / Clean Fallback
**User in ASI:One:**
> *"Investigate user unknown-user-999"*

**SentinelFlow Response:**
> *"SentinelFlow Investigation Complete: 0 security logs found for target 'unknown-user-999'. No anomalous signals detected."* (No hallucinated data).

---

## 📄 License
MIT License. Built for the Fetch.ai ASI:One Agent Challenge 2026.
