"""SentinelFlow Multi-Agent Bureau: Orchestrates all 5 specialized Fetch.ai uAgents in a single cooperative runtime."""

from __future__ import annotations

import os
from dotenv import load_dotenv

load_dotenv()

from uagents import Bureau
from agents.coordinator import coordinator_agent
from agents.investigator import investigator_agent
from agents.analyst import analyst_agent
from agents.containment import containment_agent
from agents.auditor import auditor_agent


def create_sentinelflow_bureau() -> Bureau:
    """Initialize Fetch.ai Bureau with all 5 specialized SecOps agents."""
    bureau_port = int(os.getenv("BUREAU_PORT", "8000"))
    bureau = Bureau(port=bureau_port)

    # 1. Frontline SecOps Orchestrator Agent (interfaces with ASI:One via ACP)
    bureau.add(coordinator_agent)

    # 2. SIEM & Telemetry Search Agent
    bureau.add(investigator_agent)

    # 3. MITRE ATT&CK Threat Analyst Agent
    bureau.add(analyst_agent)

    # 4. Policy Gate & Containment Remediation Agent
    bureau.add(containment_agent)

    # 5. Closed-Loop State Verification & Audit Receipt Agent
    bureau.add(auditor_agent)

    return bureau


if __name__ == "__main__":
    print("=" * 65)
    print("🛡️  Starting SentinelFlow Multi-Agent Bureau (Fetch.ai uAgents)")
    print("   1. Coordinator Agent  -> ASI:One Interface & ACP Dispatch")
    print("   2. Investigator Agent -> SIEM Log Search & Injection Defense")
    print("   3. Analyst Agent      -> MITRE ATT&CK Risk Scoring (0-100)")
    print("   4. Containment Agent  -> HITL Policy Gate & State Remediation")
    print("   5. Auditor Agent      -> Closed-Loop State Inspection & Receipts")
    print("=" * 65)
    bureau = create_sentinelflow_bureau()
    bureau.run()
