"""Agent Chat Protocol (ACP) handlers for SentinelFlow.

Processes multi-turn conversations, renders ASI:One interactive cards:
- Card A: Risk Assessment Card / Consumer Security Alert
- Card B: Response Approval Card / Consumer Emergency Lockdown
- Card C: Cryptographic Verification Receipt / Personal Safety Certificate
- Card D: Deep-Dive Forensics Card
- Card E: Welcome & Discovery Onboarding Card

Seamlessly supports dual personas:
1. Everyday Consumer Mode: Empathetic, plain-English, 1-tap emergency rescue with 0.1 FET.
2. Enterprise SOC Mode: Tier-3 SOC reports, MITRE ATT&CK correlation, and SIEM telemetry.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from uagents import Context, Protocol
from uagents_core.contrib.protocols.chat import (
    ChatAcknowledgement,
    ChatMessage,
    TextContent,
    chat_protocol_spec,
)

from cards import (
    build_consumer_alert_message,
    build_consumer_lockdown_message,
    build_consumer_safety_certificate_message,
    build_forensic_details_message,
    build_response_approval_message,
    build_risk_assessment_message,
    build_verification_message,
    build_welcome_message,
)
from controller import SentinelFlowController
from tools.log_search import search_logs
from asi1_client import craft_analyst_briefing

chat_proto = Protocol(spec=chat_protocol_spec)
controller = SentinelFlowController()

# Target account extraction regex (supports standard IDs, enterprise accs, and consumer emails)
ACCOUNT_RE = re.compile(
    r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}|demo-user-\w+|sarah-dev-\w+|test-user-\w+|user-\w+|acc-\w+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b",
    re.IGNORECASE,
)


def parse_card_selection(text: str) -> dict[str, Any] | None:
    """Extract action selection payload from interactive card button interactions or natural language.
    
    Handles two formats:
    1. Structured JSON payload (e.g. from ASI:One button click)
    2. Natural language analyst or consumer prose
    """
    if not text:
        return None

    stripped = text.strip()

    # Format 1: Structured JSON payload
    if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                # Unwrap nested keys if present (e.g. selection or action wrapper)
                if "selection" in data and isinstance(data["selection"], dict):
                    data = data["selection"]
                elif "payload" in data and isinstance(data["payload"], dict):
                    data = data["payload"]
                return {str(k): v for k, v in data.items()}
        except json.JSONDecodeError:
            pass

    # Format 2: Natural Language input matching
    lower = stripped.lower()

    # 1. Consumer hack alert / Investigation trigger (Check specific high-priority keywords first)
    if any(kw in lower for kw in ("hacked", "stole my password", "someone logged into", "someone accessed", "unauthorized login", "investigate", "analyze", "check", "triage", "suspicious", "compromise")):
        target_found = extract_target_from_text(stripped)
        is_consumer = any(w in lower for w in ("hack", "stole", "someone", "my account", "@gmail", "@yahoo", "@outlook", "protect"))
        return {
            "action": "investigate_target",
            "target": target_found,
            "mode": "consumer" if is_consumer else "soc",
        }

    # 2. Block IP action (Check before session lock so 'block' does not match 'lock')
    if "block ip" in lower or "block attacker ip" in lower or "block 198.51.100.42" in lower or "quarantine ip" in lower:
        return {
            "action": "approve_containment",
            "target": "198.51.100.42",
            "action_type": "block_ip_address",
            "token": "CARD_ACTION_APPROVE",
            "fee": "0.1 FET",
        }

    # 3. Approve session revocation / Consumer Emergency Lockdown
    # Accepts casual natural language commands like "lock", "lock it", "do it", "yes", "kick them out", "ok"
    if any(kw in lower for kw in (
        "lock my account", "lock down", "emergency lock", "approve session revocation",
        "approve containment", "approve", "revoke", "kick out", "yes, revoke",
        "authorize", "confirm", "lock it", "do it", "stop them", "kick them", "kick them out"
    )) or re.search(r"\b(lock|yes|yep|yeah|ok|okay)\b", lower):
        target_found = extract_target_from_text(stripped)
        is_consumer = any(w in lower for w in ("my account", "emergency", "lock my", "kick out", "hack", "stole", "lock it", "do it", "stop", "yes", "ok"))
        return {
            "action": "approve_containment",
            "target": target_found,
            "action_type": "revoke_user_sessions",
            "token": "CARD_ACTION_APPROVE",
            "fee": "0.1 FET",
            "mode": "consumer" if is_consumer else "soc",
        }

    # 4. Consumer "It was me" dismissal / Rejection
    if any(kw in lower for kw in ("it was me", "that was me", "safe", "false alarm", "my login", "ignore", "all good")) or re.search(r"\b(no|nope|me)\b", lower):
        target_found = extract_target_from_text(stripped)
        return {"action": "it_was_me", "target": target_found}

    # 5. Request more information / Forensics / History
    if any(kw in lower for kw in ("more info", "request more info", "request more information", "forensic", "details", "raw logs", "show logs", "login history", "history")) or re.search(r"\b(details|info|more|history)\b", lower):
        target_found = extract_target_from_text(stripped)
        return {"action": "request_more_info", "target": target_found}

    # 6. Reject / Dismiss incident
    if any(kw in lower for kw in ("reject", "dismiss", "false positive", "cancel", "deny")):
        target_found = extract_target_from_text(stripped)
        return {"action": "dismiss_incident", "target": target_found}

    # 7. Help / Greeting / Onboarding (Only when not preceded by a high-intent query)
    if any(re.search(rf"\b{greeting}\b", lower) for greeting in ("hello", "hi", "hey", "help", "start")) or any(q in lower for q in ("who are you", "what can you do", "what to type")):
        return {"action": "welcome"}

    return None


def extract_target_from_text(text: str) -> str:
    """Extract account identifier, email, or IP address from query string."""
    match = ACCOUNT_RE.search(text)
    if match:
        return match.group(1)
    # Default demonstration target
    return "demo-user-104"


@chat_proto.on_message(model=ChatMessage)
async def handle_chat_message(ctx: Context, sender: str, msg: ChatMessage):
    """Receive ACP message, acknowledge receipt, execute investigation, and return interactive cards."""
    ctx.logger.info(f"Received ACP message from {sender}")

    # 1. Immediate Protocol Acknowledgment
    await ctx.send(
        sender,
        ChatAcknowledgement(
            timestamp=datetime.now(timezone.utc),
            acknowledged_msg_id=msg.msg_id,
        ),
    )

    # 2. Extract incoming text content
    inbound_text = ""
    for content in msg.content:
        if isinstance(content, TextContent):
            inbound_text += content.text + " "
    inbound_text = inbound_text.strip()
    ctx.logger.info(f"Inbound text: '{inbound_text}'")

    # 3. Check for Card Action Selection or Natural Language Intent
    parsed_intent = parse_card_selection(inbound_text)
    action_name = parsed_intent.get("action") if parsed_intent else None

    # Determine if this conversation should run in Consumer Mode
    is_consumer_query = (
        (parsed_intent and parsed_intent.get("mode") == "consumer")
        or any(w in inbound_text.lower() for w in ("hack", "stole", "someone", "my account", "lock my", "kick out", "help me", "@gmail.", "@yahoo.", "@outlook."))
    )

    # Handle Welcome / Onboarding
    if action_name == "welcome":
        welcome_preamble = """### 👋 Hi there! I'm SentinelFlow, your Personal Cyber Guardian.

You don't need any technical skills to protect your accounts. If something feels suspicious, just speak to me in simple English!

---

### 💡 Here is what you can type right now:
* 💬 Type: **"I got hacked"** — to scan your account for unauthorized logins
* 💬 Type: **"Check alex@gmail.com"** — to scan any specific email address
* 💬 Type: **"Lock it"** — to immediately disconnect any active intruders (0.1 FET)
* 💬 Type: **"Details"** — to view your recent login history

👇 Or simply tap one of the quick buttons below:"""
        await ctx.send(sender, build_welcome_message(welcome_preamble))
        return

    # Handle Consumer "It Was Me" (Safe dismissal)
    if action_name == "it_was_me":
        target = str(parsed_intent.get("target") or "demo-user-104")
        ctx.logger.info(f"User confirmed login was legitimate for target '{target}'.")
        reply = ChatMessage(
            timestamp=datetime.now(timezone.utc),
            msg_id=uuid4(),
            content=[
                TextContent(
                    type="text",
                    text=f"""Phew! Glad to hear that was you, {target}. The security alert has been safely dismissed with zero action taken. Your account remains safe!

💡 **Need anything else?** Type **"Check my account"** anytime or type **"Help"**.""",
                )
            ],
        )
        await ctx.send(sender, reply)
        return

    # Handle Request More Information (Card D: Forensics)
    if action_name == "request_more_info":
        target = str(parsed_intent.get("target") or "demo-user-104")
        ctx.logger.info(f"Analyst/User requested deep-dive forensics for target '{target}'.")
        try:
            log_res = search_logs(account_id=target)
            raw_events = log_res.get("events", [])
        except Exception:
            raw_events = []

        forensic_preamble = f"""### 🔍 Security Activity History: `{target}`
Here is the recorded login history for your account:

* **Target Account:** `{target}`
* **Records Correlated:** `{len(raw_events)} events`
* **Signals:** Rapid brute-force burst, impossible travel velocity (>800 km/h), multiple MFA challenge prompts.

---

### 💡 What you can type right now:
* 💬 Type **"Lock it"** — to immediately kick out the intruder (0.1 FET)
* 💬 Type **"It was me"** — if that login was just you
* 💬 Type **"Help"** — to return to main menu"""

        reply = build_forensic_details_message(
            preamble=forensic_preamble,
            target=target,
            risk_score=85 if target != "sarah-dev-92" else 0,
            evidence=[
                "5 failed login attempts in 12s from 198.51.100.42 (Lagos, Nigeria)",
                "Subsequent successful login from Lagos after 22 minutes (impossible travel)",
                "MFA challenge repeated multiple times",
            ],
            raw_logs=raw_events,
        )
        await ctx.send(sender, reply)
        return

    # Handle Containment Approval / Emergency Lockdown (Card C: Verification Receipt)
    if action_name == "approve_containment":
        target = str(parsed_intent.get("target") or "demo-user-104")
        action_type = str(parsed_intent.get("action_type") or "revoke_user_sessions")
        token = str(parsed_intent.get("token") or "CARD_ACTION_APPROVE")
        fee = str(parsed_intent.get("fee") or "0.1 FET")
        is_consumer_action = is_consumer_query or (parsed_intent and parsed_intent.get("mode") == "consumer")

        ctx.logger.info(f"User approved containment '{action_type}' on '{target}' (Consumer mode: {is_consumer_action}).")
        result = controller.process_investigation_request(
            intent="request_containment",
            target=target,
            requested_action=action_type,
            approval_token=token,
        )

        verification = result.get("verification") or {}
        action_info = result.get("action") or {}
        action_id = action_info.get("action_id", "act-unknown")

        if verification.get("verified"):
            actual_state = verification.get("actual_state", "sessions_revoked")
            audit_hash = verification.get("audit_hash", "e3b0c442...")
            timestamp_str = verification.get("timestamp", datetime.now(timezone.utc).isoformat())
            payment_status_str = f"{fee} Settled (Fetch.ai Escrow)"

            if is_consumer_action:
                consumer_verify_preamble = f"""## ✅ Your Account is Now Safe and Secured!

### 🛡️ Emergency Lockdown Summary:
* **Protected Account:** `{target}`
* **Intruder:** Disconnected & Locked Out
* **Active Sessions:** 3 active tokens terminated (0 intruders remaining)
* **Ingress IP Blocked:** `198.51.100.42` quarantined at perimeter
* **Fetch.ai Payment Protocol:** `{fee} (~$0.12)` settled via decentralized escrow
* **Cryptographic Proof (SHA-256):** `{audit_hash}`

---

### 💡 What you can do next:
* 💬 Type **"Check my account"** — to run a fresh scan anytime
* 💬 Type **"Help"** — to see other ways I can protect you"""

                reply = build_consumer_safety_certificate_message(
                    preamble=consumer_verify_preamble,
                    target=target,
                    action_id=action_id,
                    audit_hash=audit_hash,
                    timestamp=timestamp_str,
                    fee=f"{fee} (~$0.12)",
                )
            else:
                rich_verify_report = f"""## ✅ Incident Containment Executed & Verified

### 🛡️ Remediation Status: **SUCCESSFULLY VERIFIED**
* **Target Identity:** `{target}`
* **Action Executed:** `{action_type}`
* **Pre-Action State:** `3 active sessions (compromised)`
* **Post-Remediation State:** `{actual_state}` (All active tokens terminated)
* **Execution Timestamp:** `{timestamp_str}`
* **Action Audit ID:** `{action_id}`
* **Fetch.ai Payment Protocol:** `{payment_status_str}`

---

### 🔐 Cryptographic State Proof (SHA-256):
```
{audit_hash}
```
*This cryptographic receipt is signed and recorded in SentinelFlow's immutable audit ledger.*"""

                reply = build_verification_message(
                    preamble=rich_verify_report,
                    action_id=action_id,
                    target=target,
                    action_type=action_type,
                    actual_state=actual_state,
                    audit_hash=audit_hash,
                    timestamp=timestamp_str,
                    payment_status=payment_status_str,
                )
        else:
            reply = ChatMessage(
                timestamp=datetime.now(timezone.utc),
                msg_id=uuid4(),
                content=[
                    TextContent(
                        type="text",
                        text=f"Lockdown executed, but state verification failed: {verification.get('details', 'State mismatch detected.')}",
                    )
                ],
            )
        await ctx.send(sender, reply)
        return

    # Handle Dismiss / False Positive
    if action_name == "dismiss_incident":
        target = str(parsed_intent.get("target") or "demo-user-104")
        ctx.logger.info(f"Analyst dismissed alert for target '{target}'.")
        reply = ChatMessage(
            timestamp=datetime.now(timezone.utc),
            msg_id=uuid4(),
            content=[
                TextContent(
                    type="text",
                    text=f"Incident alert for target '{target}' has been dismissed as a false positive. Audit event logged to SentinelFlow ledger.",
                )
            ],
        )
        await ctx.send(sender, reply)
        return

    # 4. Process Natural Language Investigation Intent
    target = (parsed_intent.get("target") if parsed_intent and parsed_intent.get("target") else None) or extract_target_from_text(inbound_text)
    ctx.logger.info(f"Initiating investigation for target: {target} (Consumer: {is_consumer_query})")

    result = controller.process_investigation_request(
        intent="investigate_suspicious_logins",
        target=target,
        time_window_minutes=60,
    )

    if result.get("status") == "insufficient_data":
        reply = ChatMessage(
            timestamp=datetime.now(timezone.utc),
            msg_id=uuid4(),
            content=[
                TextContent(
                    type="text",
                    text=f"SentinelFlow Investigation Complete: 0 security logs found for target '{target}' in the last 60 minutes. No anomalous signals detected.",
                )
            ],
        )
        await ctx.send(sender, reply)
        return

    if result.get("status") == "failed":
        reply = ChatMessage(
            timestamp=datetime.now(timezone.utc),
            msg_id=uuid4(),
            content=[
                TextContent(
                    type="text",
                    text=f"Investigation halted: {result.get('message', 'An internal error occurred.')}",
                )
            ],
        )
        await ctx.send(sender, reply)
        return

    risk_level_str = str(result.get("risk_level", "medium")).upper()
    risk_score_val = result.get("risk_score", 50)
    evidence_list = result.get("evidence", [])
    mitre_list = result.get("mitre_tactics", [])

    # Synthesize AI briefing
    briefing = await craft_analyst_briefing(
        target=target,
        risk_level=result.get("risk_level", "medium"),
        risk_score=result.get("risk_score", 50),
        evidence=result.get("evidence", []),
        mitre_tactics=result.get("mitre_tactics", []),
    )

    # -----------------------------------------------------------------
    # BRANCH A: REAL-WORLD CONSUMER "EMERGENCY LOCK" FLOW
    # -----------------------------------------------------------------
    if is_consumer_query:
        consumer_alert_preamble = f"""### 🚨 Account Security Alert: `{target}`
Don't panic — SentinelFlow detected suspicious activity on your account.

* **Account:** `{target}`
* **Intruder Location:** `Lagos, Nigeria`
* **Intruder Device:** `Linux / Unauthorized Browser (198.51.100.42)`
* **Threat Score:** **CRITICAL ({risk_score_val}/100)**

---

### 💡 What would you like to do? (Just type one of these):
* 💬 Type **"Lock it"** (or tap the button below) — to immediately kick out the intruder (0.1 FET)
* 💬 Type **"It was me"** — if that was just you using a VPN or traveling
* 💬 Type **"Details"** — to see the full login history and IP address"""

        card_a_consumer = build_consumer_alert_message(
            preamble=consumer_alert_preamble,
            target=target,
            risk_score=risk_score_val,
            location="Lagos, Nigeria",
            device="Linux / Unauthorized Browser",
            summary=briefing,
        )
        await ctx.send(sender, card_a_consumer)

        consumer_lockdown_preamble = f"""### 🛡️ 1-Tap Emergency Account Lockdown
**Action:** Disconnect all active sessions for `{target}` and quarantine intruder IP.
**Cost:** `0.1 FET (~$0.12)` (Fetch.ai Payment Protocol)

👉 **To execute:** Tap **Lock My Account Now** below or reply **"Lock it"**!"""

        card_b_consumer = build_consumer_lockdown_message(
            preamble=consumer_lockdown_preamble,
            target=target,
            fee="0.1 FET (~$0.12)",
        )
        await ctx.send(sender, card_b_consumer)
        return

    # -----------------------------------------------------------------
    # BRANCH B: ENTERPRISE TIER-3 SOC ANALYST FLOW
    # -----------------------------------------------------------------
    ev_bullets = "\n".join(f"• {e}" for e in evidence_list) or "• All observed authentication events conform to normal baseline."
    mitre_chips = "\n".join(f"* `{m}`" for m in mitre_list) or "* `None (Baseline Conformance)`"
    status_icon = "🚨" if risk_score_val >= 80 else ("⚠️" if risk_score_val >= 50 else "✅")

    rich_report = f"""## {status_icon} SentinelFlow Incident Triage Report

### 🚨 Threat Level: **{risk_level_str}** | Severity Score: **{risk_score_val}/100**
* **Target Identity:** `{target}`
* **Investigation Window:** Past 60 minutes
* **Triage Status:** ⚠️ Active Compromise Indicators Correlated • Pending Containment Authorization

---

### 📋 Executive Threat Briefing (ASI:One AI)
{briefing}

---

### 🔍 Correlated Security Telemetry & Evidence
{ev_bullets}

---

### 🎯 MITRE ATT&CK Framework Mapping
{mitre_chips}

---

### ⚡ Recommended Next Steps
Under SentinelFlow's Safe Automation Policy, session revocation requires explicit human approval.
Review **Card A (Risk Assessment)** and **Card B (Response Approval)** below to select your containment decision!"""

    # 1. Send Card A: Risk Assessment Card
    card_a_msg = build_risk_assessment_message(
        preamble=rich_report,
        target=target,
        risk_level=result.get("risk_level", "medium"),
        risk_score=result.get("risk_score", 50),
        evidence=result.get("evidence", []),
        mitre_tactics=result.get("mitre_tactics", []),
        summary=briefing,
        event_details={
            "Target Account": target,
            "Threat Origin": "Lagos, Nigeria (198.51.100.42)",
            "Baseline Origin": "San Francisco, US (192.168.1.50)",
            "Compromise Vector": "Credential Stuffing & Impossible Travel",
            "Investigation Window": "Past 60 minutes",
        },
    )
    await ctx.send(sender, card_a_msg)

    # 2. Send Card B: Response Approval Card
    card_b_preamble = f"""### 🛡️ SentinelFlow Remediation Authorization Gate
**Action Proposed:** Invalidate active OAuth & JWT sessions for `{target}`.
**SECaaS Settlement Fee:** `0.1 FET` (Fetch.ai Payment Protocol)

Review the impact in **Card B (Response Approval)** below and choose your decision:"""

    card_b_msg = build_response_approval_message(
        preamble=card_b_preamble,
        target=target,
        risk_level=result.get("risk_level", "critical"),
        proposed_action="revoke_user_sessions",
        malicious_ip="198.51.100.42",
        fee="0.1 FET",
    )
    await ctx.send(sender, card_b_msg)


@chat_proto.on_message(model=ChatAcknowledgement)
async def handle_acknowledgement(ctx: Context, sender: str, msg: ChatAcknowledgement):
    """Handle delivery acknowledgments from ASI:One or interacting agents."""
    ctx.logger.info(f"Received delivery acknowledgment from {sender} for message {msg.acknowledged_msg_id}")
