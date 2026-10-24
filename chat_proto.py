"""Agent Chat Protocol (ACP) handlers for SentinelFlow."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from uuid import uuid4

from uagents import Context, Protocol
from uagents_core.contrib.protocols.chat import (
    ChatAcknowledgement,
    ChatMessage,
    TextContent,
    chat_protocol_spec,
)

from cards import (
    build_risk_assessment_message,
    build_verification_message,
)
from controller import SentinelFlowController

chat_proto = Protocol(spec=chat_protocol_spec)
controller = SentinelFlowController()

# Target account extraction regex
ACCOUNT_RE = re.compile(r"\b(demo-user-\w+|sarah-dev-\w+|test-user-\w+|user-\w+|acc-\w+|[a-zA-Z0-9_\-\.]+@[a-zA-Z0-9_\-\.]+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", re.IGNORECASE)


def parse_card_selection(text: str) -> dict[str, str] | None:
    """Extract structured action selection payload from card button interactions."""
    if not text:
        return None
    stripped = text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                return {str(k): str(v) for k, v in data.items()}
        except json.JSONDecodeError:
            pass

    # Fallback pattern matching for planner prose
    if "approve_containment" in stripped or "revoke" in stripped:
        return {"action": "approve_containment", "action_type": "revoke_user_sessions", "token": "CARD_ACTION_APPROVE"}
    if "dismiss" in stripped:
        return {"action": "dismiss_incident"}
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

    # 3. Check if user clicked an interactive card button
    card_selection = parse_card_selection(inbound_text)
    if card_selection:
        action_name = card_selection.get("action")
        target = card_selection.get("target", "demo-user-104")
        action_type = card_selection.get("action_type", "revoke_user_sessions")
        token = card_selection.get("token", "CARD_ACTION_APPROVE")

        if action_name == "approve_containment":
            ctx.logger.info(f"User approved containment '{action_type}' on '{target}' via Card.")
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
                reply = build_verification_message(
                    preamble=f"Authorization confirmed! Simulated containment '{action_type}' executed and verified on {target}.",
                    action_id=action_id,
                    target=target,
                    action_type=action_type,
                    actual_state=verification.get("actual_state", "sessions_revoked"),
                    audit_hash=verification.get("audit_hash", "e3b0c442..."),
                    timestamp=verification.get("timestamp", datetime.now(timezone.utc).isoformat()),
                )
            else:
                reply = ChatMessage(
                    timestamp=datetime.now(timezone.utc),
                    msg_id=uuid4(),
                    content=[
                        TextContent(
                            type="text",
                            text=f"Containment executed, but state verification failed: {verification.get('details', 'State mismatch detected.')}",
                        )
                    ],
                )
            await ctx.send(sender, reply)
            return

        elif action_name == "dismiss_incident":
            ctx.logger.info(f"Analyst dismissed alert for target '{target}'.")
            reply = ChatMessage(
                timestamp=datetime.now(timezone.utc),
                msg_id=uuid4(),
                content=[
                    TextContent(
                        type="text",
                        text=f"Incident for target '{target}' has been dismissed as a false positive by the analyst. Audit event logged.",
                    )
                ],
            )
            await ctx.send(sender, reply)
            return

    # 4. Process Natural Language Investigation Intent
    target = extract_target_from_text(inbound_text)
    ctx.logger.info(f"Initiating investigation for target: {target}")

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

    # 5. Return rich Interactive Risk Assessment Card
    preamble = (
        f"SentinelFlow analyzed authentication and SIEM records for **{target}**. "
        f"Risk Level: **{str(result.get('risk_level')).upper()}** (Score: {result.get('risk_score')}/100). "
        "Review the evidence and select an authorized response below:"
    )

    reply = build_risk_assessment_message(
        preamble=preamble,
        target=target,
        risk_level=result.get("risk_level", "medium"),
        risk_score=result.get("risk_score", 50),
        evidence=result.get("evidence", []),
        mitre_tactics=result.get("mitre_tactics", []),
        summary=result.get("summary", ""),
    )
    await ctx.send(sender, reply)


@chat_proto.on_message(model=ChatAcknowledgement)
async def handle_acknowledgement(ctx: Context, sender: str, msg: ChatAcknowledgement):
    """Handle delivery acknowledgments from ASI:One or interacting agents."""
    ctx.logger.info(f"Received delivery acknowledgment from {sender} for message {msg.acknowledged_msg_id}")

