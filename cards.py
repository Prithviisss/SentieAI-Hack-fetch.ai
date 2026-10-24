"""ASI:One Interactive Cards builder using Fetch.ai dynamic element-tree primitives."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from uagents_core.contrib.protocols.chat import (
    ChatMessage,
    MetadataContent,
    TextContent,
)

CARD_PROTOCOL_VERSION = "1"
SENTINELFLOW_SOURCE = "sentinelflow_ui"


def _card_metadata(card_payload: dict[str, Any]) -> MetadataContent:
    """Wrap an element-tree payload dict into an ACP MetadataContent block."""
    return MetadataContent(
        type="metadata",
        metadata={
            "card_protocol_version": CARD_PROTOCOL_VERSION,
            "requires_card_interaction": "true",
            "card_kind": "custom",
            "card_payload": json.dumps(card_payload),
        },
    )


def build_risk_assessment_card(
    target: str,
    risk_level: str,
    risk_score: int,
    evidence: list[str],
    mitre_tactics: list[str],
    summary: str,
) -> dict[str, Any]:
    """Generate interactive incident assessment card with evidence and containment action buttons."""
    badge_variant = "error" if risk_level in ("critical", "high") else ("warning" if risk_level == "medium" else "success")
    
    evidence_items = [{"type": "text", "value": f"• {e}", "style": "body"} for e in evidence]
    mitre_badges = [{"type": "badge", "label": t, "variant": "info"} for t in mitre_tactics]

    section: dict[str, Any] = {
        "type": "section",
        "title": "SentinelFlow Incident Assessment",
        "subtitle": f"Target: {target} | Risk Score: {risk_score}/100",
        "children": [
            {
                "type": "group",
                "direction": "row",
                "gap": 8,
                "children": [
                    {
                        "type": "badge",
                        "label": f"RISK LEVEL: {risk_level.upper()}",
                        "variant": badge_variant,
                    },
                    {
                        "type": "badge",
                        "label": f"SCORE: {risk_score}/100",
                        "variant": "info",
                    },
                ],
            },
            {
                "type": "heading",
                "value": f"Investigation Findings: {target}",
                "level": 3,
            },
            {
                "type": "text",
                "value": summary,
                "style": "body",
            },
            {"type": "divider"},
            {
                "type": "heading",
                "value": "Correlated Evidence",
                "level": 4,
            },
            {
                "type": "group",
                "direction": "column",
                "gap": 4,
                "children": evidence_items or [{"type": "text", "value": "No anomalous signals detected.", "style": "muted"}],
            },
            {"type": "divider"},
            {
                "type": "heading",
                "value": "MITRE ATT&CK Mapping",
                "level": 4,
            },
            {
                "type": "group",
                "direction": "row",
                "gap": 6,
                "children": mitre_badges or [{"type": "badge", "label": "None", "variant": "info"}],
            },
            {"type": "divider"},
            {
                "type": "group",
                "direction": "row",
                "gap": 8,
                "children": [
                    {
                        "type": "button",
                        "label": "Approve Session Revocation (0.1 FET)",
                        "primary": True,
                        "action": {
                            "selection": {
                                "action": "approve_containment",
                                "target": target,
                                "action_type": "revoke_user_sessions",
                                "token": "CARD_ACTION_APPROVE",
                                "fee": "0.1 FET",
                                "source": SENTINELFLOW_SOURCE,
                            }
                        },
                    },
                    {
                        "type": "button",
                        "label": "Block Attacker IP (0.1 FET)",
                        "primary": False,
                        "action": {
                            "selection": {
                                "action": "approve_containment",
                                "target": "198.51.100.42",
                                "action_type": "block_ip_address",
                                "token": "CARD_ACTION_APPROVE",
                                "fee": "0.1 FET",
                                "source": SENTINELFLOW_SOURCE,
                            }
                        },
                    },
                    {
                        "type": "button",
                        "label": "Dismiss Alert",
                        "primary": False,
                        "action": {
                            "selection": {
                                "action": "dismiss_incident",
                                "target": target,
                                "source": SENTINELFLOW_SOURCE,
                            }
                        },
                    },
                ],
            },
        ],
    }

    return {"root": section}


def build_verification_receipt_card(
    action_id: str,
    target: str,
    action_type: str,
    actual_state: str,
    audit_hash: str,
    timestamp: str,
    payment_status: str = "0.1 FET Settled (Fetch.ai Escrow)",
) -> dict[str, Any]:
    """Generate post-containment verified receipt card with cryptographic SHA-256 hash."""
    section: dict[str, Any] = {
        "type": "section",
        "title": "Incident Containment Verified",
        "subtitle": f"Action ID: {action_id}",
        "children": [
            {
                "type": "group",
                "direction": "row",
                "gap": 8,
                "children": [
                    {
                        "type": "badge",
                        "label": "STATUS: VERIFIED & AUDITED",
                        "variant": "success",
                    },
                    {
                        "type": "badge",
                        "label": payment_status,
                        "variant": "info",
                    },
                ],
            },
            {
                "type": "group",
                "direction": "column",
                "gap": 6,
                "children": [
                    {"type": "text", "value": f"Action: {action_type}", "style": "body"},
                    {"type": "text", "value": f"Target: {target}", "style": "body"},
                    {"type": "text", "value": f"Post-Remediation State: {actual_state}", "style": "body"},
                    {"type": "text", "value": f"Execution Timestamp: {timestamp}", "style": "muted"},
                    {"type": "text", "value": f"Payment Protocol: {payment_status}", "style": "muted"},
                ],
            },
            {"type": "divider"},
            {
                "type": "heading",
                "value": "Cryptographic Audit Receipt (SHA-256)",
                "level": 4,
            },
            {
                "type": "text",
                "value": audit_hash,
                "style": "code",
            },
        ],
    }
    return {"root": section}


def build_risk_assessment_message(
    preamble: str,
    target: str,
    risk_level: str,
    risk_score: int,
    evidence: list[str],
    mitre_tactics: list[str],
    summary: str,
) -> ChatMessage:
    """Create ChatMessage with text preamble and rich interactive assessment card."""
    card_dict = build_risk_assessment_card(
        target=target,
        risk_level=risk_level,
        risk_score=risk_score,
        evidence=evidence,
        mitre_tactics=mitre_tactics,
        summary=summary,
    )
    return ChatMessage(
        timestamp=datetime.now(timezone.utc),
        msg_id=uuid4(),
        content=[
            TextContent(type="text", text=preamble),
            _card_metadata(card_dict),
        ],
    )


def build_verification_message(
    preamble: str,
    action_id: str,
    target: str,
    action_type: str,
    actual_state: str,
    audit_hash: str,
    timestamp: str,
    payment_status: str = "0.1 FET Settled (Fetch.ai Escrow)",
) -> ChatMessage:
    """Create ChatMessage with text preamble and verified audit card."""
    card_dict = build_verification_receipt_card(
        action_id=action_id,
        target=target,
        action_type=action_type,
        actual_state=actual_state,
        audit_hash=audit_hash,
        timestamp=timestamp,
        payment_status=payment_status,
    )
    return ChatMessage(
        timestamp=datetime.now(timezone.utc),
        msg_id=uuid4(),
        content=[
            TextContent(type="text", text=preamble),
            _card_metadata(card_dict),
        ],
    )
