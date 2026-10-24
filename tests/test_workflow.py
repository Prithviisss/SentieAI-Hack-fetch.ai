"""End-to-end workflow, resilience, idempotency, and card schema tests (T07, T08, T09, T10)."""

import json
import pytest
from controller import SentinelFlowController
from tools.simulated_response import reset_state_store, verify_containment_state, execute_simulated_action
from cards import build_risk_assessment_card, build_verification_receipt_card
from chat_proto import parse_card_selection, extract_target_from_text


@pytest.fixture(autouse=True)
def clean_state():
    reset_state_store()


def test_t07_tool_failure_resilience():
    """T07: When log search or backend tools fail, report clean failure instead of hallucinating success."""
    controller = SentinelFlowController()
    res = controller.process_investigation_request(
        intent="investigate_suspicious_logins",
        target="demo-user-104",
        simulate_tool_failure=True,
    )
    assert res["status"] == "failed"
    assert res["error_stage"] == "log_search"
    assert "timeout" in res["message"].lower() or "failed" in res["message"].lower()


def test_t08_verification_mismatch_detection():
    """T08: When a simulated action claims success but target state didn't change, verifier reports failure."""
    controller = SentinelFlowController()
    # Authorize action but simulate verification mismatch
    res = controller.process_investigation_request(
        intent="request_containment",
        target="demo-user-104",
        requested_action="revoke_user_sessions",
        approval_token="APPROVED_BY_ANALYST",
        simulate_verify_mismatch=True,
    )
    assert res["status"] == "failed"
    assert res["verification"] is not None
    assert res["verification"]["verified"] is False
    assert "FAILED" in res["verification"]["details"]


def test_t09_idempotency_duplicate_containment():
    """T09: Repeated containment requests on the same target return existing record without duplicate actions."""
    # First action
    res1 = execute_simulated_action("revoke_user_sessions", "demo-user-104")
    assert res1["status"] == "executed"
    act_id1 = res1["action_id"]

    # Duplicate action
    res2 = execute_simulated_action("revoke_user_sessions", "demo-user-104")
    assert res2["status"] == "duplicate_prevented"
    assert res2["action_id"] == act_id1


def test_t10_asi_one_interactive_cards_and_parsing():
    """T10: Validate ASI:One dynamic card schema structure and selection parsing."""
    card = build_risk_assessment_card(
        target="demo-user-104",
        risk_level="high",
        risk_score=85,
        evidence=["Multiple failed logins", "Anomalous location"],
        mitre_tactics=["T1110 - Brute Force"],
        summary="Suspicious burst detected.",
    )
    assert "root" in card
    assert card["root"]["type"] == "section"
    assert len(card["root"]["children"]) > 0

    # Test card button selection parsing
    raw_button_click = json.dumps({
        "action": "approve_containment",
        "target": "demo-user-104",
        "action_type": "revoke_user_sessions",
        "token": "CARD_ACTION_APPROVE",
    })
    parsed = parse_card_selection(raw_button_click)
    assert parsed is not None
    assert parsed["action"] == "approve_containment"
    assert parsed["target"] == "demo-user-104"

    # Test target regex extractor
    extracted = extract_target_from_text("Please investigate suspicious events on demo-user-104 immediately")
    assert extracted == "demo-user-104"
