"""Deterministic security log search tool for SentinelFlow.

Queries structured authentication and SIEM records without hallucinating events.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


DEFAULT_LOG_PATH = Path(__file__).resolve().parent.parent / "data" / "sample_logs.json"


class LogSearchError(Exception):
    """Raised when the log data source is unavailable or corrupted."""
    pass


def search_logs(
    account_id: str | None = None,
    ip_address: str | None = None,
    event_type: str | None = None,
    time_window_minutes: int = 60,
    log_file_path: Path | None = None,
    simulate_failure: bool = False,
) -> dict[str, Any]:
    """Retrieve matching security events based on deterministic query criteria."""
    if simulate_failure:
        raise LogSearchError("Simulated log database connection timeout (HTTP 504 / ECONNREFUSED).")

    source_path = log_file_path or DEFAULT_LOG_PATH
    if not source_path.exists():
        raise LogSearchError(f"Security log data source not found at path: {source_path}")

    try:
        with open(source_path, "r", encoding="utf-8") as f:
            all_records: list[dict[str, Any]] = json.load(f)
    except Exception as exc:
        raise LogSearchError(f"Failed to parse security logs: {exc}") from exc

    matches: list[dict[str, Any]] = []
    account_filter = account_id.strip().lower() if account_id else None
    ip_filter = ip_address.strip() if ip_address else None

    for record in all_records:
        rec_acc = str(record.get("account_id", "")).lower()
        rec_email = str(record.get("user_email", "")).lower()
        rec_ip = str(record.get("ip_address", ""))
        rec_type = str(record.get("event_type", ""))

        # Account / user match
        if account_filter:
            if account_filter not in rec_acc and account_filter not in rec_email:
                continue

        # IP address match
        if ip_filter and rec_ip != ip_filter:
            continue

        # Event type match
        if event_type and rec_type != event_type:
            continue

        matches.append(record)

    return {
        "status": "success",
        "query_target": account_id or ip_address or "all",
        "total_records_scanned": len(all_records),
        "matches_found": len(matches),
        "events": matches,
    }
