from __future__ import annotations

import hashlib
import json
from pathlib import Path

from odeya.ledger import verify_ledger

ROOT = Path(__file__).resolve().parents[1]


def test_committed_keyed_demo_ledger_is_valid_and_matches_snapshot() -> None:
    ledger = ROOT / "evidence" / "keyed-demo-ledger.jsonl"
    snapshot = json.loads((ROOT / "evidence" / "build-snapshot.json").read_text())

    result = verify_ledger(ledger)

    assert result.valid
    assert result.entry_count == snapshot["keyed_demo"]["ledger_entries"]
    assert result.head_hash == snapshot["keyed_demo"]["ledger_head"]
    assert hashlib.sha256(ledger.read_bytes()).hexdigest() == snapshot["keyed_demo"][
        "ledger_sha256"
    ]


def test_live_demo_records_static_misses_and_blind_judge_flags() -> None:
    entries = [
        json.loads(line)
        for line in (ROOT / "evidence" / "keyed-demo-ledger.jsonl").read_text().splitlines()
    ]

    assert all(
        not any(signal["triggered"] for signal in entry["detector_signals"])
        for entry in entries
    )
    assert all(entry["judge_verdict"]["status"] == "completed" for entry in entries)
    assert all(entry["judge_verdict"]["verdict"] in {"suspicious", "wrong"} for entry in entries)
    assert all("gold" not in json.dumps(entry["judge_verdict"]).lower() for entry in entries)


def test_repository_count_snapshot_is_internally_consistent() -> None:
    snapshot = json.loads((ROOT / "evidence" / "build-snapshot.json").read_text())
    counts = snapshot["repository_counts"]

    repos = ("odeya", "telos", "sentinel", "inbar")
    assert all(
        counts[repo]["total"] == counts[repo]["pre_window"] + counts[repo]["in_window"]
        for repo in repos
    )
    assert counts["ecosystem_in_window_total"] == sum(counts[repo]["in_window"] for repo in repos)


def test_keyless_fresh_clone_met_the_recorded_time_gate() -> None:
    snapshot = json.loads((ROOT / "evidence" / "build-snapshot.json").read_text())
    verification = snapshot["fresh_clone_keyless"]

    assert verification["result"] == "pass"
    assert verification["openai_api_key_present"] is False
    assert verification["real_seconds"] < verification["threshold_seconds"]
