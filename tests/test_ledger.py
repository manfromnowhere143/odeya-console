from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from odeya.ledger import (
    ENTRY_FIELDS,
    GENESIS_HASH,
    LedgerIntegrityError,
    LedgerValidationError,
    append_receipt,
    canonical_json,
    compute_entry_hash,
    read_entries,
    verify_ledger,
)

CANDIDATE_HASH = hashlib.sha256(b"candidate patch").hexdigest()
TIMESTAMP = "2026-07-17T14:00:00.000Z"


def _append(
    path: Path,
    case_id: str,
    *,
    verdict: dict[str, object] | None = None,
) -> dict[str, object]:
    return append_receipt(
        path,
        case_id=case_id,
        detector_signals=[{"name": "static_miss", "triggered": False}],
        judge_verdict=verdict,
        candidate_sha256=CANDIDATE_HASH,
        ts_utc=TIMESTAMP,
    )


def test_canonical_json_is_compact_sorted_utf8_and_rejects_nan() -> None:
    assert canonical_json({"z": "שלום", "a": [2, 1]}) == '{"a":[2,1],"z":"שלום"}'

    with pytest.raises(LedgerValidationError, match="canonical JSON"):
        canonical_json({"value": float("nan")})


def test_compute_hash_uses_prev_hash_plus_payload_without_hash_fields() -> None:
    entry = {
        "ts_utc": TIMESTAMP,
        "case_id": "case-unicode-שלום",
        "detector_signals": [],
        "judge_verdict": None,
        "candidate_sha256": CANDIDATE_HASH,
        "prev_hash": GENESIS_HASH,
        "entry_hash": "f" * 64,
    }
    payload = {key: value for key, value in entry.items() if key not in {"prev_hash", "entry_hash"}}
    expected = hashlib.sha256((GENESIS_HASH + canonical_json(payload)).encode("utf-8")).hexdigest()

    assert compute_entry_hash(entry) == expected


@pytest.mark.parametrize("create_empty", [False, True])
def test_missing_or_empty_ledger_is_valid(tmp_path: Path, create_empty: bool) -> None:
    ledger = tmp_path / "nested" / "receipts.jsonl"
    if create_empty:
        ledger.parent.mkdir()
        ledger.touch()

    result = verify_ledger(ledger)

    assert result.valid
    assert result.entry_count == 0
    assert result.entries == 0
    assert result.head_hash == GENESIS_HASH


def test_append_creates_parent_and_extends_chain_durably(tmp_path: Path) -> None:
    ledger = tmp_path / "new" / "receipts.jsonl"

    first = _append(ledger, "case-one")
    second = _append(
        ledger,
        "case-two",
        verdict={"flagged": True, "reason": "behavior narrows on an untested input"},
    )

    assert set(first) == ENTRY_FIELDS
    assert first["prev_hash"] == GENESIS_HASH
    assert first["entry_hash"] == compute_entry_hash(first)
    assert second["prev_hash"] == first["entry_hash"]
    assert second["entry_hash"] == compute_entry_hash(second)
    assert ledger.read_bytes().endswith(b"\n")
    assert ledger.read_text(encoding="utf-8").splitlines() == [
        canonical_json(first),
        canonical_json(second),
    ]

    result = verify_ledger(ledger)
    assert result.valid
    assert result.entry_count == 2
    assert result.head_hash == second["entry_hash"]
    assert read_entries(ledger) == [first, second]


def test_append_refuses_invalid_existing_chain_without_changing_it(tmp_path: Path) -> None:
    ledger = tmp_path / "receipts.jsonl"
    _append(ledger, "case-one")
    original = ledger.read_text(encoding="utf-8")
    ledger.write_text(original.replace("case-one", "case-tampered"), encoding="utf-8")
    corrupted = ledger.read_bytes()

    with pytest.raises(LedgerIntegrityError) as caught:
        _append(ledger, "case-two")

    assert caught.value.result.error_code == "hash_mismatch"
    assert ledger.read_bytes() == corrupted


@pytest.mark.parametrize(
    ("mutate", "expected_code"),
    [
        (
            lambda lines: [
                lines[0].replace('"case-one"', '"case-edited"'),
                *lines[1:],
            ],
            "hash_mismatch",
        ),
        (lambda lines: [lines[0], lines[2]], "chain_break"),
        (lambda lines: [lines[1], lines[0], lines[2]], "chain_break"),
        (lambda lines: [lines[0], "{not-json", lines[2]], "malformed_json"),
        (lambda lines: [lines[0], "", lines[2]], "malformed_entry"),
    ],
)
def test_verification_catches_corruption(
    tmp_path: Path,
    mutate: object,
    expected_code: str,
) -> None:
    ledger = tmp_path / "receipts.jsonl"
    for case_id in ("case-one", "case-two", "case-three"):
        _append(ledger, case_id)
    lines = ledger.read_text(encoding="utf-8").splitlines()
    changed = mutate(lines)  # type: ignore[operator]
    ledger.write_text("\n".join(changed) + "\n", encoding="utf-8")

    result = verify_ledger(ledger)

    assert not result.valid
    assert result.error_code == expected_code
    assert result.line_number is not None


def test_verification_catches_partial_truncation(tmp_path: Path) -> None:
    ledger = tmp_path / "receipts.jsonl"
    _append(ledger, "case-one")
    data = ledger.read_bytes()
    ledger.write_bytes(data[:-12])

    result = verify_ledger(ledger)

    assert not result.valid
    assert result.error_code == "truncated_entry"
    assert result.line_number == 1


def test_checkpoint_catches_clean_tail_deletion(tmp_path: Path) -> None:
    ledger = tmp_path / "receipts.jsonl"
    _append(ledger, "case-one")
    last = _append(ledger, "case-two")
    checkpoint = verify_ledger(ledger)
    lines = ledger.read_text(encoding="utf-8").splitlines()
    ledger.write_text(lines[0] + "\n", encoding="utf-8")

    unanchored = verify_ledger(ledger)
    anchored = verify_ledger(
        ledger,
        expected_head_hash=str(last["entry_hash"]),
        expected_entry_count=checkpoint.entry_count,
    )

    assert unanchored.valid
    assert not anchored.valid
    assert anchored.error_code == "checkpoint_mismatch"


def test_noncanonical_but_semantically_equal_entry_is_rejected(tmp_path: Path) -> None:
    ledger = tmp_path / "receipts.jsonl"
    entry = _append(ledger, "case-one")
    ledger.write_text(json.dumps(entry, ensure_ascii=False) + "\n", encoding="utf-8")

    result = verify_ledger(ledger)

    assert not result.valid
    assert result.error_code == "noncanonical_entry"


@pytest.mark.parametrize(
    "overrides",
    [
        {"case_id": ""},
        {"candidate_sha256": "not-a-hash"},
        {"ts_utc": "2026-07-17T14:00:00+01:00"},
        {"detector_signals": [float("inf")]},
        {"judge_verdict": {"score": float("nan")}},
    ],
)
def test_append_rejects_invalid_new_receipt(
    tmp_path: Path,
    overrides: dict[str, object],
) -> None:
    arguments: dict[str, object] = {
        "case_id": "case-one",
        "detector_signals": [],
        "judge_verdict": None,
        "candidate_sha256": CANDIDATE_HASH,
        "ts_utc": TIMESTAMP,
    }
    arguments.update(overrides)

    with pytest.raises(LedgerValidationError):
        append_receipt(tmp_path / "receipts.jsonl", **arguments)  # type: ignore[arg-type]


def test_invalid_checkpoint_returns_stable_result(tmp_path: Path) -> None:
    result = verify_ledger(
        tmp_path / "missing.jsonl",
        expected_head_hash="bad",
        expected_entry_count=-1,
    )

    assert not result.valid
    assert result.error_code == "invalid_checkpoint"
