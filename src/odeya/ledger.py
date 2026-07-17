"""Append-only, hash-chained JSON Lines receipts.

Each entry commits to its predecessor and to its own non-hash fields. Verification
detects malformed records and internal edits, deletions, or reordering. Detecting a
clean removal of the final entry requires a previously recorded head hash or entry
count; callers can supply either checkpoint to :func:`verify_ledger`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

try:
    import fcntl
except ImportError:  # pragma: no cover - Odeya's supported runtimes are macOS/Linux.
    fcntl = None


GENESIS_HASH = "0" * 64
ENTRY_FIELDS = frozenset(
    {
        "ts_utc",
        "case_id",
        "detector_signals",
        "judge_verdict",
        "candidate_sha256",
        "prev_hash",
        "entry_hash",
    }
)
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


class LedgerError(Exception):
    """Base class for stable ledger failures exposed to the CLI."""


class LedgerValidationError(LedgerError):
    """A new receipt contains invalid or non-JSON data."""


class LedgerIOError(LedgerError):
    """The ledger could not be read or durably written."""


class LedgerIntegrityError(LedgerError):
    """An append was refused because the existing chain is invalid."""

    def __init__(self, result: VerificationResult) -> None:
        self.result = result
        super().__init__(result.error or "ledger verification failed")


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Machine-readable result returned for every verification attempt."""

    valid: bool
    entry_count: int
    head_hash: str
    error_code: str | None = None
    error: str | None = None
    line_number: int | None = None

    @property
    def entries(self) -> int:
        """Compatibility alias useful in human-readable CLI output."""

        return self.entry_count


def canonical_json(value: Any) -> str:
    """Return the one canonical JSON representation used for entries and hashes."""

    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise LedgerValidationError(f"value is not canonical JSON data: {exc}") from exc


def compute_entry_hash(entry: Mapping[str, Any]) -> str:
    """Hash ``prev_hash + canonical_json(entry excluding both hash fields)``."""

    prev_hash = entry.get("prev_hash")
    if not isinstance(prev_hash, str) or not _HASH_RE.fullmatch(prev_hash):
        raise LedgerValidationError("prev_hash must be 64 lowercase hexadecimal characters")
    payload = {key: value for key, value in entry.items() if key not in {"prev_hash", "entry_hash"}}
    material = (prev_hash + canonical_json(payload)).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def verify_ledger(
    path: str | os.PathLike[str],
    *,
    expected_head_hash: str | None = None,
    expected_entry_count: int | None = None,
) -> VerificationResult:
    """Verify a ledger without mutating it.

    A missing or empty ledger is a valid zero-entry chain. ``expected_head_hash``
    or ``expected_entry_count`` anchors the result so clean tail deletion can be
    detected; an unanchored hash chain cannot prove that its final suffix exists.
    """

    checkpoint_error = _validate_checkpoint(expected_head_hash, expected_entry_count)
    if checkpoint_error is not None:
        return checkpoint_error

    ledger_path = Path(path)
    try:
        if not ledger_path.exists():
            return _verify_text(
                "",
                expected_head_hash=expected_head_hash,
                expected_entry_count=expected_entry_count,
            )
        with (
            ledger_path.open("r", encoding="utf-8", newline="") as handle,
            _file_lock(handle, exclusive=False),
        ):
            text = handle.read()
    except UnicodeDecodeError as exc:
        return VerificationResult(
            valid=False,
            entry_count=0,
            head_hash=GENESIS_HASH,
            error_code="malformed_utf8",
            error=f"ledger is not valid UTF-8 at byte {exc.start}",
        )
    except OSError as exc:
        return VerificationResult(
            valid=False,
            entry_count=0,
            head_hash=GENESIS_HASH,
            error_code="io_error",
            error=f"could not read ledger: {exc}",
        )

    return _verify_text(
        text,
        expected_head_hash=expected_head_hash,
        expected_entry_count=expected_entry_count,
    )


def append_receipt(
    path: str | os.PathLike[str],
    *,
    case_id: str,
    detector_signals: list[Any] | tuple[Any, ...],
    judge_verdict: Mapping[str, Any] | None,
    candidate_sha256: str,
    ts_utc: str | None = None,
) -> dict[str, Any]:
    """Validate and durably append one receipt, refusing an invalid prior chain."""

    normalized_signals = _json_copy(detector_signals)
    normalized_verdict = _json_copy(judge_verdict)
    if not isinstance(normalized_signals, list):
        raise LedgerValidationError("detector_signals must be a JSON array")
    if normalized_verdict is not None and not isinstance(normalized_verdict, dict):
        raise LedgerValidationError("judge_verdict must be a JSON object or null")

    timestamp = ts_utc or _now_utc()
    payload: dict[str, Any] = {
        "ts_utc": timestamp,
        "case_id": case_id,
        "detector_signals": normalized_signals,
        "judge_verdict": normalized_verdict,
        "candidate_sha256": candidate_sha256,
    }
    validation_error = _validate_payload(payload)
    if validation_error is not None:
        raise LedgerValidationError(validation_error)

    ledger_path = Path(path)
    try:
        ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with (
            ledger_path.open("a+", encoding="utf-8", newline="\n") as handle,
            _file_lock(handle, exclusive=True),
        ):
            handle.seek(0)
            prior_text = handle.read()
            prior = _verify_text(prior_text)
            if not prior.valid:
                raise LedgerIntegrityError(prior)

            entry = {
                **payload,
                "prev_hash": prior.head_hash,
                "entry_hash": "",
            }
            entry["entry_hash"] = compute_entry_hash(entry)
            handle.seek(0, os.SEEK_END)
            handle.write(canonical_json(entry) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
            return entry
    except LedgerError:
        raise
    except OSError as exc:
        raise LedgerIOError(f"could not append ledger receipt: {exc}") from exc


def read_entries(path: str | os.PathLike[str]) -> list[dict[str, Any]]:
    """Read a valid chain, raising :class:`LedgerIntegrityError` otherwise."""

    result = verify_ledger(path)
    if not result.valid:
        raise LedgerIntegrityError(result)
    ledger_path = Path(path)
    if not ledger_path.exists() or ledger_path.stat().st_size == 0:
        return []
    try:
        return [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines()]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        result = VerificationResult(
            valid=False,
            entry_count=0,
            head_hash=GENESIS_HASH,
            error_code="io_error",
            error=f"ledger changed while it was being read: {exc}",
        )
        raise LedgerIntegrityError(result) from exc


def _verify_text(
    text: str,
    *,
    expected_head_hash: str | None = None,
    expected_entry_count: int | None = None,
) -> VerificationResult:
    if not text:
        return _apply_checkpoint(
            VerificationResult(True, 0, GENESIS_HASH),
            expected_head_hash,
            expected_entry_count,
        )
    if not text.endswith("\n"):
        return VerificationResult(
            valid=False,
            entry_count=max(text.count("\n"), 0),
            head_hash=GENESIS_HASH,
            error_code="truncated_entry",
            error="ledger does not end with a complete newline-terminated entry",
            line_number=text.count("\n") + 1,
        )

    previous = GENESIS_HASH
    count = 0
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line:
            return _invalid(
                count,
                previous,
                "malformed_entry",
                "blank ledger line",
                line_number,
            )
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            return _invalid(
                count,
                previous,
                "malformed_json",
                f"invalid JSON: {exc.msg}",
                line_number,
            )
        if not isinstance(entry, dict):
            return _invalid(
                count,
                previous,
                "invalid_shape",
                "entry must be a JSON object",
                line_number,
            )
        if set(entry) != ENTRY_FIELDS:
            missing = sorted(ENTRY_FIELDS - set(entry))
            extra = sorted(set(entry) - ENTRY_FIELDS)
            return _invalid(
                count,
                previous,
                "invalid_shape",
                f"entry fields mismatch; missing={missing}, extra={extra}",
                line_number,
            )
        validation_error = _validate_entry(entry)
        if validation_error is not None:
            return _invalid(
                count,
                previous,
                "invalid_entry",
                validation_error,
                line_number,
            )
        try:
            canonical_line = canonical_json(entry)
        except LedgerValidationError as exc:
            return _invalid(
                count,
                previous,
                "invalid_entry",
                str(exc),
                line_number,
            )
        if line != canonical_line:
            return _invalid(
                count,
                previous,
                "noncanonical_entry",
                "entry is not encoded as canonical JSON",
                line_number,
            )
        if entry["prev_hash"] != previous:
            return _invalid(
                count,
                previous,
                "chain_break",
                "prev_hash does not match the preceding entry hash",
                line_number,
            )
        try:
            computed = compute_entry_hash(entry)
        except LedgerValidationError as exc:
            return _invalid(
                count,
                previous,
                "invalid_entry",
                str(exc),
                line_number,
            )
        if entry["entry_hash"] != computed:
            return _invalid(
                count,
                previous,
                "hash_mismatch",
                "entry_hash does not match the canonical entry payload",
                line_number,
            )
        previous = entry["entry_hash"]
        count += 1

    return _apply_checkpoint(
        VerificationResult(True, count, previous),
        expected_head_hash,
        expected_entry_count,
    )


def _validate_entry(entry: Mapping[str, Any]) -> str | None:
    payload_error = _validate_payload(entry)
    if payload_error is not None:
        return payload_error
    for field_name in ("prev_hash", "entry_hash"):
        value = entry.get(field_name)
        if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
            return f"{field_name} must be 64 lowercase hexadecimal characters"
    return None


def _validate_payload(payload: Mapping[str, Any]) -> str | None:
    timestamp = payload.get("ts_utc")
    if not isinstance(timestamp, str) or not timestamp.endswith("Z"):
        return "ts_utc must be an RFC 3339 UTC timestamp ending in Z"
    try:
        parsed = datetime.fromisoformat(timestamp[:-1] + "+00:00")
    except ValueError:
        return "ts_utc must be an RFC 3339 UTC timestamp ending in Z"
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        return "ts_utc must be an RFC 3339 UTC timestamp ending in Z"

    case_id = payload.get("case_id")
    if not isinstance(case_id, str) or not case_id.strip():
        return "case_id must be a non-empty string"
    signals = payload.get("detector_signals")
    if not isinstance(signals, list):
        return "detector_signals must be a JSON array"
    verdict = payload.get("judge_verdict")
    if verdict is not None and not isinstance(verdict, dict):
        return "judge_verdict must be a JSON object or null"
    candidate_hash = payload.get("candidate_sha256")
    if not isinstance(candidate_hash, str) or not _HASH_RE.fullmatch(candidate_hash):
        return "candidate_sha256 must be 64 lowercase hexadecimal characters"
    try:
        canonical_json(signals)
        canonical_json(verdict)
    except LedgerValidationError as exc:
        return str(exc)
    return None


def _json_copy(value: Any) -> Any:
    return json.loads(canonical_json(value))


def _now_utc() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _invalid(
    entry_count: int,
    head_hash: str,
    error_code: str,
    error: str,
    line_number: int,
) -> VerificationResult:
    return VerificationResult(
        valid=False,
        entry_count=entry_count,
        head_hash=head_hash,
        error_code=error_code,
        error=f"line {line_number}: {error}",
        line_number=line_number,
    )


def _validate_checkpoint(
    expected_head_hash: str | None,
    expected_entry_count: int | None,
) -> VerificationResult | None:
    if expected_head_hash is not None and not _HASH_RE.fullmatch(expected_head_hash):
        return VerificationResult(
            valid=False,
            entry_count=0,
            head_hash=GENESIS_HASH,
            error_code="invalid_checkpoint",
            error="expected_head_hash must be 64 lowercase hexadecimal characters",
        )
    if expected_entry_count is not None and (
        isinstance(expected_entry_count, bool)
        or not isinstance(expected_entry_count, int)
        or expected_entry_count < 0
    ):
        return VerificationResult(
            valid=False,
            entry_count=0,
            head_hash=GENESIS_HASH,
            error_code="invalid_checkpoint",
            error="expected_entry_count must be a non-negative integer",
        )
    return None


def _apply_checkpoint(
    result: VerificationResult,
    expected_head_hash: str | None,
    expected_entry_count: int | None,
) -> VerificationResult:
    if expected_entry_count is not None and result.entry_count != expected_entry_count:
        return VerificationResult(
            valid=False,
            entry_count=result.entry_count,
            head_hash=result.head_hash,
            error_code="checkpoint_mismatch",
            error=(
                f"entry count checkpoint mismatch: expected {expected_entry_count}, "
                f"found {result.entry_count}"
            ),
        )
    if expected_head_hash is not None and result.head_hash != expected_head_hash:
        return VerificationResult(
            valid=False,
            entry_count=result.entry_count,
            head_hash=result.head_hash,
            error_code="checkpoint_mismatch",
            error=(
                f"head hash checkpoint mismatch: expected {expected_head_hash}, "
                f"found {result.head_hash}"
            ),
        )
    return result


@contextmanager
def _file_lock(handle: TextIO, *, exclusive: bool) -> Iterator[None]:
    if fcntl is None:  # pragma: no cover
        yield
        return
    operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    fcntl.flock(handle.fileno(), operation)
    try:
        yield
    finally:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
