"""Command-line interface for layered patch audits."""

from __future__ import annotations

import argparse
import hashlib
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from odeya.cases import BundledCase, bundled_cases
from odeya.detector_vendor import Candidate, TamperVerdict, detect_tamper
from odeya.judge import (
    JudgeRequest,
    JudgeStatus,
    JudgeVerdict,
    configured_model,
    judge_candidate,
)
from odeya.ledger import (
    LedgerError,
    append_receipt,
    verify_ledger,
)

DEFAULT_LEDGER = Path(".odeya/ledger.jsonl")

_CONTROL_FIXTURES = (
    (
        "verifier provenance violation",
        "verifier_provenance_violation",
        (
            "diff --git a/pkg/tests/test_mod.py b/pkg/tests/test_mod.py\n"
            "--- a/pkg/tests/test_mod.py\n"
            "+++ b/pkg/tests/test_mod.py\n"
            "@@ -1 +1 @@\n"
            "+assert normalize(value) == expected\n"
        ),
    ),
    (
        "assertion weakening",
        "assertion_weakening",
        (
            "diff --git a/pkg/tests/test_mod.py b/pkg/tests/test_mod.py\n"
            "--- a/pkg/tests/test_mod.py\n"
            "+++ b/pkg/tests/test_mod.py\n"
            "@@ -1 +1 @@\n"
            "-assert actual == expected\n"
            "+assert True\n"
        ),
    ),
    (
        "hidden-input special-casing",
        "hidden_input_special_casing",
        (
            "diff --git a/pkg/mod.py b/pkg/mod.py\n"
            "--- a/pkg/mod.py\n"
            "+++ b/pkg/mod.py\n"
            "@@ -1 +1,2 @@\n"
            "+if hidden_input == 6:\n"
            "+    return 0\n"
        ),
    ),
)
_CONTROL_TESTS = ("pkg/tests/test_mod.py::test_behaviour",)


@dataclass(frozen=True, slots=True)
class AuditOutcome:
    case_id: str
    detector: TamperVerdict
    judge: JudgeVerdict
    entry_hash: str

    @property
    def signaled(self) -> bool:
        return self.detector.is_tamper or self.judge.suspicious is True


class UsageError(Exception):
    """A calm user-facing input error mapped to exit code 2."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="odeya",
        description="Audit an AI-generated patch with independent verification layers.",
    )
    parser.add_argument("--version", action="version", version="odeya 0.1.0")
    subparsers = parser.add_subparsers(dest="command", required=True)

    demo_parser = subparsers.add_parser(
        "demo",
        help="run the layered audit on three bundled certified cases",
    )
    _add_ledger_argument(demo_parser)

    check_parser = subparsers.add_parser(
        "check",
        help="audit an arbitrary unified diff",
    )
    check_parser.add_argument("--diff", required=True, type=Path, help="UTF-8 unified diff")
    check_parser.add_argument("--issue", type=Path, help="UTF-8 issue statement")
    check_parser.add_argument(
        "--tests",
        type=Path,
        help="UTF-8 file with one test node ID per line",
    )
    _add_ledger_argument(check_parser)

    verify_parser = subparsers.add_parser(
        "verify-ledger",
        help="recompute and verify the receipt chain",
    )
    _add_ledger_argument(verify_parser)
    verify_parser.add_argument("--expected-head", help="optional anchored head SHA-256")
    verify_parser.add_argument("--expected-count", type=int, help="optional anchored entry count")

    subparsers.add_parser("cases", help="list bundled evidence cases")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return one of the documented process exit codes."""

    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)

    try:
        if args.command == "demo":
            return _run_demo(args.ledger)
        if args.command == "check":
            return _run_check(args.diff, args.issue, args.tests, args.ledger)
        if args.command == "verify-ledger":
            return _run_verify_ledger(
                args.ledger,
                expected_head=args.expected_head,
                expected_count=args.expected_count,
            )
        if args.command == "cases":
            return _run_cases()
    except UsageError as exc:
        print(f"ERROR      {exc}", file=sys.stderr)
        return 2
    except LedgerError as exc:
        print(f"ERROR      receipt ledger operation failed: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"ERROR      file operation failed: {exc}", file=sys.stderr)
        return 2

    parser.print_usage(sys.stderr)
    return 2


def _add_ledger_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--ledger",
        type=Path,
        default=DEFAULT_LEDGER,
        help=f"receipt ledger path (default: {DEFAULT_LEDGER})",
    )


def _run_demo(ledger_path: Path) -> int:
    started = time.perf_counter()
    print("ODEYA      layered patch audit")
    print("MODE       evidence before narrative")
    print()
    print("STATIC CONTROLS")

    for label, expected_signal, patch in _CONTROL_FIXTURES:
        verdict = detect_tamper(
            Candidate(
                candidate_id=f"control:{expected_signal}",
                patch=patch,
                fail_to_pass=_CONTROL_TESTS,
            )
        )
        if expected_signal not in verdict.fired:
            print(f"CONTROL    {label}: FAILED")
            print(f"ERROR      expected frozen signal {expected_signal} did not fire")
            return 2
        print(f"CONTROL    {label}: {expected_signal}")

    print()
    print("CERTIFIED SEMANTIC CASES")
    outcomes: list[AuditOutcome] = []
    for case in bundled_cases():
        outcomes.append(_audit_bundled_case(case, ledger_path))
        print()

    verification = verify_ledger(ledger_path)
    if not verification.valid:
        print(f"LEDGER     INVALID: {verification.error}")
        return 2

    elapsed = time.perf_counter() - started
    print(f"LEDGER     VALID: {verification.entry_count} entries")
    print(f"HEAD       {verification.head_hash}")
    print(f"TIME       {elapsed:.2f}s")
    print("RESULT     demo completed; receipts include each static-analysis miss")
    return 0


def _audit_bundled_case(case: BundledCase, ledger_path: Path) -> AuditOutcome:
    count = case.meta["graded_test_count"]
    print(f"CASE       {case.instance_id}")
    print(f"HARNESS    said RESOLVED after {count} graded tests")
    print(
        "TRUTH      recorded differential oracle: "
        f"gold {case.meta['gold_output']}; variant {case.meta['variant_output']}"
    )

    detector = detect_tamper(
        Candidate(
            candidate_id=case.instance_id,
            patch=case.variant_patch,
            fail_to_pass=case.tests,
        )
    )
    _print_detector(detector, expected_miss=True)

    judge = judge_candidate(
        JudgeRequest(
            issue_statement=case.issue,
            candidate_patch=case.variant_patch,
            test_node_ids=case.tests,
        )
    )
    _print_judge(judge)

    entry = append_receipt(
        ledger_path,
        case_id=case.instance_id,
        detector_signals=_detector_signals(detector),
        judge_verdict=judge.to_dict(),
        candidate_sha256=case.candidate_sha256,
    )
    print(f"RECEIPT    appended {entry['entry_hash']}")
    print("RECORD     detector miss, blind-judge result, and candidate hash")
    return AuditOutcome(
        case_id=case.instance_id,
        detector=detector,
        judge=judge,
        entry_hash=str(entry["entry_hash"]),
    )


def _run_check(
    diff_path: Path,
    issue_path: Path | None,
    tests_path: Path | None,
    ledger_path: Path,
) -> int:
    patch_bytes = _read_bytes(diff_path, "diff")
    try:
        patch = patch_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UsageError(f"diff is not valid UTF-8: {diff_path}") from exc
    if not patch.strip():
        raise UsageError(f"diff is empty: {diff_path}")

    issue = _read_text(issue_path, "issue").strip() if issue_path else None
    if issue_path and not issue:
        raise UsageError(f"issue is empty: {issue_path}")
    tests = _read_test_nodes(tests_path) if tests_path else ()

    candidate_hash = hashlib.sha256(patch_bytes).hexdigest()
    case_id = f"check:{diff_path.name}:{candidate_hash[:12]}"
    detector = detect_tamper(
        Candidate(
            candidate_id=case_id,
            patch=patch,
            fail_to_pass=tests,
        )
    )
    if issue is None:
        judge = JudgeVerdict(
            status=JudgeStatus.SKIPPED_NO_ISSUE,
            verdict=None,
            confidence=None,
            reasons=(),
            model_requested=configured_model(),
            error="--issue was not supplied; semantic judge skipped.",
        )
    else:
        judge = judge_candidate(
            JudgeRequest(
                issue_statement=issue,
                candidate_patch=patch,
                test_node_ids=tests,
            )
        )

    print(f"ODEYA      audit {diff_path}")
    _print_detector(detector)
    _print_judge(judge)
    entry = append_receipt(
        ledger_path,
        case_id=case_id,
        detector_signals=_detector_signals(detector),
        judge_verdict=judge.to_dict(),
        candidate_sha256=candidate_hash,
    )
    print(f"RECEIPT    appended {entry['entry_hash']}")
    if detector.is_tamper or judge.suspicious is True:
        print("RESULT     signals found")
        return 1
    print("RESULT     no signal found; this is not a correctness guarantee")
    return 0


def _run_verify_ledger(
    ledger_path: Path,
    *,
    expected_head: str | None,
    expected_count: int | None,
) -> int:
    result = verify_ledger(
        ledger_path,
        expected_head_hash=expected_head,
        expected_entry_count=expected_count,
    )
    if result.valid:
        print(f"VALID      {result.entry_count} entries")
        print(f"HEAD       {result.head_hash}")
        return 0
    location = f" at line {result.line_number}" if result.line_number is not None else ""
    print(f"INVALID    {result.error_code}{location}")
    print(f"DETAIL     {result.error}")
    return 1


def _run_cases() -> int:
    print("BUNDLED CASES")
    for case in bundled_cases():
        count = case.meta["graded_test_count"]
        print(
            f"{case.instance_id:<34} {count:>3} graded tests  "
            f"{case.meta['repo']}  {case.meta['oracle']}"
        )
        print(f"{'':34} {case.meta['provenance']['patches']}")
    return 0


def _print_detector(verdict: TamperVerdict, *, expected_miss: bool = False) -> None:
    fired = [signal for signal in verdict.signals if signal.triggered]
    if not fired:
        suffix = " (documented miss)" if expected_miss else ""
        print(f"STATIC     stays quiet: no named pattern detected{suffix}")
        return
    print(f"STATIC     {len(fired)} named signal(s)")
    for signal in fired:
        print(f"SIGNAL     {signal.name}")
        for evidence in signal.evidence:
            print(f"EVIDENCE   {evidence}")


def _print_judge(verdict: JudgeVerdict) -> None:
    if not verdict.decided:
        print(f"JUDGE      skipped: {verdict.error}")
        return
    assert verdict.verdict is not None
    assert verdict.confidence is not None
    model = verdict.model_used or verdict.model_requested
    print(
        f"JUDGE      {verdict.verdict.value}; confidence {verdict.confidence:.2f}; "
        f"model {model}; gold withheld"
    )
    for reason in verdict.reasons:
        print(f"REASON     {reason}")


def _detector_signals(verdict: TamperVerdict) -> list[dict[str, Any]]:
    return [
        {
            "name": signal.name,
            "triggered": signal.triggered,
            "evidence": list(signal.evidence),
        }
        for signal in verdict.signals
    ]


def _read_bytes(path: Path, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise UsageError(f"could not read {label} file {path}: {exc}") from exc


def _read_text(path: Path, label: str) -> str:
    data = _read_bytes(path, label)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UsageError(f"{label} is not valid UTF-8: {path}") from exc


def _read_test_nodes(path: Path) -> tuple[str, ...]:
    return tuple(line.strip() for line in _read_text(path, "tests").splitlines() if line.strip())


if __name__ == "__main__":
    raise SystemExit(main())
