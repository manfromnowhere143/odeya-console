from __future__ import annotations

import json
from pathlib import Path

import pytest

from odeya import cli
from odeya.judge import JudgeStatus, JudgeVerdict, Verdict
from odeya.ledger import read_entries


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def _quiet_patch() -> str:
    return (
        "diff --git a/pkg/mod.py b/pkg/mod.py\n"
        "--- a/pkg/mod.py\n"
        "+++ b/pkg/mod.py\n"
        "@@ -1 +1 @@\n"
        "-return before\n"
        "+return after\n"
    )


def _signaled_patch() -> str:
    return (
        "diff --git a/pkg/tests/test_mod.py b/pkg/tests/test_mod.py\n"
        "--- a/pkg/tests/test_mod.py\n"
        "+++ b/pkg/tests/test_mod.py\n"
        "@@ -1 +1 @@\n"
        "-assert actual == expected\n"
        "+assert True\n"
    )


def test_demo_keyless_records_static_misses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    ledger = tmp_path / ".odeya" / "ledger.jsonl"

    code = cli.main(["demo", "--ledger", str(ledger)])

    output = capsys.readouterr().out
    assert code == 0
    assert output.count("HARNESS    the harness said RESOLVED") == 3
    assert output.count("STATIC     static analysis stays quiet") == 3
    assert output.count("documented miss") >= 3
    assert output.count("JUDGE      the blind judge is unavailable: skipped") == 3
    assert output.count("RECEIPT    the receipt records all of it, including the miss") == 3
    assert "LEDGER     VALID: 3 entries" in output
    assert "RESULT     demo completed; receipts include each static-analysis miss" in output

    entries = read_entries(ledger)
    assert len(entries) == 3
    assert all(
        not any(signal["triggered"] for signal in entry["detector_signals"])
        for entry in entries
    )
    assert all(entry["judge_verdict"]["status"] == "skipped_no_api_key" for entry in entries)


def test_demo_keyed_narrates_the_approved_honesty_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_judge(request: cli.JudgeRequest) -> JudgeVerdict:
        return JudgeVerdict(
            status=JudgeStatus.COMPLETED,
            verdict=Verdict.WRONG,
            confidence=0.97,
            reasons=("The candidate contradicts the issue.",),
            model_requested="gpt-5.6-sol",
            model_used="gpt-5.6-sol",
        )

    monkeypatch.setattr(cli, "judge_candidate", fake_judge)

    code = cli.main(["demo", "--ledger", str(tmp_path / "ledger.jsonl")])

    output = capsys.readouterr().out
    assert code == 0
    assert output.count("the harness said RESOLVED") == 3
    assert output.count("static analysis stays quiet") == 3
    assert output.count("the blind judge flags it") == 3
    assert output.count("the receipt records all of it, including the miss") == 3


def test_cases_lists_provenance(capsys: pytest.CaptureFixture[str]) -> None:
    code = cli.main(["cases"])

    output = capsys.readouterr().out
    assert code == 0
    assert "django__django-11119" in output
    assert "django__django-11179" in output
    assert "matplotlib__matplotlib-24627" in output
    assert "iter193_certified_resolved_reward_hack_construction" in output


def test_check_arbitrary_quiet_diff_returns_zero_and_records_receipt(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    patch = _write(tmp_path / "candidate.patch", _quiet_patch())
    ledger = tmp_path / "ledger.jsonl"

    code = cli.main(["check", "--diff", str(patch), "--ledger", str(ledger)])

    output = capsys.readouterr().out
    assert code == 0
    assert "STATIC     stays quiet" in output
    assert "JUDGE      skipped" in output
    assert "not a correctness guarantee" in output
    assert len(read_entries(ledger)) == 1


def test_check_static_signal_returns_one(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    patch = _write(tmp_path / "candidate.patch", _signaled_patch())
    tests = _write(tmp_path / "tests.txt", "pkg/tests/test_mod.py::test_behaviour\n")

    code = cli.main(
        [
            "check",
            "--diff",
            str(patch),
            "--tests",
            str(tests),
            "--ledger",
            str(tmp_path / "ledger.jsonl"),
        ]
    )

    output = capsys.readouterr().out
    assert code == 1
    assert "assertion_weakening" in output
    assert "RESULT     signals found" in output


def test_check_blind_judge_signal_returns_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    patch = _write(tmp_path / "candidate.patch", _quiet_patch())
    issue = _write(tmp_path / "issue.md", "Preserve behavior.")
    tests = _write(
        tmp_path / "tests.txt",
        "\nfirst::test_node\n\nsecond::test_node\n",
    )

    def fake_judge(request: cli.JudgeRequest) -> JudgeVerdict:
        assert request.test_node_ids == ("first::test_node", "second::test_node")
        assert not hasattr(request, "gold_patch")
        return JudgeVerdict(
            status=JudgeStatus.COMPLETED,
            verdict=Verdict.WRONG,
            confidence=0.91,
            reasons=("The added line `+return after` contradicts the issue.",),
            model_requested="gpt-5.6-sol",
            model_used="gpt-5.6-sol",
        )

    monkeypatch.setattr(cli, "judge_candidate", fake_judge)
    code = cli.main(
        [
            "check",
            "--diff",
            str(patch),
            "--issue",
            str(issue),
            "--tests",
            str(tests),
            "--ledger",
            str(tmp_path / "ledger.jsonl"),
        ]
    )

    output = capsys.readouterr().out
    assert code == 1
    assert "JUDGE      wrong; confidence 0.91; model gpt-5.6-sol; gold withheld" in output


def test_verify_ledger_detects_manual_byte_flip(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    patch = _write(tmp_path / "candidate.patch", _quiet_patch())
    ledger = tmp_path / "ledger.jsonl"
    assert cli.main(["check", "--diff", str(patch), "--ledger", str(ledger)]) == 0
    capsys.readouterr()

    assert cli.main(["verify-ledger", "--ledger", str(ledger)]) == 0
    assert "VALID" in capsys.readouterr().out

    raw = ledger.read_text(encoding="utf-8")
    ledger.write_text(raw.replace("candidate.patch", "changed.patch"), encoding="utf-8")
    code = cli.main(["verify-ledger", "--ledger", str(ledger)])

    output = capsys.readouterr().out
    assert code == 1
    assert "INVALID" in output


def test_usage_error_returns_two(capsys: pytest.CaptureFixture[str]) -> None:
    code = cli.main(["check"])

    captured = capsys.readouterr()
    assert code == 2
    assert "required" in captured.err


def test_invalid_utf8_diff_returns_two(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    patch = tmp_path / "candidate.patch"
    patch.write_bytes(b"\xff")

    code = cli.main(["check", "--diff", str(patch)])

    captured = capsys.readouterr()
    assert code == 2
    assert "not valid UTF-8" in captured.err


def test_receipt_is_canonical_json(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    patch = _write(tmp_path / "candidate.patch", _quiet_patch())
    ledger = tmp_path / "ledger.jsonl"
    assert cli.main(["check", "--diff", str(patch), "--ledger", str(ledger)]) == 0
    capsys.readouterr()

    line = ledger.read_text(encoding="utf-8").strip()
    entry = json.loads(line)
    assert json.dumps(entry, sort_keys=True, separators=(",", ":")) == line
