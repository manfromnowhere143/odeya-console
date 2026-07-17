from __future__ import annotations

from pathlib import Path

README = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")


def test_required_readme_sections_are_present_in_order() -> None:
    headings = (
        "## 1. What it is",
        "## 2. Quickstart",
        "## 3. What the demo shows",
        "## 4. How Codex and GPT-5.6 built and power this",
        "## 5. Prior work vs Build Week work",
        "## 6. The research foundation",
        "## 7. Scope and limitations",
    )

    positions = [README.index(heading) for heading in headings]

    assert positions == sorted(positions)
    assert README.count("\n## ") == len(headings)


def test_readme_carries_required_provenance_and_adjacent_limitations() -> None:
    assert "019f703b-9812-7bc2-915b-9678e2c8283a" in README
    assert "`gpt-5.6-sol`" in README
    assert "20/22 variant rows were caught, 3/22 gold-control rows were flagged, and 8/88" in README
    assert "static analysis stays quiet" in README.lower()
    assert "no named pattern is detected" in README
    assert "receipt records the detector miss" in README


def test_public_readme_omits_private_identity_material() -> None:
    lowered = README.lower()
    assert "@gmail" not in lowered
    assert "identity-resolution" not in lowered
    assert "identity chain" not in lowered
