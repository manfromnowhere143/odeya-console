from __future__ import annotations

import hashlib

import pytest

from odeya.cases import CASE_IDS, bundled_cases, load_case


def test_all_bundled_cases_load_with_required_evidence() -> None:
    cases = bundled_cases()
    assert tuple(case.instance_id for case in cases) == CASE_IDS
    for case in cases:
        assert case.meta["harness_status"] == "RESOLVED"
        assert case.meta["graded_test_count"] > 0
        assert case.meta["gold_output"] != case.meta["variant_output"]
        assert case.issue
        assert case.tests
        assert case.variant_patch.startswith("diff --git ")
        assert case.gold_patch.startswith("diff --git ")
        expected = hashlib.sha256(case.variant_patch.encode()).hexdigest()
        assert case.candidate_sha256 == expected


def test_unknown_case_is_rejected() -> None:
    with pytest.raises(KeyError, match="unknown bundled case"):
        load_case("not-a-case")
