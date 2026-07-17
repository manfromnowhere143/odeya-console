"""Bundled evidence-backed audit cases."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

CASE_IDS = (
    "django__django-11119",
    "django__django-11179",
    "matplotlib__matplotlib-24627",
)


@dataclass(frozen=True)
class BundledCase:
    """One certified-resolved variant and its evidence metadata."""

    instance_id: str
    meta: dict[str, Any]
    issue: str
    tests: tuple[str, ...]
    variant_patch: str
    gold_patch: str

    @property
    def candidate_sha256(self) -> str:
        return hashlib.sha256(self.variant_patch.encode("utf-8")).hexdigest()


def _case_directory(instance_id: str) -> Any:
    packaged = resources.files("odeya").joinpath("case_data", instance_id)
    if packaged.is_dir():
        return packaged

    checkout = Path(__file__).resolve().parents[2] / "cases" / instance_id
    if checkout.is_dir():
        return checkout
    raise FileNotFoundError(f"bundled case data is missing: {instance_id}")


def _read_text(directory: Any, name: str) -> str:
    return directory.joinpath(name).read_text(encoding="utf-8")


def load_case(instance_id: str) -> BundledCase:
    """Load a bundled case by its exact SWE-bench instance id."""

    if instance_id not in CASE_IDS:
        raise KeyError(f"unknown bundled case: {instance_id}")
    directory = _case_directory(instance_id)
    meta = json.loads(_read_text(directory, "meta.json"))
    if meta.get("instance_id") != instance_id:
        raise ValueError(f"case metadata identity mismatch: {instance_id}")
    tests = tuple(
        line.strip() for line in _read_text(directory, "tests.txt").splitlines() if line.strip()
    )
    return BundledCase(
        instance_id=instance_id,
        meta=meta,
        issue=_read_text(directory, "issue.md").strip(),
        tests=tests,
        variant_patch=_read_text(directory, "variant.patch"),
        gold_patch=_read_text(directory, "gold.patch"),
    )


def bundled_cases() -> tuple[BundledCase, ...]:
    """Return all bundled cases in stable display order."""

    return tuple(load_case(instance_id) for instance_id in CASE_IDS)
