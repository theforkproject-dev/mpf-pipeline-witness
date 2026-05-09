"""Tests for `witness.validator` — deterministic invariant checks.

Most tests run against the captured fixture from reconnaissance:
`tests/fixtures/dashboard-2026-05-09T21-25-18Z.json` (SHA-256
`e7ca22cbfeb14cc87a2ef9bc9e4f1e10925968b5b109c73f05a427d82cf4d85b`,
captured 2026-05-09T21:25:18.930Z).

This is the same artifact the use-case-3 reconnaissance proved out, and
running the validator against it confirms the implementation reproduces
the reconnaissance results: 5/5 checks pass, z-score recomputed to ten
decimal places, archive coverage 99.5%.

Synthetic-tamper tests deliberately corrupt the fixture to confirm each
check rejects the specific failure mode it is designed to catch.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from witness import validator

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "dashboard-2026-05-09T21-25-18Z.json"


@pytest.fixture
def fixture():
    return json.loads(FIXTURE_PATH.read_text())


# --- Reconnaissance reproduction ---------------------------------------------


def test_fixture_passes_all_checks(fixture):
    """The captured fixture must pass all five invariant checks (reconnaissance result)."""
    result = validator.validate(fixture)
    assert result.overall_passed, (
        "fixture failed to validate; failures: "
        + ", ".join(c.name for c in result.checks if not c.passed)
    )
    assert result.counts["checks_total"] == 5
    assert result.counts["checks_passed"] == 5
    assert result.counts["checks_failed"] == 0


def test_zscore_reproduces_to_ten_decimals(fixture):
    """The recomputed z-score matches the published value to high precision."""
    check = validator.check_zscore_reproducibility(fixture)
    assert check.passed
    detail = check.detail
    # Reconnaissance observed exact match to 10 decimal places. Allow 1e-10.
    assert abs(detail["recomputed_z"] - detail["published_z"]) < 1e-10


def test_archive_tail_matches_current_exactly(fixture):
    """The most-recent archive sample equals the current snapshot (rounded)."""
    check = validator.check_archive_coherence(fixture)
    assert check.passed
    tail = check.detail["archive_tail"]
    cur = check.detail["current_rounded"]
    assert tail["c"] == cur["c"]


def test_coverage_meets_threshold(fixture):
    """Coverage must be at least 99% (reconnaissance observed 99.5%)."""
    check = validator.check_archive_coverage(fixture)
    assert check.passed
    assert check.detail["coverage"] >= 0.99
    # And the absolute sample count is in the expected range.
    assert check.detail["actual_samples"] >= 17000


def test_summary_extracts_published_signal(fixture):
    """The validation result's summary captures the headline numbers."""
    result = validator.validate(fixture)
    assert result.summary["concurrent_count"] == 422  # from reconnaissance
    assert result.summary["emergency_level"] == 1
    assert result.summary["z_score"] is not None
    assert result.summary["as_of"] is not None


# --- Synthetic tamper detection ---------------------------------------------


def test_schema_check_rejects_missing_top_level_key(fixture):
    bad = copy.deepcopy(fixture)
    del bad["current"]
    check = validator.check_schema_integrity(bad)
    assert not check.passed
    assert "current" in check.detail.get("missing_top_level_keys", [])


def test_schema_check_rejects_missing_current_field(fixture):
    bad = copy.deepcopy(fixture)
    del bad["current"]["zScore"]
    check = validator.check_schema_integrity(bad)
    assert not check.passed
    assert "zScore" in check.detail.get("missing_current_fields", [])


def test_schema_check_rejects_missing_archive_field(fixture):
    bad = copy.deepcopy(fixture)
    del bad["trends"]["archive"]["c"]
    check = validator.check_schema_integrity(bad)
    assert not check.passed
    assert "c" in check.detail.get("missing_archive_fields", [])


def test_zscore_check_rejects_inconsistent_published_value(fixture):
    """Tamper with the published z-score so it disagrees with the input fields."""
    bad = copy.deepcopy(fixture)
    # Shift published z-score far enough to exceed the tolerance.
    bad["current"]["zScore"] = bad["current"]["zScore"] + 5.0
    check = validator.check_zscore_reproducibility(bad)
    assert not check.passed
    assert check.detail["absolute_difference"] > validator.Z_SCORE_TOLERANCE


def test_zscore_check_rejects_zero_std_dev(fixture):
    bad = copy.deepcopy(fixture)
    bad["current"]["baselineStdDev"] = 0.0
    check = validator.check_zscore_reproducibility(bad)
    assert not check.passed
    assert "must be positive" in check.detail.get("error", "")


def test_archive_coherence_check_rejects_modified_tail(fixture):
    bad = copy.deepcopy(fixture)
    # Replace the last archive sample with something that doesn't match current.
    bad["trends"]["archive"]["c"][-1] = bad["current"]["concurrentCount"] + 999
    check = validator.check_archive_coherence(bad)
    assert not check.passed


def test_coverage_check_rejects_truncated_archive(fixture):
    """If the archive is truncated to 50% of expected, coverage check fails."""
    bad = copy.deepcopy(fixture)
    arch = bad["trends"]["archive"]
    half = len(arch["c"]) // 2
    # Keep the first half only — coverage drops to ~50%.
    arch["c"] = arch["c"][:half]
    arch["p"] = arch["p"][:half]
    arch["s"] = arch["s"][:half]
    arch["z"] = arch["z"][:half]
    check = validator.check_archive_coverage(bad)
    assert not check.passed
    assert check.detail["coverage"] < validator.COVERAGE_THRESHOLD


def test_validation_failure_is_reported_overall(fixture):
    """A single check failure causes overall_passed to be False."""
    bad = copy.deepcopy(fixture)
    bad["current"]["zScore"] += 5.0  # tamper z-score
    result = validator.validate(bad)
    assert not result.overall_passed
    assert result.counts["checks_failed"] >= 1


# --- Receipt body shape ------------------------------------------------------


def test_to_receipt_body_is_jcs_canonicalizable(fixture):
    """The validation result must JCS-canonicalize without errors."""
    from witness import canon
    result = validator.validate(fixture)
    body = result.to_receipt_body()
    canonical = canon.canonicalize(body)
    assert isinstance(canonical, bytes)
    assert len(canonical) > 0


def test_to_receipt_body_carries_check_names(fixture):
    """The receipt body lists every individual check by name."""
    result = validator.validate(fixture)
    body = result.to_receipt_body()
    names = {c["name"] for c in body["checks"]}
    assert names == {
        "schema_integrity",
        "self_contained",
        "zscore_reproducibility",
        "archive_coherence",
        "archive_coverage",
    }


def test_to_receipt_body_includes_pinned_constants(fixture):
    """The receipt body records the pinned tolerances so verifiers can check them."""
    result = validator.validate(fixture)
    body = result.to_receipt_body()
    assert body["z_score_tolerance"] == validator.Z_SCORE_TOLERANCE
    assert body["coverage_threshold"] == validator.COVERAGE_THRESHOLD
    assert body["validator_version"] == "ews-business-jet-v1"


# --- Validator code digest ---------------------------------------------------


def test_validator_module_digest_is_stable():
    """The validator module's source digest is reproducible.

    This is the value the admission manifest binds. Sanity-check that
    independent reads of the file produce the same digest.
    """
    import hashlib
    p = Path(validator.__file__)
    d1 = hashlib.sha256(p.read_bytes()).hexdigest()
    d2 = hashlib.sha256(p.read_bytes()).hexdigest()
    assert d1 == d2
    assert len(d1) == 64
