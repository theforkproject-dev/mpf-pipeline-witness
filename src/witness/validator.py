"""
Validator: deterministic invariant checks over an observed artifact.

The validator is the second pinned-code module. Per MPF v0.2 §9.4.1 and
BUILD_PLAN §8, the admission manifest binds a `validator_code_digest` that
is the SHA-256 of this module's source bytes. Independent verifiers can
re-derive that digest and confirm "the validator that produced these
validation receipts was exactly this code."

This validator is specific to the EWS reference target. It implements the
five reproducibility tests proved out during reconnaissance (see
BUILD_PLAN.md §1.6 / use-case-3 spec §2 Test 1-5):

    1. Self-contained: cohort + model parameters + 365-day archive +
       current snapshot are all in one file.
    2. Reproducibility: published z-score matches recomputed z-score
       within tolerance.
    3. Archive coherence: the last archive sample matches the current
       snapshot exactly.
    4. Coverage: at least 99% of expected 30-minute samples in the year.
    5. Schema integrity: required top-level keys are present.

Each check returns a structured result. The composite `validate()` returns
a `ValidationResult` that becomes the body of a `validation.result` receipt.

The validator does NOT make truth claims about whether the underlying
signal is meaningful. It only confirms that the artifact is internally
consistent given its declared math and that no required field is missing.
A validation pass means "the artifact says what it says about itself, and
its own arithmetic checks out." A validation failure becomes a
`validation.failed` receipt under the same chain — failures are recorded,
not suppressed.

Profile-defined tolerance:

    Z_SCORE_TOLERANCE — relative tolerance for z-score recomputation.
    The observed reproduction during reconnaissance was exact to ten
    decimal places. We pin 1e-6 to allow for floating-point roundoff
    differences across hosts without admitting genuine model drift.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from typing import Any

# Pinned: changing this changes the validator code digest.
Z_SCORE_TOLERANCE = 1e-6

# Required top-level keys per the EWS dashboard.json shape captured during
# reconnaissance. If upstream removes or renames any of these, the schema
# check fails loudly rather than producing a misleading "valid" result.
REQUIRED_TOP_LEVEL_KEYS = (
    "mode",
    "cohort",
    "current",
    "trends",
    "snapshotGeneratedAt",
    "liveStatus",
)

REQUIRED_CURRENT_FIELDS = (
    "asOf",
    "concurrentCount",
    "baselineMean",
    "baselineStdDev",
    "zScore",
    "emergencyLevel",
    "elevatedSigmaThreshold",
    "alarmSigmaThreshold",
)

REQUIRED_ARCHIVE_FIELDS = ("v", "t0", "tr", "c", "p", "s", "z")

# Coverage threshold: at least this fraction of expected 30-min samples
# must be present in trends.archive over the declared span. Pinned at 0.99
# (the captured fixture observed 99.5%); below 99% suggests upstream gaps
# significant enough to warrant a validation.failed receipt.
COVERAGE_THRESHOLD = 0.99


@dataclass(frozen=True)
class CheckResult:
    """A single named check's outcome.

    `passed` is the truth value. `detail` is a small structured record the
    receipt body can carry — never raw bytes, never large payloads, only
    enough for an independent verifier to know what was claimed.
    """

    name: str
    passed: bool
    detail: dict[str, Any]


@dataclass(frozen=True)
class ValidationResult:
    """The composite outcome of all invariant checks.

    Becomes the body of a `validation.result` receipt when all checks pass,
    or the body of a `validation.failed` receipt when any check fails.
    """

    overall_passed: bool
    checks: tuple[CheckResult, ...]
    counts: dict[str, int]
    summary: dict[str, Any] = field(default_factory=dict)

    def to_receipt_body(self) -> dict[str, Any]:
        """Project this result onto a serializable receipt body."""
        return {
            "validator_version": "ews-business-jet-v1",
            "z_score_tolerance": Z_SCORE_TOLERANCE,
            "coverage_threshold": COVERAGE_THRESHOLD,
            "overall_passed": self.overall_passed,
            "counts": dict(self.counts),
            "summary": dict(self.summary),
            "checks": [asdict(c) for c in self.checks],
        }


# --- Individual checks -------------------------------------------------------


def check_schema_integrity(d: dict[str, Any]) -> CheckResult:
    """All required top-level fields and key sub-fields are present and well-typed."""
    missing_top = [k for k in REQUIRED_TOP_LEVEL_KEYS if k not in d]
    if missing_top:
        return CheckResult(
            name="schema_integrity", passed=False,
            detail={"missing_top_level_keys": missing_top},
        )

    cur = d.get("current", {})
    missing_cur = [k for k in REQUIRED_CURRENT_FIELDS if k not in cur]
    if missing_cur:
        return CheckResult(
            name="schema_integrity", passed=False,
            detail={"missing_current_fields": missing_cur},
        )

    arch = d.get("trends", {}).get("archive", {})
    missing_arch = [k for k in REQUIRED_ARCHIVE_FIELDS if k not in arch]
    if missing_arch:
        return CheckResult(
            name="schema_integrity", passed=False,
            detail={"missing_archive_fields": missing_arch},
        )

    return CheckResult(
        name="schema_integrity", passed=True,
        detail={"required_keys_present": True},
    )


def check_self_contained(d: dict[str, Any]) -> CheckResult:
    """Cohort definition + model parameters + history + current snapshot all present."""
    cohort = d.get("cohort", {})
    has_cohort = bool(cohort.get("trackedCount"))
    has_model_params = (
        "elevatedSigmaThreshold" in d.get("current", {})
        and "alarmSigmaThreshold" in d.get("current", {})
    )
    has_history = bool(d.get("trends", {}).get("archive", {}).get("c"))
    has_current = bool(d.get("current", {}).get("concurrentCount") is not None)

    passed = all([has_cohort, has_model_params, has_history, has_current])
    return CheckResult(
        name="self_contained", passed=passed,
        detail={
            "has_cohort": has_cohort,
            "has_model_params": has_model_params,
            "has_history": has_history,
            "has_current": has_current,
            "tracked_count": cohort.get("trackedCount"),
        },
    )


def check_zscore_reproducibility(d: dict[str, Any]) -> CheckResult:
    """Recompute z = (count - baseline) / std and confirm it matches the published value."""
    cur = d.get("current", {})
    try:
        actual = float(cur["concurrentCount"])
        baseline = float(cur["baselineMean"])
        std = float(cur["baselineStdDev"])
        published = float(cur["zScore"])
    except (KeyError, TypeError, ValueError) as e:
        return CheckResult(
            name="zscore_reproducibility", passed=False,
            detail={"error": f"input field error: {type(e).__name__}: {e}"},
        )

    if std <= 0:
        return CheckResult(
            name="zscore_reproducibility", passed=False,
            detail={"error": "baselineStdDev must be positive", "value": std},
        )

    recomputed = (actual - baseline) / std
    diff = abs(recomputed - published)
    # Use absolute tolerance scaled by max(1, |published|) so the threshold is
    # meaningful for both small and large z-scores.
    threshold = Z_SCORE_TOLERANCE * max(1.0, abs(published))
    passed = diff <= threshold

    return CheckResult(
        name="zscore_reproducibility", passed=passed,
        detail={
            "actual_count": actual,
            "baseline_mean": baseline,
            "baseline_std_dev": std,
            "published_z": published,
            "recomputed_z": recomputed,
            "absolute_difference": diff,
            "threshold": threshold,
        },
    )


def check_archive_coherence(d: dict[str, Any]) -> CheckResult:
    """The most-recent archive sample matches the `current` snapshot exactly."""
    cur = d.get("current", {})
    arch = d.get("trends", {}).get("archive", {})
    try:
        tail_c = arch["c"][-1]
        tail_p = arch["p"][-1]
        tail_s = arch["s"][-1]
        tail_z = arch["z"][-1]
        cur_c = cur["concurrentCount"]
        cur_p = round(float(cur["baselineMean"]), 2)
        cur_s = round(float(cur["baselineStdDev"]), 2)
        cur_z = round(float(cur["zScore"]), 2)
    except (KeyError, IndexError, TypeError, ValueError) as e:
        return CheckResult(
            name="archive_coherence", passed=False,
            detail={"error": f"missing or malformed archive/current: {type(e).__name__}: {e}"},
        )

    # Archive values are stored at 2-decimal precision; current values are at
    # full precision. Compare by rounding current to 2 decimals to match the
    # archive's resolution. This is what reconnaissance proved out: archive
    # tail = current after the rounding step.
    matches = (tail_c == cur_c and
               math.isclose(tail_p, cur_p, abs_tol=0.01) and
               math.isclose(tail_s, cur_s, abs_tol=0.01) and
               math.isclose(tail_z, cur_z, abs_tol=0.01))

    return CheckResult(
        name="archive_coherence", passed=matches,
        detail={
            "archive_tail": {"c": tail_c, "p": tail_p, "s": tail_s, "z": tail_z},
            "current_rounded": {"c": cur_c, "p": cur_p, "s": cur_s, "z": cur_z},
        },
    )


def check_archive_coverage(d: dict[str, Any]) -> CheckResult:
    """At least 99% of expected 30-minute samples are present over the archive span."""
    arch = d.get("trends", {}).get("archive", {})
    snap_at = d.get("snapshotGeneratedAt")
    try:
        t0 = arch["t0"]
        actual_samples = len(arch["c"])
    except (KeyError, TypeError) as e:
        return CheckResult(
            name="archive_coverage", passed=False,
            detail={"error": f"archive missing fields: {type(e).__name__}: {e}"},
        )

    if not snap_at:
        return CheckResult(
            name="archive_coverage", passed=False,
            detail={"error": "snapshotGeneratedAt missing"},
        )

    from datetime import datetime
    try:
        t0_dt = datetime.fromisoformat(t0.replace("Z", "+00:00"))
        snap_dt = datetime.fromisoformat(snap_at.replace("Z", "+00:00"))
    except ValueError as e:
        return CheckResult(
            name="archive_coverage", passed=False,
            detail={"error": f"timestamp parse error: {e}"},
        )

    span_seconds = (snap_dt - t0_dt).total_seconds()
    if span_seconds <= 0:
        return CheckResult(
            name="archive_coverage", passed=False,
            detail={"error": "non-positive span", "span_seconds": span_seconds},
        )

    expected = int(span_seconds / 1800)  # 30-min slots
    coverage = actual_samples / expected if expected > 0 else 0.0
    passed = coverage >= COVERAGE_THRESHOLD

    return CheckResult(
        name="archive_coverage", passed=passed,
        detail={
            "t0": t0,
            "snapshot_generated_at": snap_at,
            "span_seconds": span_seconds,
            "expected_samples": expected,
            "actual_samples": actual_samples,
            "coverage": coverage,
            "threshold": COVERAGE_THRESHOLD,
        },
    )


# --- Composite ---------------------------------------------------------------


def validate(d: dict[str, Any]) -> ValidationResult:
    """Run all five invariant checks and return the composite result.

    Args:
        d: Parsed JSON of the upstream artifact (e.g., dashboard.json).

    Returns:
        A `ValidationResult` whose `overall_passed` is True iff every
        individual check passed.
    """
    checks = (
        check_schema_integrity(d),
        check_self_contained(d),
        check_zscore_reproducibility(d),
        check_archive_coherence(d),
        check_archive_coverage(d),
    )

    overall = all(c.passed for c in checks)

    summary: dict[str, Any] = {}
    cur = d.get("current", {})
    if cur:
        summary["concurrent_count"] = cur.get("concurrentCount")
        summary["baseline_mean"] = cur.get("baselineMean")
        summary["baseline_std_dev"] = cur.get("baselineStdDev")
        summary["z_score"] = cur.get("zScore")
        summary["emergency_level"] = cur.get("emergencyLevel")
        summary["as_of"] = cur.get("asOf")

    counts = {
        "checks_total": len(checks),
        "checks_passed": sum(1 for c in checks if c.passed),
        "checks_failed": sum(1 for c in checks if not c.passed),
    }

    return ValidationResult(
        overall_passed=overall, checks=checks, counts=counts, summary=summary,
    )
