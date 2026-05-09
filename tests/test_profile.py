"""Tests for the verifier profile JSON artifact."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PROFILE_PATH = REPO_ROOT / "profiles" / "observation-external-pipeline-v0.2-fork.json"


@pytest.fixture
def profile():
    return json.loads(PROFILE_PATH.read_text())


def test_profile_file_exists():
    assert PROFILE_PATH.exists(), f"profile file missing: {PROFILE_PATH}"


def test_profile_id(profile):
    assert profile["profile_id"] == "mpf.profile.observation.external-pipeline.v0.2-fork"


def test_profile_class(profile):
    assert profile["profile_class"] == "observation"


def test_profile_extends_observed_l1(profile):
    """We extend §15's observed-l1 profile, not invent a new family."""
    assert profile["extends"] == "mpf.profile.action.observed-l1.v0.2"


def test_profile_conformance_class(profile):
    assert profile["conformance_class"] == "mpf-0.2-action-observed-conformant"
    assert profile["conformance_section_ref"] == "MPF v0.2 §20.2"


def test_profile_admits_external_pipeline_actor(profile):
    assert "external_pipeline" in profile["actor_types_admitted"]
    assert "code" in profile["actor_types_admitted"]


def test_profile_does_not_enforce_capability_tokens(profile):
    """Per §9.4.1: observation profiles MUST declare capability_token_enforced=false."""
    assert profile["capability_token_enforced"] is False


def test_profile_no_intent_layer(profile):
    """Per §9.4.1: observation profiles MUST NOT require intent.attested."""
    assert profile["intent_layer"] == "none"
    assert profile["intent_attested_required"] is False


def test_profile_uses_baseline_jcs(profile):
    """Per §2.9: claiming baseline mpf-0.2 conformance requires JCS canonicalization."""
    assert profile["canonicalization"]["scheme"] == "RFC 8785 JCS"


def test_profile_declares_all_required_observation_fields(profile):
    """§9.4.1 enumerates a set of MUST declarations for observation profiles."""
    decl = profile["observation_profile_declarations"]
    for key in [
        "source_identity_required_fields",
        "observer_code_identity_required",
        "validator_code_identity_required",
        "cadence_required",
        "guard_key_semantics",
        "retention_mode",
        "witness_independent_fetch",
        "failure_modes_recognized",
    ]:
        assert key in decl, f"missing observation declaration: {key}"


def test_profile_failure_modes_match_spec(profile):
    """The four failure-mode receipt kinds added by PR #2 must all be recognized."""
    expected = {
        "source.unavailable",
        "validation.failed",
        "validator.exception",
        "bytes.changed_in_interval",
    }
    assert set(profile["observation_profile_declarations"]["failure_modes_recognized"]) == expected


def test_profile_excludes_cross_boundary_artifacts(profile):
    """MVP is §20.2, not §20.5. Cross-boundary-only artifacts must be marked excluded."""
    excluded = profile["bundle_artifacts_excluded"]
    for art in [
        "transparency-log.jsonl",
        "substrate-attestation.json",
        "domain-attestation.json",
    ]:
        assert art in excluded, f"expected {art} to be in bundle_artifacts_excluded"


def test_profile_documents_co_resident_witness_weakness(profile):
    """The §11.5 / §20.5 weakness must be acknowledged in the profile."""
    wreq = profile["witness_requirements"]
    assert wreq["operator_independence_class"] == "co-resident"
    rationale = wreq["operator_independence_rationale"].lower()
    # The rationale must reference the spec section and acknowledge the weakness.
    assert "§11.5" in rationale or "11.5" in rationale, \
        "rationale must reference §11.5 (witness independence)"
    assert any(phrase in rationale for phrase in [
        "same node", "co-resident", "co resident", "weaker assurance",
    ]), "rationale must acknowledge the assurance weakness in plain language"


def test_profile_registration_target(profile):
    reg = profile["registration"]
    assert reg["operator"] == "theforkproject-dev"
    assert "amotivv-inc/memory-pod-fabric" in reg["registration_target"]


def test_profile_is_jcs_canonicalizable():
    """The profile JSON must be canonicalizable (no NaN, no surrogate strings)."""
    from witness import canon
    obj = json.loads(PROFILE_PATH.read_text())
    canonical = canon.canonicalize(obj)
    assert isinstance(canonical, bytes)
    assert len(canonical) > 0
