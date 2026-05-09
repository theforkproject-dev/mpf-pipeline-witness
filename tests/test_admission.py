"""Tests for `witness.admission` — Admission Manifest construction and verification."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from witness import admission, crypto, receipts


@pytest.fixture
def operator_kp():
    return crypto.generate_keypair("operator:fork-node-01:k1")


def make_manifest_payload(session_id: str | None = None) -> dict:
    return admission.build_admission_manifest(
        session_id=session_id or receipts.new_session_id(),
        operator_id="operator:fork-node-01",
        operator_key_id="operator:fork-node-01:k1",
        workflow_id="observation.ews-business-jets",
        action_id="pipeline.snapshot.observe.v1",
        verifier_profile_id="mpf.profile.observation.external-pipeline.v0.2-fork",
        action_registry_epoch_id="registry:fork-pipeline-witness:epoch-1",
        action_registry_epoch_digest="sha256:" + "0" * 64,
        witness_registry_epoch_id="registry:fork-witness-registry:epoch-1",
        witness_registry_epoch_digest="sha256:" + "1" * 64,
        observer_code_digest="sha256:" + "a" * 64,
        validator_code_digest="sha256:" + "b" * 64,
        source_url="https://pub-49bb6a6f314c47be9b481c25e5f6ca9e.r2.dev/dashboard.json",
        cadence_seconds=1800,
        expected_schema_digest="sha256:" + "c" * 64,
        pipeline_identity={
            "repo": "github.com/kylemcdonald/ews",
            "commit": None,
            "operator": "kylemcdonald",
        },
        git_commit="abc1234",
    )


def test_manifest_payload_required_fields():
    payload = make_manifest_payload()
    for f in [
        "schema_version", "session_id", "operator", "workflow",
        "verifier_profile_id", "registries", "code", "source",
        "intent_layer", "issued_at",
    ]:
        assert f in payload, f"missing {f}"


def test_manifest_intent_layer_is_none():
    """§9.4.1: observation profiles MUST NOT require intent.attested."""
    payload = make_manifest_payload()
    assert payload["intent_layer"] == "none"


def test_manifest_observation_profile_bindings():
    """§9.4.1 observation-profile required bindings."""
    payload = make_manifest_payload()
    code = payload["code"]
    assert code["observer_digest"].startswith("sha256:")
    assert code["validator_digest"].startswith("sha256:")
    src = payload["source"]
    assert src["url"].startswith("https://")
    assert src["cadence_seconds"] == 1800
    assert "pipeline_identity" in src


def test_sign_and_verify_round_trip(operator_kp):
    payload = admission.build_admission_manifest(
        session_id="s1",
        operator_id="operator:fork-node-01",
        operator_key_id=operator_kp.key_id,
        workflow_id="w",
        action_id="pipeline.snapshot.observe.v1",
        verifier_profile_id="p",
        action_registry_epoch_id="ar:1",
        action_registry_epoch_digest="sha256:" + "0" * 64,
        witness_registry_epoch_id="wr:1",
        witness_registry_epoch_digest="sha256:" + "1" * 64,
        observer_code_digest="sha256:" + "a" * 64,
        validator_code_digest="sha256:" + "b" * 64,
        source_url="https://example.test/d.json",
        cadence_seconds=1800,
        expected_schema_digest=None,
        pipeline_identity={"repo": "x"},
    )
    manifest = admission.sign_admission_manifest(payload=payload, signer=operator_kp)
    ok, errors = admission.verify_admission_manifest(
        manifest=manifest, operator_pubkey=operator_kp.public_b64(),
    )
    assert ok, f"verification failed: {errors}"


def test_verify_rejects_tampered_observer_digest(operator_kp):
    payload = make_manifest_payload()
    # Re-key the payload to use the test operator key
    payload["operator"]["operator_key_id"] = operator_kp.key_id
    manifest = admission.sign_admission_manifest(payload=payload, signer=operator_kp)
    # Tamper after signing
    manifest["code"]["observer_digest"] = "sha256:" + "f" * 64
    ok, errors = admission.verify_admission_manifest(
        manifest=manifest, operator_pubkey=operator_kp.public_b64(),
    )
    assert not ok
    assert any("digest" in e or "signature" in e for e in errors)


def test_verify_rejects_intent_layer_other_than_none(operator_kp):
    payload = make_manifest_payload()
    payload["operator"]["operator_key_id"] = operator_kp.key_id
    payload["intent_layer"] = "agent_grant"  # disallowed for observation profiles
    manifest = admission.sign_admission_manifest(payload=payload, signer=operator_kp)
    ok, errors = admission.verify_admission_manifest(
        manifest=manifest, operator_pubkey=operator_kp.public_b64(),
    )
    assert not ok
    assert any("intent_layer" in e for e in errors)


def test_file_sha256_round_trip(tmp_path: Path):
    p = tmp_path / "x.txt"
    content = b"deterministic pipeline observed"
    p.write_bytes(content)
    expected = hashlib.sha256(content).hexdigest()
    assert admission.file_sha256_hex(p) == expected
    assert len(admission.file_sha256_hex(p)) == 64


def test_file_sha256_streaming_works_for_large_file(tmp_path: Path):
    """The chunked reader correctly handles files larger than the read buffer."""
    p = tmp_path / "big.bin"
    # 256 KiB — larger than the 64 KiB read buffer to exercise the loop
    content = b"\x00" * (256 * 1024)
    p.write_bytes(content)
    expected = hashlib.sha256(content).hexdigest()
    assert admission.file_sha256_hex(p) == expected
