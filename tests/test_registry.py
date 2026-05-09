"""Tests for `witness.registry` — Action and Witness Registry epochs."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from witness import canon, crypto, registry


@pytest.fixture
def operator_kp():
    return crypto.generate_keypair("operator:fork-node-01:k1")


# --- Action Registry ---------------------------------------------------------


def test_action_registry_genesis_shape(operator_kp):
    epoch = registry.build_action_registry_epoch(
        registry_id="registry:fork-pipeline-witness",
        epoch_number=1,
        validity_seconds=86400 * 365,
        operator_key=operator_kp,
    )
    # Required envelope fields
    for f in [
        "schema_version", "registry_id", "epoch_id", "epoch_number",
        "issued_at", "expires_at", "operator", "actions",
        "verifier_profile_default", "payload_digest", "signature_set",
    ]:
        assert f in epoch, f"missing {f}"
    assert epoch["schema_version"] == registry.ACTION_REGISTRY_SCHEMA
    assert epoch["epoch_number"] == 1
    assert epoch["epoch_id"] == "registry:fork-pipeline-witness:epoch-1"
    assert isinstance(epoch["actions"], list)
    assert len(epoch["actions"]) == 1
    assert epoch["actions"][0]["action_id"] == "pipeline.snapshot.observe.v1"


def test_action_entry_has_required_section_8_2_fields(operator_kp):
    """Per §8.2 each action entry must include several specific fields."""
    epoch = registry.build_action_registry_epoch(
        registry_id="r1", epoch_number=1, validity_seconds=86400,
        operator_key=operator_kp,
    )
    entry = epoch["actions"][0]
    for f in [
        "action_id", "title", "description",
        "input_schema_ref", "output_schema_ref",
        "adapter", "actor_type", "assurance",
        "evidence_mode", "verifier_profile_id",
    ]:
        assert f in entry, f"action entry missing {f}"
    # Observation-profile specifics
    assert entry["actor_type"] == "external_pipeline"
    assert entry["assurance"]["capability_token_enforced"] is False
    assert entry["assurance"]["mode"] == "observed_l1"


def test_action_registry_verifies(operator_kp):
    epoch = registry.build_action_registry_epoch(
        registry_id="r1", epoch_number=1, validity_seconds=86400,
        operator_key=operator_kp,
    )
    ok, errors = registry.verify_registry(
        registry=epoch, operator_pubkey=operator_kp.public_b64(),
    )
    assert ok, f"verification failed: {errors}"


def test_action_registry_rejects_wrong_operator_key(operator_kp):
    other = crypto.generate_keypair("other:k1")
    epoch = registry.build_action_registry_epoch(
        registry_id="r1", epoch_number=1, validity_seconds=86400,
        operator_key=operator_kp,
    )
    ok, errors = registry.verify_registry(
        registry=epoch, operator_pubkey=other.public_b64(),
    )
    assert not ok
    assert any("signature" in e for e in errors)


def test_action_registry_rejects_tampered_actions(operator_kp):
    epoch = registry.build_action_registry_epoch(
        registry_id="r1", epoch_number=1, validity_seconds=86400,
        operator_key=operator_kp,
    )
    # Tamper: add a new action after signing
    epoch["actions"].append({"action_id": "fraudulent.action.v1"})
    ok, errors = registry.verify_registry(
        registry=epoch, operator_pubkey=operator_kp.public_b64(),
    )
    assert not ok
    # Either digest mismatch or signature failure; both indicate tamper.
    assert any("digest" in e or "signature" in e for e in errors)


def test_action_registry_rejects_outside_validity_window(operator_kp):
    """Verification with a time outside [issued_at, expires_at] must fail."""
    issued_dt = datetime(2026, 1, 1, tzinfo=timezone.utc)
    epoch = registry.build_action_registry_epoch(
        registry_id="r1", epoch_number=1, validity_seconds=86400,
        operator_key=operator_kp,
        issued_at=issued_dt.isoformat().replace("+00:00", "Z"),
    )
    # Verify at a time *before* issued_at
    too_early = (issued_dt - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    ok, errors = registry.verify_registry(
        registry=epoch, operator_pubkey=operator_kp.public_b64(),
        verification_time=too_early,
    )
    assert not ok
    assert any("before issued_at" in e for e in errors)

    # Verify at a time *after* expires_at
    too_late = (issued_dt + timedelta(days=2)).isoformat().replace("+00:00", "Z")
    ok, errors = registry.verify_registry(
        registry=epoch, operator_pubkey=operator_kp.public_b64(),
        verification_time=too_late,
    )
    assert not ok
    assert any("after expires_at" in e for e in errors)


def test_action_registry_extra_actions(operator_kp):
    extra = [{
        "action_id": "pipeline.snapshot.observe.v2",
        "title": "Future variant",
        "description": "x",
        "input_schema_ref": "x",
        "output_schema_ref": "x",
        "adapter": {"type": "x", "audience": "x", "method": "GET"},
        "actor_type": "external_pipeline",
        "assurance": {"mode": "observed_l1", "capability_token_enforced": False,
                      "mechanical_witness_threshold": 1,
                      "policy_witness_required": False,
                      "domain_attestation_required": False},
        "evidence_mode": "full",
        "verifier_profile_id": "x",
    }]
    epoch = registry.build_action_registry_epoch(
        registry_id="r1", epoch_number=1, validity_seconds=86400,
        operator_key=operator_kp, extra_actions=extra,
    )
    assert len(epoch["actions"]) == 2


# --- Witness Registry --------------------------------------------------------


def make_witness_entry(witness_id: str, key_id: str, pubkey_b64: str, tier: str = "L1") -> dict:
    return {
        "witness_id": witness_id,
        "key_id": key_id,
        "public_key": pubkey_b64,
        "tier": tier,
        "operator_id": "operator:fork-node-01",
        "independence_class": "co-resident",
    }


def test_witness_registry_basic_shape(operator_kp):
    wkp = crypto.generate_keypair("witness:l1:1")
    epoch = registry.build_witness_registry_epoch(
        registry_id="registry:fork-witness-registry",
        epoch_number=1, validity_seconds=86400,
        operator_key=operator_kp,
        witness_entries=[make_witness_entry("w1", wkp.key_id, wkp.public_b64())],
    )
    for f in [
        "schema_version", "registry_id", "epoch_id", "epoch_number",
        "issued_at", "expires_at", "operator", "witnesses",
        "payload_digest", "signature_set",
    ]:
        assert f in epoch, f"missing {f}"
    assert len(epoch["witnesses"]) == 1


def test_witness_registry_requires_at_least_one_witness(operator_kp):
    with pytest.raises(ValueError, match="at least one witness"):
        registry.build_witness_registry_epoch(
            registry_id="r1", epoch_number=1, validity_seconds=86400,
            operator_key=operator_kp, witness_entries=[],
        )


def test_witness_registry_rejects_invalid_tier(operator_kp):
    wkp = crypto.generate_keypair("w1")
    with pytest.raises(ValueError, match="invalid tier"):
        registry.build_witness_registry_epoch(
            registry_id="r1", epoch_number=1, validity_seconds=86400,
            operator_key=operator_kp,
            witness_entries=[make_witness_entry("w1", wkp.key_id, wkp.public_b64(), tier="L4")],
        )


def test_witness_registry_rejects_missing_required_fields(operator_kp):
    with pytest.raises(ValueError, match="missing required fields"):
        registry.build_witness_registry_epoch(
            registry_id="r1", epoch_number=1, validity_seconds=86400,
            operator_key=operator_kp,
            witness_entries=[{"witness_id": "w1"}],  # missing key_id, public_key, tier, operator_id
        )


def test_witness_registry_entries_sorted_by_id(operator_kp):
    """Sorting witness entries deterministically prevents nondeterministic registry digests."""
    w1 = crypto.generate_keypair("w1")
    w2 = crypto.generate_keypair("w2")
    entries = [
        make_witness_entry("zebra-witness", w2.key_id, w2.public_b64()),
        make_witness_entry("alpha-witness", w1.key_id, w1.public_b64()),
    ]
    epoch = registry.build_witness_registry_epoch(
        registry_id="r1", epoch_number=1, validity_seconds=86400,
        operator_key=operator_kp, witness_entries=entries,
    )
    ids = [e["witness_id"] for e in epoch["witnesses"]]
    assert ids == ["alpha-witness", "zebra-witness"]


def test_witness_registry_verifies(operator_kp):
    wkp = crypto.generate_keypair("witness:l1:1")
    epoch = registry.build_witness_registry_epoch(
        registry_id="r1", epoch_number=1, validity_seconds=86400,
        operator_key=operator_kp,
        witness_entries=[make_witness_entry("w1", wkp.key_id, wkp.public_b64())],
    )
    ok, errors = registry.verify_registry(
        registry=epoch, operator_pubkey=operator_kp.public_b64(),
    )
    assert ok, f"verification failed: {errors}"


def test_witness_registry_rejects_added_witness_after_signing(operator_kp):
    wkp = crypto.generate_keypair("witness:l1:1")
    epoch = registry.build_witness_registry_epoch(
        registry_id="r1", epoch_number=1, validity_seconds=86400,
        operator_key=operator_kp,
        witness_entries=[make_witness_entry("w1", wkp.key_id, wkp.public_b64())],
    )
    # Tamper: inject an unauthorized witness.
    rogue = crypto.generate_keypair("rogue:1")
    epoch["witnesses"].append(make_witness_entry("rogue", rogue.key_id, rogue.public_b64()))
    ok, errors = registry.verify_registry(
        registry=epoch, operator_pubkey=operator_kp.public_b64(),
    )
    assert not ok
    assert any("digest" in e or "signature" in e for e in errors)
