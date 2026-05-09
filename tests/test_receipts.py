"""Tests for `witness.receipts` — receipt construction and state-root chain."""

from __future__ import annotations

import pytest

from witness import canon, crypto, receipts


@pytest.fixture
def witness_kp():
    return crypto.generate_keypair("witness:test-l1-1")


@pytest.fixture
def observer_kp():
    return crypto.generate_keypair("observer:test-1")


@pytest.fixture
def keyring(witness_kp, observer_kp):
    return {
        witness_kp.key_id: witness_kp.public_b64(),
        observer_kp.key_id: observer_kp.public_b64(),
    }


def make_payload(sequence: int, kind: str = "observation", session: str = "s1"):
    return receipts.build_receipt_payload(
        session_id=session,
        sequence=sequence,
        receipt_kind=kind,
        actor={"type": "external_pipeline", "id": "test:pipeline:v1"},
        body={"sequence_marker": sequence, "kind": kind},
        previous_state_root_hex=receipts.GENESIS_STATE_ROOT.hex(),
    )


def test_genesis_state_root_is_stable():
    """Genesis is a fixed domain-tagged constant, not zeros."""
    assert len(receipts.GENESIS_STATE_ROOT) == 32
    assert receipts.GENESIS_STATE_ROOT != b"\x00" * 32
    # Re-derive and confirm the constant matches the docstring formula
    expected = canon.sha256(b"mpf-0.2:state-root:genesis")
    assert receipts.GENESIS_STATE_ROOT == expected


def test_payload_required_fields():
    payload = make_payload(0)
    for field in [
        "schema_version",
        "receipt_kind",
        "session_id",
        "sequence",
        "previous_state_root",
        "actor",
        "body",
        "issued_at",
    ]:
        assert field in payload, f"missing required field: {field}"


def test_disallowed_receipt_kind_rejected():
    with pytest.raises(ValueError, match="not in the observation profile"):
        receipts.build_receipt_payload(
            session_id="s1",
            sequence=0,
            receipt_kind="memory.store",  # not an observation-profile kind
            actor={"type": "external_pipeline"},
            body={},
            previous_state_root_hex=receipts.GENESIS_STATE_ROOT.hex(),
        )


def test_signature_set_is_sorted_by_key_id():
    payload = make_payload(0)
    kp_z = crypto.generate_keypair("z-signer")
    kp_a = crypto.generate_keypair("a-signer")
    sig_set = receipts.sign_receipt(payload=payload, signers=[kp_z, kp_a])
    keys = list(sig_set.keys())
    assert keys == sorted(keys), "signature_set keys must be sorted"
    assert keys[0] == "a-signer"


def test_state_root_size():
    payload = make_payload(0)
    sig_set = {"sig:1": "ed25519:" + "A" * 88}  # synthetic 64-byte b64
    sr = receipts.compute_state_root(
        previous_state_root=receipts.GENESIS_STATE_ROOT,
        payload=payload,
        signature_set=sig_set,
    )
    assert len(sr) == 32


def test_state_root_deterministic():
    """Same inputs → same state root, every time."""
    payload = make_payload(0)
    sig_set = {"sig:1": "ed25519:AAA"}
    a = receipts.compute_state_root(
        previous_state_root=receipts.GENESIS_STATE_ROOT,
        payload=payload, signature_set=sig_set,
    )
    b = receipts.compute_state_root(
        previous_state_root=receipts.GENESIS_STATE_ROOT,
        payload=payload, signature_set=sig_set,
    )
    assert a == b


def test_state_root_changes_on_payload_change():
    p1 = make_payload(0)
    p2 = make_payload(1)
    sig_set = {"sig:1": "ed25519:AAA"}
    sr1 = receipts.compute_state_root(
        previous_state_root=receipts.GENESIS_STATE_ROOT,
        payload=p1, signature_set=sig_set,
    )
    sr2 = receipts.compute_state_root(
        previous_state_root=receipts.GENESIS_STATE_ROOT,
        payload=p2, signature_set=sig_set,
    )
    assert sr1 != sr2


def test_state_root_changes_on_signature_change():
    payload = make_payload(0)
    sr1 = receipts.compute_state_root(
        previous_state_root=receipts.GENESIS_STATE_ROOT,
        payload=payload, signature_set={"sig:1": "ed25519:AAA"},
    )
    sr2 = receipts.compute_state_root(
        previous_state_root=receipts.GENESIS_STATE_ROOT,
        payload=payload, signature_set={"sig:1": "ed25519:BBB"},
    )
    assert sr1 != sr2


def test_state_root_changes_on_previous_root_change():
    payload = make_payload(0)
    sig_set = {"sig:1": "ed25519:AAA"}
    sr1 = receipts.compute_state_root(
        previous_state_root=receipts.GENESIS_STATE_ROOT,
        payload=payload, signature_set=sig_set,
    )
    other_prev = canon.sha256(b"other")
    sr2 = receipts.compute_state_root(
        previous_state_root=other_prev,
        payload=payload, signature_set=sig_set,
    )
    assert sr1 != sr2


def test_state_root_signature_order_independence():
    """Two signatures in different dict insertion orders produce the same state root."""
    payload = make_payload(0)
    sig_a_then_b = {"a": "ed25519:1", "b": "ed25519:2"}
    sig_b_then_a = {"b": "ed25519:2", "a": "ed25519:1"}
    sr1 = receipts.compute_state_root(
        previous_state_root=receipts.GENESIS_STATE_ROOT,
        payload=payload, signature_set=sig_a_then_b,
    )
    sr2 = receipts.compute_state_root(
        previous_state_root=receipts.GENESIS_STATE_ROOT,
        payload=payload, signature_set=sig_b_then_a,
    )
    assert sr1 == sr2


def test_round_trip_sign_and_verify(witness_kp, keyring):
    payload = make_payload(0)
    sig_set = receipts.sign_receipt(payload=payload, signers=[witness_kp])
    state_root = receipts.compute_state_root(
        previous_state_root=receipts.GENESIS_STATE_ROOT,
        payload=payload, signature_set=sig_set,
    )
    receipt = receipts.assemble_receipt(
        payload=payload, signature_set=sig_set, state_root=state_root,
    )
    ok, errors = receipts.verify_receipt(
        receipt=receipt,
        keyring=keyring,
        expected_previous_state_root=receipts.GENESIS_STATE_ROOT,
    )
    assert ok, f"verification failed: {errors}"


def test_verify_rejects_tampered_body(witness_kp, keyring):
    payload = make_payload(0)
    sig_set = receipts.sign_receipt(payload=payload, signers=[witness_kp])
    state_root = receipts.compute_state_root(
        previous_state_root=receipts.GENESIS_STATE_ROOT,
        payload=payload, signature_set=sig_set,
    )
    receipt = receipts.assemble_receipt(
        payload=payload, signature_set=sig_set, state_root=state_root,
    )
    # Tamper with the body after signing
    receipt["body"] = {"tampered": True}
    ok, errors = receipts.verify_receipt(receipt=receipt, keyring=keyring)
    assert not ok
    # Either signature fails or state root mismatches; both are valid failure modes.
    assert any("signature" in e or "state_root" in e for e in errors)


def test_verify_rejects_tampered_state_root(witness_kp, keyring):
    payload = make_payload(0)
    sig_set = receipts.sign_receipt(payload=payload, signers=[witness_kp])
    state_root = receipts.compute_state_root(
        previous_state_root=receipts.GENESIS_STATE_ROOT,
        payload=payload, signature_set=sig_set,
    )
    receipt = receipts.assemble_receipt(
        payload=payload, signature_set=sig_set, state_root=state_root,
    )
    # Replace the state root
    receipt["state_root"] = "00" * 32
    ok, errors = receipts.verify_receipt(receipt=receipt, keyring=keyring)
    assert not ok
    assert any("state_root mismatch" in e for e in errors)


def test_verify_rejects_unknown_key_id(witness_kp):
    payload = make_payload(0)
    sig_set = receipts.sign_receipt(payload=payload, signers=[witness_kp])
    state_root = receipts.compute_state_root(
        previous_state_root=receipts.GENESIS_STATE_ROOT,
        payload=payload, signature_set=sig_set,
    )
    receipt = receipts.assemble_receipt(
        payload=payload, signature_set=sig_set, state_root=state_root,
    )
    # Empty keyring — signer is unknown
    ok, errors = receipts.verify_receipt(receipt=receipt, keyring={})
    assert not ok
    assert any("not in keyring" in e for e in errors)


def test_chain_of_three_receipts(witness_kp, observer_kp, keyring):
    """A 3-receipt chain verifies end-to-end with state-root continuity."""
    session = receipts.new_session_id()
    prev = receipts.GENESIS_STATE_ROOT

    chain = []
    for seq, kind in enumerate(["session.start", "data.request", "data.response"]):
        payload = receipts.build_receipt_payload(
            session_id=session, sequence=seq, receipt_kind=kind,
            actor={"type": "external_pipeline"},
            body={"step": kind, "n": seq},
            previous_state_root_hex=prev.hex(),
        )
        sig_set = receipts.sign_receipt(payload=payload, signers=[witness_kp, observer_kp])
        state_root = receipts.compute_state_root(
            previous_state_root=prev, payload=payload, signature_set=sig_set,
        )
        receipt = receipts.assemble_receipt(
            payload=payload, signature_set=sig_set, state_root=state_root,
        )
        chain.append(receipt)
        prev = state_root

    # Verify each receipt with continuity
    expected_prev = receipts.GENESIS_STATE_ROOT
    for receipt in chain:
        ok, errors = receipts.verify_receipt(
            receipt=receipt, keyring=keyring,
            expected_previous_state_root=expected_prev,
        )
        assert ok, f"chain verification failed: {errors}"
        expected_prev = bytes.fromhex(receipt["state_root"])


def test_chain_breaks_on_intermediate_tamper(witness_kp, keyring):
    """If receipt N is tampered with, receipt N+1's continuity check fails."""
    session = receipts.new_session_id()
    prev = receipts.GENESIS_STATE_ROOT
    chain = []
    for seq, kind in enumerate(["session.start", "data.request"]):
        payload = receipts.build_receipt_payload(
            session_id=session, sequence=seq, receipt_kind=kind,
            actor={"type": "external_pipeline"},
            body={"step": kind},
            previous_state_root_hex=prev.hex(),
        )
        sig_set = receipts.sign_receipt(payload=payload, signers=[witness_kp])
        state_root = receipts.compute_state_root(
            previous_state_root=prev, payload=payload, signature_set=sig_set,
        )
        receipt = receipts.assemble_receipt(
            payload=payload, signature_set=sig_set, state_root=state_root,
        )
        chain.append(receipt)
        prev = state_root

    # Tamper with chain[0] — this should make chain[1]'s continuity check fail
    # when validated against the tampered state root.
    chain[0]["state_root"] = "00" * 32
    ok, errors = receipts.verify_receipt(
        receipt=chain[1],
        keyring=keyring,
        expected_previous_state_root=bytes.fromhex(chain[0]["state_root"]),
    )
    assert not ok
    assert any("previous_state_root mismatch" in e for e in errors)
