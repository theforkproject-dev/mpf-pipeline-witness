"""Tests for `witness.witness` — L1 mechanical witness with anti-equivocation."""

from __future__ import annotations

from pathlib import Path

import pytest

from witness import canon, crypto
from witness.witness import (
    EquivocationError,
    GuardKey,
    GuardKeyStore,
    L1Witness,
    WITNESS_TIER_L1,
)


@pytest.fixture
def store():
    return GuardKeyStore(":memory:")


@pytest.fixture
def witness_kp():
    return crypto.generate_keypair("witness:l1:test-1")


@pytest.fixture
def witness(store, witness_kp):
    return L1Witness(
        witness_id="w:test-1", signing_key=witness_kp, store=store,
    )


# --- GuardKey ---------------------------------------------------------------


def test_guard_key_canonical_form():
    gk = GuardKey(
        source_url="https://example.test/x.json",
        observed_timestamp="2026-05-09T20:59:50Z",
    )
    assert gk.to_canonical() == "https://example.test/x.json|2026-05-09T20:59:50Z"


def test_guard_key_rejects_pipe_in_fields():
    with pytest.raises(ValueError, match="must not contain"):
        GuardKey(
            source_url="https://example.test|x.json",
            observed_timestamp="2026-05-09T20:59:50Z",
        ).to_canonical()


# --- GuardKeyStore ----------------------------------------------------------


def test_first_record_returns_first(store):
    gk = GuardKey("https://x.test/a", "2026-05-09T20:00:00Z")
    assert store.record_or_check(gk, "a" * 64) == "first"


def test_idempotent_resign_returns_idempotent(store):
    gk = GuardKey("https://x.test/a", "2026-05-09T20:00:00Z")
    store.record_or_check(gk, "a" * 64)
    assert store.record_or_check(gk, "a" * 64) == "idempotent"


def test_equivocation_raises(store):
    gk = GuardKey("https://x.test/a", "2026-05-09T20:00:00Z")
    store.record_or_check(gk, "a" * 64)
    with pytest.raises(EquivocationError) as exc_info:
        store.record_or_check(gk, "b" * 64)
    err = exc_info.value
    assert err.previous_digest_hex == "a" * 64
    assert err.new_digest_hex == "b" * 64
    assert err.guard_key == gk


def test_equivocation_persists_conflict_evidence(store):
    """Per §11.1: 'persist conflict evidence in its anti-equivocation store'."""
    gk = GuardKey("https://x.test/a", "2026-05-09T20:00:00Z")
    store.record_or_check(gk, "a" * 64)
    with pytest.raises(EquivocationError):
        store.record_or_check(gk, "b" * 64)
    conflicts = store.list_conflicts()
    assert len(conflicts) == 1
    c = conflicts[0]
    assert c["previous_digest_hex"] == "a" * 64
    assert c["attempted_digest_hex"] == "b" * 64
    assert c["guard_key_canonical"] == gk.to_canonical()


def test_distinct_guard_keys_are_independent(store):
    gk1 = GuardKey("https://x.test/a", "2026-05-09T20:00:00Z")
    gk2 = GuardKey("https://x.test/a", "2026-05-09T20:30:00Z")  # different time
    gk3 = GuardKey("https://y.test/a", "2026-05-09T20:00:00Z")  # different URL
    assert store.record_or_check(gk1, "a" * 64) == "first"
    assert store.record_or_check(gk2, "b" * 64) == "first"
    assert store.record_or_check(gk3, "c" * 64) == "first"


def test_get_signed_digest(store):
    gk = GuardKey("https://x.test/a", "2026-05-09T20:00:00Z")
    assert store.get_signed_digest(gk) is None
    store.record_or_check(gk, "deadbeef" * 8)
    assert store.get_signed_digest(gk) == "deadbeef" * 8


def test_persistence_across_connections(tmp_path: Path):
    """A file-backed store survives close/reopen — anti-equivocation must be durable."""
    db_path = tmp_path / "guard.db"
    s1 = GuardKeyStore(db_path)
    gk = GuardKey("https://x.test/a", "2026-05-09T20:00:00Z")
    s1.record_or_check(gk, "a" * 64)
    s1.close()

    # Reopen and check that the record persists.
    s2 = GuardKeyStore(db_path)
    assert s2.get_signed_digest(gk) == "a" * 64
    # And equivocation across restarts is detected.
    with pytest.raises(EquivocationError):
        s2.record_or_check(gk, "b" * 64)
    s2.close()


# --- L1Witness --------------------------------------------------------------


def test_witness_signs_subject(witness, witness_kp):
    subject = {"kind": "observation", "value": 42}
    gk = GuardKey("https://x.test/a", "2026-05-09T20:00:00Z")
    ws = witness.sign_subject(subject=subject, guard_key=gk)
    assert ws.witness_id == "w:test-1"
    assert ws.key_id == witness_kp.key_id
    assert ws.guard_outcome == "first"
    # Signature must verify under the witness's public key over the canonical bytes.
    canonical = canon.canonicalize(subject)
    assert crypto.verify_signature(witness_kp.public_b64(), canonical, ws.signature_b64)


def test_witness_idempotent_resign(witness):
    subject = {"kind": "observation", "value": 42}
    gk = GuardKey("https://x.test/a", "2026-05-09T20:00:00Z")
    ws1 = witness.sign_subject(subject=subject, guard_key=gk)
    ws2 = witness.sign_subject(subject=subject, guard_key=gk)
    assert ws1.guard_outcome == "first"
    assert ws2.guard_outcome == "idempotent"
    # Ed25519 is deterministic; signatures over the same bytes are equal.
    assert ws1.signature_b64 == ws2.signature_b64


def test_witness_refuses_equivocation(witness):
    """The headline §11.1 invariant: refuse a different digest for the same guard key."""
    gk = GuardKey("https://x.test/a", "2026-05-09T20:00:00Z")
    witness.sign_subject(subject={"kind": "observation", "value": 1}, guard_key=gk)
    with pytest.raises(EquivocationError):
        witness.sign_subject(subject={"kind": "observation", "value": 2}, guard_key=gk)


def test_witness_registry_entry_shape(witness, witness_kp):
    entry = witness.witness_registry_entry()
    assert entry["witness_id"] == "w:test-1"
    assert entry["tier"] == WITNESS_TIER_L1
    assert entry["public_key"] == witness_kp.public_b64()
    assert entry["operator_id"] == "operator:fork-node-01"
    assert entry["independence_class"] == "co-resident"
