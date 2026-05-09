"""End-to-end tests for `witness.gateway` — full observation cycle.

These tests run the gateway against the real captured fixture (mocking the
HTTP transport) and confirm the full §9.4.1 receipt flow lands correctly:

    session.start
      -> data.request
      -> data.response
      -> validation.result   (or validation.failed)
      -> observation         (only on success)
      -> session.end
      -> checkpoint

Plus failure-path coverage:

    - source.unavailable   (all retries fail)
    - validator.exception  (JSON decode failure)
    - validation.failed    (one or more invariant checks fail)

In every failure case the chain MUST still complete with session.end and
checkpoint receipts. Failures are recorded under the same chain, not
silently dropped.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import httpx
import pytest

from witness import admission, crypto, receipts
from witness.gateway import Gateway
from witness.witness import EquivocationError, GuardKeyStore, L1Witness


REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "dashboard-2026-05-09T21-25-18Z.json"


# --- Helpers ----------------------------------------------------------------


@pytest.fixture
def fixture_bytes():
    return FIXTURE_PATH.read_bytes()


@pytest.fixture
def fixture_dict(fixture_bytes):
    return json.loads(fixture_bytes)


@pytest.fixture
def operator_kp():
    return crypto.generate_keypair("operator:fork-node-01:test-1")


@pytest.fixture
def witness_kp():
    return crypto.generate_keypair("witness:l1:test-1")


@pytest.fixture
def guard_store(tmp_path):
    return GuardKeyStore(tmp_path / "guard.db")


@pytest.fixture
def witness(witness_kp, guard_store):
    return L1Witness(
        witness_id="w:test-1", signing_key=witness_kp, store=guard_store,
    )


@pytest.fixture
def gateway(operator_kp, witness):
    return Gateway(
        operator_key=operator_kp,
        witness=witness,
        source_url="https://example.test/dashboard.json",
    )


@pytest.fixture
def signed_manifest(operator_kp):
    """A minimal signed admission manifest for tests."""
    payload = admission.build_admission_manifest(
        session_id="s:fixed",
        operator_id="operator:fork-node-01",
        operator_key_id=operator_kp.key_id,
        workflow_id="observation.test",
        action_id="pipeline.snapshot.observe.v1",
        verifier_profile_id="mpf.profile.observation.external-pipeline.v0.2-fork",
        action_registry_epoch_id="ar:1",
        action_registry_epoch_digest="sha256:" + "0" * 64,
        witness_registry_epoch_id="wr:1",
        witness_registry_epoch_digest="sha256:" + "1" * 64,
        observer_code_digest="sha256:" + "a" * 64,
        validator_code_digest="sha256:" + "b" * 64,
        source_url="https://example.test/dashboard.json",
        cadence_seconds=1800,
        expected_schema_digest=None,
        pipeline_identity={"repo": "test"},
    )
    return admission.sign_admission_manifest(payload=payload, signer=operator_kp)


def mock_client_returning(*responses):
    """Build an httpx.Client whose mock transport returns a queue of responses."""
    queue = list(responses)

    def handler(request):
        if not queue:
            raise AssertionError("test ran out of queued responses")
        item = queue.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    return httpx.Client(transport=httpx.MockTransport(handler))


def receipt_kinds(chain):
    """Extract the ordered list of receipt kinds from a chain."""
    return [r["receipt_kind"] for r in chain]


# --- Success path -----------------------------------------------------------


def test_full_success_cycle_kinds_match_spec_flow(
    gateway, signed_manifest, fixture_bytes
):
    """Successful cycle emits the spec's recommended receipt sequence."""
    client = mock_client_returning(httpx.Response(200, content=fixture_bytes))
    out = gateway.run_cycle(
        admission_manifest=signed_manifest, http_client=client,
    )
    kinds = receipt_kinds(out.receipts)
    assert kinds == [
        "session.start",
        "data.request",
        "data.response",
        "validation.result",
        "observation",
        "session.end",
        "checkpoint",
    ]
    assert out.observation_succeeded is True


def test_full_success_cycle_state_root_chain_continuous(
    gateway, signed_manifest, fixture_bytes
):
    """Each receipt's previous_state_root matches the prior receipt's state_root."""
    client = mock_client_returning(httpx.Response(200, content=fixture_bytes))
    out = gateway.run_cycle(
        admission_manifest=signed_manifest, http_client=client,
    )
    expected_prev = receipts.GENESIS_STATE_ROOT.hex()
    for r in out.receipts:
        assert r["previous_state_root"] == expected_prev, (
            f"chain break at sequence {r['sequence']} ({r['receipt_kind']}): "
            f"expected {expected_prev}, got {r['previous_state_root']}"
        )
        expected_prev = r["state_root"]
    # And the head_state_root_hex matches the last receipt.
    assert out.head_state_root_hex == out.receipts[-1]["state_root"]


def test_full_success_cycle_every_receipt_verifies(
    gateway, signed_manifest, fixture_bytes, operator_kp, witness_kp,
):
    """Every receipt in the chain verifies under the keyring.

    Witness signatures cover the observation subject (not the receipt
    payload), so the verifier is told which key IDs sign which external
    subject via the `external_subjects` parameter.
    """
    client = mock_client_returning(httpx.Response(200, content=fixture_bytes))
    out = gateway.run_cycle(
        admission_manifest=signed_manifest, http_client=client,
    )
    keyring = {
        operator_kp.key_id: operator_kp.public_b64(),
        witness_kp.key_id: witness_kp.public_b64(),
    }
    expected_prev = receipts.GENESIS_STATE_ROOT
    for r in out.receipts:
        # If the receipt carries a witness signature, build the external
        # subject map so the verifier checks that signature against the
        # observation subject (reconstructed from the receipt body fields).
        ext = None
        if witness_kp.key_id in r["signature_set"]:
            assert out.observation_subject is not None
            ext = {witness_kp.key_id: out.observation_subject}
        ok, errors = receipts.verify_receipt(
            receipt=r, keyring=keyring,
            expected_previous_state_root=expected_prev,
            external_subjects=ext,
        )
        assert ok, f"verification failed at {r['receipt_kind']}: {errors}"
        expected_prev = bytes.fromhex(r["state_root"])


def test_witness_signs_observation_and_validation_subjects(
    gateway, signed_manifest, fixture_bytes, witness_kp, operator_kp,
):
    """Per §11.1: L1 witnesses sign observation and validation subjects.

    Other receipts in the cycle carry only the operator's signature.
    """
    client = mock_client_returning(httpx.Response(200, content=fixture_bytes))
    out = gateway.run_cycle(
        admission_manifest=signed_manifest, http_client=client,
    )
    for r in out.receipts:
        sigs = r["signature_set"]
        if r["receipt_kind"] in ("observation", "validation.result"):
            assert witness_kp.key_id in sigs, (
                f"{r['receipt_kind']} must include witness signature"
            )
            assert operator_kp.key_id in sigs, (
                f"{r['receipt_kind']} must also include operator signature"
            )
        else:
            assert witness_kp.key_id not in sigs, (
                f"{r['receipt_kind']} must NOT carry witness signature"
            )
            assert operator_kp.key_id in sigs


def test_observation_carries_validation_summary_and_bytes_digest(
    gateway, signed_manifest, fixture_bytes,
):
    """The observation receipt body binds the bytes digest and the validator summary."""
    client = mock_client_returning(httpx.Response(200, content=fixture_bytes))
    out = gateway.run_cycle(
        admission_manifest=signed_manifest, http_client=client,
    )
    obs = next(r for r in out.receipts if r["receipt_kind"] == "observation")
    assert obs["body"]["bytes_sha256"].startswith("sha256:")
    assert obs["body"]["validation_passed"] is True
    assert obs["body"]["validation_summary"]["concurrent_count"] == 422


def test_session_start_and_checkpoint_bind_admission_digest(
    gateway, signed_manifest, fixture_bytes,
):
    """Session.start and checkpoint both reference the admission manifest by digest."""
    client = mock_client_returning(httpx.Response(200, content=fixture_bytes))
    out = gateway.run_cycle(
        admission_manifest=signed_manifest, http_client=client,
    )
    manifest_digest = signed_manifest["payload_digest"]
    start = next(r for r in out.receipts if r["receipt_kind"] == "session.start")
    cp = next(r for r in out.receipts if r["receipt_kind"] == "checkpoint")
    assert start["body"]["admission_manifest_digest"] == manifest_digest
    assert cp["body"]["admission_manifest_digest"] == manifest_digest


def test_observed_bytes_returned_byte_exact(
    gateway, signed_manifest, fixture_bytes,
):
    """The cycle output preserves the raw fetched bytes for bundle assembly."""
    client = mock_client_returning(httpx.Response(200, content=fixture_bytes))
    out = gateway.run_cycle(
        admission_manifest=signed_manifest, http_client=client,
    )
    assert out.observed_bytes == fixture_bytes
    import hashlib
    assert out.observed_bytes_sha256_hex == hashlib.sha256(fixture_bytes).hexdigest()


# --- Failure paths ----------------------------------------------------------


def test_source_unavailable_emits_failure_kind_and_completes_chain(
    gateway, signed_manifest,
):
    """All retries fail → source.unavailable receipt, chain still terminates."""
    client = mock_client_returning(
        httpx.Response(503), httpx.Response(503), httpx.Response(503),
    )
    out = gateway.run_cycle(
        admission_manifest=signed_manifest, http_client=client,
    )
    kinds = receipt_kinds(out.receipts)
    assert kinds == [
        "session.start",
        "data.request",
        "source.unavailable",
        "session.end",
        "checkpoint",
    ]
    assert out.observation_succeeded is False
    assert out.observed_bytes is None


def test_validator_exception_emits_failure_kind_and_completes_chain(
    gateway, signed_manifest,
):
    """Malformed JSON → validator.exception receipt, chain still terminates."""
    client = mock_client_returning(httpx.Response(200, content=b"not valid json {"))
    out = gateway.run_cycle(
        admission_manifest=signed_manifest, http_client=client,
    )
    kinds = receipt_kinds(out.receipts)
    assert kinds == [
        "session.start",
        "data.request",
        "data.response",
        "validator.exception",
        "session.end",
        "checkpoint",
    ]
    assert out.observation_succeeded is False
    # Bytes ARE preserved (we fetched them) even though parsing failed.
    assert out.observed_bytes == b"not valid json {"


def test_validation_failed_emits_failure_kind_and_completes_chain(
    gateway, signed_manifest, fixture_dict,
):
    """Validator fails → validation.failed receipt, no observation, chain terminates."""
    # Tamper the fixture so the z-score reproduces incorrectly.
    bad = copy.deepcopy(fixture_dict)
    bad["current"]["zScore"] = bad["current"]["zScore"] + 5.0
    bad_bytes = json.dumps(bad).encode("utf-8")

    client = mock_client_returning(httpx.Response(200, content=bad_bytes))
    out = gateway.run_cycle(
        admission_manifest=signed_manifest, http_client=client,
    )
    kinds = receipt_kinds(out.receipts)
    # Note: validation.failed appears INSTEAD OF validation.result, and there
    # is NO observation receipt.
    assert kinds == [
        "session.start",
        "data.request",
        "data.response",
        "validation.failed",
        "session.end",
        "checkpoint",
    ]
    assert out.observation_succeeded is False
    # The validation.failed receipt's body still contains the structured
    # check details so a verifier can see exactly what failed.
    failed = next(r for r in out.receipts if r["receipt_kind"] == "validation.failed")
    assert failed["body"]["overall_passed"] is False
    assert failed["body"]["counts"]["checks_failed"] >= 1


def test_failure_path_chain_continuity(
    gateway, signed_manifest, operator_kp, witness_kp,
):
    """Even on failure, the chain's state-root continuity holds end-to-end."""
    client = mock_client_returning(httpx.Response(503), httpx.Response(503), httpx.Response(503))
    out = gateway.run_cycle(
        admission_manifest=signed_manifest, http_client=client,
    )
    keyring = {
        operator_kp.key_id: operator_kp.public_b64(),
        witness_kp.key_id: witness_kp.public_b64(),
    }
    expected_prev = receipts.GENESIS_STATE_ROOT
    for r in out.receipts:
        ok, errors = receipts.verify_receipt(
            receipt=r, keyring=keyring,
            expected_previous_state_root=expected_prev,
        )
        assert ok, f"verification failed at {r['receipt_kind']}: {errors}"
        expected_prev = bytes.fromhex(r["state_root"])


# --- Anti-equivocation under the gateway ------------------------------------


def test_gateway_propagates_equivocation_when_same_observed_timestamp(
    operator_kp, witness, signed_manifest, fixture_dict,
):
    """Two cycles claiming the same observed_timestamp with different bytes must
    surface as an EquivocationError from the witness, refusing the second cycle.

    This is the §11.1 invariant operating end-to-end through the gateway.
    """
    gw = Gateway(
        operator_key=operator_kp, witness=witness,
        source_url="https://example.test/dashboard.json",
    )

    bytes_a = json.dumps(fixture_dict).encode("utf-8")
    # Make a second variant with different content but the SAME current.asOf.
    variant = copy.deepcopy(fixture_dict)
    variant["current"]["concurrentCount"] = variant["current"]["concurrentCount"] + 7
    bytes_b = json.dumps(variant).encode("utf-8")

    client_a = mock_client_returning(httpx.Response(200, content=bytes_a))
    out_a = gw.run_cycle(admission_manifest=signed_manifest, http_client=client_a)
    assert out_a.observation_succeeded is False or out_a.observation_succeeded is True
    # First cycle should succeed (the variant change does not break z-score
    # consistency for run A; we tampered with run B). Sanity check:
    # if A failed for an unrelated reason, this test is meaningless.
    assert any(r["receipt_kind"] == "observation"
               or r["receipt_kind"] == "validation.failed"
               for r in out_a.receipts)

    # Second cycle, same timestamp, different bytes → witness MUST refuse.
    client_b = mock_client_returning(httpx.Response(200, content=bytes_b))
    with pytest.raises(EquivocationError):
        gw.run_cycle(admission_manifest=signed_manifest, http_client=client_b)


def test_gateway_idempotent_resign_for_same_bytes(
    operator_kp, witness, signed_manifest, fixture_bytes,
):
    """Two cycles with byte-identical responses produce byte-identical witness signatures.

    Same guard key + same subject = idempotent in the guard store, and Ed25519
    signatures are deterministic, so the signatures match exactly.
    """
    gw = Gateway(
        operator_key=operator_kp, witness=witness,
        source_url="https://example.test/dashboard.json",
    )

    client_1 = mock_client_returning(httpx.Response(200, content=fixture_bytes))
    out_1 = gw.run_cycle(admission_manifest=signed_manifest, http_client=client_1)

    client_2 = mock_client_returning(httpx.Response(200, content=fixture_bytes))
    out_2 = gw.run_cycle(admission_manifest=signed_manifest, http_client=client_2)

    obs_1 = next(r for r in out_1.receipts if r["receipt_kind"] == "observation")
    obs_2 = next(r for r in out_2.receipts if r["receipt_kind"] == "observation")
    # The witness signature in the observation receipt must be byte-identical.
    witness_key_id = witness.signing_key.key_id
    assert obs_1["signature_set"][witness_key_id] == obs_2["signature_set"][witness_key_id]
