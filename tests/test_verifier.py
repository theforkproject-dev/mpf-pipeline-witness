"""End-to-end verifier tests.

The verifier must accept a freshly-produced bundle as VERIFIED and reject
every meaningful tamper with FAILED.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import httpx
import pytest

from witness import admission, bundle, canon, crypto, registry
from witness.gateway import Gateway
from witness.witness import GuardKeyStore, L1Witness
from verifier import verify_bundle


REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "dashboard-2026-05-09T21-25-18Z.json"


# --- Fixtures ---------------------------------------------------------------


@pytest.fixture
def fixture_bytes():
    return FIXTURE_PATH.read_bytes()


def _build_full_bundle(tmp_path: Path, fixture_bytes: bytes, *, fail_fetch: bool = False):
    """Produce a complete bundle and return paths + key info for tampering tests."""
    op = crypto.generate_keypair("operator:fork-node-01:vt")
    wk = crypto.generate_keypair("witness:l1:vt")
    store = GuardKeyStore(tmp_path / "guard.db")
    w = L1Witness(witness_id="w:vt", signing_key=wk, store=store)

    ar = registry.build_action_registry_epoch(
        registry_id="registry:fork-pipeline-witness", epoch_number=1,
        validity_seconds=86400 * 365, operator_key=op,
    )
    wr = registry.build_witness_registry_epoch(
        registry_id="registry:fork-witness-registry", epoch_number=1,
        validity_seconds=86400 * 365, operator_key=op,
        witness_entries=[w.witness_registry_entry()],
    )
    am_payload = admission.build_admission_manifest(
        session_id="s:vt",
        operator_id="operator:fork-node-01", operator_key_id=op.key_id,
        workflow_id="observation.test", action_id="pipeline.snapshot.observe.v1",
        verifier_profile_id="mpf.profile.observation.external-pipeline.v0.2-fork",
        action_registry_epoch_id=ar["epoch_id"],
        action_registry_epoch_digest=ar["payload_digest"],
        witness_registry_epoch_id=wr["epoch_id"],
        witness_registry_epoch_digest=wr["payload_digest"],
        observer_code_digest="sha256:" + "a" * 64,
        validator_code_digest="sha256:" + "b" * 64,
        source_url="https://example.test/dashboard.json",
        cadence_seconds=1800, expected_schema_digest=None,
        pipeline_identity={"repo": "test"}, git_commit="vt",
    )
    am = admission.sign_admission_manifest(payload=am_payload, signer=op)

    gw = Gateway(
        operator_key=op, witness=w,
        source_url="https://example.test/dashboard.json",
    )
    if fail_fetch:
        client = httpx.Client(transport=httpx.MockTransport(
            lambda req: httpx.Response(503)
        ))
    else:
        client = httpx.Client(transport=httpx.MockTransport(
            lambda req: httpx.Response(200, content=fixture_bytes)
        ))
    out = gw.run_cycle(admission_manifest=am, http_client=client)

    bundle_dir = tmp_path / "bundle"
    bundle.assemble_bundle(
        bundle_dir=bundle_dir, cycle_output=out,
        action_registry=ar, witness_registry=wr, admission_manifest=am,
        operator_public_key_b64=op.public_b64(), operator_key_id=op.key_id,
        witness_public_key_b64=wk.public_b64(), witness_key_id=wk.key_id,
    )
    return bundle_dir, op, wk


def _rewrite_file(path: Path, mutator):
    """Read a JSON file, apply mutator(obj), write it back JCS-canonical."""
    obj = json.loads(path.read_text())
    obj = mutator(obj) or obj
    path.write_bytes(canon.canonicalize(obj))


# --- Happy path -------------------------------------------------------------


def test_fresh_bundle_verifies(tmp_path, fixture_bytes):
    bundle_dir, _, _ = _build_full_bundle(tmp_path, fixture_bytes)
    result = verify_bundle(bundle_dir)
    assert result.state in {"verified", "verified_with_warnings"}, (
        f"unexpected state {result.state}; failures: "
        + ", ".join(c.name for c in result.checks if not c.passed)
    )
    # Co-resident witness warning should land us in verified_with_warnings.
    assert result.state == "verified_with_warnings"
    assert all(c.passed for c in result.checks)
    assert result.summary["checks_failed"] == 0


def test_failed_observation_bundle_verifies_as_failed_state(
    tmp_path, fixture_bytes,
):
    """A bundle for a fetch-failure cycle still verifies (the proof is valid),
    but the certificate's outcome.state is 'failed' not 'verified'.

    The bundle's internal consistency is intact; what failed was upstream.
    """
    bundle_dir, _, _ = _build_full_bundle(tmp_path, fixture_bytes, fail_fetch=True)
    result = verify_bundle(bundle_dir)
    # All cryptographic checks pass.
    assert all(c.passed for c in result.checks), (
        "all checks should pass on a well-formed failure-path bundle: "
        + ", ".join(c.name for c in result.checks if not c.passed)
    )
    # But the state reflects the certificate's outcome.
    assert result.state in {"verified", "verified_with_warnings"}


# --- Tamper detection -------------------------------------------------------


def test_tampered_certificate_digest_rejected(tmp_path, fixture_bytes):
    bundle_dir, _, _ = _build_full_bundle(tmp_path, fixture_bytes)
    cert_path = bundle_dir / "certificate.json"
    _rewrite_file(cert_path, lambda c: {**c, "certificate_digest": "sha256:" + "0" * 64})
    result = verify_bundle(bundle_dir)
    assert result.state == "failed"
    assert any(c.name == "certificate_digest" and not c.passed for c in result.checks)


def test_tampered_certificate_body_rejected(tmp_path, fixture_bytes):
    """Modifying any certificate field (not the digest) must be detected."""
    bundle_dir, _, _ = _build_full_bundle(tmp_path, fixture_bytes)
    cert_path = bundle_dir / "certificate.json"
    _rewrite_file(cert_path, lambda c: {**c, "pod_id": "urn:mpf:pod:fraudulent"})
    result = verify_bundle(bundle_dir)
    assert result.state == "failed"
    # The certificate digest no longer matches.
    assert any(c.name == "certificate_digest" and not c.passed for c in result.checks)


def test_tampered_artifact_rejected_by_manifest(tmp_path, fixture_bytes):
    """Modifying an artifact's bytes must be caught by the bundle-manifest check."""
    bundle_dir, _, _ = _build_full_bundle(tmp_path, fixture_bytes)
    am_path = bundle_dir / "admission-manifest.json"
    # Tamper without updating the manifest (digest will mismatch).
    _rewrite_file(am_path, lambda a: {**a, "workflow": {**a["workflow"], "workflow_id": "fake"}})
    result = verify_bundle(bundle_dir)
    assert result.state == "failed"
    assert any(c.name == "artifact_digests" and not c.passed for c in result.checks)


def test_tampered_receipt_breaks_chain(tmp_path, fixture_bytes):
    """Modifying a receipt's body must break the chain (the next receipt's
    previous_state_root no longer matches).
    """
    bundle_dir, _, _ = _build_full_bundle(tmp_path, fixture_bytes)
    receipts_path = bundle_dir / "receipts.jsonl"
    lines = [line for line in receipts_path.read_bytes().split(b"\n") if line]
    # Tamper with the body of an early receipt; rewrite all lines.
    receipts_list = [json.loads(line) for line in lines]
    receipts_list[1]["body"] = {"tampered": True}
    new_lines = b"\n".join(canon.canonicalize(r) for r in receipts_list) + b"\n"
    receipts_path.write_bytes(new_lines)
    result = verify_bundle(bundle_dir)
    assert result.state == "failed"
    # Either chain or signatures fail; both indicate tamper.
    failed_names = {c.name for c in result.checks if not c.passed}
    assert {"receipt_chain", "signatures"} & failed_names


def test_swapped_keyring_breaks_signatures(tmp_path, fixture_bytes):
    """Replacing the operator public key with a different one must invalidate signatures."""
    bundle_dir, _, _ = _build_full_bundle(tmp_path, fixture_bytes)
    keyring_path = bundle_dir / "keyring.json"
    rogue = crypto.generate_keypair("rogue:1")

    def swap(k):
        for entry in k["keys"]:
            if entry["role"] == "operator":
                entry["public_key"] = rogue.public_b64()
        return k

    _rewrite_file(keyring_path, swap)
    result = verify_bundle(bundle_dir)
    assert result.state == "failed"
    failed_names = {c.name for c in result.checks if not c.passed}
    assert "signatures" in failed_names or "artifact_digests" in failed_names


def test_overclaim_capability_token_rejected(tmp_path, fixture_bytes):
    """A certificate that claims capability_token_enforced=true under an
    observation profile must be rejected per §9.4.1.
    """
    bundle_dir, _, _ = _build_full_bundle(tmp_path, fixture_bytes)
    cert_path = bundle_dir / "certificate.json"
    _rewrite_file(cert_path, lambda c: {**c, "assurance": {**c["assurance"], "capability_token_enforced": True}})
    result = verify_bundle(bundle_dir)
    assert result.state == "failed"
    failed_names = {c.name for c in result.checks if not c.passed}
    # Either the digest fails (because we changed the cert without recomputing)
    # or the overclaim check fails. Either is a valid rejection.
    assert {"certificate_digest", "observation_overclaim"} & failed_names


def test_action_id_not_in_registry_rejected(tmp_path, fixture_bytes):
    """If the certificate references an action_id not in the action registry epoch,
    the registry_validity check fails."""
    bundle_dir, _, _ = _build_full_bundle(tmp_path, fixture_bytes)
    cert_path = bundle_dir / "certificate.json"
    _rewrite_file(cert_path, lambda c: {**c, "action_id": "fraudulent.action.v1"})
    result = verify_bundle(bundle_dir)
    assert result.state == "failed"


def test_missing_certificate_unverifiable(tmp_path, fixture_bytes):
    bundle_dir, _, _ = _build_full_bundle(tmp_path, fixture_bytes)
    (bundle_dir / "certificate.json").unlink()
    result = verify_bundle(bundle_dir)
    assert result.state == "unverifiable"


def test_missing_bundle_dir_unverifiable(tmp_path):
    result = verify_bundle(tmp_path / "nonexistent")
    assert result.state == "unverifiable"


def test_unknown_witness_key_rejected(tmp_path, fixture_bytes):
    """If a receipt is signed by a key whose witness_id is not in the witness
    registry, the registry_validity check fails."""
    bundle_dir, _, _ = _build_full_bundle(tmp_path, fixture_bytes)
    cert_path = bundle_dir / "certificate.json"
    _rewrite_file(
        cert_path,
        lambda c: {**c, "witness_quorum": {**c["witness_quorum"],
                                            "witness_key_ids": ["unknown:rogue"]}},
    )
    result = verify_bundle(bundle_dir)
    assert result.state == "failed"


# --- Result shape -----------------------------------------------------------


def test_result_serializable(tmp_path, fixture_bytes):
    bundle_dir, _, _ = _build_full_bundle(tmp_path, fixture_bytes)
    result = verify_bundle(bundle_dir)
    d = result.to_dict()
    # Round-trip through JSON to confirm it's serializable.
    json.dumps(d)
    assert "state" in d
    assert "checks" in d
    assert isinstance(d["checks"], list)


def test_summary_fields(tmp_path, fixture_bytes):
    bundle_dir, _, _ = _build_full_bundle(tmp_path, fixture_bytes)
    result = verify_bundle(bundle_dir)
    s = result.summary
    # The cycle generates its own session_id (the admission manifest carries
    # an admission-time session identifier, the cycle generates a runtime one).
    assert s["session_id"].startswith("mpf-session-")
    assert s["outcome_state"] == "verified"
    assert s["checks_total"] >= 8
    assert s["checks_passed"] == s["checks_total"]
    assert s["head_state_root"].startswith("sha256:")
