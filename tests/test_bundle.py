"""End-to-end tests for `witness.bundle` — full certificate bundle assembly."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import httpx
import pytest

from witness import admission, bundle, canon, crypto, registry
from witness.gateway import Gateway
from witness.witness import GuardKeyStore, L1Witness


REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "dashboard-2026-05-09T21-25-18Z.json"


# --- Fixtures ---------------------------------------------------------------


@pytest.fixture
def fixture_bytes():
    return FIXTURE_PATH.read_bytes()


@pytest.fixture
def operator_kp():
    return crypto.generate_keypair("operator:fork-node-01:test-1")


@pytest.fixture
def witness_kp():
    return crypto.generate_keypair("witness:l1:test-1")


@pytest.fixture
def witness(witness_kp, tmp_path):
    store = GuardKeyStore(tmp_path / "guard.db")
    return L1Witness(witness_id="w:test-1", signing_key=witness_kp, store=store)


@pytest.fixture
def action_registry_epoch(operator_kp):
    return registry.build_action_registry_epoch(
        registry_id="registry:fork-pipeline-witness",
        epoch_number=1, validity_seconds=86400 * 365,
        operator_key=operator_kp,
    )


@pytest.fixture
def witness_registry_epoch(operator_kp, witness):
    return registry.build_witness_registry_epoch(
        registry_id="registry:fork-witness-registry",
        epoch_number=1, validity_seconds=86400 * 365,
        operator_key=operator_kp,
        witness_entries=[witness.witness_registry_entry()],
    )


@pytest.fixture
def signed_admission_manifest(
    operator_kp, action_registry_epoch, witness_registry_epoch,
):
    payload = admission.build_admission_manifest(
        session_id="s:fixed",
        operator_id="operator:fork-node-01",
        operator_key_id=operator_kp.key_id,
        workflow_id="observation.test",
        action_id="pipeline.snapshot.observe.v1",
        verifier_profile_id="mpf.profile.observation.external-pipeline.v0.2-fork",
        action_registry_epoch_id=action_registry_epoch["epoch_id"],
        action_registry_epoch_digest=action_registry_epoch["payload_digest"],
        witness_registry_epoch_id=witness_registry_epoch["epoch_id"],
        witness_registry_epoch_digest=witness_registry_epoch["payload_digest"],
        observer_code_digest="sha256:" + "a" * 64,
        validator_code_digest="sha256:" + "b" * 64,
        source_url="https://example.test/dashboard.json",
        cadence_seconds=1800,
        expected_schema_digest=None,
        pipeline_identity={"repo": "github.com/kylemcdonald/ews"},
        git_commit="testcommit",
    )
    return admission.sign_admission_manifest(payload=payload, signer=operator_kp)


@pytest.fixture
def cycle_output(operator_kp, witness, signed_admission_manifest, fixture_bytes):
    """A successful cycle's output, for bundle assembly."""
    gw = Gateway(
        operator_key=operator_kp, witness=witness,
        source_url="https://example.test/dashboard.json",
    )
    client = httpx.Client(transport=httpx.MockTransport(
        lambda req: httpx.Response(200, content=fixture_bytes)
    ))
    return gw.run_cycle(
        admission_manifest=signed_admission_manifest, http_client=client,
    )


# --- Bundle assembly --------------------------------------------------------


def test_assemble_creates_all_required_artifacts(
    tmp_path, cycle_output, action_registry_epoch, witness_registry_epoch,
    signed_admission_manifest, operator_kp, witness_kp,
):
    bundle_dir = tmp_path / "bundle"
    result = bundle.assemble_bundle(
        bundle_dir=bundle_dir,
        cycle_output=cycle_output,
        action_registry=action_registry_epoch,
        witness_registry=witness_registry_epoch,
        admission_manifest=signed_admission_manifest,
        operator_public_key_b64=operator_kp.public_b64(),
        operator_key_id=operator_kp.key_id,
        witness_public_key_b64=witness_kp.public_b64(),
        witness_key_id=witness_kp.key_id,
    )

    expected_files = {
        "certificate.json",
        "receipts.jsonl",
        "keyring.json",
        "action-registry.json",
        "witness-registry-epoch.json",
        "admission-manifest.json",
        "checkpoint.json",
        "observation-subject.json",
        "observed-bytes.bin",
        "verification.json",
        "replay.json",
        "bundle-manifest.json",
    }
    actual_files = {p.name for p in bundle_dir.iterdir()}
    assert expected_files.issubset(actual_files), (
        f"missing artifacts: {expected_files - actual_files}"
    )


def test_certificate_has_required_section_13_1_fields(
    tmp_path, cycle_output, action_registry_epoch, witness_registry_epoch,
    signed_admission_manifest, operator_kp, witness_kp,
):
    bundle_dir = tmp_path / "bundle"
    bundle.assemble_bundle(
        bundle_dir=bundle_dir, cycle_output=cycle_output,
        action_registry=action_registry_epoch,
        witness_registry=witness_registry_epoch,
        admission_manifest=signed_admission_manifest,
        operator_public_key_b64=operator_kp.public_b64(),
        operator_key_id=operator_kp.key_id,
        witness_public_key_b64=witness_kp.public_b64(),
        witness_key_id=witness_kp.key_id,
    )
    cert = json.loads((bundle_dir / "certificate.json").read_text())

    # Per §13.1 a certificate MUST include these fields (or close MPF-named equivalents).
    for f in [
        "schema_version",
        "certificate_id",
        "certificate_digest",
        "issued_at",
        "pod_id",
        "action_id",
        "session_id",
        "verifier_profile_id",
        "outcome",
        "receipt_log",
        "registries",
        "admission",
        "witness_quorum",
        "evidence_mode",
        "warnings",
        "assurance",
    ]:
        assert f in cert, f"certificate missing required field {f!r}"

    # capability_token_enforced is in assurance per the §20.2 / observation profile.
    assert cert["assurance"]["capability_token_enforced"] is False

    # outcome.state for a successful observation should be 'verified'.
    assert cert["outcome"]["state"] == "verified"

    # The certificate_digest field is self-referential; the digest of the
    # certificate without that field should equal the value it carries.
    cert_no_digest = {k: v for k, v in cert.items() if k != "certificate_digest"}
    expected_digest = "sha256:" + canon.sha256_hex(canon.canonicalize(cert_no_digest))
    assert cert["certificate_digest"] == expected_digest


def test_certificate_digest_matches_bundle_result(
    tmp_path, cycle_output, action_registry_epoch, witness_registry_epoch,
    signed_admission_manifest, operator_kp, witness_kp,
):
    bundle_dir = tmp_path / "bundle"
    result = bundle.assemble_bundle(
        bundle_dir=bundle_dir, cycle_output=cycle_output,
        action_registry=action_registry_epoch,
        witness_registry=witness_registry_epoch,
        admission_manifest=signed_admission_manifest,
        operator_public_key_b64=operator_kp.public_b64(),
        operator_key_id=operator_kp.key_id,
        witness_public_key_b64=witness_kp.public_b64(),
        witness_key_id=witness_kp.key_id,
    )
    cert = json.loads((bundle_dir / "certificate.json").read_text())
    assert cert["certificate_digest"] == "sha256:" + result.certificate_digest_hex


def test_receipts_jsonl_one_per_line_canonical(
    tmp_path, cycle_output, action_registry_epoch, witness_registry_epoch,
    signed_admission_manifest, operator_kp, witness_kp,
):
    bundle_dir = tmp_path / "bundle"
    bundle.assemble_bundle(
        bundle_dir=bundle_dir, cycle_output=cycle_output,
        action_registry=action_registry_epoch,
        witness_registry=witness_registry_epoch,
        admission_manifest=signed_admission_manifest,
        operator_public_key_b64=operator_kp.public_b64(),
        operator_key_id=operator_kp.key_id,
        witness_public_key_b64=witness_kp.public_b64(),
        witness_key_id=witness_kp.key_id,
    )
    text = (bundle_dir / "receipts.jsonl").read_bytes()
    lines = [line for line in text.split(b"\n") if line]
    assert len(lines) == len(cycle_output.receipts)
    # Each line must be JCS-canonical of the corresponding receipt.
    for line, receipt in zip(lines, cycle_output.receipts):
        assert line == canon.canonicalize(receipt)


def test_observed_bytes_byte_exact(
    tmp_path, cycle_output, action_registry_epoch, witness_registry_epoch,
    signed_admission_manifest, operator_kp, witness_kp, fixture_bytes,
):
    bundle_dir = tmp_path / "bundle"
    bundle.assemble_bundle(
        bundle_dir=bundle_dir, cycle_output=cycle_output,
        action_registry=action_registry_epoch,
        witness_registry=witness_registry_epoch,
        admission_manifest=signed_admission_manifest,
        operator_public_key_b64=operator_kp.public_b64(),
        operator_key_id=operator_kp.key_id,
        witness_public_key_b64=witness_kp.public_b64(),
        witness_key_id=witness_kp.key_id,
    )
    on_disk = (bundle_dir / "observed-bytes.bin").read_bytes()
    assert on_disk == fixture_bytes
    # And the digest in the certificate's upstream.bytes_sha256 matches.
    cert = json.loads((bundle_dir / "certificate.json").read_text())
    assert cert["upstream"]["bytes_sha256"] == "sha256:" + hashlib.sha256(fixture_bytes).hexdigest()


def test_keyring_has_operator_and_witness(
    tmp_path, cycle_output, action_registry_epoch, witness_registry_epoch,
    signed_admission_manifest, operator_kp, witness_kp,
):
    bundle_dir = tmp_path / "bundle"
    bundle.assemble_bundle(
        bundle_dir=bundle_dir, cycle_output=cycle_output,
        action_registry=action_registry_epoch,
        witness_registry=witness_registry_epoch,
        admission_manifest=signed_admission_manifest,
        operator_public_key_b64=operator_kp.public_b64(),
        operator_key_id=operator_kp.key_id,
        witness_public_key_b64=witness_kp.public_b64(),
        witness_key_id=witness_kp.key_id,
    )
    keyring = json.loads((bundle_dir / "keyring.json").read_text())
    keys_by_role = {k["role"]: k for k in keyring["keys"]}
    assert "operator" in keys_by_role
    assert "witness_l1" in keys_by_role
    assert keys_by_role["operator"]["public_key"] == operator_kp.public_b64()
    assert keys_by_role["witness_l1"]["public_key"] == witness_kp.public_b64()


def test_bundle_manifest_digests_match_files(
    tmp_path, cycle_output, action_registry_epoch, witness_registry_epoch,
    signed_admission_manifest, operator_kp, witness_kp,
):
    """Every artifact's digest in bundle-manifest.json matches the file on disk."""
    bundle_dir = tmp_path / "bundle"
    bundle.assemble_bundle(
        bundle_dir=bundle_dir, cycle_output=cycle_output,
        action_registry=action_registry_epoch,
        witness_registry=witness_registry_epoch,
        admission_manifest=signed_admission_manifest,
        operator_public_key_b64=operator_kp.public_b64(),
        operator_key_id=operator_kp.key_id,
        witness_public_key_b64=witness_kp.public_b64(),
        witness_key_id=witness_kp.key_id,
    )
    manifest = json.loads((bundle_dir / "bundle-manifest.json").read_text())
    for rel_path, declared_digest in manifest["artifacts"].items():
        file_bytes = (bundle_dir / rel_path).read_bytes()
        actual = "sha256:" + hashlib.sha256(file_bytes).hexdigest()
        assert actual == declared_digest, (
            f"manifest digest mismatch for {rel_path}: "
            f"declared {declared_digest}, actual {actual}"
        )


def test_replay_guide_carries_independent_inputs(
    tmp_path, cycle_output, action_registry_epoch, witness_registry_epoch,
    signed_admission_manifest, operator_kp, witness_kp,
):
    bundle_dir = tmp_path / "bundle"
    bundle.assemble_bundle(
        bundle_dir=bundle_dir, cycle_output=cycle_output,
        action_registry=action_registry_epoch,
        witness_registry=witness_registry_epoch,
        admission_manifest=signed_admission_manifest,
        operator_public_key_b64=operator_kp.public_b64(),
        operator_key_id=operator_kp.key_id,
        witness_public_key_b64=witness_kp.public_b64(),
        witness_key_id=witness_kp.key_id,
    )
    replay = json.loads((bundle_dir / "replay.json").read_text())
    assert replay["source"]["url"] == "https://example.test/dashboard.json"
    assert replay["source"]["expected_bytes_sha256"].startswith("sha256:")
    assert replay["code"]["observer_digest"].startswith("sha256:")
    assert replay["code"]["validator_digest"].startswith("sha256:")
    assert replay["code"]["implementation_repo"] == "github.com/theforkproject-dev/mpf-pipeline-witness"
    assert len(replay["instructions"]) >= 5


def test_self_verification_records_chain_continuity(
    tmp_path, cycle_output, action_registry_epoch, witness_registry_epoch,
    signed_admission_manifest, operator_kp, witness_kp,
):
    bundle_dir = tmp_path / "bundle"
    bundle.assemble_bundle(
        bundle_dir=bundle_dir, cycle_output=cycle_output,
        action_registry=action_registry_epoch,
        witness_registry=witness_registry_epoch,
        admission_manifest=signed_admission_manifest,
        operator_public_key_b64=operator_kp.public_b64(),
        operator_key_id=operator_kp.key_id,
        witness_public_key_b64=witness_kp.public_b64(),
        witness_key_id=witness_kp.key_id,
    )
    ver = json.loads((bundle_dir / "verification.json").read_text())
    assert ver["self_check"]["all_receipts_chain_continuously"] is True
    assert ver["self_check"]["observed_bytes_digest_matches_subject"] is True
    assert ver["observation_succeeded"] is True
    assert ver["receipt_count"] == len(cycle_output.receipts)


def test_warnings_include_co_resident_disclosure(
    tmp_path, cycle_output, action_registry_epoch, witness_registry_epoch,
    signed_admission_manifest, operator_kp, witness_kp,
):
    """Per §13.1: certificates MUST carry warnings/taints/limitations explicitly.

    A co-resident witness is the §11.5 weakness this profile carries; it must
    be in the certificate's warnings list.
    """
    bundle_dir = tmp_path / "bundle"
    bundle.assemble_bundle(
        bundle_dir=bundle_dir, cycle_output=cycle_output,
        action_registry=action_registry_epoch,
        witness_registry=witness_registry_epoch,
        admission_manifest=signed_admission_manifest,
        operator_public_key_b64=operator_kp.public_b64(),
        operator_key_id=operator_kp.key_id,
        witness_public_key_b64=witness_kp.public_b64(),
        witness_key_id=witness_kp.key_id,
    )
    cert = json.loads((bundle_dir / "certificate.json").read_text())
    assert any("co-resident" in w.lower() for w in cert["warnings"])


def test_failure_path_bundle_outcome_state(
    tmp_path, operator_kp, witness, signed_admission_manifest,
    action_registry_epoch, witness_registry_epoch, witness_kp,
):
    """A failed cycle still produces a complete bundle, with outcome.state reflecting failure."""
    gw = Gateway(
        operator_key=operator_kp, witness=witness,
        source_url="https://example.test/dashboard.json",
    )
    # All retries fail.
    client = httpx.Client(transport=httpx.MockTransport(
        lambda req: httpx.Response(503)
    ))
    out = gw.run_cycle(
        admission_manifest=signed_admission_manifest, http_client=client,
    )
    assert out.observation_succeeded is False

    bundle_dir = tmp_path / "bundle"
    bundle.assemble_bundle(
        bundle_dir=bundle_dir, cycle_output=out,
        action_registry=action_registry_epoch,
        witness_registry=witness_registry_epoch,
        admission_manifest=signed_admission_manifest,
        operator_public_key_b64=operator_kp.public_b64(),
        operator_key_id=operator_kp.key_id,
        witness_public_key_b64=witness_kp.public_b64(),
        witness_key_id=witness_kp.key_id,
    )
    cert = json.loads((bundle_dir / "certificate.json").read_text())
    assert cert["outcome"]["state"] == "failed"
    assert cert["outcome"]["observation_outcome"] == "source_unavailable"
    # No observation-subject.json or observed-bytes.bin should exist on this path.
    assert not (bundle_dir / "observation-subject.json").exists()
    assert not (bundle_dir / "observed-bytes.bin").exists()
