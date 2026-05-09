"""
Certificate Bundle assembly for MPF v0.2 observation profiles.

Per MPF v0.2 §13: "The certificate is the summary. The bundle is the proof."

This module takes a `CycleOutput` from the gateway plus the bound registry
and admission artifacts and produces a complete certificate bundle on disk:

    bundle/
      certificate.json              # summary, JCS-canonicalized, digested
      receipts.jsonl                # one receipt per line, JCS-canonicalized
      keyring.json                  # operator + witness public keys
      action-registry.json          # the bound registry epoch
      witness-registry-epoch.json   # the bound witness registry epoch
      admission-manifest.json       # the bound admission manifest
      checkpoint.json               # extracted from the receipt chain
      observation-subject.json      # the witness-signed protocol subject
      observed-bytes.bin            # raw fetched bytes (evidence_mode=full)
      verification.json             # self-test result for human readability
      replay.json                   # independent-verifier reproduction guide
      bundle-manifest.json          # SHA-256 of every file in the bundle

Bundle layout choice — directory rather than tar.gz:

    The §13.2 list is a set of artifact filenames, not a packaging format.
    A directory layout is the simplest defensible choice: it preserves
    file mtimes for forensic review, lets verifiers fetch artifacts
    individually over HTTP, and avoids any ambiguity about archive
    format. Public hosting (Phase 7) can serve the directory directly
    via static file hosting. A future profile can specify an archive
    format if needed.

Per §13.1 (PR #4): "Bundle artifact digests for JSON artifacts ... are
computed over their JCS-canonicalized form. Non-JSON artifacts ... are
digested as-received." The bundle manifest enforces this distinction.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from . import canon, crypto, receipts


CERTIFICATE_SCHEMA = "mpf-0.2-certificate-v1"
BUNDLE_MANIFEST_SCHEMA = "mpf-0.2-bundle-manifest-v1"


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class BundleResult:
    """The output of bundle assembly.

    Attributes:
        bundle_dir: Path to the assembled bundle directory.
        certificate_digest_hex: SHA-256 of JCS(certificate.json).
        manifest_digest_hex: SHA-256 of JCS(bundle-manifest.json).
        artifact_digests: Mapping of relative-path -> sha256:<hex>.
    """

    bundle_dir: Path
    certificate_digest_hex: str
    manifest_digest_hex: str
    artifact_digests: dict[str, str]


def _write_json(path: Path, obj: Mapping[str, Any]) -> bytes:
    """Write `obj` as JCS-canonicalized JSON. Returns the bytes written."""
    canonical = canon.canonicalize(obj)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical)
    return canonical


def _write_jsonl(path: Path, items: list[Mapping[str, Any]]) -> bytes:
    """Write each item as one JCS-canonicalized JSON line. Returns the full bytes."""
    lines = []
    for item in items:
        lines.append(canon.canonicalize(item))
    body = b"\n".join(lines) + (b"\n" if lines else b"")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    return body


def _digest_file_bytes(b: bytes) -> str:
    """SHA-256 of bytes as `sha256:<hex>` for bundle-manifest entries."""
    return "sha256:" + canon.sha256_hex(b)


def assemble_bundle(
    *,
    bundle_dir: Path | str,
    cycle_output,  # CycleOutput; avoid circular import
    action_registry: Mapping[str, Any],
    witness_registry: Mapping[str, Any],
    admission_manifest: Mapping[str, Any],
    operator_public_key_b64: str,
    operator_key_id: str,
    witness_public_key_b64: str,
    witness_key_id: str,
    verifier_profile_id: str = "mpf.profile.observation.external-pipeline.v0.2-fork",
    pod_id: str = "urn:mpf:pod:fork-node-01:pipeline-witness",
) -> BundleResult:
    """Assemble a complete v0.2 certificate bundle from a cycle output.

    Args:
        bundle_dir: Directory to write the bundle into. Created if missing.
        cycle_output: The `CycleOutput` from `Gateway.run_cycle`.
        action_registry: The signed Action Registry epoch.
        witness_registry: The signed Witness Registry epoch.
        admission_manifest: The signed Admission Manifest.
        operator_public_key_b64: Operator public key (`ed25519:<b64>`).
        operator_key_id: Operator key ID matching the signing key.
        witness_public_key_b64: Witness public key (`ed25519:<b64>`).
        witness_key_id: Witness key ID.
        verifier_profile_id: Profile this bundle conforms to.
        pod_id: Stable identifier for the pod producing the bundle.

    Returns:
        A `BundleResult` describing the assembled bundle.
    """
    bundle_path = Path(bundle_dir)
    bundle_path.mkdir(parents=True, exist_ok=True)

    artifact_bytes: dict[str, bytes] = {}

    # --- 1. receipts.jsonl ---------------------------------------------------
    receipts_bytes = _write_jsonl(
        bundle_path / "receipts.jsonl", list(cycle_output.receipts)
    )
    artifact_bytes["receipts.jsonl"] = receipts_bytes

    # --- 2. keyring.json -----------------------------------------------------
    keyring = {
        "schema_version": "mpf-0.2-keyring-v1",
        "keys": [
            {
                "key_id": operator_key_id,
                "role": "operator",
                "algorithm": "ed25519",
                "public_key": operator_public_key_b64,
            },
            {
                "key_id": witness_key_id,
                "role": "witness_l1",
                "algorithm": "ed25519",
                "public_key": witness_public_key_b64,
            },
        ],
    }
    artifact_bytes["keyring.json"] = _write_json(
        bundle_path / "keyring.json", keyring,
    )

    # --- 3. action-registry.json --------------------------------------------
    artifact_bytes["action-registry.json"] = _write_json(
        bundle_path / "action-registry.json", action_registry,
    )

    # --- 4. witness-registry-epoch.json -------------------------------------
    artifact_bytes["witness-registry-epoch.json"] = _write_json(
        bundle_path / "witness-registry-epoch.json", witness_registry,
    )

    # --- 5. admission-manifest.json -----------------------------------------
    artifact_bytes["admission-manifest.json"] = _write_json(
        bundle_path / "admission-manifest.json", admission_manifest,
    )

    # --- 6. checkpoint.json --------------------------------------------------
    checkpoint_receipt = next(
        (r for r in cycle_output.receipts if r["receipt_kind"] == "checkpoint"),
        None,
    )
    if checkpoint_receipt is None:
        raise ValueError("cycle_output contains no checkpoint receipt")
    artifact_bytes["checkpoint.json"] = _write_json(
        bundle_path / "checkpoint.json", checkpoint_receipt,
    )

    # --- 7. observation-subject.json (the witness-signed protocol subject) -
    if cycle_output.observation_subject is not None:
        artifact_bytes["observation-subject.json"] = _write_json(
            bundle_path / "observation-subject.json",
            cycle_output.observation_subject,
        )

    # --- 8. observed-bytes.bin (raw evidence, evidence_mode=full) ----------
    if cycle_output.observed_bytes is not None:
        bytes_path = bundle_path / "observed-bytes.bin"
        bytes_path.write_bytes(cycle_output.observed_bytes)
        artifact_bytes["observed-bytes.bin"] = cycle_output.observed_bytes

    # --- 9. certificate.json (the summary; computed and self-digested) -----
    certificate = build_certificate(
        cycle_output=cycle_output,
        action_registry=action_registry,
        witness_registry=witness_registry,
        admission_manifest=admission_manifest,
        verifier_profile_id=verifier_profile_id,
        pod_id=pod_id,
        operator_key_id=operator_key_id,
        witness_key_id=witness_key_id,
    )
    cert_canonical = canon.canonicalize(certificate)
    cert_digest_hex = canon.sha256_hex(cert_canonical)
    # The certificate carries its own digest as a self-reference field; we
    # populate it AFTER computing the digest of the rest of the certificate.
    certificate_with_digest = {
        **certificate,
        "certificate_digest": "sha256:" + cert_digest_hex,
    }
    artifact_bytes["certificate.json"] = _write_json(
        bundle_path / "certificate.json", certificate_with_digest,
    )

    # --- 10. verification.json (self-test for human readability) -----------
    verification = build_self_verification(
        cycle_output=cycle_output,
        certificate_digest_hex=cert_digest_hex,
        artifact_byte_count=sum(len(v) for v in artifact_bytes.values()),
    )
    artifact_bytes["verification.json"] = _write_json(
        bundle_path / "verification.json", verification,
    )

    # --- 11. replay.json (independent-verifier reproduction guide) ---------
    replay = build_replay_guide(
        cycle_output=cycle_output,
        action_registry=action_registry,
        witness_registry=witness_registry,
        admission_manifest=admission_manifest,
        verifier_profile_id=verifier_profile_id,
    )
    artifact_bytes["replay.json"] = _write_json(
        bundle_path / "replay.json", replay,
    )

    # --- 12. bundle-manifest.json (digests of every artifact above) --------
    # Per §13.1 (PR #4): JSON artifacts are digested over their JCS-canonical
    # form (which is what we wrote). Non-JSON artifacts are digested
    # as-received. The bytes we have in `artifact_bytes` are exactly what
    # was written, so file_digest_hex(bytes) is the canonical digest.
    artifact_digests = {
        rel_path: _digest_file_bytes(b)
        for rel_path, b in artifact_bytes.items()
    }
    bundle_manifest = {
        "schema_version": BUNDLE_MANIFEST_SCHEMA,
        "bundle_id": cycle_output.session_id,
        "verifier_profile_id": verifier_profile_id,
        "pod_id": pod_id,
        "assembled_at": _utcnow_iso(),
        "artifacts": artifact_digests,
        "head_state_root": "sha256:" + cycle_output.head_state_root_hex,
    }
    manifest_canonical = canon.canonicalize(bundle_manifest)
    manifest_digest_hex = canon.sha256_hex(manifest_canonical)
    bundle_manifest_with_digest = {
        **bundle_manifest,
        "manifest_digest": "sha256:" + manifest_digest_hex,
    }
    (bundle_path / "bundle-manifest.json").write_bytes(
        canon.canonicalize(bundle_manifest_with_digest)
    )

    return BundleResult(
        bundle_dir=bundle_path,
        certificate_digest_hex=cert_digest_hex,
        manifest_digest_hex=manifest_digest_hex,
        artifact_digests=artifact_digests,
    )


def build_certificate(
    *,
    cycle_output,
    action_registry: Mapping[str, Any],
    witness_registry: Mapping[str, Any],
    admission_manifest: Mapping[str, Any],
    verifier_profile_id: str,
    pod_id: str,
    operator_key_id: str,
    witness_key_id: str,
) -> dict[str, Any]:
    """Build the certificate summary per §13.1 required fields.

    Returns the certificate WITHOUT its self-referential `certificate_digest`
    field. The caller computes the digest over this object and adds the
    digest field afterward.
    """
    # Outcome state per §13.4 / §14.3.
    if cycle_output.observation_succeeded:
        outcome_state = "verified"
        observation_outcome = "success"
    else:
        # Distinguish the failure modes we can produce.
        kinds = [r["receipt_kind"] for r in cycle_output.receipts]
        if "source.unavailable" in kinds:
            outcome_state = "failed"
            observation_outcome = "source_unavailable"
        elif "validator.exception" in kinds:
            outcome_state = "failed"
            observation_outcome = "validator_exception"
        elif "validation.failed" in kinds:
            outcome_state = "verified_denial"
            observation_outcome = "validation_failed"
        else:
            outcome_state = "failed"
            observation_outcome = "unknown"

    # Receipt log digest = SHA-256 of the receipts.jsonl bytes we'll write.
    # Recompute here so the certificate's receipt_log_digest matches what
    # the bundle_manifest will record.
    receipts_jsonl_bytes = b"\n".join(
        canon.canonicalize(r) for r in cycle_output.receipts
    ) + (b"\n" if cycle_output.receipts else b"")
    receipt_log_digest_hex = canon.sha256_hex(receipts_jsonl_bytes)

    return {
        "schema_version": CERTIFICATE_SCHEMA,
        "certificate_id": f"cert:{cycle_output.session_id}",
        "issued_at": _utcnow_iso(),
        "pod_id": pod_id,
        "action_id": "pipeline.snapshot.observe.v1",
        "session_id": cycle_output.session_id,
        "verifier_profile_id": verifier_profile_id,
        "assurance": {
            "mode": "observed_l1",
            "capability_token_enforced": False,
            "L1_witness_threshold": 1,
            "L2_witness_required": False,
            "L3_witness_required": False,
        },
        "outcome": {
            "state": outcome_state,
            "observation_outcome": observation_outcome,
            "observation_succeeded": cycle_output.observation_succeeded,
        },
        "upstream": {
            "system_identity": "external_pipeline:ews-kylemcdonald-business-jet-v1",
            "source_url": admission_manifest["source"]["url"],
            "pipeline_identity": dict(admission_manifest["source"]["pipeline_identity"]),
            "observed_timestamp": (
                cycle_output.observation_subject["observed_timestamp"]
                if cycle_output.observation_subject else None
            ),
            "bytes_sha256": (
                "sha256:" + cycle_output.observed_bytes_sha256_hex
                if cycle_output.observed_bytes_sha256_hex else None
            ),
        },
        "registries": {
            "action_registry": {
                "epoch_id": action_registry["epoch_id"],
                "epoch_digest": action_registry["payload_digest"],
            },
            "witness_registry": {
                "epoch_id": witness_registry["epoch_id"],
                "epoch_digest": witness_registry["payload_digest"],
            },
        },
        "admission": {
            "manifest_digest": admission_manifest["payload_digest"],
        },
        "receipt_log": {
            "receipt_count": len(cycle_output.receipts),
            "head_state_root": "sha256:" + cycle_output.head_state_root_hex,
            "receipt_log_digest": "sha256:" + receipt_log_digest_hex,
        },
        "witness_quorum": {
            "L1_witnesses_required": 1,
            "L1_witnesses_present": 1 if cycle_output.observation_subject else 0,
            "witness_key_ids": [witness_key_id]
                if cycle_output.observation_subject else [],
        },
        "evidence_mode": "full",
        "warnings": _build_warnings(cycle_output),
        "operator_key_id": operator_key_id,
    }


def _build_warnings(cycle_output) -> list[str]:
    """Per §13.1, certificates carry warnings/taints/limitations explicitly."""
    warnings = []
    # Always-on warning: this profile is co-resident, not cross-boundary.
    warnings.append(
        "co-resident L1 witness: operator independence is not claimed (§11.5); "
        "verify under the profile's documented independence_class"
    )
    if not cycle_output.observation_succeeded:
        warnings.append(
            f"observation did not succeed: see receipts.jsonl for the failure-mode "
            f"receipt and validation details"
        )
    return warnings


def build_self_verification(
    *,
    cycle_output,
    certificate_digest_hex: str,
    artifact_byte_count: int,
) -> dict[str, Any]:
    """A small human-readable self-test summary embedded in the bundle."""
    return {
        "schema_version": "mpf-0.2-verification-v1",
        "session_id": cycle_output.session_id,
        "certificate_digest": "sha256:" + certificate_digest_hex,
        "head_state_root": "sha256:" + cycle_output.head_state_root_hex,
        "receipt_count": len(cycle_output.receipts),
        "receipt_kinds": [r["receipt_kind"] for r in cycle_output.receipts],
        "observation_succeeded": cycle_output.observation_succeeded,
        "artifact_byte_count": artifact_byte_count,
        "self_check": {
            "all_receipts_chain_continuously": _check_chain_continuity(
                list(cycle_output.receipts)
            ),
            "observed_bytes_digest_matches_subject": _check_observation_subject(
                cycle_output
            ),
        },
        "verified_at": _utcnow_iso(),
        "note": (
            "This is a self-test for human readability. An independent verifier "
            "MUST recompute every digest, signature, and state root from the "
            "raw bundle artifacts; do not rely on this file for verification."
        ),
    }


def _check_chain_continuity(receipt_list: list[Mapping[str, Any]]) -> bool:
    if not receipt_list:
        return False
    expected_prev = receipts.GENESIS_STATE_ROOT.hex()
    for r in receipt_list:
        if r["previous_state_root"] != expected_prev:
            return False
        expected_prev = r["state_root"]
    return True


def _check_observation_subject(cycle_output) -> bool:
    if cycle_output.observation_subject is None:
        return cycle_output.observed_bytes_sha256_hex is None
    expected_digest = "sha256:" + (cycle_output.observed_bytes_sha256_hex or "")
    return cycle_output.observation_subject["bytes_sha256"] == expected_digest


def build_replay_guide(
    *,
    cycle_output,
    action_registry: Mapping[str, Any],
    witness_registry: Mapping[str, Any],
    admission_manifest: Mapping[str, Any],
    verifier_profile_id: str,
) -> dict[str, Any]:
    """Instructions for an independent verifier to reproduce the bundle's claims.

    Per BUILD_PLAN §6 open question #4, the spec doesn't fully specify what
    `replay.json` contains. This implementation includes the source URL, the
    code digests, the registry references, and the expected observation
    digest — enough that an independent verifier with the same code at the
    bound git commit can re-derive each digest from public inputs.
    """
    code = admission_manifest.get("code", {})
    source = admission_manifest.get("source", {})
    return {
        "schema_version": "mpf-0.2-replay-v1",
        "session_id": cycle_output.session_id,
        "verifier_profile_id": verifier_profile_id,
        "source": {
            "url": source.get("url"),
            "expected_bytes_sha256": (
                "sha256:" + cycle_output.observed_bytes_sha256_hex
                if cycle_output.observed_bytes_sha256_hex else None
            ),
            "pipeline_identity": source.get("pipeline_identity", {}),
        },
        "code": {
            "observer_digest": code.get("observer_digest"),
            "validator_digest": code.get("validator_digest"),
            "git_commit": code.get("git_commit"),
            "implementation_repo": "github.com/theforkproject-dev/mpf-pipeline-witness",
        },
        "registries": {
            "action_registry_epoch_id": action_registry["epoch_id"],
            "action_registry_epoch_digest": action_registry["payload_digest"],
            "witness_registry_epoch_id": witness_registry["epoch_id"],
            "witness_registry_epoch_digest": witness_registry["payload_digest"],
        },
        "admission_manifest_digest": admission_manifest["payload_digest"],
        "expected_head_state_root": "sha256:" + cycle_output.head_state_root_hex,
        "instructions": [
            "1. Fetch the source URL.",
            "2. Compute SHA-256 of the response bytes; compare to source.expected_bytes_sha256.",
            "3. Check out the implementation repo at the bound git_commit.",
            "4. Compute SHA-256 of src/witness/observer.py; compare to code.observer_digest.",
            "5. Compute SHA-256 of src/witness/validator.py; compare to code.validator_digest.",
            "6. Run the validator against the parsed bytes; confirm the same checks pass.",
            "7. Reconstruct the observation subject from the receipt body and verify the witness signature.",
            "8. Recompute every receipt's state root from previous_state_root, payload digest, and signature_set.",
            "9. Confirm the chain head matches expected_head_state_root.",
        ],
    }
