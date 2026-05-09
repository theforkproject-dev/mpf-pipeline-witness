"""
Admission Manifest construction for MPF v0.2 observation profiles.

Per MPF v0.2 §3.14, the Admission Manifest is "a signed declaration binding a
certified session to operator identity, tenant/workflow scope, active action
surface, policy digest, verifier profile, runtime/config evidence, and MCP or
API authorization context."

For observation profiles (§3.14 + §9.4.1, both as updated by PRs #2 and #4),
the manifest additionally binds:

  - observer code digest
  - validator code digest
  - source URL
  - cadence
  - expected schema (or schema digest)
  - pipeline identity

Per §9.4.1: "There is no agent-intent layer in observation profiles; the
manifest plus the cadence declaration is the equivalent admission evidence."

The manifest is computed once per session (one observation cycle) and signed
by the operator key. Its digest is bound into the certificate bundle as
admission evidence and into the receipt log as part of the session.start
receipt body.

Code digests are SHA-256 over the source file bytes pinned to a specific git
commit. This is the simplest defensible identification per BUILD_PLAN §8
("validator code = SHA-256 of validator.py source bytes, pinned to git commit").
For higher assurance, future profiles could require image digests, WASM
digests, or reproducible build attestations.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from . import canon, crypto, receipts

ADMISSION_MANIFEST_SCHEMA = "mpf-0.2-admission-manifest-v1"


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def file_sha256_hex(path: Path) -> str:
    """SHA-256 of the file at `path`, returned as 64-char lowercase hex.

    Used to compute observer/validator code digests. Caller is responsible for
    ensuring the file represents the actual code that will run during the
    observation cycle.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_admission_manifest(
    *,
    session_id: str,
    operator_id: str,
    operator_key_id: str,
    workflow_id: str,
    action_id: str,
    verifier_profile_id: str,
    action_registry_epoch_id: str,
    action_registry_epoch_digest: str,
    witness_registry_epoch_id: str,
    witness_registry_epoch_digest: str,
    observer_code_digest: str,
    validator_code_digest: str,
    source_url: str,
    cadence_seconds: int,
    expected_schema_digest: str | None,
    pipeline_identity: Mapping[str, Any],
    git_commit: str | None = None,
    issued_at: str | None = None,
) -> dict[str, Any]:
    """Build an unsigned Admission Manifest payload.

    Args:
        session_id: The MPF session identifier this manifest binds.
        operator_id: Stable operator identifier (e.g., "operator:fork-node-01").
        operator_key_id: Key ID of the operator's signing key.
        workflow_id: Workflow scope (e.g., "observation.ews-business-jets").
        action_id: Action being admitted (e.g., "pipeline.snapshot.observe.v1").
        verifier_profile_id: Profile this session conforms to.
        action_registry_epoch_id: Epoch_id of the bound Action Registry.
        action_registry_epoch_digest: Payload digest of the registry (sha256:<hex>).
        witness_registry_epoch_id: Epoch_id of the bound Witness Registry.
        witness_registry_epoch_digest: Payload digest of the witness registry.
        observer_code_digest: sha256:<hex> of observer module source.
        validator_code_digest: sha256:<hex> of validator module source.
        source_url: The URL the observer fetches.
        cadence_seconds: Declared poll interval.
        expected_schema_digest: Optional sha256:<hex> of the expected upstream schema.
        pipeline_identity: Free-form identity of the observed upstream
            (e.g., {"repo": "github.com/kylemcdonald/ews", "commit": null,
            "operator": "kylemcdonald"}).
        git_commit: Optional git commit pinning observer/validator code.
        issued_at: Optional ISO-8601 timestamp; defaults to now.

    Returns:
        The unsigned manifest payload. Pass to `sign_admission_manifest` to
        produce the complete signed artifact.
    """
    return {
        "schema_version": ADMISSION_MANIFEST_SCHEMA,
        "session_id": session_id,
        "operator": {
            "operator_id": operator_id,
            "operator_key_id": operator_key_id,
        },
        "workflow": {
            "workflow_id": workflow_id,
            "action_id": action_id,
        },
        "verifier_profile_id": verifier_profile_id,
        "registries": {
            "action_registry": {
                "epoch_id": action_registry_epoch_id,
                "epoch_digest": action_registry_epoch_digest,
            },
            "witness_registry": {
                "epoch_id": witness_registry_epoch_id,
                "epoch_digest": witness_registry_epoch_digest,
            },
        },
        "code": {
            "observer_digest": observer_code_digest,
            "validator_digest": validator_code_digest,
            "git_commit": git_commit,
        },
        "source": {
            "url": source_url,
            "cadence_seconds": cadence_seconds,
            "expected_schema_digest": expected_schema_digest,
            "pipeline_identity": dict(pipeline_identity),
        },
        # Per §9.4.1: observation profiles MUST NOT require intent.attested.
        "intent_layer": "none",
        "issued_at": issued_at or _utcnow_iso(),
    }


def sign_admission_manifest(
    *,
    payload: Mapping[str, Any],
    signer: crypto.KeyPair,
) -> dict[str, Any]:
    """Sign an Admission Manifest payload with the operator key.

    Returns the manifest with `payload_digest` and `signature_set` appended.
    """
    digest_hex = canon.digest_hex(payload)
    canonical_bytes = canon.canonicalize(payload)
    sig_set = receipts.canonical_signature_set(
        {signer.key_id: signer.sign_b64(canonical_bytes)}
    )
    return {
        **payload,
        "payload_digest": "sha256:" + digest_hex,
        "signature_set": sig_set,
    }


def verify_admission_manifest(
    *,
    manifest: Mapping[str, Any],
    operator_pubkey: str,
) -> tuple[bool, list[str]]:
    """Verify an Admission Manifest's digest and signature.

    Validity window checks are not performed here; the manifest's authority
    derives from the bound registries and the session it admits, not from a
    standalone validity window.

    Args:
        manifest: A complete signed manifest object.
        operator_pubkey: The operator public key (ed25519:<b64>) the caller
            chooses to trust.

    Returns:
        (ok, errors).
    """
    errors: list[str] = []

    payload = {
        k: v for k, v in manifest.items()
        if k not in {"payload_digest", "signature_set"}
    }

    # Required §3.14 + §9.4.1 fields.
    required_top = {
        "schema_version", "session_id", "operator", "workflow",
        "verifier_profile_id", "registries", "code", "source",
        "intent_layer", "issued_at",
    }
    missing = required_top - set(payload)
    if missing:
        errors.append(f"missing required fields: {sorted(missing)}")
        return False, errors

    # Observation profiles MUST NOT have an intent layer (§9.4.1).
    if payload["intent_layer"] != "none":
        errors.append(
            f"observation profile must declare intent_layer='none', got "
            f"{payload['intent_layer']!r}"
        )

    # Code identity.
    code = payload["code"]
    for k in ("observer_digest", "validator_digest"):
        if k not in code or not isinstance(code[k], str):
            errors.append(f"missing or invalid code.{k}")

    # Source binding.
    source = payload["source"]
    for k in ("url", "cadence_seconds", "pipeline_identity"):
        if k not in source:
            errors.append(f"missing source.{k}")

    # Payload digest.
    expected_digest = "sha256:" + canon.digest_hex(payload)
    if manifest.get("payload_digest") != expected_digest:
        errors.append(
            f"payload_digest mismatch: manifest={manifest.get('payload_digest')} "
            f"recomputed={expected_digest}"
        )

    # Signature.
    sig_set = manifest.get("signature_set")
    if not isinstance(sig_set, dict) or not sig_set:
        errors.append("missing or empty signature_set")
        return False, errors

    canonical_bytes = canon.canonicalize(payload)
    operator_key_id = payload["operator"].get("operator_key_id")
    if operator_key_id not in sig_set:
        errors.append(f"signature for operator_key_id {operator_key_id!r} not present")
    else:
        if not crypto.verify_signature(operator_pubkey, canonical_bytes, sig_set[operator_key_id]):
            errors.append(f"signature for {operator_key_id!r} failed verification")

    return (len(errors) == 0), errors
