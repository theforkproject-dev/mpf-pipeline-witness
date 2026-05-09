"""
Action Registry and Witness Registry construction for MPF v0.2.

This module produces the two registry artifacts an observation profile needs:

  - Action Registry Epoch (§8.1) declaring the action `pipeline.snapshot.observe.v1`
  - Witness Registry Epoch (§11.4) authorizing the L1 witness public key

Each registry is a signed JSON object with:

  - schema version
  - registry ID (stable, per implementation)
  - epoch ID (per-epoch, monotonically increasing)
  - validity window (issued_at, expires_at)
  - body (action entries or witness entries, profile-specific)
  - canonical digest (SHA-256 of JCS(body))
  - signature(s) by the operator key over JCS(payload)

The operator key signs both registries directly. In a future cross-boundary
deployment, registry signing keys would be distinct from the operator's
day-to-day key and rotated independently; for the MVP `observed-l1` profile
that's out of scope.

Verification of a registry is independent of the receipt log: any party with
the operator's public key can fetch the registry artifact and confirm the
canonical digest, validity window, signatures, and entry contents.

Both registries reference an "epoch_id" of the form `<registry_id>:<epoch_n>`
where `epoch_n` is a monotonic small integer starting at 1 (genesis = 1).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from . import canon, crypto, receipts

# --- Schema versions ---------------------------------------------------------

ACTION_REGISTRY_SCHEMA = "mpf-0.2-action-registry-v1"
WITNESS_REGISTRY_SCHEMA = "mpf-0.2-witness-registry-v1"


# --- Action Registry ---------------------------------------------------------

# Profile this implementation conforms to (see profiles/*.json).
DEFAULT_VERIFIER_PROFILE_ID = "mpf.profile.observation.external-pipeline.v0.2-fork"

# The single action this implementation registers. Per MPF v0.2 §8.2 each
# action entry needs a stable action_id, schemas, adapter target, assurance
# mode, capability-token requirement, witness requirements, evidence mode, and
# verifier profile binding.
PIPELINE_OBSERVE_ACTION_ENTRY = {
    "action_id": "pipeline.snapshot.observe.v1",
    "title": "Observe a published deterministic-pipeline snapshot",
    "description": (
        "Fetch a single periodically-refreshed public artifact at its declared "
        "cadence, commit to its bytes, validate declared deterministic invariants, "
        "and emit a witnessed observation receipt. The certificate certifies the "
        "observation, not the upstream pipeline's execution."
    ),
    "input_schema_ref": "schema://mpf-pipeline-witness/observe-snapshot/input/v1",
    "output_schema_ref": "schema://mpf-pipeline-witness/observe-snapshot/output/v1",
    "adapter": {
        "type": "external_pipeline_observation",
        "audience": "observer:mpf-pipeline-witness",
        "method": "GET",
    },
    "actor_type": "external_pipeline",
    "assurance": {
        "mode": "observed_l1",
        "capability_token_enforced": False,
        "mechanical_witness_threshold": 1,
        "policy_witness_required": False,
        "domain_attestation_required": False,
    },
    "evidence_mode": "full",
    "verifier_profile_id": DEFAULT_VERIFIER_PROFILE_ID,
    "registered_failure_modes": [
        "source.unavailable",
        "validation.failed",
        "validator.exception",
        "bytes.changed_in_interval",
    ],
}


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sign_registry(
    *,
    payload: Mapping[str, Any],
    signer: crypto.KeyPair,
) -> dict[str, Any]:
    """Sign a registry payload with the operator key.

    Returns the payload with `signature_set` and `payload_digest` fields
    appended (both derived). The payload itself is unchanged so the digest
    remains recomputable from a signature-stripped copy.
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


def build_action_registry_epoch(
    *,
    registry_id: str,
    epoch_number: int,
    validity_seconds: int,
    operator_key: crypto.KeyPair,
    extra_actions: list[Mapping[str, Any]] | None = None,
    issued_at: str | None = None,
) -> dict[str, Any]:
    """Build and sign an Action Registry Epoch declaring this implementation's actions.

    Args:
        registry_id: Stable identifier (e.g., "registry:fork-pipeline-witness").
        epoch_number: Monotonic per-epoch integer; genesis epoch is 1.
        validity_seconds: Epoch lifetime; verifiers must reject signatures
            outside the validity window.
        operator_key: The operator key that signs the registry.
        extra_actions: Optional additional action entries beyond the default
            pipeline.snapshot.observe.v1 entry.
        issued_at: Optional ISO-8601 timestamp; defaults to now.

    Returns:
        The complete registry epoch object (payload + payload_digest + signature_set).
    """
    issued = issued_at or utcnow_iso()
    issued_dt = datetime.fromisoformat(issued.replace("Z", "+00:00"))
    expires_dt = issued_dt.replace(microsecond=0) + _seconds_to_timedelta(validity_seconds)
    expires = expires_dt.isoformat().replace("+00:00", "Z")

    actions = [PIPELINE_OBSERVE_ACTION_ENTRY] + list(extra_actions or [])

    payload = {
        "schema_version": ACTION_REGISTRY_SCHEMA,
        "registry_id": registry_id,
        "epoch_id": f"{registry_id}:epoch-{epoch_number}",
        "epoch_number": epoch_number,
        "issued_at": issued,
        "expires_at": expires,
        "operator": {
            "operator_id": "operator:fork-node-01",
            "operator_key_id": operator_key.key_id,
        },
        "actions": actions,
        "verifier_profile_default": DEFAULT_VERIFIER_PROFILE_ID,
    }
    return _sign_registry(payload=payload, signer=operator_key)


# --- Witness Registry --------------------------------------------------------


def build_witness_registry_epoch(
    *,
    registry_id: str,
    epoch_number: int,
    validity_seconds: int,
    operator_key: crypto.KeyPair,
    witness_entries: list[Mapping[str, Any]],
    issued_at: str | None = None,
) -> dict[str, Any]:
    """Build and sign a Witness Registry Epoch authorizing one or more witness keys.

    Each entry in `witness_entries` MUST include (per §11.4):

      - witness_id
      - key_id
      - public_key (ed25519:<b64>)
      - tier (one of "L1", "L2", "L3")
      - operator_id (the party operating the witness)

    Optional fields per profile:

      - independence_class (e.g., "co-resident", "administratively-independent")
      - operator_role (e.g., "self", "third-party")

    Args:
        registry_id: Stable identifier (e.g., "registry:fork-witness-registry").
        epoch_number: Monotonic per-epoch integer; genesis is 1.
        validity_seconds: Epoch lifetime.
        operator_key: The operator key that signs the registry.
        witness_entries: One or more witness records.
        issued_at: Optional ISO-8601 timestamp; defaults to now.

    Returns:
        The complete registry epoch object.
    """
    if not witness_entries:
        raise ValueError("witness registry must include at least one witness entry")

    required = {"witness_id", "key_id", "public_key", "tier", "operator_id"}
    for i, entry in enumerate(witness_entries):
        missing = required - set(entry)
        if missing:
            raise ValueError(
                f"witness entry {i} missing required fields: {sorted(missing)}"
            )
        if entry["tier"] not in {"L1", "L2", "L3"}:
            raise ValueError(
                f"witness entry {i} has invalid tier {entry['tier']!r}; "
                f"must be one of L1, L2, L3"
            )

    issued = issued_at or utcnow_iso()
    issued_dt = datetime.fromisoformat(issued.replace("Z", "+00:00"))
    expires_dt = issued_dt.replace(microsecond=0) + _seconds_to_timedelta(validity_seconds)
    expires = expires_dt.isoformat().replace("+00:00", "Z")

    # Sort entries by witness_id so the registry digest is deterministic.
    entries = [dict(e) for e in sorted(witness_entries, key=lambda e: e["witness_id"])]

    payload = {
        "schema_version": WITNESS_REGISTRY_SCHEMA,
        "registry_id": registry_id,
        "epoch_id": f"{registry_id}:epoch-{epoch_number}",
        "epoch_number": epoch_number,
        "issued_at": issued,
        "expires_at": expires,
        "operator": {
            "operator_id": "operator:fork-node-01",
            "operator_key_id": operator_key.key_id,
        },
        "witnesses": entries,
    }
    return _sign_registry(payload=payload, signer=operator_key)


# --- Verification ------------------------------------------------------------


def verify_registry(
    *,
    registry: Mapping[str, Any],
    operator_pubkey: str,
    verification_time: str | None = None,
) -> tuple[bool, list[str]]:
    """Verify a registry epoch's signature, digest, and validity window.

    Args:
        registry: A complete registry object as produced by `build_*_registry_epoch`.
        operator_pubkey: Operator public key (ed25519:<b64>) authorized to sign
            this registry. Trust roots are out of scope; the caller chooses
            which key to trust.
        verification_time: Optional ISO-8601 timestamp at which the registry
            should be valid. Defaults to now. Pass an explicit time to verify
            historically.

    Returns:
        (ok, errors) where ok is True iff every check passed.
    """
    errors: list[str] = []

    payload = {
        k: v for k, v in registry.items()
        if k not in {"signature_set", "payload_digest"}
    }

    # Schema and required envelope fields.
    if "schema_version" not in payload:
        errors.append("missing schema_version")
        return False, errors
    if "epoch_id" not in payload or "issued_at" not in payload or "expires_at" not in payload:
        errors.append("missing epoch envelope fields (epoch_id, issued_at, expires_at)")
        return False, errors

    # Validity window.
    vt = verification_time or utcnow_iso()
    try:
        vt_dt = datetime.fromisoformat(vt.replace("Z", "+00:00"))
        issued_dt = datetime.fromisoformat(payload["issued_at"].replace("Z", "+00:00"))
        expires_dt = datetime.fromisoformat(payload["expires_at"].replace("Z", "+00:00"))
    except ValueError as e:
        errors.append(f"timestamp parse error: {e}")
        return False, errors
    if vt_dt < issued_dt:
        errors.append(f"verification_time {vt} is before issued_at {payload['issued_at']}")
    if vt_dt > expires_dt:
        errors.append(f"verification_time {vt} is after expires_at {payload['expires_at']}")

    # Payload digest.
    expected_digest = "sha256:" + canon.digest_hex(payload)
    if registry.get("payload_digest") != expected_digest:
        errors.append(
            f"payload_digest mismatch: registry={registry.get('payload_digest')} "
            f"recomputed={expected_digest}"
        )

    # Signature.
    sig_set = registry.get("signature_set")
    if not isinstance(sig_set, dict) or not sig_set:
        errors.append("missing or empty signature_set")
        return False, errors

    canonical_bytes = canon.canonicalize(payload)
    operator_key_id = payload.get("operator", {}).get("operator_key_id")
    if operator_key_id not in sig_set:
        errors.append(
            f"signature for operator_key_id {operator_key_id!r} not present in signature_set"
        )
    else:
        if not crypto.verify_signature(operator_pubkey, canonical_bytes, sig_set[operator_key_id]):
            errors.append(f"signature for {operator_key_id!r} failed verification")

    return (len(errors) == 0), errors


# --- Helpers -----------------------------------------------------------------


def _seconds_to_timedelta(seconds: int):
    """Avoid importing timedelta at module top to keep the import surface small."""
    from datetime import timedelta
    return timedelta(seconds=seconds)
