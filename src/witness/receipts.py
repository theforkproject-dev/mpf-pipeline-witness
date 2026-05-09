"""
Receipt construction and state-root chain for MPF v0.2.

Per MPF v0.2 §10.1, each receipt MUST include:

    - schema version
    - receipt kind
    - session ID or operation ID
    - sequence or step index
    - previous state root
    - actor
    - body
    - issued timestamp
    - signature set
    - resulting state root

Per §10.3, the receipt state root MUST be recomputable from the previous
state root, receipt payload digest, and receipt signatures under the
declared canonicalization profile. For baseline `mpf-0.2` conformance, the
receipt payload digest is computed over the JCS-canonicalized receipt JSON
per §2.9.

The spec leaves the *combination function* unspecified. This implementation
adopts the following construction and documents it explicitly so independent
verifiers can recompute:

    state_root[0] = sha256(b"mpf-0.2:state-root:genesis")
    state_root[n] = sha256(
        b"mpf-0.2:state-root:v1\\x00"
        + state_root[n-1]
        + sha256(JCS(receipt_payload[n]))
        + sha256(JCS(canonical_signature_set[n]))
    )

Notes:

    1. The genesis state root is a fixed domain-tagged constant, not zeros.
       Zeros could be reached by accident; a tagged constant cannot.

    2. The combination uses domain separation (`mpf-0.2:state-root:v1\\x00`)
       to prevent any future MPF surface from accidentally producing a
       collision with a state-root computation. The trailing NUL is to
       prevent length-extension ambiguity with future tags that share a
       prefix.

    3. The signature set is canonicalized as a JSON object with sorted
       key_ids before digesting. The signature set must be deterministic
       given the same set of (key_id, signature) pairs, because the state
       root would otherwise depend on signature ordering.

    4. The receipt payload that gets digested is the receipt object MINUS
       the `signature_set` and `state_root` fields. Those two are derived
       from the payload; they cannot be inputs to themselves.

This construction is one of the four open questions logged in BUILD_PLAN.md
§6 to raise upstream after MVP. The implementation pins it now so the chain
is well-defined; if the working group lands on a different combination, this
implementation can be updated and re-anchored to a new genesis.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from . import canon, crypto

SCHEMA_VERSION = "mpf-0.2-receipt-v1"
GENESIS_STATE_ROOT = canon.sha256(b"mpf-0.2:state-root:genesis")
STATE_ROOT_DOMAIN = b"mpf-0.2:state-root:v1\x00"


# -- Receipt kinds permitted in this implementation's profile -----------------
# Subset of MPF v0.2 §10.2 (as updated by PR #2). Observation profiles do not
# emit memory.* or intent.* receipts.
ALLOWED_RECEIPT_KINDS = frozenset(
    {
        "session.start",
        "data.request",
        "data.response",
        "validation.result",
        "observation",
        "session.end",
        "checkpoint",
        # Failure-mode kinds (added by PR #2 to §10.2)
        "source.unavailable",
        "validation.failed",
        "validator.exception",
        "bytes.changed_in_interval",
    }
)


def utcnow_iso() -> str:
    """Current UTC timestamp in ISO 8601 with second precision and `Z` suffix.

    All MPF receipt timestamps in this implementation use UTC second precision.
    Sub-second precision is unnecessary at our 30-minute observation cadence
    and would just be a source of cross-implementation noise.
    """
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def new_session_id() -> str:
    """Generate a fresh session identifier.

    Format: `mpf-session-<16 hex chars>`. Sessions correspond to a single
    observation cycle in this implementation.
    """
    return f"mpf-session-{secrets.token_hex(8)}"


def canonical_signature_set(signatures: Mapping[str, str]) -> dict[str, str]:
    """Return a deterministic representation of a signature set.

    The dict is shallow-copied with keys ordered by the JCS rule (UTF-16 code
    point order, which `rfc8785` enforces). Values are signature strings in
    the `ed25519:<b64>` form. Returning a dict (not bytes) means callers can
    embed it back into the receipt structure.
    """
    return {k: signatures[k] for k in sorted(signatures.keys())}


def build_receipt_payload(
    *,
    session_id: str,
    sequence: int,
    receipt_kind: str,
    actor: Mapping[str, Any],
    body: Mapping[str, Any],
    previous_state_root_hex: str,
    issued_at: str | None = None,
) -> dict[str, Any]:
    """Build the payload portion of a receipt (everything except signatures and state_root).

    The payload is what gets digested for state-root computation, so it must
    contain every field that the receipt commits to except the signature set
    and the resulting state root.
    """
    if receipt_kind not in ALLOWED_RECEIPT_KINDS:
        raise ValueError(
            f"Receipt kind {receipt_kind!r} is not in the observation profile's "
            f"allowed kinds: {sorted(ALLOWED_RECEIPT_KINDS)}"
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "receipt_kind": receipt_kind,
        "session_id": session_id,
        "sequence": sequence,
        "previous_state_root": previous_state_root_hex,
        "actor": dict(actor),
        "body": dict(body),
        "issued_at": issued_at or utcnow_iso(),
    }


def compute_state_root(
    *,
    previous_state_root: bytes,
    payload: Mapping[str, Any],
    signature_set: Mapping[str, str],
) -> bytes:
    """Compute the resulting state root for a receipt.

    See module docstring for the construction and rationale. Returns 32 bytes.
    """
    if len(previous_state_root) != 32:
        raise ValueError(
            f"previous_state_root must be 32 bytes, got {len(previous_state_root)}"
        )
    payload_digest = canon.digest(payload)
    sig_set = canonical_signature_set(signature_set)
    sig_digest = canon.digest(sig_set)
    return canon.sha256(
        STATE_ROOT_DOMAIN + previous_state_root + payload_digest + sig_digest
    )


def sign_receipt(
    *,
    payload: Mapping[str, Any],
    signers: Iterable[crypto.KeyPair],
) -> dict[str, str]:
    """Produce a signature_set for a receipt payload.

    Each signer signs the JCS-canonical bytes of the payload. The returned
    dict maps `key_id` to `ed25519:<b64>` signature strings, deterministically
    ordered by `canonical_signature_set`.

    Multiple signers (witness + observer, for example) all sign the same
    canonical bytes. This is simpler than nested signatures and matches the
    "signature set" wording in §10.1.
    """
    canonical_bytes = canon.canonicalize(payload)
    signatures = {kp.key_id: kp.sign_b64(canonical_bytes) for kp in signers}
    return canonical_signature_set(signatures)


def assemble_receipt(
    *,
    payload: Mapping[str, Any],
    signature_set: Mapping[str, str],
    state_root: bytes,
) -> dict[str, Any]:
    """Combine payload + signature_set + state_root into the final receipt object."""
    return {
        **payload,
        "signature_set": canonical_signature_set(signature_set),
        "state_root": state_root.hex(),
    }


def verify_receipt(
    *,
    receipt: Mapping[str, Any],
    keyring: Mapping[str, str],
    expected_previous_state_root: bytes | None = None,
    external_subjects: Mapping[str, Mapping[str, Any]] | None = None,
) -> tuple[bool, list[str]]:
    """Verify a receipt's signatures and state-root continuity.

    Most signatures in a receipt's signature_set cover the receipt's own
    canonical payload. Some signatures (notably L1 witness signatures in
    observation profiles) cover an *external subject* that is referenced
    from the receipt body but signed independently. Pass `external_subjects`
    to tell the verifier which key IDs sign which external subject.

    Args:
        receipt: A complete receipt object as produced by `assemble_receipt`.
        keyring: Mapping of `key_id` to public-key string (`ed25519:<b64>` or
            bare base64).
        expected_previous_state_root: If provided, the receipt's
            `previous_state_root` field MUST match this value (32 bytes).
            Used by chain verifiers; pass None for a single-receipt check.
        external_subjects: Optional mapping of `key_id` -> the canonical
            JSON subject that key signed (instead of the receipt payload).
            Verifier reconstructs and JCS-canonicalizes the subject and
            checks the signature against it. Any key_id NOT in this map
            is verified against the receipt payload.

    Returns:
        A tuple `(ok, errors)` where `ok` is True iff every check passed and
        `errors` is a (possibly empty) list of human-readable failure reasons.
    """
    errors: list[str] = []

    # Reconstruct the payload by stripping derived fields.
    payload = {k: v for k, v in receipt.items() if k not in {"signature_set", "state_root"}}

    # Required fields per §10.1
    required = {
        "schema_version",
        "receipt_kind",
        "session_id",
        "sequence",
        "previous_state_root",
        "actor",
        "body",
        "issued_at",
    }
    missing = required - set(payload)
    if missing:
        errors.append(f"missing required fields: {sorted(missing)}")
        return False, errors

    if "signature_set" not in receipt:
        errors.append("missing signature_set")
        return False, errors
    if "state_root" not in receipt:
        errors.append("missing state_root")
        return False, errors

    # Previous-state-root continuity (if requested)
    if expected_previous_state_root is not None:
        if receipt["previous_state_root"] != expected_previous_state_root.hex():
            errors.append(
                f"previous_state_root mismatch: receipt={receipt['previous_state_root']} "
                f"expected={expected_previous_state_root.hex()}"
            )

    # Signature verification
    canonical_payload_bytes = canon.canonicalize(payload)
    sig_set = receipt["signature_set"]
    if not isinstance(sig_set, dict) or not sig_set:
        errors.append("signature_set must be a non-empty object")
        return False, errors
    ext = external_subjects or {}
    for key_id, sig_b64 in sig_set.items():
        if key_id not in keyring:
            errors.append(f"signature key_id {key_id!r} not in keyring")
            continue
        if key_id in ext:
            signed_bytes = canon.canonicalize(ext[key_id])
        else:
            signed_bytes = canonical_payload_bytes
        if not crypto.verify_signature(keyring[key_id], signed_bytes, sig_b64):
            errors.append(f"signature for key_id {key_id!r} failed verification")

    # State-root recomputation
    try:
        prev = bytes.fromhex(receipt["previous_state_root"])
    except ValueError:
        errors.append("previous_state_root is not valid hex")
        return False, errors
    if len(prev) != 32:
        errors.append(f"previous_state_root must be 32 bytes, got {len(prev)}")
        return False, errors

    recomputed = compute_state_root(
        previous_state_root=prev, payload=payload, signature_set=sig_set
    )
    if recomputed.hex() != receipt["state_root"]:
        errors.append(
            f"state_root mismatch: receipt={receipt['state_root']} "
            f"recomputed={recomputed.hex()}"
        )

    return (len(errors) == 0), errors
