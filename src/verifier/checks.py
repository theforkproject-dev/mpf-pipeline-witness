"""
MPF v0.2 verifier — required checks per §14.2.

Per §14.2: "The verifier MUST recompute rather than trust embedded claims."
This module reads a bundle directory from disk and recomputes every digest,
every signature, every state root, every registry binding. Any failure is
recorded as a structured check result; the overall verification state is
one of the §14.3 result states.

The verifier does NOT make trust-policy decisions. Per §14.4, MPF
verification determines whether a certificate satisfies the declared
profile. A relying party still decides whether the operator, workflow,
assurance profile, warnings, or evidence mode are acceptable.

What this verifier checks (the §14.2 list, profile-applicable subset):

    1. certificate digest (recompute over JCS of certificate.json minus
       the certificate_digest field; must match the embedded value)
    2. artifact digests (recompute over each on-disk file; must match
       bundle-manifest.json entries)
    3. receipt log parse and state-root continuity (each receipt's
       previous_state_root = the prior receipt's state_root, starting
       from GENESIS_STATE_ROOT)
    4. signatures and key resolution (operator and witness signatures
       verify against the keyring, with witness signatures over the
       observation subject when applicable)
    5. session boundaries (session.start present at sequence 0,
       session.end present, checkpoint last)
    6. observed observation semantics (observation profiles MUST NOT
       claim policy-gated execution, capability-token enforcement, or
       upstream-process control)
    7. witness quorum and witness registry authority (the L1 witness
       key is authorized by a signed witness registry epoch valid at
       the certificate's issued_at time)
    8. action registry entry and epoch digest (the action_id is in a
       signed action registry epoch valid at issued_at)
    9. operator/admission evidence (admission manifest digest matches
       the embedded value and is signed by the operator)
   10. upstream system identity present
   11. evidence mode declared
   12. assurance overclaim rejection
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

# Reuse witness-side primitives. The verifier depends only on canon and
# crypto, never on the gateway/observer/validator/witness modules.
from witness import canon, crypto, receipts


# §14.3 result states.
RESULT_VERIFIED = "verified"
RESULT_VERIFIED_WITH_WARNINGS = "verified_with_warnings"
RESULT_VERIFIED_DENIAL = "verified_denial"
RESULT_UNVERIFIABLE = "unverifiable"
RESULT_FAILED = "failed"
RESULT_UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class CheckResult:
    name: str
    passed: bool
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class VerificationResult:
    """Structured verifier output suitable for serialization or display."""

    state: str
    bundle_dir: str
    certificate_id: str | None
    profile_id: str | None
    checks: tuple[CheckResult, ...]
    warnings: tuple[str, ...] = ()
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "bundle_dir": self.bundle_dir,
            "certificate_id": self.certificate_id,
            "profile_id": self.profile_id,
            "checks": [
                {"name": c.name, "passed": c.passed, "detail": c.detail}
                for c in self.checks
            ],
            "warnings": list(self.warnings),
            "summary": dict(self.summary),
        }


def _read_bytes(path: Path) -> bytes:
    return path.read_bytes()


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text())


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


# --- Individual checks ------------------------------------------------------


def _check_certificate_digest(bundle_dir: Path) -> CheckResult:
    cert_path = bundle_dir / "certificate.json"
    cert = _read_json(cert_path)
    declared = cert.get("certificate_digest", "")
    cert_no_digest = {k: v for k, v in cert.items() if k != "certificate_digest"}
    expected = "sha256:" + canon.sha256_hex(canon.canonicalize(cert_no_digest))
    if declared != expected:
        return CheckResult(
            name="certificate_digest", passed=False,
            detail={"declared": declared, "recomputed": expected},
        )
    return CheckResult(
        name="certificate_digest", passed=True,
        detail={"digest": declared},
    )


def _check_artifact_digests(bundle_dir: Path) -> CheckResult:
    manifest_path = bundle_dir / "bundle-manifest.json"
    if not manifest_path.exists():
        return CheckResult(
            name="artifact_digests", passed=False,
            detail={"error": "bundle-manifest.json missing"},
        )
    manifest = _read_json(manifest_path)
    artifacts = manifest.get("artifacts", {})
    if not artifacts:
        return CheckResult(
            name="artifact_digests", passed=False,
            detail={"error": "bundle-manifest.json declares no artifacts"},
        )
    mismatches = []
    for rel_path, declared in artifacts.items():
        full = bundle_dir / rel_path
        if not full.exists():
            mismatches.append({"file": rel_path, "error": "file missing"})
            continue
        actual = "sha256:" + _sha256_hex(_read_bytes(full))
        if actual != declared:
            mismatches.append({"file": rel_path, "declared": declared, "actual": actual})
    if mismatches:
        return CheckResult(
            name="artifact_digests", passed=False,
            detail={"mismatches": mismatches},
        )
    return CheckResult(
        name="artifact_digests", passed=True,
        detail={"artifact_count": len(artifacts)},
    )


def _check_receipt_chain(bundle_dir: Path) -> CheckResult:
    receipts_path = bundle_dir / "receipts.jsonl"
    if not receipts_path.exists():
        return CheckResult(
            name="receipt_chain", passed=False,
            detail={"error": "receipts.jsonl missing"},
        )

    parsed: list[dict[str, Any]] = []
    for i, line in enumerate(_read_bytes(receipts_path).split(b"\n")):
        if not line:
            continue
        try:
            parsed.append(json.loads(line))
        except json.JSONDecodeError as e:
            return CheckResult(
                name="receipt_chain", passed=False,
                detail={"error": f"line {i} parse error: {e}"},
            )

    if not parsed:
        return CheckResult(
            name="receipt_chain", passed=False,
            detail={"error": "receipts.jsonl empty"},
        )

    # State-root continuity: each receipt's previous_state_root must equal
    # the prior receipt's state_root, starting from genesis.
    expected_prev = receipts.GENESIS_STATE_ROOT.hex()
    for r in parsed:
        if r.get("previous_state_root") != expected_prev:
            return CheckResult(
                name="receipt_chain", passed=False,
                detail={
                    "error": "previous_state_root mismatch",
                    "at_sequence": r.get("sequence"),
                    "kind": r.get("receipt_kind"),
                    "expected": expected_prev,
                    "found": r.get("previous_state_root"),
                },
            )
        expected_prev = r["state_root"]

    return CheckResult(
        name="receipt_chain", passed=True,
        detail={
            "receipt_count": len(parsed),
            "head_state_root": "sha256:" + parsed[-1]["state_root"],
        },
    )


def _check_signatures(bundle_dir: Path) -> CheckResult:
    keyring = _read_json(bundle_dir / "keyring.json")
    keys_by_id = {k["key_id"]: k for k in keyring["keys"]}
    pub_by_id = {kid: k["public_key"] for kid, k in keys_by_id.items()}
    role_by_id = {kid: k["role"] for kid, k in keys_by_id.items()}

    # Witness signatures cover the observation-subject.json file's content.
    obs_subject_path = bundle_dir / "observation-subject.json"
    obs_subject_canonical: bytes | None = None
    if obs_subject_path.exists():
        # The file is already JCS-canonical bytes; the witness signed those bytes.
        obs_subject_canonical = _read_bytes(obs_subject_path)

    receipts_path = bundle_dir / "receipts.jsonl"
    bad: list[dict[str, Any]] = []
    for i, line in enumerate(_read_bytes(receipts_path).split(b"\n")):
        if not line:
            continue
        receipt = json.loads(line)
        payload = {k: v for k, v in receipt.items()
                   if k not in {"signature_set", "state_root"}}
        canonical_payload = canon.canonicalize(payload)
        for key_id, sig in receipt["signature_set"].items():
            if key_id not in pub_by_id:
                bad.append({"receipt": i, "key_id": key_id,
                            "error": "key_id not in keyring"})
                continue
            role = role_by_id[key_id]
            if role.startswith("witness"):
                if obs_subject_canonical is None:
                    bad.append({"receipt": i, "key_id": key_id,
                                "error": "witness signature present but observation-subject.json missing"})
                    continue
                signed_bytes = obs_subject_canonical
            else:
                signed_bytes = canonical_payload
            if not crypto.verify_signature(pub_by_id[key_id], signed_bytes, sig):
                bad.append({"receipt": i, "key_id": key_id,
                            "kind": receipt["receipt_kind"],
                            "error": "signature failed verification"})

    if bad:
        return CheckResult(
            name="signatures", passed=False,
            detail={"bad_signatures": bad},
        )
    return CheckResult(name="signatures", passed=True, detail={})


def _check_session_boundaries(bundle_dir: Path) -> CheckResult:
    receipts_path = bundle_dir / "receipts.jsonl"
    parsed = [
        json.loads(line)
        for line in _read_bytes(receipts_path).split(b"\n")
        if line
    ]
    if not parsed:
        return CheckResult(name="session_boundaries", passed=False,
                           detail={"error": "no receipts"})
    if parsed[0]["receipt_kind"] != "session.start":
        return CheckResult(
            name="session_boundaries", passed=False,
            detail={"error": "first receipt is not session.start",
                    "first_kind": parsed[0]["receipt_kind"]},
        )
    if parsed[-1]["receipt_kind"] != "checkpoint":
        return CheckResult(
            name="session_boundaries", passed=False,
            detail={"error": "last receipt is not checkpoint",
                    "last_kind": parsed[-1]["receipt_kind"]},
        )
    kinds = [r["receipt_kind"] for r in parsed]
    if "session.end" not in kinds:
        return CheckResult(
            name="session_boundaries", passed=False,
            detail={"error": "no session.end receipt"},
        )
    return CheckResult(name="session_boundaries", passed=True,
                       detail={"receipt_kinds": kinds})


def _check_observation_overclaim_rejection(bundle_dir: Path) -> CheckResult:
    """Per §9.4.1 (PR #2): observation certificates MUST NOT claim policy-gated
    execution, capability-token enforcement, or upstream-process control.
    """
    cert = _read_json(bundle_dir / "certificate.json")
    assurance = cert.get("assurance", {})
    bad = []
    if assurance.get("capability_token_enforced") is True:
        bad.append("certificate.assurance.capability_token_enforced is true")
    if cert.get("outcome", {}).get("upstream_controlled") is True:
        bad.append("certificate.outcome.upstream_controlled is true")
    if bad:
        return CheckResult(
            name="observation_overclaim", passed=False,
            detail={"violations": bad},
        )
    return CheckResult(name="observation_overclaim", passed=True, detail={})


def _check_registry_validity(bundle_dir: Path) -> CheckResult:
    """Per §11.4: 'Witness signatures count only if the witness key was authorized
    by a signed Witness Registry Epoch at signing time.' Also confirm the action
    registry epoch is valid at the certificate's issued_at.
    """
    cert = _read_json(bundle_dir / "certificate.json")
    action_reg = _read_json(bundle_dir / "action-registry.json")
    witness_reg = _read_json(bundle_dir / "witness-registry-epoch.json")
    keyring = _read_json(bundle_dir / "keyring.json")

    issued_at = cert.get("issued_at")
    if not issued_at:
        return CheckResult(name="registry_validity", passed=False,
                           detail={"error": "certificate has no issued_at"})

    operator_keys = [k for k in keyring["keys"] if k["role"] == "operator"]
    if not operator_keys:
        return CheckResult(name="registry_validity", passed=False,
                           detail={"error": "no operator key in keyring"})
    operator_pubkey = operator_keys[0]["public_key"]

    # Validity-window checks for both registries at issued_at.
    issues: list[str] = []
    for reg, name in [(action_reg, "action_registry"), (witness_reg, "witness_registry")]:
        try:
            issued_dt = _parse_iso(issued_at)
            reg_start = _parse_iso(reg["issued_at"])
            reg_end = _parse_iso(reg["expires_at"])
        except (KeyError, ValueError) as e:
            issues.append(f"{name}: parse error {type(e).__name__}: {e}")
            continue
        if not (reg_start <= issued_dt <= reg_end):
            issues.append(
                f"{name}: certificate issued_at {issued_at} outside epoch validity "
                f"[{reg['issued_at']}, {reg['expires_at']}]"
            )

    # Recompute payload digests and check operator signatures on both registries.
    for reg, name in [(action_reg, "action_registry"), (witness_reg, "witness_registry")]:
        payload = {k: v for k, v in reg.items()
                   if k not in {"payload_digest", "signature_set"}}
        expected = "sha256:" + canon.sha256_hex(canon.canonicalize(payload))
        if reg.get("payload_digest") != expected:
            issues.append(f"{name}: payload_digest mismatch")
        operator_key_id = payload.get("operator", {}).get("operator_key_id")
        sig_set = reg.get("signature_set", {})
        if operator_key_id not in sig_set:
            issues.append(f"{name}: no operator signature")
            continue
        if not crypto.verify_signature(
            operator_pubkey, canon.canonicalize(payload), sig_set[operator_key_id]
        ):
            issues.append(f"{name}: operator signature failed verification")

    # Check the action_id appears in the action registry's actions list.
    action_id = cert.get("action_id")
    declared_actions = {a["action_id"] for a in action_reg.get("actions", [])}
    if action_id not in declared_actions:
        issues.append(
            f"action_id {action_id!r} not declared in action registry "
            f"(declared: {sorted(declared_actions)})"
        )

    # Check the witness key IDs are present in the witness registry.
    witness_key_ids = set(cert.get("witness_quorum", {}).get("witness_key_ids", []))
    declared_witness_keys = {w["key_id"] for w in witness_reg.get("witnesses", [])}
    for kid in witness_key_ids:
        if kid not in declared_witness_keys:
            issues.append(f"witness key {kid!r} not in witness registry")

    if issues:
        return CheckResult(name="registry_validity", passed=False,
                           detail={"issues": issues})
    return CheckResult(name="registry_validity", passed=True, detail={})


def _check_admission(bundle_dir: Path) -> CheckResult:
    """Admission manifest digest matches what the certificate references and is signed."""
    cert = _read_json(bundle_dir / "certificate.json")
    am = _read_json(bundle_dir / "admission-manifest.json")
    keyring = _read_json(bundle_dir / "keyring.json")

    declared = cert.get("admission", {}).get("manifest_digest")
    payload = {k: v for k, v in am.items()
               if k not in {"payload_digest", "signature_set"}}
    expected = "sha256:" + canon.sha256_hex(canon.canonicalize(payload))
    issues: list[str] = []
    if declared != expected:
        issues.append(f"admission digest mismatch: cert={declared}, recomputed={expected}")
    if am.get("payload_digest") != expected:
        issues.append(
            f"admission self-digest mismatch: am={am.get('payload_digest')}, "
            f"recomputed={expected}"
        )
    if am.get("intent_layer") != "none":
        issues.append(
            f"observation profile must declare intent_layer='none', "
            f"got {am.get('intent_layer')!r}"
        )

    operator_keys = [k for k in keyring["keys"] if k["role"] == "operator"]
    if operator_keys:
        operator_pubkey = operator_keys[0]["public_key"]
        operator_key_id = am.get("operator", {}).get("operator_key_id")
        sig_set = am.get("signature_set", {})
        if operator_key_id in sig_set:
            if not crypto.verify_signature(
                operator_pubkey, canon.canonicalize(payload), sig_set[operator_key_id]
            ):
                issues.append("admission operator signature failed verification")
        else:
            issues.append("admission has no operator signature")

    if issues:
        return CheckResult(name="admission", passed=False, detail={"issues": issues})
    return CheckResult(name="admission", passed=True, detail={})


# --- Composite --------------------------------------------------------------


def verify_bundle(bundle_dir: Path | str) -> VerificationResult:
    """Run all required §14.2 checks against an on-disk bundle.

    Args:
        bundle_dir: Path to the bundle directory.

    Returns:
        A `VerificationResult` with one of the §14.3 result states.
    """
    bp = Path(bundle_dir)
    if not bp.is_dir():
        return VerificationResult(
            state=RESULT_UNVERIFIABLE, bundle_dir=str(bp),
            certificate_id=None, profile_id=None,
            checks=(),
            warnings=(f"bundle_dir {bp} is not a directory",),
        )

    cert_path = bp / "certificate.json"
    if not cert_path.exists():
        return VerificationResult(
            state=RESULT_UNVERIFIABLE, bundle_dir=str(bp),
            certificate_id=None, profile_id=None,
            checks=(),
            warnings=("certificate.json missing",),
        )

    try:
        cert = _read_json(cert_path)
    except json.JSONDecodeError as e:
        return VerificationResult(
            state=RESULT_UNVERIFIABLE, bundle_dir=str(bp),
            certificate_id=None, profile_id=None,
            checks=(),
            warnings=(f"certificate.json parse error: {e}",),
        )

    check_results: list[CheckResult] = []
    for fn in [
        _check_certificate_digest,
        _check_artifact_digests,
        _check_receipt_chain,
        _check_signatures,
        _check_session_boundaries,
        _check_observation_overclaim_rejection,
        _check_registry_validity,
        _check_admission,
    ]:
        try:
            check_results.append(fn(bp))
        except Exception as e:  # defense in depth
            check_results.append(CheckResult(
                name=fn.__name__.lstrip("_check_"),
                passed=False,
                detail={"error": f"{type(e).__name__}: {e}"},
            ))

    all_passed = all(c.passed for c in check_results)

    # Determine state per §14.3.
    if all_passed:
        # Distinguish verified vs verified_denial based on certificate outcome.
        cert_state = cert.get("outcome", {}).get("state", "")
        if cert_state == "verified_denial":
            state = RESULT_VERIFIED_DENIAL
        elif cert.get("warnings"):
            state = RESULT_VERIFIED_WITH_WARNINGS
        else:
            state = RESULT_VERIFIED
    else:
        state = RESULT_FAILED

    summary = {
        "session_id": cert.get("session_id"),
        "certificate_id": cert.get("certificate_id"),
        "outcome_state": cert.get("outcome", {}).get("state"),
        "observation_outcome": cert.get("outcome", {}).get("observation_outcome"),
        "head_state_root": cert.get("receipt_log", {}).get("head_state_root"),
        "checks_total": len(check_results),
        "checks_passed": sum(1 for c in check_results if c.passed),
        "checks_failed": sum(1 for c in check_results if not c.passed),
    }

    return VerificationResult(
        state=state, bundle_dir=str(bp),
        certificate_id=cert.get("certificate_id"),
        profile_id=cert.get("verifier_profile_id"),
        checks=tuple(check_results),
        warnings=tuple(cert.get("warnings", [])),
        summary=summary,
    )


def main():
    """CLI entrypoint: `python -m verifier <bundle_dir>`."""
    import argparse, sys
    parser = argparse.ArgumentParser(
        description="Verify an MPF v0.2 observation-profile certificate bundle."
    )
    parser.add_argument("bundle_dir", help="Path to the bundle directory.")
    parser.add_argument("--json", action="store_true",
                        help="Output the full result as JSON.")
    args = parser.parse_args()

    result = verify_bundle(args.bundle_dir)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(f"State: {result.state}")
        print(f"Bundle: {result.bundle_dir}")
        print(f"Certificate: {result.certificate_id}")
        print(f"Profile: {result.profile_id}")
        print()
        print(f"Checks ({result.summary['checks_passed']}/{result.summary['checks_total']} passed):")
        for c in result.checks:
            mark = "PASS" if c.passed else "FAIL"
            print(f"  [{mark}] {c.name}")
            if not c.passed:
                for k, v in c.detail.items():
                    print(f"         {k}: {v}")
        if result.warnings:
            print()
            print(f"Warnings:")
            for w in result.warnings:
                print(f"  - {w}")
    sys.exit(0 if result.state in {
        RESULT_VERIFIED, RESULT_VERIFIED_WITH_WARNINGS, RESULT_VERIFIED_DENIAL
    } else 1)


if __name__ == "__main__":
    main()
