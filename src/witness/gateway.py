"""
Gateway: orchestrate one observation cycle and produce a signed receipt chain.

Per MPF v0.2 §9.4.1, the recommended receipt flow for a single observation
cycle is:

    session.start
      -> data.request          (observer issues fetch against source URL)
      -> data.response         (observer commits to fetched bytes by digest)
      -> validation.result     (validator commits to declared-invariant outcomes)
      -> observation           (witness signs the observation subject)
      -> session.end
      -> checkpoint            (gateway publishes certificate bundle)

This gateway implements the in-process orchestration: it builds, signs, and
chains every receipt and returns the complete chain plus the raw fetched
bytes for downstream bundle assembly. It does NOT itself write the bundle
to disk (that's Phase 5) or expose a public verifier (that's Phase 6).

Witness signing model:

    Per §11.1, L1 witnesses sign canonical *protocol subjects* — not
    arbitrary receipt payloads. A single observation cycle produces one
    *observation subject*: a stable JSON object describing what was
    observed. The witness signs that subject once, and the same signature
    is embedded in both the validation.result and observation receipts'
    signature_sets. This is what lets two receipts share a guard key
    without triggering equivocation: the witness commits to the same
    underlying observation, and the per-receipt distinctions (kind,
    sequence, body) are carried by the operator's signature on the full
    receipt payload.

    The observation subject is:

        {
          "schema": "mpf-0.2-observation-subject-v1",
          "source_url": <str>,
          "observed_timestamp": <ISO-8601>,
          "bytes_sha256": "sha256:<hex>",
          "validation_passed": <bool>,
        }

    On validation failure, the subject still exists (the witness commits
    to "I observed these bytes at this time and they failed validation"),
    just with `validation_passed: false`.

Receipt-level signatures:

    - All receipts in the chain carry the operator signature over the
      receipt's full canonical payload. This binds the kind, sequence,
      body, and previous_state_root to the operator's identity.

    - validation.result, validation.failed, and observation receipts
      additionally carry the witness signature over the *observation
      subject* (NOT the receipt payload). Verifiers check the witness
      signature by reconstructing the observation subject from the
      receipt body and verifying against the witness public key.

Failure modes:

    - source.unavailable    all retries failed
    - validator.exception   JSON decode failure or validator runtime error
    - validation.failed     emitted instead of observation when invariants fail

In every failure case the chain still completes with session.end and
checkpoint receipts.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from . import canon, crypto, observer, receipts, validator
from .witness import GuardKey, L1Witness, WitnessSignature


OBSERVATION_SUBJECT_SCHEMA = "mpf-0.2-observation-subject-v1"


@dataclass(frozen=True)
class CycleOutput:
    """The output of a single observation cycle.

    Attributes:
        session_id: The MPF session identifier.
        receipts: Ordered list of complete signed receipt JSON objects.
        head_state_root_hex: The state root of the final receipt in the chain.
        observation_succeeded: True if the cycle produced an `observation`
            receipt; False if it produced a `validation.failed` or earlier
            failure receipt instead. The chain completes either way.
        observed_bytes: The raw fetched bytes (held in memory until the
            bundle assembler persists them in Phase 5). MAY be None if the
            cycle failed before the fetch.
        observed_bytes_sha256_hex: SHA-256 of `observed_bytes`.
        validation_summary: The validator's summary fields for the cycle.
        observation_subject: The JSON object the witness signed (or None if
            no witness signature was produced this cycle).
        observation_subject_digest_hex: SHA-256 of JCS(observation_subject).
    """

    session_id: str
    receipts: tuple[dict[str, Any], ...]
    head_state_root_hex: str
    observation_succeeded: bool
    observed_bytes: bytes | None
    observed_bytes_sha256_hex: str | None
    validation_summary: dict[str, Any] = field(default_factory=dict)
    observation_subject: dict[str, Any] | None = None
    observation_subject_digest_hex: str | None = None


def build_observation_subject(
    *,
    source_url: str,
    observed_timestamp: str,
    bytes_sha256_hex: str,
    validation_passed: bool,
) -> dict[str, Any]:
    """Build the canonical observation subject the witness signs.

    This is the single object the witness commits to per cycle. Its digest
    is what the guard-key store records; equivocation is "the witness was
    asked to commit to a different subject digest under the same guard key."
    """
    return {
        "schema": OBSERVATION_SUBJECT_SCHEMA,
        "source_url": source_url,
        "observed_timestamp": observed_timestamp,
        "bytes_sha256": "sha256:" + bytes_sha256_hex,
        "validation_passed": validation_passed,
    }


class Gateway:
    """Single-cycle observation orchestrator."""

    def __init__(
        self,
        *,
        operator_key: crypto.KeyPair,
        witness: L1Witness,
        source_url: str,
        action_id: str = "pipeline.snapshot.observe.v1",
        verifier_profile_id: str = "mpf.profile.observation.external-pipeline.v0.2-fork",
    ):
        self.operator_key = operator_key
        self.witness = witness
        self.source_url = source_url
        self.action_id = action_id
        self.verifier_profile_id = verifier_profile_id

    # -- helpers --------------------------------------------------------------

    def _build_and_sign(
        self,
        *,
        session_id: str,
        sequence: int,
        receipt_kind: str,
        body: dict[str, Any],
        previous_state_root_hex: str,
        actor: dict[str, Any],
        witness_signature: WitnessSignature | None = None,
    ) -> dict[str, Any]:
        """Build, sign, and chain a single receipt.

        The operator always signs the receipt payload. If `witness_signature`
        is provided, the witness's signature (over the observation subject,
        NOT the receipt payload) is added to the signature set as well.
        """
        payload = receipts.build_receipt_payload(
            session_id=session_id,
            sequence=sequence,
            receipt_kind=receipt_kind,
            actor=actor,
            body=body,
            previous_state_root_hex=previous_state_root_hex,
        )

        canonical_bytes = canon.canonicalize(payload)
        operator_sig = self.operator_key.sign_b64(canonical_bytes)
        sig_dict = {self.operator_key.key_id: operator_sig}
        if witness_signature is not None:
            sig_dict[witness_signature.key_id] = witness_signature.signature_b64
        sig_set = receipts.canonical_signature_set(sig_dict)

        prev = bytes.fromhex(previous_state_root_hex)
        state_root = receipts.compute_state_root(
            previous_state_root=prev, payload=payload, signature_set=sig_set,
        )
        return receipts.assemble_receipt(
            payload=payload, signature_set=sig_set, state_root=state_root,
        )

    # -- main entry -----------------------------------------------------------

    def run_cycle(
        self,
        *,
        admission_manifest: dict[str, Any],
        session_id: str | None = None,
        http_client: Any | None = None,
    ) -> CycleOutput:
        """Run one full observation cycle and return the signed receipt chain.

        Args:
            admission_manifest: A signed Admission Manifest; the gateway
                binds its digest into session.start and checkpoint receipts.
            session_id: Optional pre-allocated session ID. If None, a fresh
                one is generated.
            http_client: Optional pre-configured httpx.Client (for tests).

        Returns:
            A `CycleOutput` with the complete signed chain.
        """
        sess = session_id or receipts.new_session_id()
        manifest_digest = admission_manifest.get("payload_digest")
        if not manifest_digest:
            raise ValueError("admission_manifest must include payload_digest")

        operator_actor = {
            "type": "operator",
            "operator_id": "operator:fork-node-01",
            "key_id": self.operator_key.key_id,
        }

        chain: list[dict[str, Any]] = []
        prev_root = receipts.GENESIS_STATE_ROOT.hex()
        seq = 0

        # 1. session.start — bind the admission manifest by digest.
        session_start = self._build_and_sign(
            session_id=sess, sequence=seq, receipt_kind="session.start",
            body={
                "verifier_profile_id": self.verifier_profile_id,
                "action_id": self.action_id,
                "admission_manifest_digest": manifest_digest,
                "source_url": self.source_url,
            },
            previous_state_root_hex=prev_root, actor=operator_actor,
        )
        chain.append(session_start)
        prev_root = session_start["state_root"]
        seq += 1

        # 2. Fetch.
        fetch_failed = False
        observed_bytes: bytes | None = None
        observed_digest_hex: str | None = None
        request_body: dict[str, Any]
        response_body: dict[str, Any] | None = None

        try:
            obs = observer.fetch(self.source_url, client=http_client)
            observed_bytes = obs.body
            observed_digest_hex = obs.bytes_sha256_hex
            bodies = observer.fetch_to_receipt_bodies(obs)
            request_body, response_body = bodies["data.request"], bodies["data.response"]
        except observer.ObserverError as e:
            fetch_failed = True
            request_body = {
                "url": self.source_url, "method": "GET",
                "attempt_count": len(e.attempts),
                "attempt_history": [
                    {"attempt": n, "status": s, "error": err}
                    for (n, s, err) in e.attempts
                ],
            }

        # 3. data.request
        chain.append(self._build_and_sign(
            session_id=sess, sequence=seq, receipt_kind="data.request",
            body=request_body,
            previous_state_root_hex=prev_root, actor=operator_actor,
        ))
        prev_root = chain[-1]["state_root"]
        seq += 1

        if fetch_failed:
            # 4'. source.unavailable — terminal failure mode for the fetch.
            chain.append(self._build_and_sign(
                session_id=sess, sequence=seq, receipt_kind="source.unavailable",
                body={"url": self.source_url, "reason": "all retry attempts failed"},
                previous_state_root_hex=prev_root, actor=operator_actor,
            ))
            prev_root = chain[-1]["state_root"]
            seq += 1
            return self._finalize(
                chain=chain, session_id=sess, prev_root=prev_root, seq=seq,
                manifest_digest=manifest_digest, operator_actor=operator_actor,
                observation_succeeded=False, observed_bytes=None,
                observed_digest_hex=None, validation_summary={},
                observation_subject=None, observation_subject_digest_hex=None,
            )

        # 4. data.response
        chain.append(self._build_and_sign(
            session_id=sess, sequence=seq, receipt_kind="data.response",
            body=response_body, previous_state_root_hex=prev_root, actor=operator_actor,
        ))
        prev_root = chain[-1]["state_root"]
        seq += 1

        # 5. Validate.
        try:
            parsed = json.loads(observed_bytes)
        except json.JSONDecodeError as e:
            chain.append(self._build_and_sign(
                session_id=sess, sequence=seq, receipt_kind="validator.exception",
                body={
                    "exception_type": "JSONDecodeError",
                    "message": str(e),
                    "bytes_sha256": "sha256:" + observed_digest_hex,
                },
                previous_state_root_hex=prev_root, actor=operator_actor,
            ))
            prev_root = chain[-1]["state_root"]
            seq += 1
            return self._finalize(
                chain=chain, session_id=sess, prev_root=prev_root, seq=seq,
                manifest_digest=manifest_digest, operator_actor=operator_actor,
                observation_succeeded=False, observed_bytes=observed_bytes,
                observed_digest_hex=observed_digest_hex, validation_summary={},
                observation_subject=None, observation_subject_digest_hex=None,
            )

        try:
            validation_result = validator.validate(parsed)
        except Exception as e:  # validator should not raise; defense in depth
            chain.append(self._build_and_sign(
                session_id=sess, sequence=seq, receipt_kind="validator.exception",
                body={
                    "exception_type": type(e).__name__,
                    "message": str(e),
                    "bytes_sha256": "sha256:" + observed_digest_hex,
                },
                previous_state_root_hex=prev_root, actor=operator_actor,
            ))
            prev_root = chain[-1]["state_root"]
            seq += 1
            return self._finalize(
                chain=chain, session_id=sess, prev_root=prev_root, seq=seq,
                manifest_digest=manifest_digest, operator_actor=operator_actor,
                observation_succeeded=False, observed_bytes=observed_bytes,
                observed_digest_hex=observed_digest_hex, validation_summary={},
                observation_subject=None, observation_subject_digest_hex=None,
            )

        upstream_observed_ts = (
            validation_result.summary.get("as_of") or "unknown"
        )

        # Build the canonical observation subject and have the witness sign
        # it ONCE. The same WitnessSignature is then attached to both the
        # validation receipt and (if successful) the observation receipt.
        observation_subject = build_observation_subject(
            source_url=self.source_url,
            observed_timestamp=upstream_observed_ts,
            bytes_sha256_hex=observed_digest_hex,
            validation_passed=validation_result.overall_passed,
        )
        guard = GuardKey(
            source_url=self.source_url, observed_timestamp=upstream_observed_ts,
        )
        witness_sig = self.witness.sign_subject(
            subject=observation_subject, guard_key=guard,
        )
        observation_subject_digest_hex = witness_sig.subject_digest_hex

        # 6. validation.result OR validation.failed (witness-signed via subject)
        validation_kind = (
            "validation.result" if validation_result.overall_passed
            else "validation.failed"
        )
        validation_body = {
            **validation_result.to_receipt_body(),
            "bytes_sha256": "sha256:" + observed_digest_hex,
            "observed_timestamp": upstream_observed_ts,
            "observation_subject_digest": "sha256:" + observation_subject_digest_hex,
        }
        chain.append(self._build_and_sign(
            session_id=sess, sequence=seq, receipt_kind=validation_kind,
            body=validation_body,
            previous_state_root_hex=prev_root, actor=operator_actor,
            witness_signature=witness_sig,
        ))
        prev_root = chain[-1]["state_root"]
        seq += 1

        # 7. observation — only on validation success (witness-signed via subject)
        if validation_result.overall_passed:
            observation_body = {
                "url": self.source_url,
                "observed_timestamp": upstream_observed_ts,
                "bytes_sha256": "sha256:" + observed_digest_hex,
                "validation_passed": True,
                "validation_summary": dict(validation_result.summary),
                "observation_subject_digest": "sha256:" + observation_subject_digest_hex,
            }
            chain.append(self._build_and_sign(
                session_id=sess, sequence=seq, receipt_kind="observation",
                body=observation_body,
                previous_state_root_hex=prev_root, actor=operator_actor,
                witness_signature=witness_sig,
            ))
            prev_root = chain[-1]["state_root"]
            seq += 1

        return self._finalize(
            chain=chain, session_id=sess, prev_root=prev_root, seq=seq,
            manifest_digest=manifest_digest, operator_actor=operator_actor,
            observation_succeeded=validation_result.overall_passed,
            observed_bytes=observed_bytes,
            observed_digest_hex=observed_digest_hex,
            validation_summary=dict(validation_result.summary),
            observation_subject=observation_subject,
            observation_subject_digest_hex=observation_subject_digest_hex,
        )

    def _finalize(
        self, *,
        chain: list[dict[str, Any]],
        session_id: str,
        prev_root: str,
        seq: int,
        manifest_digest: str,
        operator_actor: dict[str, Any],
        observation_succeeded: bool,
        observed_bytes: bytes | None,
        observed_digest_hex: str | None,
        validation_summary: dict[str, Any],
        observation_subject: dict[str, Any] | None,
        observation_subject_digest_hex: str | None,
    ) -> CycleOutput:
        # session.end
        chain.append(self._build_and_sign(
            session_id=session_id, sequence=seq, receipt_kind="session.end",
            body={"observation_succeeded": observation_succeeded},
            previous_state_root_hex=prev_root, actor=operator_actor,
        ))
        prev_root = chain[-1]["state_root"]
        seq += 1

        # checkpoint
        chain.append(self._build_and_sign(
            session_id=session_id, sequence=seq, receipt_kind="checkpoint",
            body={
                "session_id": session_id,
                "admission_manifest_digest": manifest_digest,
                "head_state_root": prev_root,
                "receipt_count": len(chain) + 1,  # +1 for this receipt
                "verifier_profile_id": self.verifier_profile_id,
            },
            previous_state_root_hex=prev_root, actor=operator_actor,
        ))
        head_root = chain[-1]["state_root"]

        return CycleOutput(
            session_id=session_id,
            receipts=tuple(chain),
            head_state_root_hex=head_root,
            observation_succeeded=observation_succeeded,
            observed_bytes=observed_bytes,
            observed_bytes_sha256_hex=observed_digest_hex,
            validation_summary=validation_summary,
            observation_subject=observation_subject,
            observation_subject_digest_hex=observation_subject_digest_hex,
        )
