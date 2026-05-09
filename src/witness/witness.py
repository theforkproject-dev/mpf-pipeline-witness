"""
L1 Mechanical Witness for MPF v0.2 observation profiles.

Per MPF v0.2 §11.1, L1 witnesses sign canonical protocol subjects. The subject
digest is computed over the JCS-canonicalized subject JSON per §2.9. Witnesses
MUST maintain anti-equivocation state for guard keys defined by profile.
L1 witnesses MUST refuse a different digest for the same guard key.

This implementation is a co-resident L1 witness — it runs in the same process
as the gateway. The §11.5 / §20.5 weakness of co-resident witness operation
is acknowledged in the verifier profile. The implementation correctness of
the witness is independent of operator independence.

Anti-equivocation:

    The guard-key semantics for this profile (per the profile JSON) is
    `(source_url, observed_timestamp)`. The witness records, for each guard
    key, the digest of the subject it has previously signed. If a second
    sign request arrives for the same guard key with a different subject
    digest, the witness MUST refuse and persist conflict evidence. This is
    the only line of defense against an attacker who can persuade the
    gateway to claim two different observed-byte sets for the same upstream
    cycle.

    The guard-key store is a SQLite table; persistence across process
    restarts is necessary for the anti-equivocation property to hold under
    crash-restart cycles.

What the L1 witness does NOT do:

    - It does not validate the subject's semantic correctness. Per §11.1,
      L1 mechanical witnesses do not claim semantic correctness or policy
      wisdom. The claim is "this subject was presented to me, I had not
      previously signed a different subject for the same guard key, and I
      am cryptographically committing to this digest at this moment."
    - It does not fetch the upstream URL itself. Witness-independent
      fetch is a profile-defined option (see profile JSON
      `witness_independent_fetch`) and is not required for this profile.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

from . import canon, crypto


WITNESS_TIER_L1 = "L1"


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class GuardKey:
    """The pinned guard-key shape for this profile.

    `(source_url, observed_timestamp)` per the verifier profile JSON.

    `observed_timestamp` is the upstream-supplied ISO-8601 string from the
    artifact's `current.asOf` field, NOT the wall-clock fetch time. The
    gateway is responsible for plumbing the right value into sign requests;
    the witness signs whatever guard key it is presented with.
    """

    source_url: str
    observed_timestamp: str

    def to_canonical(self) -> str:
        """Render as a flat string for SQLite primary-key use.

        Format: `<source_url>|<observed_timestamp>`. The pipe is the
        delimiter because neither field can contain it: source_url is a URL
        (no unescaped pipes) and observed_timestamp is an ISO-8601 string.
        """
        if "|" in self.source_url or "|" in self.observed_timestamp:
            raise ValueError("guard-key fields must not contain '|'")
        return f"{self.source_url}|{self.observed_timestamp}"


class EquivocationError(Exception):
    """Raised when a witness is asked to sign a different subject for the same guard key.

    Per §11.1: "L1 witnesses MUST refuse a different digest for the same guard
    key." This exception carries the conflict evidence the spec requires the
    witness to persist.
    """

    def __init__(
        self,
        guard_key: GuardKey,
        previous_digest_hex: str,
        new_digest_hex: str,
    ):
        self.guard_key = guard_key
        self.previous_digest_hex = previous_digest_hex
        self.new_digest_hex = new_digest_hex
        super().__init__(
            f"equivocation refused: guard_key={guard_key!r}, "
            f"previous={previous_digest_hex}, new={new_digest_hex}"
        )


class GuardKeyStore:
    """SQLite-backed anti-equivocation store for L1 witness guard keys.

    The store maps each guard key to the digest the witness has previously
    signed for it, plus metadata for forensic review. A second sign request
    for the same guard key with the same digest is idempotent (no error,
    no new row). A second sign request with a different digest raises
    `EquivocationError` and writes a conflict-evidence row.
    """

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS guard_keys (
        guard_key_canonical TEXT PRIMARY KEY,
        source_url TEXT NOT NULL,
        observed_timestamp TEXT NOT NULL,
        subject_digest_hex TEXT NOT NULL,
        first_signed_at TEXT NOT NULL,
        sign_count INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS conflicts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guard_key_canonical TEXT NOT NULL,
        previous_digest_hex TEXT NOT NULL,
        attempted_digest_hex TEXT NOT NULL,
        attempted_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_conflicts_guard_key
        ON conflicts (guard_key_canonical);
    """

    def __init__(self, db_path: Path | str):
        self.db_path = str(db_path)
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        # For in-memory DBs we keep one connection alive; for file DBs we
        # open/close per call so multi-process operation works.
        if self.db_path == ":memory:":
            self._conn = sqlite3.connect(self.db_path)
            self._conn.executescript(self.SCHEMA)
        else:
            self._conn = None
            with self._connect() as conn:
                conn.executescript(self.SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        if self._conn is not None:
            yield self._conn
            return
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
        finally:
            conn.close()

    def record_or_check(self, guard_key: GuardKey, subject_digest_hex: str) -> str:
        """Atomically record a (guard_key, digest) pair or detect equivocation.

        Args:
            guard_key: The guard key being signed.
            subject_digest_hex: SHA-256 of the JCS-canonicalized subject.

        Returns:
            "first" if this is the first sign for this guard key.
            "idempotent" if the same digest was previously recorded.

        Raises:
            EquivocationError: If a different digest was previously recorded
                for the same guard key. Conflict evidence is persisted.
        """
        canonical = guard_key.to_canonical()
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT subject_digest_hex, sign_count FROM guard_keys "
                "WHERE guard_key_canonical = ?",
                (canonical,),
            )
            row = cur.fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO guard_keys "
                    "(guard_key_canonical, source_url, observed_timestamp, "
                    " subject_digest_hex, first_signed_at, sign_count) "
                    "VALUES (?, ?, ?, ?, ?, 1)",
                    (canonical, guard_key.source_url, guard_key.observed_timestamp,
                     subject_digest_hex, _utcnow_iso()),
                )
                conn.commit()
                return "first"

            previous_digest = row[0]
            if previous_digest == subject_digest_hex:
                conn.execute(
                    "UPDATE guard_keys SET sign_count = sign_count + 1 "
                    "WHERE guard_key_canonical = ?",
                    (canonical,),
                )
                conn.commit()
                return "idempotent"

            # Equivocation. Persist conflict evidence per §11.1, then refuse.
            conn.execute(
                "INSERT INTO conflicts "
                "(guard_key_canonical, previous_digest_hex, attempted_digest_hex, attempted_at) "
                "VALUES (?, ?, ?, ?)",
                (canonical, previous_digest, subject_digest_hex, _utcnow_iso()),
            )
            conn.commit()
            raise EquivocationError(
                guard_key=guard_key,
                previous_digest_hex=previous_digest,
                new_digest_hex=subject_digest_hex,
            )

    def get_signed_digest(self, guard_key: GuardKey) -> str | None:
        """Return the previously-signed digest for a guard key, or None."""
        canonical = guard_key.to_canonical()
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT subject_digest_hex FROM guard_keys "
                "WHERE guard_key_canonical = ?",
                (canonical,),
            )
            row = cur.fetchone()
            return row[0] if row else None

    def list_conflicts(self) -> list[dict[str, Any]]:
        """Return all conflict-evidence rows for forensic review."""
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT guard_key_canonical, previous_digest_hex, "
                "       attempted_digest_hex, attempted_at "
                "FROM conflicts ORDER BY id"
            )
            return [
                {
                    "guard_key_canonical": row[0],
                    "previous_digest_hex": row[1],
                    "attempted_digest_hex": row[2],
                    "attempted_at": row[3],
                }
                for row in cur.fetchall()
            ]

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None


@dataclass(frozen=True)
class WitnessSignature:
    """The output of a successful witness sign operation.

    Attributes:
        witness_id: Stable identifier from the witness registry.
        key_id: Signing key identifier.
        subject_digest_hex: SHA-256 of the JCS-canonicalized subject.
        signature_b64: Signature in `ed25519:<b64>` form.
        guard_key: The guard key under which this signature was recorded.
        guard_outcome: "first" | "idempotent". Equivocation never returns;
            it raises.
        signed_at: ISO-8601 UTC timestamp of the sign operation.
    """

    witness_id: str
    key_id: str
    subject_digest_hex: str
    signature_b64: str
    guard_key: GuardKey
    guard_outcome: str
    signed_at: str


class L1Witness:
    """A co-resident L1 mechanical witness.

    Holds a signing keypair, a guard-key store, and a stable witness identity
    that matches an entry in the Witness Registry epoch. All three are
    bound at construction; rotating any of them requires a new instance.
    """

    def __init__(
        self,
        *,
        witness_id: str,
        signing_key: crypto.KeyPair,
        store: GuardKeyStore,
        operator_id: str = "operator:fork-node-01",
    ):
        self.witness_id = witness_id
        self.signing_key = signing_key
        self.store = store
        self.operator_id = operator_id
        self.tier = WITNESS_TIER_L1

    def sign_subject(
        self,
        *,
        subject: Mapping[str, Any],
        guard_key: GuardKey,
    ) -> WitnessSignature:
        """Sign a canonical protocol subject under anti-equivocation rules.

        Args:
            subject: The JSON object the witness is committing to. Will be
                JCS-canonicalized per §2.9 before digesting.
            guard_key: The guard key for this sign operation.

        Returns:
            A `WitnessSignature` with the signature and outcome.

        Raises:
            EquivocationError: If a different subject was previously signed
                for the same guard key. The conflict is persisted and the
                operation refused.
        """
        canonical_bytes = canon.canonicalize(subject)
        digest_hex = canon.sha256_hex(canonical_bytes)

        outcome = self.store.record_or_check(guard_key, digest_hex)
        # If we got here, we are authorized to sign (either first time or
        # idempotent re-sign of the same digest).
        sig_b64 = self.signing_key.sign_b64(canonical_bytes)

        return WitnessSignature(
            witness_id=self.witness_id,
            key_id=self.signing_key.key_id,
            subject_digest_hex=digest_hex,
            signature_b64=sig_b64,
            guard_key=guard_key,
            guard_outcome=outcome,
            signed_at=_utcnow_iso(),
        )

    def witness_registry_entry(
        self,
        *,
        independence_class: str = "co-resident",
    ) -> dict[str, Any]:
        """Return this witness's entry shape for inclusion in a Witness Registry epoch.

        The returned dict matches the required-field schema in
        `registry.build_witness_registry_epoch`.
        """
        return {
            "witness_id": self.witness_id,
            "key_id": self.signing_key.key_id,
            "public_key": self.signing_key.public_b64(),
            "tier": self.tier,
            "operator_id": self.operator_id,
            "independence_class": independence_class,
        }
