"""
Cryptographic primitives for MPF v0.2 receipts and certificates.

This module wraps `cryptography.hazmat.primitives.asymmetric.ed25519` with a
narrow surface tailored to MPF needs:

  - generate, save, and load Ed25519 keypairs
  - sign canonical bytes (the output of `canon.canonicalize`)
  - verify a signature against a known public key
  - serialize public keys to a stable on-the-wire form for keyring artifacts

Ed25519 is chosen because the MPF v0.2 spec is algorithm-agnostic but its
example artifacts and reference implementation use Ed25519, and Ed25519 has
deterministic signatures (RFC 8032) which is desirable for reproducible
receipts. JCS-canonicalized input + Ed25519 signing means "same JSON object,
same key" produces "same signature bytes," which is what an independent
verifier needs to check signature equality.

Key serialization format: 32-byte raw seeds for private keys and 32-byte raw
public-key bytes, each base64-encoded with the `ed25519:` prefix when used in
JSON contexts (per the convention used in MPF certificate examples).
"""

from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from cryptography.exceptions import InvalidSignature

PUBKEY_PREFIX = "ed25519:"
SIGNATURE_PREFIX = "ed25519:"


@dataclass(frozen=True)
class KeyPair:
    """An Ed25519 keypair.

    Both `private_key` and `public_key` are the raw cryptography library
    objects. Use `public_b64()` / `private_b64()` for storage/serialization.
    """

    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    key_id: str

    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def private_bytes(self) -> bytes:
        return self.private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )

    def public_b64(self) -> str:
        """Public key as base64, with the `ed25519:` prefix used in JSON artifacts."""
        return PUBKEY_PREFIX + base64.b64encode(self.public_bytes()).decode("ascii")

    def private_b64(self) -> str:
        """Private key as base64. Storage format only; do not put in artifacts."""
        return base64.b64encode(self.private_bytes()).decode("ascii")

    def sign(self, data: bytes) -> bytes:
        """Ed25519-sign raw `data`. Caller is responsible for canonicalizing."""
        return self.private_key.sign(data)

    def sign_b64(self, data: bytes) -> str:
        """Sign and return the signature with the `ed25519:` prefix used in artifacts."""
        return SIGNATURE_PREFIX + base64.b64encode(self.sign(data)).decode("ascii")


def generate_keypair(key_id: str) -> KeyPair:
    """Generate a fresh Ed25519 keypair with the given stable identifier."""
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    return KeyPair(private_key=private, public_key=public, key_id=key_id)


def save_private_key(kp: KeyPair, path: Path) -> None:
    """Write the private key to `path` as raw 32 bytes. Sets file mode 0o600.

    The format is the raw 32-byte Ed25519 seed (no PEM/DER wrapping). This is
    the simplest defensible storage format and avoids any ambiguity about
    encoding choices that other implementations would have to mirror.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(kp.private_bytes())
    path.chmod(0o600)


def load_private_key(path: Path, key_id: str) -> KeyPair:
    """Load a raw 32-byte Ed25519 private key and return its KeyPair."""
    raw = Path(path).read_bytes()
    if len(raw) != 32:
        raise ValueError(
            f"Expected 32-byte raw Ed25519 private key at {path}, got {len(raw)} bytes."
        )
    private = Ed25519PrivateKey.from_private_bytes(raw)
    public = private.public_key()
    return KeyPair(private_key=private, public_key=public, key_id=key_id)


def parse_public_key_b64(s: str) -> Ed25519PublicKey:
    """Parse `ed25519:<base64>` (or bare base64) into an Ed25519PublicKey."""
    if s.startswith(PUBKEY_PREFIX):
        s = s[len(PUBKEY_PREFIX):]
    raw = base64.b64decode(s)
    if len(raw) != 32:
        raise ValueError(
            f"Expected 32-byte raw Ed25519 public key, got {len(raw)} bytes."
        )
    return Ed25519PublicKey.from_public_bytes(raw)


def parse_signature_b64(s: str) -> bytes:
    """Parse `ed25519:<base64>` (or bare base64) into raw signature bytes."""
    if s.startswith(SIGNATURE_PREFIX):
        s = s[len(SIGNATURE_PREFIX):]
    raw = base64.b64decode(s)
    if len(raw) != 64:
        raise ValueError(
            f"Expected 64-byte Ed25519 signature, got {len(raw)} bytes."
        )
    return raw


def verify_signature(
    public_key: Ed25519PublicKey | str,
    data: bytes,
    signature: bytes | str,
) -> bool:
    """Verify an Ed25519 signature.

    Args:
        public_key: Either an `Ed25519PublicKey` or a base64 string (`ed25519:...`).
        data: Raw bytes that were signed (typically JCS-canonicalized JSON).
        signature: Either raw signature bytes or a base64 string (`ed25519:...`).

    Returns:
        True if the signature is valid, False otherwise. Does not raise.
    """
    if isinstance(public_key, str):
        public_key = parse_public_key_b64(public_key)
    if isinstance(signature, str):
        signature = parse_signature_b64(signature)
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False


def random_key_id(prefix: str = "key") -> str:
    """Generate a random key identifier suitable for keyring entries.

    Format: `<prefix>:<8-hex-chars>`. Not cryptographically meaningful — this is
    just a stable label for use in keyring JSON artifacts.
    """
    return f"{prefix}:{secrets.token_hex(4)}"
