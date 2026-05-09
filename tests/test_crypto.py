"""Tests for `witness.crypto` — Ed25519 keys, signing, verification."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from witness import crypto


def test_generate_keypair_has_correct_sizes():
    kp = crypto.generate_keypair("test-key-1")
    assert len(kp.public_bytes()) == 32
    assert len(kp.private_bytes()) == 32
    assert kp.key_id == "test-key-1"


def test_public_b64_has_prefix():
    kp = crypto.generate_keypair("test-key-1")
    assert kp.public_b64().startswith("ed25519:")


def test_round_trip_save_load(tmp_path: Path):
    kp = crypto.generate_keypair("test-key-1")
    key_path = tmp_path / "k.key"
    crypto.save_private_key(kp, key_path)
    loaded = crypto.load_private_key(key_path, key_id="test-key-1")
    assert kp.public_bytes() == loaded.public_bytes()
    assert kp.private_bytes() == loaded.private_bytes()


def test_save_private_key_is_0600(tmp_path: Path):
    kp = crypto.generate_keypair("test-key-1")
    key_path = tmp_path / "k.key"
    crypto.save_private_key(kp, key_path)
    mode = key_path.stat().st_mode & 0o777
    assert mode == 0o600


def test_load_rejects_wrong_size(tmp_path: Path):
    p = tmp_path / "bad.key"
    p.write_bytes(b"too short")
    with pytest.raises(ValueError, match="Expected 32-byte"):
        crypto.load_private_key(p, key_id="x")


def test_sign_and_verify_round_trip():
    kp = crypto.generate_keypair("k1")
    data = b"hello, mpf"
    sig = kp.sign(data)
    assert len(sig) == 64
    assert crypto.verify_signature(kp.public_key, data, sig)


def test_sign_b64_format():
    kp = crypto.generate_keypair("k1")
    sig_b64 = kp.sign_b64(b"x")
    assert sig_b64.startswith("ed25519:")
    raw = base64.b64decode(sig_b64.split(":", 1)[1])
    assert len(raw) == 64


def test_verify_with_b64_strings():
    kp = crypto.generate_keypair("k1")
    data = b"the witness signs this"
    sig_b64 = kp.sign_b64(data)
    pub_b64 = kp.public_b64()
    assert crypto.verify_signature(pub_b64, data, sig_b64)


def test_verify_rejects_tampered_data():
    kp = crypto.generate_keypair("k1")
    sig = kp.sign(b"original")
    assert not crypto.verify_signature(kp.public_key, b"tampered", sig)


def test_verify_rejects_wrong_key():
    kp1 = crypto.generate_keypair("k1")
    kp2 = crypto.generate_keypair("k2")
    sig = kp1.sign(b"data")
    assert not crypto.verify_signature(kp2.public_key, b"data", sig)


def test_ed25519_signatures_are_deterministic():
    """Ed25519 (RFC 8032) is deterministic: same key + same message = same sig."""
    kp = crypto.generate_keypair("k1")
    data = b"deterministic input"
    sig1 = kp.sign(data)
    sig2 = kp.sign(data)
    assert sig1 == sig2


def test_parse_public_key_handles_bare_base64():
    kp = crypto.generate_keypair("k1")
    bare = base64.b64encode(kp.public_bytes()).decode("ascii")
    parsed = crypto.parse_public_key_b64(bare)
    assert parsed.public_bytes_raw() == kp.public_bytes()


def test_parse_public_key_handles_prefixed():
    kp = crypto.generate_keypair("k1")
    parsed = crypto.parse_public_key_b64(kp.public_b64())
    assert parsed.public_bytes_raw() == kp.public_bytes()


def test_parse_signature_handles_both_forms():
    kp = crypto.generate_keypair("k1")
    sig = kp.sign(b"x")
    bare = base64.b64encode(sig).decode("ascii")
    prefixed = "ed25519:" + bare
    assert crypto.parse_signature_b64(bare) == sig
    assert crypto.parse_signature_b64(prefixed) == sig


def test_random_key_id_is_unique():
    ids = {crypto.random_key_id() for _ in range(100)}
    assert len(ids) == 100  # cryptographically very likely


def test_random_key_id_format():
    kid = crypto.random_key_id("witness")
    assert kid.startswith("witness:")
    assert len(kid.split(":", 1)[1]) == 8
