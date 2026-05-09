"""
Canonicalization helpers for MPF v0.2.

Per MPF v0.2 §2.9 (Common Canonicalization), MPF JSON protocol objects that
are hashed, signed, witnessed, included in receipt state-root computation, or
otherwise digested for verification MUST be canonicalized using RFC 8785 JSON
Canonicalization Scheme (JCS) before digest, signature, or state-root
computation.

This module wraps the `rfc8785` package and adds:

  - a strict no-NaN/Infinity guard (RFC 8785 §3.2.2.3 disallows them; we fail
    early rather than letting upstream choices propagate)
  - a SHA-256 helper for canonical bytes (the most common derived value)
  - a `digest_hex` helper for receipt construction

The intent is that no other module in this package serializes JSON for
digesting, signing, or verification. All such surfaces flow through `canon`.

Reference: https://datatracker.ietf.org/doc/html/rfc8785
"""

from __future__ import annotations

import hashlib
import math
from typing import Any

import rfc8785


def _validate_no_nan(obj: Any, path: str = "$") -> None:
    """Recursively reject NaN and Infinity float values.

    JCS does not define a canonical encoding for non-finite floats. Producing
    a signature over a value JCS cannot canonicalize would be incorrect and
    silently divergent across implementations. Fail loudly instead.
    """
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            raise ValueError(
                f"Non-finite float at {path}: {obj!r}. JCS (RFC 8785) does not "
                f"canonicalize NaN or Infinity. Use a different representation "
                f"(string label, JSON null, or omit the field)."
            )
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise ValueError(
                    f"Non-string key at {path}: {k!r}. JCS canonicalizes only "
                    f"objects with string keys."
                )
            _validate_no_nan(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _validate_no_nan(v, f"{path}[{i}]")


def canonicalize(obj: Any) -> bytes:
    """Return the JCS canonical byte sequence for an MPF JSON object.

    Args:
        obj: A JSON-compatible Python value (dict, list, str, int, float, bool, None).

    Returns:
        The RFC 8785 JCS canonical byte sequence as `bytes`.

    Raises:
        ValueError: If the value contains NaN, Infinity, or non-string object keys.
    """
    _validate_no_nan(obj)
    return rfc8785.dumps(obj)


def sha256(data: bytes) -> bytes:
    """SHA-256 digest of `data` as raw 32 bytes."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """SHA-256 digest of `data` as a 64-character lowercase hex string."""
    return hashlib.sha256(data).hexdigest()


def digest(obj: Any) -> bytes:
    """JCS-canonicalize `obj` and return its SHA-256 digest as raw 32 bytes.

    This is the standard MPF v0.2 digest construction for JSON protocol objects:
    JCS-canonicalize, then SHA-256.
    """
    return sha256(canonicalize(obj))


def digest_hex(obj: Any) -> str:
    """JCS-canonicalize `obj` and return its SHA-256 digest as 64-char hex string."""
    return sha256_hex(canonicalize(obj))
