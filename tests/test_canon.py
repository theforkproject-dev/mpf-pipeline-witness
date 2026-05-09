"""Tests for `witness.canon` — JCS canonicalization."""

from __future__ import annotations

import math

import pytest

from witness import canon


# RFC 8785 example test vectors.
# Source: https://datatracker.ietf.org/doc/html/rfc8785#section-3.2.3
RFC8785_VECTORS: list[tuple[dict, bytes]] = [
    # Section 3.2.3 example: simple ASCII keys, mixed value types, key reordering.
    (
        {"numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 0.000000000000000000000000001],
         "string": "\u20ac$\u000F\u000aA'B\"\\\\\"\u0080\U0001D11E",
         "literals": [None, True, False]},
        b'{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
        b'"string":"\xe2\x82\xac$\\u000f\\nA\'B\\"\\\\\\\\\\"\xc2\x80\xf0\x9d\x84\x9e"}',
    ),
    # Empty object
    ({}, b"{}"),
    # Empty array
    ({"a": []}, b'{"a":[]}'),
]


def test_jcs_simple_object():
    """JCS sorts object keys lexicographically (UTF-16 code points)."""
    obj = {"b": 1, "a": 2}
    assert canon.canonicalize(obj) == b'{"a":2,"b":1}'


def test_jcs_nested_object():
    """JCS recursively sorts nested objects."""
    obj = {"outer": {"z": 1, "a": 2}, "first": True}
    assert canon.canonicalize(obj) == b'{"first":true,"outer":{"a":2,"z":1}}'


def test_jcs_array_order_preserved():
    """JCS preserves array element order (does NOT sort arrays)."""
    obj = {"x": [3, 1, 2]}
    assert canon.canonicalize(obj) == b'{"x":[3,1,2]}'


def test_jcs_unicode_keys():
    """JCS sorts keys by UTF-16 code points, not byte order."""
    # Reference implementation behavior: 'a' < 'z' < 'ä' (U+00E4)
    obj = {"\u00e4": 1, "z": 2, "a": 3}
    canonical = canon.canonicalize(obj)
    # 'a' (0x61) < 'z' (0x7a) < 'ä' (0x00e4 in UTF-16)
    assert canonical == b'{"a":3,"z":2,"\xc3\xa4":1}'


@pytest.mark.parametrize("obj,expected", RFC8785_VECTORS)
def test_jcs_published_vectors(obj, expected):
    """JCS reproduces RFC 8785 published test vectors byte-for-byte."""
    assert canon.canonicalize(obj) == expected


def test_jcs_idempotent():
    """Canonicalizing twice produces the same bytes (JCS is idempotent)."""
    obj = {"hello": "world", "x": [1, 2, 3]}
    once = canon.canonicalize(obj)
    twice = canon.canonicalize(obj)
    assert once == twice


def test_jcs_input_independence():
    """Same logical content produces same canonical bytes regardless of input dict order."""
    a = {"x": 1, "y": 2, "z": 3}
    b = {"z": 3, "y": 2, "x": 1}
    assert canon.canonicalize(a) == canon.canonicalize(b)


def test_reject_nan():
    """NaN must be rejected before canonicalization (RFC 8785 disallows)."""
    with pytest.raises(ValueError, match="Non-finite float"):
        canon.canonicalize({"x": float("nan")})


def test_reject_infinity():
    """Infinity must be rejected before canonicalization."""
    with pytest.raises(ValueError, match="Non-finite float"):
        canon.canonicalize({"x": math.inf})
    with pytest.raises(ValueError, match="Non-finite float"):
        canon.canonicalize({"x": -math.inf})


def test_reject_nan_in_nested_array():
    """Non-finite floats are rejected even in deeply nested positions."""
    with pytest.raises(ValueError, match=r"Non-finite float at \$\.outer\[1\]"):
        canon.canonicalize({"outer": [1.0, float("nan"), 3.0]})


def test_reject_non_string_key():
    """Object keys must be strings (JCS does not canonicalize int keys)."""
    with pytest.raises(ValueError, match="Non-string key"):
        canon.canonicalize({1: "a"})


def test_digest_helpers():
    """`digest` and `digest_hex` are SHA-256 of the canonical bytes."""
    obj = {"a": 1}
    canonical = canon.canonicalize(obj)
    expected_digest = canon.sha256(canonical)
    assert canon.digest(obj) == expected_digest
    assert canon.digest_hex(obj) == expected_digest.hex()
    assert len(canon.digest(obj)) == 32
    assert len(canon.digest_hex(obj)) == 64


def test_digest_stable_across_runs():
    """The same JSON object produces the same digest every time, byte-for-byte."""
    obj = {"timestamp": "2026-05-09T20:59:50Z", "count": 422, "z_score": -1.34}
    digests = {canon.digest_hex(obj) for _ in range(10)}
    assert len(digests) == 1


def test_digest_different_for_different_content():
    """Different content produces different digests (sanity check)."""
    a = {"x": 1}
    b = {"x": 2}
    assert canon.digest(a) != canon.digest(b)
