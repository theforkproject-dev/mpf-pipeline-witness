"""Tests for `witness.observer` — HTTP fetch with pinned retry policy."""

from __future__ import annotations

import hashlib

import httpx
import pytest

from witness import observer


# A stable test payload. Hashed once at module import; tests reuse the digest.
PAYLOAD = b'{"hello": "mpf"}'
PAYLOAD_DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


def _client_with_responses(responses):
    """Build an httpx.Client whose transport returns a queue of responses.

    Each `responses` element is either:
      - an httpx.Response (the next call returns it)
      - an Exception subclass instance (the next call raises it)
    """
    queue = list(responses)

    def handler(request):
        if not queue:
            raise AssertionError("test ran out of queued responses")
        item = queue.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_fetch_success_first_attempt():
    client = _client_with_responses([
        httpx.Response(200, content=PAYLOAD, headers={"content-type": "application/json"}),
    ])
    obs = observer.fetch("https://example.test/x.json", client=client)
    assert obs.url == "https://example.test/x.json"
    assert obs.status_code == 200
    assert obs.bytes_length == len(PAYLOAD)
    assert obs.bytes_sha256_hex == PAYLOAD_DIGEST
    assert obs.body == PAYLOAD
    assert obs.attempt_count == 1
    assert obs.content_type.startswith("application/json")


def test_fetch_byte_exact():
    """The observer captures bytes byte-exactly without re-encoding."""
    weird = b"\x00\x01\xff\xfe\x80\x7fbinary\xc3\xa9data"
    client = _client_with_responses([httpx.Response(200, content=weird)])
    obs = observer.fetch("https://example.test/x.bin", client=client)
    assert obs.body == weird
    assert obs.bytes_sha256_hex == hashlib.sha256(weird).hexdigest()


def test_fetch_retries_on_5xx_then_succeeds():
    client = _client_with_responses([
        httpx.Response(503),
        httpx.Response(200, content=PAYLOAD),
    ])
    obs = observer.fetch("https://example.test/x.json", client=client)
    assert obs.attempt_count == 2
    assert obs.status_code == 200
    # First attempt history entry should be the 503
    history = obs.attempt_history
    assert history[0][1] == 503
    assert history[1][1] == 200


def test_fetch_retries_on_transport_error_then_succeeds():
    client = _client_with_responses([
        httpx.ConnectError("test induced"),
        httpx.Response(200, content=PAYLOAD),
    ])
    obs = observer.fetch("https://example.test/x.json", client=client)
    assert obs.attempt_count == 2
    assert "ConnectError" in obs.attempt_history[0][2]


def test_fetch_exhausts_retries_and_raises():
    client = _client_with_responses([
        httpx.Response(503),
        httpx.Response(503),
        httpx.Response(503),
    ])
    with pytest.raises(observer.ObserverError) as exc_info:
        observer.fetch("https://example.test/x.json", client=client)
    err = exc_info.value
    assert err.url == "https://example.test/x.json"
    assert len(err.attempts) == 3
    assert all(a[1] == 503 for a in err.attempts)


def test_fetch_to_receipt_bodies_shape():
    client = _client_with_responses([httpx.Response(200, content=PAYLOAD)])
    obs = observer.fetch("https://example.test/x.json", client=client)
    bodies = observer.fetch_to_receipt_bodies(obs)
    assert set(bodies.keys()) == {"data.request", "data.response"}

    req = bodies["data.request"]
    assert req["url"] == obs.url
    assert req["method"] == "GET"
    assert req["attempt_count"] == 1

    resp = bodies["data.response"]
    assert resp["url"] == obs.url
    assert resp["status_code"] == 200
    assert resp["bytes_length"] == len(PAYLOAD)
    assert resp["bytes_sha256"] == "sha256:" + PAYLOAD_DIGEST
    # CRITICAL: receipt body MUST NOT contain raw bytes. Only the digest.
    assert "body" not in resp
    assert "bytes" not in resp


def test_fetch_to_receipt_bodies_records_full_attempt_history():
    client = _client_with_responses([
        httpx.Response(503),
        httpx.Response(200, content=PAYLOAD),
    ])
    obs = observer.fetch("https://example.test/x.json", client=client)
    req = observer.fetch_to_receipt_bodies(obs)["data.request"]
    assert len(req["attempt_history"]) == 2
    assert req["attempt_history"][0]["status"] == 503
    assert req["attempt_history"][1]["status"] == 200


def test_observer_module_digest_is_stable():
    """The observer module's source digest is reproducible.

    This is the value the admission manifest binds. If the digest changes,
    the admission manifest binding is broken. Sanity-check that we can
    compute it consistently.
    """
    from pathlib import Path
    p = Path(observer.__file__)
    d1 = hashlib.sha256(p.read_bytes()).hexdigest()
    d2 = hashlib.sha256(p.read_bytes()).hexdigest()
    assert d1 == d2
    assert len(d1) == 64
