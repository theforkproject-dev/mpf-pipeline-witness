"""
Observer: fetch a public artifact and commit to its bytes.

The observer is one of two pieces of pinned code in this implementation
(the other being the validator). Per MPF v0.2 §9.4.1 and BUILD_PLAN §8, the
admission manifest binds an `observer_code_digest` that is the SHA-256 of
this module's source bytes. Independent verifiers can re-derive that digest
from this file at the bound git commit and confirm "the observer that
produced these receipts was exactly this code."

Responsibilities:

    1. Fetch a URL with a fixed, documented retry policy.
    2. Capture the raw response bytes byte-exactly.
    3. Capture the wall-clock time of the fetch and the upstream-supplied
       freshness signal where present.
    4. Compute the SHA-256 of the bytes.
    5. Return a structured `ObservationFetch` value the gateway can pass to
       the validator and bind into receipts.

Deliberate limitations:

    - The observer does NOT parse content. It returns raw bytes plus a
      content-type hint. Parsing belongs to the validator.
    - The observer does NOT decide retry policy beyond a small fixed
      schedule. Aggressive retry would distort cadence; aggressive failure
      would lose observations. Three attempts with linear backoff is the
      pinned policy; deviating from it changes the observer code digest.
    - The observer does NOT cache. Each cycle is an independent fetch.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx


# Pinned retry policy. Changing these constants changes the observer code
# digest, which is what we want — verifiers should be able to detect any
# deviation from the documented behavior.
RETRY_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = (1, 3, 7)  # cumulative wait before attempts 2, 3
TIMEOUT_SECONDS = 30.0


@dataclass(frozen=True)
class ObservationFetch:
    """The byte-exact result of a single observer fetch.

    Attributes:
        url: The URL that was fetched.
        fetched_at: ISO-8601 UTC timestamp of when the fetch completed.
        status_code: HTTP status code of the successful response.
        content_type: Server-reported Content-Type header (informational).
        bytes_length: Length of `body` in bytes.
        bytes_sha256_hex: SHA-256 of `body` as 64-char lowercase hex.
        body: The raw response bytes, byte-exact.
        attempt_count: How many fetch attempts were required (1-N).
        attempt_history: Per-attempt status: list of (attempt_n, status_code, error_str_or_None).
    """

    url: str
    fetched_at: str
    status_code: int
    content_type: str
    bytes_length: int
    bytes_sha256_hex: str
    body: bytes
    attempt_count: int
    attempt_history: tuple[tuple[int, int | None, str | None], ...] = field(default_factory=tuple)


class ObserverError(Exception):
    """Raised when all retry attempts fail."""

    def __init__(self, url: str, attempts: list[tuple[int, int | None, str | None]]):
        self.url = url
        self.attempts = attempts
        super().__init__(
            f"observer failed to fetch {url} after {len(attempts)} attempts: "
            f"{attempts!r}"
        )


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fetch(url: str, *, client: httpx.Client | None = None) -> ObservationFetch:
    """Fetch a URL with the pinned retry policy.

    Args:
        url: The URL to fetch.
        client: Optional pre-configured `httpx.Client`. Tests inject a mock
            transport here. Production callers should pass None.

    Returns:
        An `ObservationFetch` with the byte-exact response.

    Raises:
        ObserverError: If every retry attempt fails.
    """
    own_client = client is None
    if own_client:
        client = httpx.Client(timeout=TIMEOUT_SECONDS, follow_redirects=True)

    attempts: list[tuple[int, int | None, str | None]] = []
    body: bytes | None = None
    final_status: int | None = None
    final_content_type: str = ""

    try:
        for attempt in range(1, RETRY_ATTEMPTS + 1):
            if attempt > 1:
                wait = RETRY_BACKOFF_SECONDS[attempt - 2]
                time.sleep(wait)
            try:
                resp = client.get(url)
                if resp.status_code >= 200 and resp.status_code < 300:
                    body = resp.content
                    final_status = resp.status_code
                    final_content_type = resp.headers.get("content-type", "")
                    attempts.append((attempt, resp.status_code, None))
                    break
                else:
                    attempts.append((attempt, resp.status_code, f"HTTP {resp.status_code}"))
            except httpx.HTTPError as e:
                attempts.append((attempt, None, type(e).__name__ + ": " + str(e)))
        else:
            # All attempts exhausted without a 2xx response.
            raise ObserverError(url, attempts)
    finally:
        if own_client:
            client.close()

    assert body is not None and final_status is not None  # for type checker
    fetched_at = _utcnow_iso()
    digest_hex = hashlib.sha256(body).hexdigest()

    return ObservationFetch(
        url=url,
        fetched_at=fetched_at,
        status_code=final_status,
        content_type=final_content_type,
        bytes_length=len(body),
        bytes_sha256_hex=digest_hex,
        body=body,
        attempt_count=len(attempts),
        attempt_history=tuple(attempts),
    )


def fetch_to_receipt_bodies(observation: ObservationFetch) -> dict[str, dict[str, Any]]:
    """Project an ObservationFetch onto the receipt bodies it should produce.

    Returns a dict with two keys: 'data.request' and 'data.response'. Each
    value is the receipt `body` for that receipt kind, ready to embed in
    `receipts.build_receipt_payload`.

    The bodies do NOT include the raw bytes — those are kept out of the
    receipt JSON to keep receipts small and to let the bundle's evidence
    artifact (the raw bytes file) carry the payload separately. The receipt
    binds the bytes by digest only, which is what gives the chain its
    tamper-evidence: changing the bytes changes the receipt body, which
    changes the receipt digest, which breaks the chain.
    """
    return {
        "data.request": {
            "url": observation.url,
            "method": "GET",
            "attempt_count": observation.attempt_count,
            "attempt_history": [
                {"attempt": n, "status": s, "error": e}
                for (n, s, e) in observation.attempt_history
            ],
        },
        "data.response": {
            "url": observation.url,
            "fetched_at": observation.fetched_at,
            "status_code": observation.status_code,
            "content_type": observation.content_type,
            "bytes_length": observation.bytes_length,
            "bytes_sha256": "sha256:" + observation.bytes_sha256_hex,
        },
    }
