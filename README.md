# mpf-pipeline-witness

Independent MPF v0.2 implementation: cryptographic verified observation of external deterministic pipelines.

**Status:** Phases 1–6 complete. Implementation produces v0.2-conformant certificate bundles that an independent verifier accepts end-to-end. Phases 7 (public deployment) and 8 (registration PR) pending.

**Conformance target:** [MPF v0.2 draft](https://github.com/amotivv-inc/memory-pod-fabric/blob/main/SPECIFICATION-v0.2-draft.md) at upstream commit `ab5d308`. Conformance class: §20.2 *MPF v0.2 Action Observed Conformant*.

**Profile (self-declared):** `mpf.profile.observation.external-pipeline.v0.2-fork` (extends `mpf.profile.action.observed-l1.v0.2` per §15)

**Reference observed pipeline:** Kyle McDonald's [Apocalypse Early Warning System](https://ews.kylemcdonald.net/). This implementation does not modify or interfere with Kyle's pipeline; it only observes the public artifact it publishes.

---

## Why

MPF v0.2 specifies a protocol for cryptographically witnessing computational claims. Two implementations (one by amotivv as Strata, one by another operator) test that the protocol is real — that it produces interoperable artifacts across independent operators, not just internal consistency for a single vendor.

This is the second implementation. It is operated by [theforkproject-dev](https://github.com/theforkproject-dev/) under Fork Node 01's custody.

---

## Status

| Phase | Status | Commit | Tests |
|---|---|---|---|
| Build plan published | ✅ done | `80df8a6` | — |
| 1 — Foundations (canon, crypto, receipts) | ✅ done | `218a171` | 48 |
| 2 — Registry & admission | ✅ done | `db61c65` | +37 |
| 3 — Observer & validator | ✅ done | `b3444e2` | +25 |
| 4 — Witness & receipt chain | ✅ done | `6c6c6e6` | +26 |
| 5 — Certificate bundle | ✅ done | `c18efc4` | +11 |
| 6 — Independent verifier | ✅ done | `9ff787b` | +14 |
| 7 — Public deployment (FastAPI, scheduler, R2) | ⏸ pending | — | — |
| 8 — Registration PR to MPF `IMPLEMENTATIONS.md` | ⏸ pending | — | — |
| 9 — Refactor to `mpf-implementer-template` | ⏸ pending | — | — |
| 10 — v0.2.1 spec PRs reducing implementer friction | ⏸ pending | — | — |

**Cumulative:** 6,498 lines of code + tests · 161 tests passing in ~28s · all on `main`.

The single most important property — a bundle produced by this implementation verifies under an independent verifier that does not share state with the producer — is empirically demonstrated. Run `python -m verifier <bundle_dir>` against any bundle this code emits and the result is `verified_with_warnings`, 8/8 checks passing, with the disclosed §11.5 co-resident-witness warning.

See [BUILD_PLAN.md](./BUILD_PLAN.md) for the detailed plan, the implementer's reading of the merged spec, the decision log for profile-defined items, and the open questions for the MPF working group.

---

## Architecture (Phases 1–6)

```
upstream (out of scope, not modified)
    Kyle's EWS pipeline → publishes dashboard.json @ R2 public URL, 30 min cadence
                              ↓ HTTP GET (publicly fetched)
┌────────────────────────────────────────────────────────────────────────────┐
│  PRODUCER · src/witness/                                                   │
│                                                                            │
│  observer ──→ validator ──→ gateway ──→ bundle assembler                   │
│   (fetch)   (5 invariants)  (orchestrate    (12 artifacts,                 │
│              z-score, etc.)  §9.4.1 flow)    JCS-canonical,                │
│                                  ↑          self-digesting cert)           │
│                              witness                                       │
│                              (signs subject                                │
│                              once, anti-                                   │
│                              equivocation                                  │
│                              guard keys)                                   │
│                                                                            │
│  Foundations: canon (RFC 8785 JCS) + crypto (Ed25519) + receipts (chain)   │
│  Bound at admission: registry + witness registry + admission manifest      │
└────────────────────────────────────────────────────────────────────────────┘
                              ↓ writes
                    certificate bundle (12 artifacts on disk)
                              ↓ handed to anyone with no shared state
┌────────────────────────────────────────────────────────────────────────────┐
│  INDEPENDENT VERIFIER · src/verifier/                                      │
│                                                                            │
│  Depends ONLY on canon + crypto. Recomputes every digest, signature,       │
│  state root, and registry binding from on-disk bytes per §14.2.            │
│                                                                            │
│  8 required checks:                                                        │
│    1. certificate_digest      5. session_boundaries                        │
│    2. artifact_digests        6. observation_overclaim                     │
│    3. receipt_chain           7. registry_validity                         │
│    4. signatures              8. admission                                 │
└────────────────────────────────────────────────────────────────────────────┘
                              ↓
                  state ∈ {verified, verified_with_warnings,
                           verified_denial, failed, unverifiable}
```

The receipt cycle (§9.4.1):

```
session.start
  → data.request           (observer issues fetch)
  → data.response          (observer commits to fetched bytes by digest)
  → validation.result      (validator commits to declared-invariant outcomes)
  → observation            (witness signs the observation subject)
  → session.end
  → checkpoint             (gateway publishes certificate bundle)
```

Failure paths (`source.unavailable`, `validator.exception`, `validation.failed`) emit the corresponding receipt kind and still terminate the chain with `session.end` + `checkpoint`. Failures are recorded under the same chain, not silently dropped.

---

## Witness signing model

L1 witnesses sign **canonical protocol subjects**, not arbitrary receipt payloads (per §11.1). One observation cycle produces one *observation subject* — a small stable JSON object that says what was observed:

```json
{
  "schema": "mpf-0.2-observation-subject-v1",
  "source_url": "...",
  "observed_timestamp": "2026-05-09T20:59:50+00:00",
  "bytes_sha256": "sha256:...",
  "validation_passed": true
}
```

The witness signs that subject **once** per cycle. The same `WitnessSignature` is embedded in both the `validation.result` and `observation` receipts. Per-receipt uniqueness lives in the operator's signature on the full receipt payload. This is the architecture that lets two receipts in the same cycle share a guard key without triggering anti-equivocation, and it matches §11.1's wording exactly.

The verifier knows about this: when it verifies a receipt's signature set, it consults the keyring's `role` field. Signatures from `operator` keys are checked against the receipt payload; signatures from `witness_l1` keys are checked against `observation-subject.json`'s bytes.

---

## Bundle layout (§13)

A complete bundle is a directory with 12 artifacts:

```
bundle/
  certificate.json              ← summary, JCS-canonicalized, self-digesting
  receipts.jsonl                ← one receipt per line, JCS-canonicalized
  keyring.json                  ← operator + witness public keys
  action-registry.json          ← bound registry epoch
  witness-registry-epoch.json   ← bound witness registry epoch
  admission-manifest.json       ← bound admission manifest
  checkpoint.json               ← extracted from the receipt chain
  observation-subject.json      ← the witness-signed protocol subject
  observed-bytes.bin            ← raw fetched bytes (evidence_mode=full)
  verification.json             ← self-test result for human readability
  replay.json                   ← independent-verifier reproduction guide
  bundle-manifest.json          ← SHA-256 of every file in the bundle
```

Per §13.1 (PR #4): JSON artifacts are digested over their JCS-canonical form; non-JSON artifacts (raw observed bytes) are digested as-received.

---

## Verifying a bundle

```bash
python -m verifier path/to/bundle/
```

Or programmatically:

```python
from verifier import verify_bundle
result = verify_bundle("path/to/bundle/")
print(result.state)        # "verified_with_warnings"
print(result.summary)      # 8/8 checks passed
```

The verifier package depends only on `witness.canon` (JCS) and `witness.crypto` (Ed25519). It does NOT import the gateway, observer, validator, witness, or bundle modules. A relying party can take `src/verifier/` alone and verify any bundle this codebase emits without trusting the production-side code.

---

## Profile-defined choices

Items §9.4.1 leaves to verifier-profile choice are documented in [`profiles/observation-external-pipeline-v0.2-fork.json`](./profiles/observation-external-pipeline-v0.2-fork.json) and pinned in source:

| Item | This profile's choice | Rationale |
|---|---|---|
| Guard-key semantics | `(source_url, observed_timestamp)` | Upstream-supplied `current.asOf` is a stable per-cycle identifier |
| Witness-independent fetch | `false` | MVP is `observed-l1`-class; independence is §20.5 |
| Retention mode | raw bytes retained | Public URLs are mutable; digest-only would block replay |
| Validator code identification | sha256 of source bytes pinned to git commit | Simplest defensible identity |

A future profile that disagrees can pin different values and remain v0.2-conformant.

---

## Provenance

Drafting this implementation included two contributions to the MPF v0.2 spec, both merged into `amotivv-inc/memory-pod-fabric` before any implementation code was written:

- **[PR #2](https://github.com/amotivv-inc/memory-pod-fabric/pull/2)** (commit `1bc7f31`) — Clarify observed-action profile applicability to deterministic pipelines. Added §9.4.1 covering observation of external deterministic processes; standardized `actor.type` taxonomy (`agent`, `human`, `service`, `external_pipeline`, `code`); added receipt kinds for observation cycles (`observation.request`, `validation.result`, `source.unavailable`, `validation.failed`, `validator.exception`, `bytes.changed_in_interval`).
- **[PR #4](https://github.com/amotivv-inc/memory-pod-fabric/pull/4)** (commit `ab5d308`) — Make RFC 8785 JCS normative for v0.2 MPF JSON protocol objects. Added §2.9 (Common Canonicalization) with profile-level escape hatch; updated §9.2, §10.3, §11.1, §11.2, §13.1; resolved the `JCS everywhere?` open question in §23.

Each PR went through public review by the maintainer (`amotivv`), and the second PR's review caught a real overclaim in the first draft of §3.3 ("the gateway certifies what the agent caused" was tightened to "the certificate proves the request, authorization or attestation, execution or observation, and boundaries required by the profile; it MUST NOT claim causation or control beyond those artifacts"). The exchange itself is part of the public record at `amotivv-inc/memory-pod-fabric/issues` and `/pull`.

The implementer's reading of the merged v0.2 spec is captured in [BUILD_PLAN.md §2](./BUILD_PLAN.md). Open questions surfaced during implementation (state-root construction, profile naming for non-agent observation, verifier endpoint independence requirements, replay artifact contents) are logged in [BUILD_PLAN.md §6](./BUILD_PLAN.md) for future upstream issues.

---

## Running tests

```bash
# from the repo root, using a Python 3.11+ environment with deps installed
pytest tests/
```

Expected output: `161 passed` in roughly 28 seconds. Most of the runtime is parsing the 1.4 MB captured fixture (`tests/fixtures/dashboard-2026-05-09T21-25-18Z.json`, sha256 `e7ca22cbfeb14cc87a2ef9bc9e4f1e10925968b5b109c73f05a427d82cf4d85b`) repeatedly across validator and gateway tests.

---

## License

Apache 2.0. See [LICENSE](./LICENSE).

---

*Implementation drafted by [Fork Node 01](mailto:fork-node-01@theforkproject.com) under operator oversight. Reference observed pipeline credit: Kyle McDonald (`kylemcdonald.net`, GitHub `kylemcdonald/ews`).*
