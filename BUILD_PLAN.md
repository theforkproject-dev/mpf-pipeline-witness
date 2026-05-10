# Build Plan — MPF v0.2 Pipeline Witness

**Author:** Fork Node 01
**Date:** May 9, 2026
**Status:** Phases 1–6 complete. Phases 7 (deployment), 8 (registration PR), and 9 (refactor to `mpf-implementer-template`) deferred and committed. Last updated: May 9, 2026 end of session, commit `9ff787b`.
**Conformance target:** [MPF v0.2 draft](https://github.com/amotivv-inc/memory-pod-fabric/blob/main/SPECIFICATION-v0.2-draft.md) at commit `ab5d308`
**Conformance class:** §20.2 *MPF v0.2 Action Observed Conformant*
**Profile ID (proposed):** `mpf.profile.observation.external-pipeline.v0.2-fork`

---

## 1 — Purpose

This document is the implementer's reading of MPF v0.2 as merged at commit `ab5d308`, plus the build plan for an independent implementation that will sit alongside amotivv's Strata as the second registered implementation of the protocol.

The implementation produces verified observations of external deterministic pipelines (the case formalized in §9.4.1 and resolved by issues #1/#3 and PRs #2/#4). The reference target is Kyle McDonald's Apocalypse Early Warning System (`ews.kylemcdonald.net`), but the implementation is generic over any deterministic pipeline whose published artifact is publicly addressable.

### 1.1 What this implementation IS

- A scheduled observer that fetches a public artifact at a declared cadence
- A canonical receipt log producing JCS-canonicalized, Ed25519-signed receipts per §10.1 and §2.9
- An L1 mechanical witness that signs observation/validation subjects per §11.1
- A certificate bundle assembler producing v0.2-conformant bundles per §13
- A public verifier endpoint per the §20.2 conformance class and §14 verifier inputs
- Intended to be byte-compatible with amotivv's Strata under the same profile, per the §2.9 interoperability rationale

### 1.2 What this implementation IS NOT

- Not a gateway for agent-initiated actions. No intent grants, no capability tokens, no agent intent layer (§9.4.1 explicitly excludes `intent.attested` from observation profiles).
- Not a policy witness. L2 is optional in §9.4.1 and excluded from MVP scope.
- Not a domain attestor. L3 is out of scope.
- Not a memory pod. Memory operations (§7.1) are not exposed.
- Not Strata. This is a separate implementation from a separate operator (theforkproject-dev), built to test that v0.2 is a real protocol rather than a single-implementation specification.

---

## 2 — Reading of v0.2 As Merged

This section captures the implementer's interpretation of the spec surfaces this implementation has to satisfy. If interpretation differs from intent, the implementation is wrong; the spec is authoritative.

### 2.1 Conformance class (§20.2)

> *An implementation is action observed conformant if it supports action registry binding, receipt logs, witnessed intent or intent attestation, observed execution evidence, certificate bundles, and verifier reports that do not claim tool-side token enforcement.*

For an observation profile (§9.4.1), "witnessed intent or intent attestation" is satisfied by the Admission Manifest plus cadence declaration, since observation profiles MUST NOT require `intent.attested`. The implementer's reading: "witnessed intent" is the L1-witnessed `observation` subject; the "intent" being witnessed is the gateway's commitment to an observation cycle, not an agent's intent to act.

### 2.2 Observation profile declarations (§9.4.1)

The profile MUST declare, at minimum:

| Field | This implementation's value |
|---|---|
| `capability_token_enforced` | `false` |
| `actor.type` | `external_pipeline` |
| Source identity binding | `source_url`, `expected_schema_digest`, `pipeline_identity` (GitHub repo + commit), `provider_storage_identity` (the R2 bucket prefix) |
| Observer code identity | SHA-256 of the observer module bytes; pinned to git commit |
| Validator code identity | SHA-256 of the validator module bytes; pinned to git commit |
| Cadence | 30 minutes, aligned with upstream's heatmap cadence |
| Retention mode | Raw bytes retained for higher assurance (§9.4.1 SHOULD for higher-assurance profiles since public URLs are mutable) |
| Failure-mode handling | Documented receipt kinds: `source.unavailable`, `validation.failed`, `validator.exception`, `bytes.changed_in_interval` (per §10.2 as updated in PR #2) |

### 2.3 Receipt requirements (§10.1, §10.3)

Each receipt MUST include: schema version, receipt kind, session ID or operation ID, sequence or step index, previous state root, actor, body, issued timestamp, signature set, resulting state root.

For `mpf-0.2` baseline conformance, the receipt payload digest is computed over the JCS-canonicalized receipt JSON per §2.9 (added in PR #4).

State root = `H(prev_state_root || H(JCS(receipt_payload)) || H(signature_set))` where `H` is SHA-256. The spec says "recomputable from … under the declared canonicalization profile" but does not normatively specify the combination function. The implementation MUST document its state-root construction so verifiers can recompute. Open question: *is the state-root construction itself profile-defined, or normatively specified somewhere I missed?* See §6 below for open questions to raise upstream.

### 2.4 Receipt flow for one observation cycle (§9.4.1)

```
session.start
  -> data.request          (observer issues fetch against source URL)
  -> data.response         (observer commits to fetched bytes by digest)
  -> validation.result     (validator commits to declared-invariant outcomes)
  -> observation           (witness signs the observation subject)
  -> session.end
  -> checkpoint            (gateway publishes certificate bundle)
```

This is the recommended flow. The implementation follows it as-is for MVP.

### 2.5 Canonicalization (§2.9)

JCS (RFC 8785) for all MPF JSON protocol objects: receipts, certificates, registry JSON, witness subjects, admission manifests. Non-JSON artifacts (raw fetched bytes, signatures, transparency entries) are digested as-received.

JCS implementation: `rfc8785` (Python package, RFC 8785-compliant). Selected because (a) it is a pure-Python reference implementation of RFC 8785, (b) it is widely used and tested, (c) it produces deterministic output a Strata verifier can recompute.

### 2.6 Witness Network (§11.1, §11.4)

L1 mechanical witness signs observation/validation subjects. JCS-canonicalized. Anti-equivocation state for guard keys.

For the MVP, the witness is a co-resident process on the same node as the observer. **This is a deliberate weakness:** §11.5 (operator independence) and §20.5 (cross-boundary conformant) require independent witnesses for higher assurance profiles. MVP is `observed-l1`-equivalent; cross-boundary conformance is a future iteration.

Witness key authorization comes from a signed Witness Registry Epoch (§11.4). The registry is self-signed by Fork Node 01's identity key for v1; future versions can introduce independent registry custody.

### 2.7 Certificate Bundle (§13)

Required bundle artifacts for this profile (subset of §13.2 list):

- `certificate.json` — the summary, JCS-canonicalized, digested
- `receipts.jsonl` — one receipt per line, each line a JCS-canonicalized JSON object
- `keyring.json` — public keys for observer, validator, witness, signing key chain
- `action-registry.json` — the registry epoch declaring `pipeline.snapshot.observe.v1`
- `witness-registry-epoch.json` — the witness registry epoch authorizing the L1 witness key
- `admission-manifest.json` — observer code digest, validator code digest, source URL, cadence, expected schema, pipeline identity, verifier profile (per §3.14 and §9.4.1)
- `checkpoint.json` — gateway checkpoint publishing the bundle
- `verification.json` — verifier output for self-test, for human readability
- `replay.json` — instructions for an independent verifier to reproduce the certificate

NOT included (per §13.2 SHOULD-when-required): policy-bundle, policy-decision, operator-registry (for MVP a single operator is the implementation owner), substrate-attestation, domain-attestation, transparency-log.

The certificate digest is the SHA-256 of the JCS-canonicalized `certificate.json` per §13.1 (PR #4 update).

### 2.8 Verification (§14)

The implementation MUST also publish a verifier that satisfies §14.2 required checks. Open question: *can the verifier endpoint itself be co-resident with the gateway, or is independence required for the §20.2 conformance class?* My reading of §20.2 is that independent verifier operation is a §20.5 (cross-boundary) requirement, not a §20.2 (action observed) requirement. MVP keeps verifier co-resident; cross-boundary independence is future work.

---

## 3 — Architecture

```
┌───────────────────────────────────────────────────────────────────────┐
│  Upstream (out of scope, not modified)                                │
│  Kyle McDonald's EWS pipeline                                         │
│  - publishes dashboard.json @ R2 R/O public URL, 30 min cadence       │
└───────────────────────────────────────────────────────────────────────┘
                              │
                              │  HTTP GET (publicly fetched)
                              ▼
┌───────────────────────────────────────────────────────────────────────┐
│  This implementation (mpf-pipeline-witness)                           │
│                                                                       │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐               │
│  │   Observer   │──▶│   Validator  │──▶│   Gateway    │               │
│  │              │   │              │   │              │               │
│  │ fetch+digest │   │ deterministic│   │ assembles    │               │
│  │              │   │ invariants   │   │ receipts +   │               │
│  │              │   │              │   │ certificate  │               │
│  └──────────────┘   └──────────────┘   └─┬────────────┘               │
│                                          │                            │
│                                          ▼                            │
│                                ┌──────────────────┐                   │
│                                │  L1 Witness      │                   │
│                                │  (co-resident)   │                   │
│                                │  signs subjects  │                   │
│                                └─────┬────────────┘                   │
│                                      │                                │
│                                      ▼                                │
│                            ┌─────────────────────┐                    │
│                            │  Receipt Log        │                    │
│                            │  SQLite + JSONL     │                    │
│                            │  state-root chain   │                    │
│                            └─────┬───────────────┘                    │
│                                  │                                    │
│                                  ▼                                    │
│                            ┌─────────────────────┐                    │
│                            │  Bundle Assembler   │                    │
│                            │  certificate.json   │                    │
│                            │  + 8 artifacts      │                    │
│                            └─────┬───────────────┘                    │
│                                  │                                    │
│                                  ▼                                    │
│                            ┌─────────────────────┐                    │
│                            │  Public Storage     │                    │
│                            │  (R2 or fork-node)  │                    │
│                            │  bundle.tar.gz      │                    │
│                            └─────────────────────┘                    │
│                                                                       │
│                            ┌─────────────────────┐                    │
│                            │  Verifier Endpoint  │                    │
│                            │  (FastAPI)          │                    │
│                            │  GET /verify/:id    │                    │
│                            └─────────────────────┘                    │
└───────────────────────────────────────────────────────────────────────┘
```

---

## 4 — Module Layout

```
mpf-pipeline-witness/
├── BUILD_PLAN.md                  # this document
├── README.md                      # to be written
├── pyproject.toml
├── requirements.txt
│
├── src/witness/
│   ├── __init__.py
│   ├── canon.py                   # JCS canonicalization, RFC 8785
│   ├── crypto.py                  # Ed25519 key management, sign/verify, SHA-256
│   ├── observer.py                # HTTP fetch + raw bytes commitment
│   ├── validator.py               # deterministic invariant checks (z-score recompute, archive coherence)
│   ├── witness.py                 # L1 mechanical witness, anti-equivocation guard keys
│   ├── receipts.py                # receipt construction per §10.1, state root chain
│   ├── registry.py                # Action Registry, Witness Registry epochs
│   ├── admission.py               # Admission Manifest assembly
│   ├── certificate.py             # certificate.json assembly per §13.1
│   ├── bundle.py                  # bundle assembly per §13.2 (subset)
│   ├── gateway.py                 # orchestrator: runs one observation cycle
│   └── store.py                   # SQLite + filesystem persistence
│
├── src/verifier/
│   ├── __init__.py
│   ├── server.py                  # FastAPI app
│   ├── checks.py                  # §14.2 required checks
│   └── results.py                 # §14.3 result states
│
├── profiles/
│   └── observation-external-pipeline-v0.2-fork.json
│
├── registries/
│   ├── action-registry-genesis.json
│   └── witness-registry-genesis.json
│
├── targets/
│   └── ews-kylemcdonald-business-jet-v1.json   # source URL + expected schema + pipeline identity
│
├── tests/
│   ├── test_canon.py              # JCS round-trip vs. RFC 8785 test vectors
│   ├── test_crypto.py             # signing determinism, verification correctness
│   ├── test_validator.py          # against the captured fixture
│   ├── test_receipt_chain.py      # state root continuity
│   ├── test_bundle.py             # bundle artifact digest correctness
│   ├── test_verifier.py           # end-to-end: fixture → bundle → verifier → verified
│   └── fixtures/
│       └── dashboard-2026-05-09T21:25:18Z.json   # captured during reconnaissance
│
└── scripts/
    ├── run-cycle.py               # one-shot observation cycle (manual)
    ├── run-loop.py                # scheduled loop (PM2 or systemd entry)
    └── verify-bundle.py           # CLI verifier for sanity checks
```

---

## 5 — Implementation Phases

### Phase 1 — Foundations (no observation cycle yet)

**✅ Done** · commit `218a171` · 48 tests

Build and test the primitives in isolation. No I/O, no real network.

- [ ] `canon.py` with JCS via `rfc8785` package + round-trip tests against published RFC 8785 vectors
- [ ] `crypto.py` with Ed25519 key generation, signing, verification, SHA-256 digest helpers
- [ ] Receipt schema in `receipts.py` per §10.1; state-root chain construction
- [ ] Tests for canonical determinism: same JSON input ⇒ same bytes ⇒ same digest ⇒ same signature

**Done when:** `pytest` passes, JCS test vectors produce expected output, signing/verification round-trips cleanly.

### Phase 2 — Registry and admission

**✅ Done** · commit `db61c65` · +37 tests

- [ ] Genesis Action Registry epoch declaring `pipeline.snapshot.observe.v1`, signed
- [ ] Genesis Witness Registry epoch authorizing the L1 witness key
- [ ] Admission Manifest assembly per §3.14 + §9.4.1 binding requirements
- [ ] Profile JSON file declaring `mpf.profile.observation.external-pipeline.v0.2-fork`

**Done when:** registries verify against their own signatures, admission manifest binds all required fields, profile is loadable.

### Phase 3 — Observer + validator

**✅ Done** · commit `b3444e2` · +25 tests

- [ ] HTTP fetch with retries, byte-exact commitment
- [ ] Validator: z-score reproducibility check, archive coherence check, sample count, coverage percentage (the five checks already implemented in reconnaissance)
- [ ] Pinned validator code digest (SHA-256 of `validator.py` source)
- [ ] Tests against the captured fixture

**Done when:** running observer+validator against the May 9 fixture produces a `validation.result` matching the values in §1.6 of the use-case-3 reconnaissance.

### Phase 4 — Witness + receipt chain

**✅ Done** · commit `6c6c6e6` · +26 tests

- [ ] L1 witness signing observation/validation subjects per §11.1
- [ ] Anti-equivocation guard-key store (`(source_url, observed_timestamp)` chosen from §9.4.1's options)
- [ ] Full receipt sequence (`session.start` → `checkpoint`) for one cycle
- [ ] State-root continuity tests across multiple cycles

**Done when:** a complete one-cycle receipt log writes, state roots chain correctly, witness signatures verify.

### Phase 5 — Certificate bundle

**✅ Done** · commit `c18efc4` · +11 tests

- [ ] Bundle assembler producing the eight artifacts in §2.7 above
- [ ] All JSON artifacts JCS-canonicalized
- [ ] Bundle digest computation
- [ ] Bundle persisted as `bundle.tar.gz` plus manifest

**Done when:** running gateway against one cycle produces a complete v0.2-conformant bundle.

### Phase 6 — Verifier

**✅ Done** · commit `9ff787b` · +14 tests

- [ ] FastAPI app implementing §14.2 required checks
- [ ] CORS-open responses
- [ ] CLI verifier (`scripts/verify-bundle.py`)
- [ ] §14.3 result states returned correctly

**Done when:** the verifier checks a freshly-produced bundle and returns `verified` (or `verified_with_warnings` if any §13 SHOULD artifacts are absent).

### Phase 7 — Public deployment

**⏸ Pending** · deferred for next session (deployment realities dominate code time)

- [ ] Observer loop wired to fork-node `create_task` recurrence at `interval_minutes: 30`
- [ ] Public storage for bundles (R2 or fork-node nginx, CORS-open)
- [ ] Public verifier endpoint
- [ ] Public landing page at the configured subdomain

**Done when:** at least one bundle is publicly fetchable + verifiable end-to-end by an independent party.

### Phase 8 — Conformance evidence + IMPLEMENTATIONS.md PR

**⏸ Pending** · requires Phase 7 deployed and ≥24h of public bundles

- [ ] At least 24 hours of running cycles producing bundles
- [ ] Public verification evidence URL
- [ ] PR to `amotivv-inc/memory-pod-fabric/IMPLEMENTATIONS.md` per the documented registration process

**Done when:** the registration PR is merged and the implementation appears in `IMPLEMENTATIONS.md` as the second registered v0.2 implementation.

### Phase 9 — Refactor to `mpf-implementer-template`

**⏸ Pending** · starts only after Phase 8 (registered reference implementation in place)

Most of the work in Phases 1–6 is one-time work that should not need to be repeated by future v0.2 implementers. This phase extracts the reusable core into a separate template repository so the cost of building a third or fourth v0.2 implementation drops from ~20–30 hours to ~3–5 hours (write a custom validator + observer, capture a fixture, run the template's test suite).

**Why this happens after Phase 8, not before:**

- Phase 7 (public deployment) will surface details about the FastAPI endpoint shape and run-loop scheduler integration that the template should encode. Extracting before Phase 7 means redoing parts of the template later.
- A template that ships *before* any implementation is registered is lower-credibility than one that ships *after*. "Here is the template; here is the registered reference implementation that uses it" is stronger than "here is a template; trust me it works."
- The registration PR itself benefits from having the reference implementation feel real and used before being held up as a model.

**Scope:**

- New repo: `theforkproject-dev/mpf-implementer-template` (Apache 2.0, public).
- Extract reusable modules into a `mpf_witness_core` package:
  - `canon` (JCS + NaN guard) — reusable verbatim
  - `crypto` (Ed25519 + ed25519:&lt;b64&gt; format) — reusable verbatim
  - `receipts` (§10.1 schema + state-root chain + `verify_receipt` with `external_subjects`) — reusable verbatim
  - `witness` (L1Witness + GuardKeyStore + anti-equivocation) — reusable verbatim
  - `registry` (Action / Witness epoch construction) — reusable with implementer providing the action entry contents
  - `admission` (Admission Manifest builder) — reusable with implementer providing source-identity binding
  - `bundle` (12-artifact assembly) — reusable with implementer providing actor type, upstream identity, warnings
  - `gateway_base` (Gateway base class implementing the §9.4.1 flow) — reusable; implementer subclasses to plug in observation_subject construction
- Extract verifier as `mpf_verifier` package — reusable verbatim, including the eight §14.2 checks and the CLI entrypoint.
- Implementer-facing surface: a `impl_yourname/` directory with placeholder `observer.py`, `validator.py`, `profile.py` and TODO markers showing exactly what to fill in.
- Approximately 131 of the 161 tests parameterize cleanly across implementations; the implementer adds 25–30 implementation-specific tests (their validator invariants, their end-to-end with their captured fixture).
- Top-level `STAGES.md` guide drawn from this BUILD_PLAN, generalized: not "how I built EWS observation" but "how to build any v0.2 observation profile," with the gotchas surfaced explicitly (witness-signs-canonical-subject architecture, certificate self-digest pattern, validation-failure-still-completes-the-chain rule, surrogate-pair fixture trap, etc.).

**Validation criterion:** the original `mpf-pipeline-witness` repo can be re-expressed as `mpf-implementer-template` plus an `impl_ews/` package of about 400–700 lines, and the test suite passes against the re-expressed implementation. If the extraction can't be done cleanly, the template isn't ready.

**Done when:**

- `mpf-implementer-template` is public, Apache 2.0, with a working example `impl_ews/` reference.
- The template README explains the implementer surface in &lt;30 minutes of reading.
- A `STAGES.md` guide captures the meta-process (contribute upstream first, pin choices and document, separate verifier from producer, test against real captured fixtures, fail loudly on validation, log open questions instead of guessing).
- The four open questions in §6 below are landed as v0.2.1 clarification PRs upstream so future implementers don't hit the same ambiguities.

**Estimated effort:** ~4–6 hours refactoring + 2–3 hours STAGES.md + 1–2 hours per upstream clarification PR. Roughly a full focused day.

---

## 6 — Open Questions To Raise Upstream

These are spec ambiguities the implementer's reading surfaced. They do not block MVP — defaults and assumptions are documented above — but they're worth raising for v0.3 work or for the working group's awareness.

1. **State-root construction.** §10.3 says "recomputable from previous state root, receipt payload digest, and receipt signatures under the declared canonicalization profile" — but does not specify the combination function. My implementation uses `SHA-256(prev_state_root || SHA-256(JCS(receipt)) || SHA-256(canonical(signature_set)))`. Two independent implementations could pick different combination orders or functions and both technically conform while producing incompatible chains. Worth a clarification PR if the working group has a canonical answer in mind. **(Issue candidate after MVP.)**

2. **Profile naming for non-agent observation.** §15 defines `mpf.profile.action.observed-l1.v0.2` as "observed agent actions." The MVP profile name `mpf.profile.observation.external-pipeline.v0.2-fork` falls under the §2.9 escape hatch (must be explicitly declared, MUST NOT claim baseline `mpf-0.2` conformance for objects using non-baseline canonicalization — but I'm using JCS, so this is fine for canonicalization). Worth raising whether non-agent observation should have a standardized profile ID in §15 rather than a per-implementation-named profile. **(Issue candidate.)**

3. **Verifier endpoint independence.** §20.5 names independent verifier operation for cross-boundary conformance. §20.2 for action observed conformance does not. Worth confirming MVP's co-resident verifier is admissible for §20.2 registration, or whether IMPLEMENTATIONS.md registration requires §20.5 minima. **(Likely a comment on the registration PR rather than a separate issue.)**

4. **Replay artifact contents.** §13.2 lists `replay.json` as a SHOULD artifact but does not specify its contents. My current plan: instructions for an independent verifier to reproduce the certificate (source URL, fetch time, observer code digest with link to commit, validator code digest with link to commit, expected JCS digest of the bundle). Worth confirming this is the working group's intent. **(Comment on registration PR.)**

---

## 7 — What's Out Of Scope For MVP

To keep the build disciplined and the registration PR small, MVP excludes:

- Multiple independent witnesses (single co-resident L1 witness)
- L2 policy witness (optional in §9.4.1)
- L3 domain attestor (out of scope per §1.2)
- TEE substrate attestation (§19) — not required for §20.2
- Public transparency log (§18) — required for §20.5, not §20.2
- Memory operations (§7.1) — implementation does not expose memory
- Multiple observation targets — MVP observes only Kyle's EWS dashboard
- Historical backfill — MVP starts from cycle 1, no attempt to retroactively witness older snapshots
- Bundle sharding or large-evidence external_ref — MVP keeps full bytes inline for higher assurance
- Witness-independent fetch (§9.4.1's stronger-evidence option) — co-resident witness signs observer's digest

These are post-registration iteration targets, not v1 commitments.

---

## 8 — Decision Log (Profile-Defined Items)

§9.4.1 explicitly leaves several items to verifier-profile choice. The MVP profile pins the following:

| Item | MVP profile choice | Rationale |
|---|---|---|
| Guard-key semantics for recurring observations | `(source_url, observed_timestamp)` | Matches the natural shape of an observation cycle; observed_timestamp comes from upstream's `current.asOf` field, providing a stable upstream-supplied identifier. |
| Witness independent fetch | Not required (co-resident witness signs observer digest) | MVP is `observed-l1`-class, not `cross-boundary`. Witness independence is a §20.5 concern. |
| Retention mode | Raw bytes retained | §9.4.1 SHOULD for higher-assurance; public R2 URLs are mutable, so digest+URL is insufficient for replay. |
| Validator code identification | SHA-256 of `validator.py` source bytes, pinned to git commit | Simplest defensible approach; image digest or WASM digest are post-MVP. |

These are explicit choices, not silences. A future profile that disagrees can pin different values and both implementations remain v0.2-conformant.

---

## 9 — Estimated Effort

Honest estimate, not a commitment:

| Phase | Hours |
|---|---|
| 1 — Foundations | 3 |
| 2 — Registry and admission | 2 |
| 3 — Observer + validator | 2 |
| 4 — Witness + receipt chain | 3 |
| 5 — Certificate bundle | 3 |
| 6 — Verifier | 4 |
| 7 — Public deployment | 3 |
| 8 — Registration PR | 1 |
| **Total** | **~21 hours** |

Three to four focused work sessions. Probably across a week, not a single push.

Lines of code estimate: 1500-2000 (significantly larger than my earlier 530-LOC estimate for a freelance receipt schema, because v0.2 has more surface).

---

## 10 — Credits And Provenance

This implementation builds on:

- **MPF v0.2 specification** by amotivv, inc. and the MPF working group, published at `github.com/amotivv-inc/memory-pod-fabric` under Apache 2.0
- **PR #2** (commit `1bc7f31`) — observed-action profile clarification for deterministic pipelines, drafted by Fork Node 01, reviewed and merged by amotivv
- **PR #4** (commit `ab5d308`) — RFC 8785 JCS made normative, drafted by Fork Node 01, reviewed and merged by amotivv
- **The reference target** is Kyle McDonald's Apocalypse Early Warning System (`ews.kylemcdonald.net`, GitHub `kylemcdonald/ews`), used here only as an upstream observed pipeline. This implementation does not modify, fork, or interfere with Kyle's code.

This implementation is operated by **theforkproject-dev**. The signing keys and witness keys for this implementation are under Fork Node 01's custody. The implementation is independent of amotivv and any conformance claims it makes are subject to independent verification per §20.2 and the registration bar in `IMPLEMENTATIONS.md`.

---

*End of build plan. No code has been written against this plan yet. The build begins after this document is committed and reviewed.*
