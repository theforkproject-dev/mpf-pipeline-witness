# mpf-pipeline-witness

Independent MPF v0.2 implementation: cryptographic verified observation of external deterministic pipelines.

**Status:** Pre-implementation. See [BUILD_PLAN.md](./BUILD_PLAN.md) for the implementer's reading of MPF v0.2 and the staged plan.

**Conformance target:** [MPF v0.2 draft](https://github.com/amotivv-inc/memory-pod-fabric/blob/main/SPECIFICATION-v0.2-draft.md) at commit `ab5d308`. Conformance class: §20.2 *MPF v0.2 Action Observed Conformant*.

**Profile (proposed):** `mpf.profile.observation.external-pipeline.v0.2-fork`

**Reference target:** Kyle McDonald's [Apocalypse Early Warning System](https://ews.kylemcdonald.net/), used as an upstream observed pipeline. This implementation does not modify or interfere with Kyle's pipeline; it only observes the public artifact it publishes.

## Why

MPF v0.2 specifies a protocol for cryptographically witnessing computational claims. Two reference implementations (one by amotivv as Strata, one by another operator) test that the protocol is real — that it produces interoperable, byte-compatible artifacts across independent operators, not just an internal consistency for a single vendor.

This is the second implementation. It is operated by [theforkproject-dev](https://github.com/theforkproject-dev/) under Fork Node 01's custody.

## Status

| Phase | Status |
|---|---|
| Build plan published | Complete |
| Phase 1 — Foundations | Pending |
| Phase 2 — Registry and admission | Pending |
| Phase 3 — Observer + validator | Pending |
| Phase 4 — Witness + receipt chain | Pending |
| Phase 5 — Certificate bundle | Pending |
| Phase 6 — Verifier | Pending |
| Phase 7 — Public deployment | Pending |
| Phase 8 — Registration PR to MPF IMPLEMENTATIONS.md | Pending |

See [BUILD_PLAN.md](./BUILD_PLAN.md) for the detailed plan including module layout, decision log, and open questions for the working group.

## Provenance

Drafting this implementation included two contributions to the MPF v0.2 spec, both merged:

- [PR #2](https://github.com/amotivv-inc/memory-pod-fabric/pull/2) — Clarify observed-action profile applicability to deterministic pipelines (added §9.4.1, standardized `actor.type` taxonomy, added receipt kinds for observation cycles)
- [PR #4](https://github.com/amotivv-inc/memory-pod-fabric/pull/4) — Make RFC 8785 JCS normative for v0.2 MPF JSON protocol objects (added §2.9, with profile-level escape hatch for future formats)

These PRs were filed by Fork Node 01 from this account before any code was written, to ensure the implementation builds against final spec language. The implementer's reading of the merged spec is captured in [BUILD_PLAN.md §2](./BUILD_PLAN.md#2--reading-of-v02-as-merged).

## License

Apache 2.0. See [LICENSE](./LICENSE).
