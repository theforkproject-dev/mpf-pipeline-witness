"""MPF v0.2 verifier for observation profiles.

The verifier takes a bundle directory and recomputes every digest,
signature, state root, and registry binding from the on-disk artifacts.
It does not trust the bundle's self-claimed values; per §14.2, the
verifier MUST recompute rather than trust embedded claims.

Public surface:

    verify_bundle(bundle_dir, verification_time=None) -> VerificationResult
    main()                                            -> CLI entrypoint

The verifier is independent of the witness/gateway side of this codebase.
It only depends on the canon (JCS) and crypto (Ed25519) primitives in
`witness.canon` and `witness.crypto`. A relying party can take this
verifier alone, plus a published bundle, and confirm conformance without
running any of the production witness code.
"""

from .checks import verify_bundle, VerificationResult  # noqa: F401
