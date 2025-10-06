# Roadmap

- explicitly document the panics that my happen when using ecc
- Track and publish long term test metrics (coverage trends, flaky test dashboards).
- Add CI gates for benchmark regressions to detect performance drifts automatically.
- SLSA Level 4 compliance
- Add automated verification that release artifacts match the published provenance (for example verify signatures in CI).
- Nightly Fuzzing.
- Nightly Mutation testing.
- Introduce automated architectural conformance checks (for example static analysis that flags direct backend access outside adapters).
- Expand formal design reviews for new curve integrations and record decisions in the repository.
- edwards25519: hash to curve uses `hash2curve.HashToFieldXMD`, which requires a `big.Int`. We should use a fiat-crypto backed reduction after `hash2curve.ExpandXMD` instead. 
- edwards25519: implement cofactor clearing (e.g., multiply by 8) for identity decoding?
- add support for curve25519
- add edwards448 and decaf448 once they are implemented
- support double-odd
- Secure erasure: add best‑effort memory clearing method for Scalar and Elements, and document GC caveats.
- explore if model‑based tests are feasible and make sense
