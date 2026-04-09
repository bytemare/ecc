# ecc - Elliptic Curve Groups
[![CI](https://github.com/bytemare/ecc/actions/workflows/wf-analysis.yaml/badge.svg)](https://github.com/bytemare/ecc/actions/workflows/wf-analysis.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/ecc.svg)](https://pkg.go.dev/github.com/bytemare/ecc)
[![codecov](https://codecov.io/gh/bytemare/ecc/branch/main/graph/badge.svg?token=5bQfB0OctA)](https://codecov.io/gh/bytemare/ecc)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/bytemare/ecc/badge)](https://scorecard.dev/viewer/?uri=github.com/bytemare/ecc)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/9521/badge)](https://www.bestpractices.dev/projects/9521)

```Go
  import "github.com/bytemare/ecc"
```

High-level Go wrapper for multiple elliptic curve groups. The package unifies scalar, element, and hash-to-curve ([RFC 9380](https://datatracker.ietf.org/doc/rfc9380)) operations behind a single API so callers can swap groups with minimal code changes while relying on common and secure backends of well-maintained cryptographic libraries.

You don't have to care about the parameters and the specifics of each group or backend. Simply pick a Group identifier to get scalars and elements and perform operations.

## Elliptic Curve Groups

The following table shows supported groups with hash-to-curve capability and links each one to the underlying
implementations:

| ID | Name         |  Prime-order   | Backend                       | Encoding Endianness |
|:--:|--------------|:--------------:|-------------------------------|---------------------|
| 1  | Ristretto255 |       ✓        | github.com/gtank/ristretto255 | little-endian       |
| 3  | P-256        |       ✓        | filippo.io/nistec             | big-endian          |
| 4  | P-384        |       ✓        | filippo.io/nistec             | big-endian          |
| 5  | P-521        |       ✓        | filippo.io/nistec             | big-endian          |
| 6  | Edwards25519 | ✗ (cofactor 8) | filippo.io/edwards25519       | little-endian       |
| 7  | Secp256k1    |       ✓        | github.com/bytemare/secp256k1 | big-endian          |

Some identifiers are reserved for future use, waiting for compatible, stable, and secure implementations to become available (e.g. Curve25519, Decaf448, Double-Odd).

### Documentation [![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/ecc.svg)](https://pkg.go.dev/github.com/bytemare/ecc)

You can find the documentation and usage examples in [the package doc](https://pkg.go.dev/github.com/bytemare/ecc) and [the project wiki](https://github.com/bytemare/ecc/wiki).

### Identity / Point at infinity

Encoding may succeed (e.g., all‑zeros on some curves), but do not feed identity encodings back into decoders.
Decoding the identity/infinity element is rejected across all groups except NIST curves.

### Domain Separation Tags (DST)

DSTs must not be empty, and are recommended to tbe longer than 16 bytes.
You can build DSTs with `Group.MakeDST(app, version)`, which include the group and ciphersuite identifier.

## Versioning

Releases follow [Semantic Versioning](https://semver.org).

---

## Release Integrity (SLSA Level 3)
Releases are built with the reusable [bytemare/slsa](https://github.com/bytemare/slsa) workflow and ship the evidence required for SLSA Level 3 compliance:

- 📦 Artifacts are uploaded to the release page, and include the deterministic source archive plus subjects.sha256, signed SBOM (sbom.cdx.json), GitHub provenance (*.intoto.jsonl), a reproducibility report (verification.json), and a signed Verification Summary Attestation (verification-summary.attestation.json[.bundle]).
- ✍️ All artifacts are signed using [Sigstore](https://sigstore.dev) with transparency via [Rekor](https://rekor.sigstore.dev).
- ✅ Verification (or see the latest docs at [bytemare/slsa](https://github.com/bytemare/slsa)):
```shell
curl -sSL https://raw.githubusercontent.com/bytemare/slsa/main/verify-release.sh -o verify-release.sh
chmod +x verify-release.sh
./verify-release.sh --repo <owner>/<repo> --tag <tag> --mode full --signer-repo bytemare/slsa
```
Run again with `--mode reproduce` to build in a container, or `--mode vsa` to validate just the verification summary.

## Contributing and Feedback

Use **GitHub Issues** for bug reports, feature requests, and general feedback. If you have questions about contributing, start with [CONTRIBUTING.md](.github/CONTRIBUTING.md).

In [docs/](docs/) you can also find:
- Architecture and engineering guidelines: [docs/architecture_and_guidelines.md](docs/architecture_and_guidelines.md)
- Security assurance and threat model: [docs/secure_design.md](docs/secure_design.md)
- Roadmap and longer-term goals: [docs/roadmap.md](docs/roadmap.md)
- Governance and releasing processes: [docs/governance.md](docs/governance.md), [docs/releasing.md](docs/releasing.md)

## License

This project is licensed under the [MIT License](LICENSE).

## Citation

If you use this package in academic work, please cite it via [CITATION.cff](CITATION.cff).
