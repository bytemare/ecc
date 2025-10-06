# Project Overview

`github.com/bytemare/ecc` provides high-level abstractions for working with multiple elliptic curve groups in Go. It exposes common scalar, element, and hash-to-curve operations through a unified interface while delegating curve-specific logic to optimized backends.

## Goals

- Offer a single package that can switch between supported groups with minimal call-site changes.
- Provide consistent error handling and encoding semantics across backends.
- Adhere to RFC 9380 ciphersuite definitions and domain separation rules.
- Keep dependencies limited to well-maintained cryptographic libraries.

## Module Layout

- `element.go`, `scalar.go`, `groups.go`: Public API and wrapper types that embed backend implementations.
- `internal/`: Curve-specific implementations grouped by backend (`nist`, `ristretto`, `edwards25519`, `secp256k1`). The internal layer satisfies the shared interfaces for elements, scalars, and groups.
- `debug/`: Helpers used in tests for generating malformed inputs.
- `tests/`: Compatibility, encoding, and fuzz tests covering shared behaviors.

## Supported Go Versions

The module is developed using the current stable release, and CI verifies compatibility with the latest 3 stables versions. While other versions may work, they are not part of regular validation.

## Compatibility Policy

- Semantic Versioning governs API stability. Breaking changes require a minor version bump.
- Hash-to-curve implementations follow the latest published RFCs. Updates may occur to track specification changes but will be highlighted in the release changelog.
- Upstream breaking changes in backends are introduced only after evaluation and version pinning.

## Policies

- [Contribution workflow](../.github/CONTRIBUTING.md)
- [Developer Certificate of Origin](../.github/CONTRIBUTING.md#4-commit-standards)
- [Code of Conduct](../.github/CODE_OF_CONDUCT.md)
- [Security assurance case](secure_design.md)
- [Governance](governance)
- [License](../LICENSE)
