# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For releases prior to this changelog, see [GitHub Releases](https://github.com/bytemare/ecc/releases).

## [Unreleased]

## v0.10.0

### Added
- `Scalar.DecodeWithReduction` for reducing oversized scalar inputs modulo the group order during decoding.
- Stronger validation and release automation, including nightly fuzzing, `govulncheck`, dependency review, and a reusable release-verification workflow.

### Releases
- Automated releases via GitHub Actions using [bytemare/slsa](https://github.com/bytemare/slsa) for SLSA Level 3 compliance.

### Changed
- `HashToScalar`, `HashToGroup`, and `EncodeToGroup` now return `(*T, error)` instead of panicking on empty DST.
- JSON marshaling for `Element` and `Scalar` now encodes `{"group": ..., "data": ...}` instead of a bare hex string to prevent cross-group confusion.
- Error types refactored: added `ErrDecodeElement`, `ErrDecodeScalar`, `ErrZeroLengthDST`; replaced `ErrCastScalar`/`ErrCastElement` with unified `ErrWrongGroup`.

### Fixed
- Ristretto255 adapter updated to use upstream's new `SetCanonicalBytes` and `SetUniformBytes` APIs.
- Edwards25519 hash-to-scalar now uses `SetUniformBytes` directly, avoiding `big.Int` intermediates.

### Security
- Updated crypto backends and supporting dependencies
- Minimum Go version bumped to 1.26.

### Documentation
- Consolidated architecture and coding practices into `docs/architecture_and_guidelines.md`.
- Merged security design and threat model into `docs/secure_design.md`.
- Added releasing and roadmap documents, refreshed the README, and added `CITATION.cff`.
