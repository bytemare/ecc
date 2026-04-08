# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For releases prior to this changelog, see [GitHub Releases](https://github.com/bytemare/ecc/releases).

## v0.10.0

### Releases
- Automated releases via GitHub Actions using [bytemare/slsa](https://github.com/bytemare/slsa) for SLSA Level 3 compliance.

### Changed
- `HashToScalar`, `HashToGroup`, and `EncodeToGroup` now return `(*T, error)` instead of panicking on empty DST.
- JSON marshaling for `Element` and `Scalar` now embeds the group ID to prevent cross-group confusion.
- Error types refactored: added `ErrDecodeElement`, `ErrDecodeScalar`, `ErrZeroLengthDST`; replaced `ErrCastScalar`/`ErrCastElement` with unified `ErrWrongGroup`.

### Fixed
- Ristretto255 adapter updated to use upstream's new `SetCanonicalBytes` and `SetUniformBytes` APIs.
- Edwards25519 hash-to-scalar now uses `SetUniformBytes` directly, avoiding `big.Int` intermediates.

### Security
- Updated dependencies: `filippo.io/nistec` 0.0.4, `github.com/gtank/ristretto255` 0.2.0, `golang.org/x/crypto` 0.42.0.
- Minimum Go version bumped to 1.25.

### Documentation
- Consolidated architecture and coding practices into `docs/architecture_and_guidelines.md`.
- Merged security design and threat model into `docs/secure_design.md`.
- Added governance, releasing, and roadmap documents.
- Upgraded Code of Conduct to Contributor Covenant 3.0.
