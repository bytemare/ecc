# Example: docs/security_model.md (bytemare/ecc) — Minimal pattern

# Security model

## 1. Overview
- Project: ecc
- Purpose: elliptic-curve cryptography primitives and scalar/point operations used as building blocks for higher-level protocols.
- Security-critical scope:
  - scalar arithmetic, point arithmetic, encoding/decoding, and scalar multiplication for supported curves.
- Out of scope / non-goals:
  - Side-channel resistance beyond what is explicitly stated as constant-time/secret-independent.
  - Protection against physical attacks, fault injection, or microarchitectural leakage beyond the project’s explicit constant-time scope.

## 2. Threat model (short)
### 2.1 Assets
- Secret scalars (private keys, ephemeral secrets)
- Intermediate field/scalar values derived from secrets
- Protocol correctness and signature/key agreement security assumptions (as applicable)

### 2.2 Trust boundaries
- Inputs from callers are untrusted (public keys, points, encoded byte strings).
- Dependency boundary: Go toolchain + selected dependencies (if any) are trusted within the stated versions.

### 2.3 Attacker model and assumptions
Attacker capabilities:
- Provides chosen inputs to public APIs (malformed points/encodings, edge-case scalars).
- Observes outcomes and may measure timing remotely; may also measure timing locally in some deployments.

Assumptions:
- Built with supported Go versions as documented in README/releasing.md.
- Callers follow API requirements (e.g., do not reuse nonces if any API exposes nonce-based operations; validate caller responsibilities as documented).
- Constant-time claims apply only to the functions and secrets explicitly listed below (and may be architecture/toolchain dependent).

## 3. Security guarantees
- G1 (Top claim): ecc provides correct elliptic-curve operations for supported curves and aims to minimize side-channel leakage for operations documented as secret-independent, within the stated scope and assumptions.
- G2 (Correctness): operations match the curve/group specifications and implemented algorithms, validated through tests and vectors.
- G3 (Secret-independence / constant-time): operations handling secret scalars avoid secret-dependent branches and memory access patterns where documented as constant-time, within the project’s defined scope.
- G4 (Robustness): decoding/validation rejects malformed inputs or fails safely (errors) without panics for expected invalid inputs.
- G5 (Release integrity): releases provide consumers with verifiable integrity metadata (SBOM/provenance/checksums) and a documented release process.

## 4. Assurance case (Claims → Evidence map)

| Claim | What it means (scope) | How to verify (evidence pointers) |
|------:|------------------------|-----------------------------------|
| G2 | Implementations behave according to the intended math/spec for supported curves and encodings. | Repo: `testdata/` vectors (if present), unit tests in `*_test.go`. CI: `.github/workflows/ci.yml` runs `go test ./...` (and any vector tests). |
| G3 | For documented secret-bearing operations, control flow and memory access do not depend on secrets (as defined here), within stated assumptions. | Design note: `docs/security_model.md` (this section) + any `docs/side_channels.md` if present. CI: `.github/workflows/ct.yml` (if present) and `.github/workflows/ci.yml` for targeted tests. Constraints: claims apply only to functions explicitly listed in README/docs. |
| G4 | Invalid inputs are handled safely and consistently (error returns, no undefined behavior). | Repo: negative tests in `*_test.go`; fuzz harnesses in `fuzz/` or `internal/fuzz/` (if present). CI: `.github/workflows/fuzz.yml`. |
| G5 | Release artifacts are accompanied by integrity/provenance metadata and reproducible or verifiable build information where supported. | Process: `docs/releasing.md`. CI: `.github/workflows/release.yml` attaches assets to GitHub Releases. Release page assets: `sbom.spdx.json`, `provenance.intoto.jsonl`, `checksums.txt`, `build-info.txt`. |

## 5. Evidence: how to verify (operational)

### 5.1 CI workflows (source of truth)
- Correctness / unit tests: `.github/workflows/ci.yml`
- Static analysis (vet/staticcheck/govulncheck): `.github/workflows/analysis.yml`
- Fuzzing: `.github/workflows/fuzz.yml`
- Constant-time / secret-independence checks (if enabled): `.github/workflows/ct.yml`
- Release pipeline: `.github/workflows/release.yml`

### 5.2 Release assets (snapshotted evidence)
For each tag `vX.Y.Z`, the GitHub Release includes:
- `checksums.txt`
- `sbom.spdx.json`
- `provenance.intoto.jsonl`
- `build-info.txt`

Consumers can verify:
- the tag corresponds to the published source,
- release assets match checksums,
- provenance references the release build inputs and outputs (per your chosen provenance format).

## 6. Residual risks and limitations
- R1: Constant-time/secret-independence claims are scoped; functions not explicitly covered are not claimed constant-time.
- R2: Behavior depends on toolchain/architecture assumptions; changes in compiler/codegen may require re-validation.

## 7. Security reporting
See `SECURITY.md`.
