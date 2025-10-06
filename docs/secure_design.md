# Secure Design and Assurance Case

This document consolidates the threat model, secure design rationale, and assurance arguments for `github.com/bytemare/ecc`. It explains how the library resists misuse and where residual risks remain. For architectural details see [architecture_and_guidelines.md](architecture_and_guidelines.md). For contribution workflow steps see [.github/CONTRIBUTING.md](../.github/CONTRIBUTING.md).

## 1. Threat Model

### 1.1 Assets

- Correct scalar and element computations for every supported group.
- Confidentiality of caller-provided inputs and random material derived by the package.
- Integrity of encoded values that may cross trust boundaries (storage, network, other services).

### 1.2 Trust Boundaries

1. **Caller → Public API**: Callers provide group identifiers, domain separation tags (DST), encoded elements, and scalars.
2. **Public API → Internal adapters**: Validated inputs are delegated to backend-specific adapters implementing `internal.Group`, `internal.Element`, and `internal.Scalar`.
3. **Internal adapters → Third-party backends**: Wrappers rely on vetted external libraries for constant-time arithmetic and hash-to-curve behaviour.

### 1.3 STRIDE Analysis

| Component                                 | Threat                 | Mechanism                                                                     | Likelihood | Impact | Risk   | Mitigations                                                                                             |
|-------------------------------------------|------------------------|-------------------------------------------------------------------------------|------------|--------|--------|---------------------------------------------------------------------------------------------------------|
| Public API (`Group`, `Element`, `Scalar`) | Spoofing               | Caller supplies an unsupported group identifier to coerce a different backend | Low        | High   | Medium | Enum validation rejects unknown identifiers and panics on misuse.                                       |
| Public API                                | Tampering              | Caller passes an empty domain separation tag to bypass protocol separation    | Low        | High   | Medium | `MakeDST` rejects empty tags and formats application details into every DST.                            |
| Public API                                | Tampering              | Caller submits malformed encodings that could slip into backend logic         | Low        | High   | Medium | Decode routines validate length and canonical form before delegating.                                   |
| Public API                                | Repudiation            | Error messages lack clarity, making it hard to trace invalid inputs           | Low        | Medium | Low    | Errors wrap backend context alongside package-level sentinel values.                                    |
| Public API                                | Information Disclosure | Nil operands leak whether a caller forgot to supply values                    | Low        | Medium | Low    | Nil operands are treated as neutral elements without logging, limiting observable differences.          |
| Public API                                | Denial of Service      | Malicious inputs could trigger panics that halt execution                     | Medium     | Medium | Medium | Decode paths prefer returning errors. Panics remain only for configuration mistakes.                    |
| Adapters (NIST)                           | Tampering              | Mixing element types across curves could corrupt arithmetic                   | Low        | High   | Medium | Type assertions ensure operands originate from the same adapter and panic otherwise.                    |
| Adapters (Ristretto and Edwards25519)     | Elevation of Privilege | Accepting identity encodings could enable subgroup or cofactor attacks        | Low        | High   | Medium | Adapters reject identity encodings and enforce explicit error wrapping.                                 |
| Adapters (Secp256k1)                      | Information Disclosure | Encoding identity as zero bytes could leak internal state                     | Low        | Medium | Low    | Identity encodings are normalised and equality checks remain constant-time.                             |
| Hash-to-curve helpers                     | Tampering              | Crafted DST or mapping inputs might yield unintended points                   | Medium     | High   | Medium | RFC 9380 helpers enforce DST format, and test vectors cover expected outputs.                           |
| Randomness routines                       | Spoofing               | Backends could return zero scalars, enabling small-subgroup attacks           | Low        | High   | Medium | Random draws loop until a non-zero scalar is produced. Failures panic instead of returning low entropy. |
| Debug utilities                           | Tampering              | Test fixtures copied into production could bypass validation                  | Low        | Medium | Low    | Helpers live in the `debug/` package and documentation marks them test-only.                            |

Residual risks and assumptions are enumerated in Section 4.

## 2. Assurance Case

**Claim**: The library maintains a secure-by-default posture for supported elliptic-curve operations.

- **Design argument**: Input validation, panic-on-misconfiguration, and adapter isolation enforce invariants before delegating to backends. DST formatting, identity checks, and group-specific adapters implement defence in depth (Section 3).
- **Implementation argument**: Table-driven tests, RFC 9380 vectors, and fuzz suites exercise encode/decode, hashing, and random generation paths. CI integrates linting, `go test`, coverage, `golangci-lint`, `govulncheck`, Semgrep, Sonar, Dependency Review, CodeQL, and OpenSSF Scorecard, providing continuous verification.
- **Operational argument**: Vulnerability reports flow through the private GitHub Security Advisory workflow, providing a confidential path to the maintainer. Releases follow documented steps in [realising.md](releasing.md) ensuring changes are reviewed and tagged with DCO compliance.

## 3. Secure Design Principles

| Principle                | Applied? | Notes                                                                                                                                             |
|--------------------------|----------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| **Fail-safe defaults**   | Yes      | Invalid groups, zero-length DST, and mismatched adapters panic rather than attempt undefined behaviour.                                           |
| **Input validation**     | Yes      | Every public entry point validates inputs before passing to adapters. JSON payloads embed group identifiers to prevent reuse across contexts.     |
| **Least privilege**      | N/A      | Library does not manage permissions or dynamic privileges. Callers integrate it within their own trust models.                                    |
| **Defense in depth**     | Yes      | Adapters layer checks atop backend guarantees (identity rejection, canonical encodings, constant-time equality). CI adds multiple security scans. |
| **Separation of duties** | Partial  | Maintainer currently handles releases and security triage. Governance encourages future delegation as contributors join.                          |
| **Economy of mechanism** | Yes      | Minimal dependency surface (cryptography-focused). Public API remains small and consistent across groups.                                         |
| **Secure defaults**      | Yes      | Random scalars avoid zero, DSTs must be non-empty, identity decoding rejected.                                                                    |
| **Auditability**         | Yes      | Errors contain sentinel values, structured JSON outputs include group metadata, and tests document expected failure modes.                        |

Principles not yet fully addressed (e.g., separation of duties) are tracked on the [roadmap](roadmap.md) for future governance enhancements.

## 4. Common Weakness Coverage

| Weakness                                        | Implemented countermeasures                                                                                                                                                |
|-------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Accepting invalid inputs or malformed encodings | Decode routines validate length and structure. Adapters panic on mismatched groups. Tests include malformed fixtures via `debug/`.                                         |
| Identity or low-order point acceptance          | Cofactor groups reject identity encodings. Random scalar generators loop until non-zero. Adapters enforce constant-time equality.                                          |
| Zero-length or reused DST values                | Hashing to scalars or elements and `MakeDST` rejects empty DSTs and encodes group identifiers to reduce cross-protocol reuse.                                              |
| Insecure randomness                             | Sources rely on `crypto/rand`. Failures cause panics rather than returning low-entropy values.                                                                             |
| Unsupported group usage                         | Enum range checks and panic-on-invalid ID prevent accidental activation of unimplemented curves.                                                                           |
| Side effects leaking secrets through logs       | This modules does not log. Callers control any logging.                                                                                                                    |
| Dependency risks                                | Pinned dependencies, tests cover encoding, fuzzing, specific arithmetic tests, and some attacks, invariable test vectors, automated dependency vulnerability notification. |

## 5. Residual Risks and Assumptions

- No explicit memory clearing is performed. Callers handling long-lived secrets should manage secure buffers.
- The module depends on backend constant-time implementations and does not mitigate system-level side channels (cache, power analysis).
- Panic surfaces for programmer errors (e.g., invalid group) are acceptable within this library’s threat model. Callers should recover or treat them as fatal configuration bugs.
- Only the latest supported Go versions are exercised in CI. Older versions may not benefit from all security checks.

## 6. Reporting and Incident Handling

Potential vulnerabilities should be reported via the private [GitHub Security Advisory form](https://github.com/bytemare/ecc/security/advisories). Maintainers target acknowledgement within seven calendar days and a remediation plan within thirty days depending on severity. All advisory threads remain private until a coordinated disclosure is agreed. If timelines slip the maintainer will update reporters inside the advisory and document the outcome in the next release notes. Incident response activities and lessons learned are recorded alongside the advisory reference in the changelog to keep a historical trail.

---

This document evolves alongside the implementation. When adding new functionality, update the threat analysis and assurance arguments to reflect the new surface area.
