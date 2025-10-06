# Architecture and Engineering Guidelines

This guide summarises how `github.com/bytemare/ecc` is structured, how the codebase should evolve, and where to find complementary references. Refer to [.github/CONTRIBUTING.md](../.github/CONTRIBUTING.md) for workflow expectations and to [secure_design.md](secure_design.md) for the security assurance case.

## Layered Architecture

```mermaid
flowchart LR
    Client[Downstream application] -->|Selects group, calls API| PublicAPI
    PublicAPI[Package `ecc` (groups.go, element.go, scalar.go)] -->|Delegates| InternalLayer
    InternalLayer[Adapters under internal/*] -->|Wrap| Backends
    Backends[Third-party curve libraries]
    PublicAPI -->|Domain separation| Hash2Curve[github.com/bytemare/hash2curve]
```

- **Public API (`package ecc`)** exposes `Group`, `Element`, and `Scalar`. Callers select a group identifier to obtain instances without importing curve-specific packages. This approach was chosen over interfaces to simplify usage by allowing clients to import only a single module.
- **Adapter layer (`internal/*`)** implements shared interfaces (`internal.Group`, `internal.Element`, `internal.Scalar`) for each backend family (e.g. Ristretto255, NIST curves, Edwards25519, Secp256k1). Adapters enforce invariants (canonical encodings, identity rejection, panic on mixed groups) before delegating.
- **Backends** are vetted libraries (e.g. `filippo.io/nistec`, `filippo.io/edwards25519`, `github.com/gtank/ristretto255`, `github.com/bytemare/secp256k1`) that provide constant-time arithmetic.
- **Hash-to-curve** support leverages `github.com/bytemare/hash2curve` to follow RFC 9380 suites. `Group.MakeDST` formats application-specific tags and rejects empty input.

### Public API Layer

- `Group` is a byte-backed enum that lazily instantiates the appropriate backend via. Invalid IDs panic to avoid silent misuse.
- `Group.MakeDST` provides non-empty RFC 9380 suggested domain separation tags.
- `Element` and `Scalar` embed their `internal` counterparts. They guard against nil operands, returning early rather than panicking for additive operations.
- JSON marshaling adds group metadata.

## Data Flow and Lifetimes

1. Client code selects a `Group` constant.
2. Lazy initialization (`sync.Once`) configures a shared backend instance and caches it.
3. Public API calls (e.g., `HashToGroup`) verify DST invariants, then proxy to the backend which returns an `internal.Element`.
4. Results are wrapped in public structs that copy or reference backend state depending on operation. Copying uses backend-provided duplication to avoid aliasing.

All operations occur in-memory. There's no persistent state or network I/O.

## Implementation Guidelines

- **Idiomatic Go**: Follow [Effective Go](https://go.dev/doc/effective_go) and [Go Code Review Comments](https://go.dev/wiki/CodeReviewComments). Source files include SPDX headers.
- **Nil semantics**: Public methods treat `nil` operands as neutral (no-op or identity) to reduce caller boilerplate. Adapters panic on `nil` inputs to expose misuse during development.
- **Error strategy**: Configuration mistakes (unsupported groups) intentionally panic. Runtime errors (decode failures, mismatched JSON payloads) return wrapped `error`s using `errors.Join` for context.
- **Encoding rules**: All encoders produce canonical bytes. Identity encodings are normalised (e.g. NIST) or rejected outright (cofactor groups). JSON marshalers always include both group ID and payload to prevent cross-group confusion.
- **Generics**: Use where they meaningfully reduce duplication (e.g., the NIST adapters). Prefer concrete types when external APIs dictate specific representations.
- **Minimal dependencies**: Keep the dependency surface small and cryptography-focused. Propose new packages via issues before adding them.

## Testing and Automation

- **Table-driven tests** exercise all supported groups for consistent semantics (e.g., `tests/groups_test.go`).
- **Test vectors** from RFC 9380 validate encode/decode symmetry, hash-to-curve mappings, and identity handling across backends (`tests/h2c/`, `tests/encoding_test.go`).
- **Fuzzers and fixtures** validate encode/decode behaviour (`tests/fuzz_test.go`, helpers in `debug/`).
- **Rich CI workflows** with strict linting and security rules run on every commit. Before opening a PR, make sure `make -C .github/ lint vuln test fuzz` passes locally, and that coverage does not decrease (`make -C .github/ cover`).
- **Coverage expectations**: Maintain or improve existing coverage. Highlight meaningful gaps in PR descriptions if they cannot be addressed immediately.

## Extending the Library

When adding a group or backend:

1. Implement the adapter trio (`internal.Group`, `internal.Element`, `internal.Scalar`) with the same invariants (panic on wrong group, reject invalid encodings, ensure constant-time comparisons).
2. Register the new identifier in `groups.go`, update `maxID`, extend the `sync.Once` registry, and document any DST implications.
3. Provide hash-to-curve and encode-to-curve wiring consistent with RFC 9380.
4. Add tests covering availability, base element, encode/decode round-trips, JSON serialisation, and hash-to-curve mappings for the new group.
5. Update `docs/ROADMAP.md` if the new capability addresses a planned milestone, and mention the change in the changelog.

Document new trust boundaries or assumptions in [secure_design.md](secure_design.md) and update the threat analysis when introducing new functionality.

## Related Documents

- Contribution workflow and review expectations: [.github/CONTRIBUTING.md](../.github/CONTRIBUTING.md)
- Security assurance case, principles, and threat model: [secure_design.md](secure_design.md)
- Strategic goals and future work: [roadmap.md](roadmap.md)
- Release process: [releasing.md](releasing.md)
