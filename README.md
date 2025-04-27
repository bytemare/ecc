# Elliptic Curve Groups
[![CI](https://github.com/bytemare/ecc/actions/workflows/wf-analysis.yaml/badge.svg)](https://github.com/bytemare/ecc/actions/workflows/wf-analysis.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/ecc.svg)](https://pkg.go.dev/github.com/bytemare/ecc)
[![codecov](https://codecov.io/gh/bytemare/ecc/branch/main/graph/badge.svg?token=5bQfB0OctA)](https://codecov.io/gh/bytemare/ecc)

```Go
  import "github.com/bytemare/ecc"
```

This package exposes abstract operations over opaque elliptic curve groups, some of which are prime-order, and their scalars and elements,
and support hash-to-curve as per [RFC 9380](https://datatracker.ietf.org/doc/rfc9380).

It makes using different elliptic curves easy, flexible, and without loosing performance or security. You don't have to
care about the parameters.
You can swap between primitives with no code change and only the Group identifier, a byte.
The package is a wrapper to optimized and secure implementations that serve as backends, and to which you
don't need to adapt and learn about.

The following table shows supported groups with hash-to-curve capability and links each one to the underlying
implementations:

| ID | Name         | Prime-order       | Backend                       |
|----|--------------|-------------------|-------------------------------|
| 1  | Ristretto255 | yes               | github.com/gtank/ristretto255 |
| 2  | Decaf448     | not supported     | not supported                 |
| 3  | P-256        | yes               | filippo.io/nistec             |
| 4  | P-384        | yes               | filippo.io/nistec             |
| 5  | P-521        | yes               | filippo.io/nistec             |
| 6  | Edwards25519 | no                | filippo.io/edwards25519       |
| 7  | Secp256k1    | yes               | github.com/bytemare/secp256k1 |
| 9  | Curve25519   | not yet supported | not yet supported             |
| 8  | Double-Odd   | not yet supported | not yet supported             |

## Group interface

This package exposes types that can handle different implementations under the hood, internally using an interface
to the group and its scalars and elements, but you don't need to instantiate or implement anything. Just use the type in
the top package.

### Group

```Go
// Group abstracts operations in a prime-order group.
type Group interface {
	NewScalar() Scalar
	NewElement() Element
	Base() Element
	HashFunc() crypto.Hash
	HashToScalar(input, dst []byte) Scalar
	HashToGroup(input, dst []byte) Element
	EncodeToGroup(input, dst []byte) Element
	Ciphersuite() string
	ScalarLength() int
	ElementLength() int
	Order() []byte
}
```

### Scalar interface

```Go
// Scalar interface abstracts common operations on scalars in a prime-order Group.
type Scalar interface {
	Group() Group
	Zero() Scalar
	One() Scalar
	MinusOne() Scalar
	Random() Scalar
	Add(Scalar) Scalar
	Subtract(Scalar) Scalar
	Multiply(Scalar) Scalar
	Pow(Scalar) Scalar
	Invert() Scalar
	Equal(Scalar) int
	LessOrEqual(Scalar) bool
	IsZero() bool
	Set(Scalar) Scalar
	SetUInt64(uint64) Scalar
	UInt64() (uint64, error)
	Copy() Scalar
	Encode() []byte
	Decode([]byte) error
	Hex() string
	HexDecode([]byte) error
	MarshalJSON()
	UnmarshalJSON()
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}
```

### Element interface
```Go
// Element interface abstracts common operations on an Element in a prime-order Group.
type Element interface {
	Group() Group
	Base() Element
	Identity() Element
	Add(Element) Element
	Double() Element
	Negate() Element
	Subtract(Element) Element
	Multiply(Scalar) Element
	Equal(element Element) int
	IsIdentity() bool
	Set(Element) Element
	Copy() Element
	Encode() []byte
	XCoordinate() []byte
	Decode(data []byte) error
	Hex() string
	HexDecode([]byte) error
	MarshalJSON() ([]byte, error)
	UnmarshalJSON(data []byte) error
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}
```

## Documentation [![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/ecc.svg)](https://pkg.go.dev/github.com/bytemare/ecc)

You can find the documentation and usage examples in [the package doc](https://pkg.go.dev/github.com/bytemare/ecc) and [the project wiki](https://github.com/bytemare/ecc/wiki) .

## Versioning

[SemVer](https://semver.org) is used for versioning. For the versions available, see the [tags on the repository](https://github.com/bytemare/ecc/tags).

## Contributing

Please read [CONTRIBUTING.md](.github/CONTRIBUTING.md) for details on the code of conduct, and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
