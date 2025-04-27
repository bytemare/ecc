// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package edwards25519 allows simple and abstracted operations in the Edwards25519 group.
package edwards25519

import (
	"crypto"
	"slices"

	"github.com/bytemare/ecc/internal"

	ed "filippo.io/edwards25519"
)

const (
	// Identifier distinguishes this group from the others by a byte representation.
	Identifier = byte(6)

	canonicalEncodingLength = 32
	orderPrime              = "7237005577332262213973186563042994240857116359379907606001950938285454250989"
)

// Group represents the Edwards25519 group. It exposes a prime-order group API with hash-to-curve operations.
type Group struct{}

// New returns a new instantiation of the Edwards25519 Group.
func New() internal.Group {
	return Group{}
}

// NewScalar returns a new scalar set to 0.
func (g Group) NewScalar() internal.Scalar {
	return &Scalar{*ed.NewScalar()}
}

// NewElement returns the identity element (point at infinity).
func (g Group) NewElement() internal.Element {
	return &Element{*ed.NewIdentityPoint()}
}

// Base returns group's base point a.k.a. canonical generator.
func (g Group) Base() internal.Element {
	return &Element{*ed.NewGeneratorPoint()}
}

// HashFunc returns the RFC9380 associated hash function of the group.
func (g Group) HashFunc() crypto.Hash {
	return crypto.SHA512
}

// HashToScalar returns a safe mapping of the arbitrary input to a Scalar.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func (g Group) HashToScalar(input, dst []byte) internal.Scalar {
	return &Scalar{*HashToEdwards25519Field(input, dst)}
}

// HashToGroup returns a safe mapping of the arbitrary input to an Element in the Group.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func (g Group) HashToGroup(input, dst []byte) internal.Element {
	return &Element{*HashToEdwards25519(input, dst)}
}

// EncodeToGroup returns a non-uniform mapping of the arbitrary input to an Element in the Group.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func (g Group) EncodeToGroup(input, dst []byte) internal.Element {
	return &Element{*EncodeToEdwards25519(input, dst)}
}

// Ciphersuite returns the hash-to-curve ciphersuite identifier.
func (g Group) Ciphersuite() string {
	return H2C
}

// ScalarLength returns the byte size of an encoded element.
func (g Group) ScalarLength() int {
	return canonicalEncodingLength
}

// ElementLength returns the byte size of an encoded element.
func (g Group) ElementLength() int {
	return canonicalEncodingLength
}

// Order returns the order of the canonical group of scalars.
func (g Group) Order() []byte {
	return slices.Clone(orderBytes)
}
