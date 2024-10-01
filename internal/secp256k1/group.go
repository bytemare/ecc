// SPDX-License-Identifier: MIT
//
// Copyright (C)2020-2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package secp256k1 allows simple and abstracted operations in the Secp256k1 group.
package secp256k1

import (
	"crypto"

	"github.com/bytemare/secp256k1"

	"github.com/bytemare/crypto/internal"
)

const (
	// Identifier distinguishes this group from the others by a byte representation.
	Identifier = byte(7)

	// H2CSECP256K1 represents the hash-to-curve string identifier for Secp256k1.
	H2CSECP256K1 = "secp256k1_XMD:SHA-256_SSWU_RO_"

	// E2CSECP256K1 represents the encode-to-curve string identifier for Secp256k1.
	E2CSECP256K1 = "secp256k1_XMD:SHA-256_SSWU_NU_"

	groupOrder    = "115792089237316195423570985008687907852837564279074904382605163141518161494337"
	scalarLength  = 32
	elementLength = 33
)

// Group represents the Secp256k1 group. It exposes a prime-order group API with hash-to-curve operations.
type Group struct{}

// New returns a new instantiation of the Secp256k1 Group.
func New() internal.Group {
	return Group{}
}

// NewScalar returns a new scalar set to 0.
func (g Group) NewScalar() internal.Scalar {
	return newScalar()
}

// NewElement returns the identity element (point at infinity).
func (g Group) NewElement() internal.Element {
	return newElement()
}

// Base returns the group's base point a.k.a. canonical generator.
func (g Group) Base() internal.Element {
	return newElement().Base()
}

// HashFunc returns the RFC9380 associated hash function of the group.
func (g Group) HashFunc() crypto.Hash {
	return crypto.SHA256
}

// HashToScalar returns a safe mapping of the arbitrary input to a Scalar.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func (g Group) HashToScalar(input, dst []byte) internal.Scalar {
	return &Scalar{scalar: secp256k1.HashToScalar(input, dst)}
}

// HashToGroup returns a safe mapping of the arbitrary input to an Element in the Group.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func (g Group) HashToGroup(input, dst []byte) internal.Element {
	return &Element{element: secp256k1.HashToGroup(input, dst)}
}

// EncodeToGroup returns a non-uniform mapping of the arbitrary input to an Element in the Group.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func (g Group) EncodeToGroup(input, dst []byte) internal.Element {
	return &Element{element: secp256k1.EncodeToGroup(input, dst)}
}

// Ciphersuite returns the hash-to-curve ciphersuite identifier.
func (g Group) Ciphersuite() string {
	return H2CSECP256K1
}

// ScalarLength returns the byte size of an encoded scalar.
func (g Group) ScalarLength() int {
	return scalarLength
}

// ElementLength returns the byte size of an encoded element.
func (g Group) ElementLength() int {
	return elementLength
}

// Order returns the order of the canonical group of scalars.
func (g Group) Order() string {
	return groupOrder
}
