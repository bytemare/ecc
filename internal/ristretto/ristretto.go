// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package ristretto allows simple and abstracted operations in the Ristretto255 group.
package ristretto

import (
	"crypto"

	"github.com/bytemare/hash2curve"
	"github.com/gtank/ristretto255"

	"github.com/bytemare/crypto/internal"
)

const (
	// Identifier distinguishes this group from the others by a byte representation.
	Identifier = byte(1)

	inputLength = 64

	// H2C represents the hash-to-curve string identifier.
	H2C = "ristretto255_XMD:SHA-512_R255MAP_RO_"

	// orderPrime represents curve25519's subgroup prime-order
	// = 2^252 + 27742317777372353535851937790883648493
	// = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
	// cofactor h = 8.
	orderPrime = "7237005577332262213973186563042994240857116359379907606001950938285454250989"
)

// Group represents the Ristretto255 group. It exposes a prime-order group API with hash-to-curve operations.
type Group struct{}

// New returns a new instantiation of the Ristretto255 Group.
func New() internal.Group {
	return Group{}
}

// NewScalar returns a new scalar set to 0.
func (g Group) NewScalar() internal.Scalar {
	return &Scalar{*ristretto255.NewScalar()}
}

// NewElement returns the identity element (point at infinity).
func (g Group) NewElement() internal.Element {
	return &Element{*ristretto255.NewElement()}
}

// Base returns group's base point a.k.a. canonical generator.
func (g Group) Base() internal.Element {
	return &Element{*ristretto255.NewElement().Base()}
}

// HashFunc returns the RFC9380 associated hash function of the group.
func (g Group) HashFunc() crypto.Hash {
	return crypto.SHA512
}

// HashToScalar returns a safe mapping of the arbitrary input to a Scalar.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func (g Group) HashToScalar(input, dst []byte) internal.Scalar {
	uniform := hash2curve.ExpandXMD(crypto.SHA512, input, dst, inputLength)
	return &Scalar{*ristretto255.NewScalar().FromUniformBytes(uniform)}
}

// HashToGroup returns a safe mapping of the arbitrary input to an Element in the Group.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func (g Group) HashToGroup(input, dst []byte) internal.Element {
	uniform := hash2curve.ExpandXMD(crypto.SHA512, input, dst, inputLength)

	return &Element{*ristretto255.NewElement().FromUniformBytes(uniform)}
}

// EncodeToGroup returns a non-uniform mapping of the arbitrary input to an Element in the Group.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func (g Group) EncodeToGroup(input, dst []byte) internal.Element {
	return g.HashToGroup(input, dst)
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
func (g Group) Order() string {
	return orderPrime
}
