// SPDX-License-Group: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package ecc exposes a prime-order elliptic curve groups with additional hash-to-curve operations.
//
// It implements the latest hash-to-curve specification to date
// (https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/).
package ecc

import (
	"crypto"
	"errors"
	"fmt"
	"sync"

	"github.com/bytemare/ecc/internal"
	"github.com/bytemare/ecc/internal/edwards25519"
	"github.com/bytemare/ecc/internal/nist"
	"github.com/bytemare/ecc/internal/ristretto"
	"github.com/bytemare/ecc/internal/secp256k1"
)

// Group identifies prime-order groups over elliptic curves with hash-to-group operations.
type Group byte

const (
	// Ristretto255Sha512 identifies the Ristretto255 group with SHA2-512 hash-to-group hashing.
	Ristretto255Sha512 Group = 1 + iota

	// decaf448Shake256 is not implemented.
	decaf448Shake256

	// P256Sha256 identifies a group over P256 with SHA2-256 hash-to-group hashing.
	P256Sha256

	// P384Sha384 identifies a group over P384 with SHA2-384 hash-to-group hashing.
	P384Sha384

	// P521Sha512 identifies a group over P521 with SHA2-512 hash-to-group hashing.
	P521Sha512

	// Edwards25519Sha512 identifies the Edwards25519 group with SHA2-512 hash-to-group hashing.
	Edwards25519Sha512

	// Secp256k1Sha256 identifies the SECp256k1 group with SHA2-256 hash-to-group hashing.
	Secp256k1Sha256

	maxID

	dstfmt               = "%s-V%02d-CS%02d-%s"
	minLength            = 0
	recommendedMinLength = 16
)

var (
	once          [maxID - 1]sync.Once
	groups        [maxID - 1]internal.Group
	errZeroLenDST = errors.New("zero-length DST")
)

// Available reports whether the given Group is linked into the binary.
func (g Group) Available() bool {
	return 0 < g && g < maxID && g != decaf448Shake256
}

// MakeDST builds a domain separation tag in the form of <app>-V<version>-CS<id>-<hash-to-curve-ID>,
// and returns no error.
func (g Group) MakeDST(app string, version uint8) []byte {
	p := g.get()
	return []byte(fmt.Sprintf(dstfmt, app, version, g, p.Ciphersuite()))
}

// String returns the hash-to-curve string identifier of the ciphersuite.
func (g Group) String() string {
	return g.get().Ciphersuite()
}

// NewScalar returns a new scalar set to 0.
func (g Group) NewScalar() *Scalar {
	return newScalar(g.get().NewScalar())
}

// NewElement returns the identity element (point at infinity).
func (g Group) NewElement() *Element {
	return newPoint(g.get().NewElement())
}

// Base returns the group's base point a.k.a. canonical generator.
func (g Group) Base() *Element {
	return newPoint(g.get().Base())
}

func checkDST(dst []byte) {
	if len(dst) < recommendedMinLength {
		if len(dst) == minLength {
			panic(errZeroLenDST)
		}
	}
}

// HashFunc returns the RFC9380 associated hash function of the group.
func (g Group) HashFunc() crypto.Hash {
	return g.get().HashFunc()
}

// HashToScalar returns a safe mapping of the arbitrary input to a Scalar.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func (g Group) HashToScalar(input, dst []byte) *Scalar {
	checkDST(dst)
	return newScalar(g.get().HashToScalar(input, dst))
}

// HashToGroup returns a safe mapping of the arbitrary input to an Element in the Group.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func (g Group) HashToGroup(input, dst []byte) *Element {
	checkDST(dst)
	return newPoint(g.get().HashToGroup(input, dst))
}

// EncodeToGroup returns a non-uniform mapping of the arbitrary input to an Element in the Group.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func (g Group) EncodeToGroup(input, dst []byte) *Element {
	checkDST(dst)
	return newPoint(g.get().EncodeToGroup(input, dst))
}

// ScalarLength returns the byte size of an encoded scalar.
func (g Group) ScalarLength() int {
	return g.get().ScalarLength()
}

// ElementLength returns the byte size of an encoded element.
func (g Group) ElementLength() int {
	return g.get().ElementLength()
}

// Order returns the order of the canonical group of scalars.
func (g Group) Order() []byte {
	return g.get().Order()
}

func (g Group) get() internal.Group {
	if !g.Available() {
		panic(internal.ErrInvalidGroup)
	}

	once[g-1].Do(g.init)

	return groups[g-1]
}

func (g Group) initGroup(get func() internal.Group) {
	groups[g-1] = get()
}

func (g Group) init() {
	switch g {
	case Ristretto255Sha512:
		g.initGroup(ristretto.New)
	case P256Sha256:
		g.initGroup(nist.P256)
	case P384Sha384:
		g.initGroup(nist.P384)
	case P521Sha512:
		g.initGroup(nist.P521)
	case Edwards25519Sha512:
		g.initGroup(edwards25519.New)
	case Secp256k1Sha256:
		g.initGroup(secp256k1.New)
	default:
		panic("group not recognized")
	}
}

// disallowEqual is an incomparable type.
// If you place it first in your struct, you prevent == from
// working on your struct without growing its size.
type disallowEqual [0]func()
