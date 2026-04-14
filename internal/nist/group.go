// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package nist allows simple and abstracted operations in the NIST P-256,
// P-384, and P-521 groups, wrapping filippo.io/nistec.
package nist

import (
	"crypto"
	"sync"

	"filippo.io/nistec"

	"github.com/bytemare/ecc/internal"

	nistP256 "github.com/bytemare/ecc/internal/nist/p256"
	nistP384 "github.com/bytemare/ecc/internal/nist/p384"
	nistP521 "github.com/bytemare/ecc/internal/nist/p521"
)

const (
	// H2CP256 is the hash-to-curve ciphersuite identifier for P-256.
	H2CP256 = nistP256.H2CP256
	// E2CP256 is the encode-to-curve ciphersuite identifier for P-256.
	E2CP256 = nistP256.E2CP256
	// H2CP384 is the hash-to-curve ciphersuite identifier for P-384.
	H2CP384 = nistP384.H2CP384
	// E2CP384 is the encode-to-curve ciphersuite identifier for P-384.
	E2CP384 = nistP384.E2CP384
	// H2CP521 is the hash-to-curve ciphersuite identifier for P-521.
	H2CP521 = nistP521.H2CP521
	// E2CP521 is the encode-to-curve ciphersuite identifier for P-521.
	E2CP521 = nistP521.E2CP521

	// IdentifierP256 identifies the P-256 group internally.
	IdentifierP256 = byte(3)
	// IdentifierP384 identifies the P-384 group internally.
	IdentifierP384 = byte(4)
	// IdentifierP521 identifies the P-521 group internally.
	IdentifierP521 = byte(5)
)

// P256 returns the singleton P-256 group instance.
func P256() internal.Group {
	initOnceP256.Do(initP256)
	return &p256
}

// P384 returns the singleton P-384 group instance.
func P384() internal.Group {
	initOnceP384.Do(initP384)
	return &p384
}

// P521 returns the singleton P-521 group instance.
func P521() internal.Group {
	initOnceP521.Do(initP521)
	return &p521
}

// Group exposes the prime-order API for a NIST curve backed by nistec points.
type Group[Point nistECPoint[Point]] struct {
	NewPoint func() Point
	scalar   *scalarParams
	mapping[Point]
	h2c string
}

// NewScalar returns a new zero scalar.
func (g Group[P]) NewScalar() internal.Scalar {
	return newScalar(g.scalar)
}

// NewElement returns the identity element.
func (g Group[P]) NewElement() internal.Element {
	return &Element[P]{
		p:   g.NewPoint(),
		new: g.NewPoint,
	}
}

// Base returns the canonical generator.
func (g Group[P]) Base() internal.Element {
	b := g.NewPoint()
	b.SetGenerator()
	return g.newPoint(b)
}

func (g Group[P]) newPoint(p P) *Element[P] {
	return &Element[P]{
		p:   p,
		new: g.NewPoint,
	}
}

// HashFunc returns the RFC9380 associated hash function of the group.
func (g Group[P]) HashFunc() crypto.Hash {
	return g.hash
}

// HashToScalar hashes arbitrary input to a scalar.
func (g Group[P]) HashToScalar(input, dst []byte) (internal.Scalar, error) {
	return hashToScalar(g.scalar, input, dst)
}

// HashToGroup hashes arbitrary input to a group element.
func (g Group[P]) HashToGroup(input, dst []byte) (internal.Element, error) {
	p, err := g.hashToCurve(input, dst)
	if err != nil {
		return nil, err
	}

	return g.newPoint(p), nil
}

// EncodeToGroup encodes arbitrary input to a non-uniform group element.
func (g Group[P]) EncodeToGroup(input, dst []byte) (internal.Element, error) {
	p, err := g.mapToCurve(input, dst)
	if err != nil {
		return nil, err
	}

	return g.newPoint(p), nil
}

// Ciphersuite returns the RFC 9380 ciphersuite identifier.
func (g Group[P]) Ciphersuite() string {
	return g.h2c
}

// ScalarLength returns the encoded scalar length in bytes.
func (g Group[P]) ScalarLength() int {
	return g.scalar.length
}

// ElementLength returns the encoded element length in bytes.
func (g Group[P]) ElementLength() int {
	return 1 + g.scalar.length
}

// Order returns the canonical scalar field order encoding.
func (g Group[P]) Order() []byte {
	out := make([]byte, g.scalar.length)
	copy(out, g.scalar.orderBytes[:g.scalar.length])
	return out
}

var (
	initOnceP256 sync.Once
	initOnceP384 sync.Once
	initOnceP521 sync.Once

	p256 Group[*nistec.P256Point]
	p384 Group[*nistec.P384Point]
	p521 Group[*nistec.P521Point]
)

func initP256() {
	p256.h2c = H2CP256
	p256.NewPoint = nistec.NewP256Point
	p256.scalar = p256ScalarParams
	p256.setMapping(crypto.SHA256, nistP256.HashToCurve, nistP256.EncodeToCurve)
}

func initP384() {
	p384.h2c = H2CP384
	p384.NewPoint = nistec.NewP384Point
	p384.scalar = p384ScalarParams
	p384.setMapping(crypto.SHA384, nistP384.HashToCurve, nistP384.EncodeToCurve)
}

func initP521() {
	p521.h2c = H2CP521
	p521.NewPoint = nistec.NewP521Point
	p521.scalar = p521ScalarParams
	p521.setMapping(crypto.SHA512, nistP521.HashToCurve, nistP521.EncodeToCurve)
}
