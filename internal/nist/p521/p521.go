// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package p521

import (
	"crypto"
	"sync"

	"filippo.io/nistec"

	"github.com/bytemare/ecc/internal/nist/fiat"
	"github.com/bytemare/ecc/internal/nist/sswu"
)

const (
	// H2CP521 is the RFC 9380 hash-to-curve ciphersuite identifier for P-521.
	H2CP521 = "P521_XMD:SHA-512_SSWU_RO_"
	// E2CP521 is the RFC 9380 encode-to-curve ciphersuite identifier for P-521.
	E2CP521 = "P521_XMD:SHA-512_SSWU_NU_"

	fieldLength   = 66
	uniformLength = 98
)

var (
	initOnce sync.Once
	engine   sswu.Engine[*fiat.P521Element, *nistec.P521Point]
)

// HashToCurve returns the RFC 9380 random-oracle mapping for P-521.
func HashToCurve(input, dst []byte) (*nistec.P521Point, error) {
	initOnce.Do(initEngine)
	return engine.HashToCurve(input, dst)
}

// EncodeToCurve returns the RFC 9380 non-uniform mapping for P-521.
func EncodeToCurve(input, dst []byte) (*nistec.P521Point, error) {
	initOnce.Do(initEngine)
	return engine.EncodeToCurve(input, dst)
}

// initEngine materializes the shared P-521 SSWU engine from precomputed
// field constants.
func initEngine() {
	engine = sswu.Engine[*fiat.P521Element, *nistec.P521Point]{
		Hash:          crypto.SHA512,
		FieldLength:   fieldLength,
		UniformLength: uniformLength,
		One:           fiat.P521One(),
		A:             fiat.P521A(),
		B:             fiat.P521B(),
		Z:             fiat.P521Z(),
		Two64:         fiat.P521Two64(),
		NewElement: func() *fiat.P521Element {
			return new(fiat.P521Element)
		},
		Sqrt:    p521Sqrt,
		ToPoint: toPoint,
		AddPoints: func(p, q *nistec.P521Point) *nistec.P521Point {
			return p.Add(p, q)
		},
	}
}

// toPoint converts affine P-521 coordinates into an uncompressed SEC 1 point
// and lets nistec validate the encoding.
func toPoint(x, y *fiat.P521Element) *nistec.P521Point {
	var in [133]byte
	in[0] = 4
	copy(in[1:67], x.Bytes())
	copy(in[67:], y.Bytes())
	p, err := nistec.NewP521Point().SetBytes(in[:])
	if err != nil {
		panic(err)
	}
	return p
}

// p521Sqrt sets e to a square root of x if one exists and returns 1 on
// success. The addition chain is adapted from filippo.io/nistec.
func p521Sqrt(e, x *fiat.P521Element) int {
	candidate := new(fiat.P521Element)
	p521SqrtCandidate(candidate, x)
	square := new(fiat.P521Element).Square(candidate)
	e.Set(candidate)
	return square.Equal(x)
}

// p521SqrtCandidate computes the P-521 square-root candidate using the
// addition chain adapted from filippo.io/nistec.
func p521SqrtCandidate(z, x *fiat.P521Element) {
	z.Square(x)
	for s := 1; s < 519; s++ {
		z.Square(z)
	}
}
