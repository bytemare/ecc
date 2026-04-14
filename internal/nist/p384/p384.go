// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package p384

import (
	"crypto"
	"sync"

	"filippo.io/nistec"

	"github.com/bytemare/ecc/internal/nist/fiat"
	"github.com/bytemare/ecc/internal/nist/sswu"
)

const (
	// H2CP384 is the RFC 9380 hash-to-curve ciphersuite identifier for P-384.
	H2CP384 = "P384_XMD:SHA-384_SSWU_RO_"
	// E2CP384 is the RFC 9380 encode-to-curve ciphersuite identifier for P-384.
	E2CP384 = "P384_XMD:SHA-384_SSWU_NU_"

	fieldLength   = 48
	uniformLength = 72
)

var (
	initOnce sync.Once
	engine   sswu.Engine[*fiat.P384Element, *nistec.P384Point]
)

// HashToCurve returns the RFC 9380 random-oracle mapping for P-384.
func HashToCurve(input, dst []byte) (*nistec.P384Point, error) {
	initOnce.Do(initEngine)
	return engine.HashToCurve(input, dst)
}

// EncodeToCurve returns the RFC 9380 non-uniform mapping for P-384.
func EncodeToCurve(input, dst []byte) (*nistec.P384Point, error) {
	initOnce.Do(initEngine)
	return engine.EncodeToCurve(input, dst)
}

// initEngine materializes the shared P-384 SSWU engine from precomputed
// field constants.
func initEngine() {
	engine = sswu.Engine[*fiat.P384Element, *nistec.P384Point]{
		Hash:          crypto.SHA384,
		FieldLength:   fieldLength,
		UniformLength: uniformLength,
		One:           fiat.P384One(),
		A:             fiat.P384A(),
		B:             fiat.P384B(),
		Z:             fiat.P384Z(),
		Two64:         fiat.P384Two64(),
		NewElement: func() *fiat.P384Element {
			return new(fiat.P384Element)
		},
		Sqrt:    p384Sqrt,
		ToPoint: toPoint,
		AddPoints: func(p, q *nistec.P384Point) *nistec.P384Point {
			return p.Add(p, q)
		},
	}
}

// toPoint converts affine P-384 coordinates into an uncompressed SEC 1 point
// and lets nistec validate the encoding.
func toPoint(x, y *fiat.P384Element) *nistec.P384Point {
	var in [97]byte
	in[0] = 4
	copy(in[1:49], x.Bytes())
	copy(in[49:], y.Bytes())
	p, err := nistec.NewP384Point().SetBytes(in[:])
	if err != nil {
		panic(err)
	}
	return p
}

// p384Sqrt sets e to a square root of x if one exists and returns 1 on
// success. The addition chain is adapted from filippo.io/nistec.
func p384Sqrt(e, x *fiat.P384Element) int {
	candidate := new(fiat.P384Element)
	p384SqrtCandidate(candidate, x)
	square := new(fiat.P384Element).Square(candidate)
	e.Set(candidate)
	return square.Equal(x)
}

// p384SqrtCandidate computes the P-384 square-root candidate using the
// addition chain adapted from filippo.io/nistec.
func p384SqrtCandidate(z, x *fiat.P384Element) {
	t0 := new(fiat.P384Element)
	t1 := new(fiat.P384Element)
	t2 := new(fiat.P384Element)

	z.Square(x)
	z.Mul(x, z)
	z.Square(z)
	t0.Mul(x, z)
	z.Square(t0)
	for s := 1; s < 3; s++ {
		z.Square(z)
	}
	t1.Mul(t0, z)
	t2.Square(t1)
	z.Mul(x, t2)
	for range 5 {
		t2.Square(t2)
	}
	t1.Mul(t1, t2)
	t2.Square(t1)
	for s := 1; s < 12; s++ {
		t2.Square(t2)
	}
	t1.Mul(t1, t2)
	for range 7 {
		t1.Square(t1)
	}
	t1.Mul(z, t1)
	z.Square(t1)
	z.Mul(x, z)
	t2.Square(z)
	for s := 1; s < 31; s++ {
		t2.Square(t2)
	}
	t1.Mul(t1, t2)
	t2.Square(t1)
	for s := 1; s < 63; s++ {
		t2.Square(t2)
	}
	t1.Mul(t1, t2)
	t2.Square(t1)
	for s := 1; s < 126; s++ {
		t2.Square(t2)
	}
	t1.Mul(t1, t2)
	for range 3 {
		t1.Square(t1)
	}
	t0.Mul(t0, t1)
	for range 33 {
		t0.Square(t0)
	}
	z.Mul(z, t0)
	for range 64 {
		z.Square(z)
	}
	z.Mul(x, z)
	for range 30 {
		z.Square(z)
	}
}
