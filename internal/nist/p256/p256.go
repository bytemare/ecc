// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package p256

import (
	"crypto"
	"sync"

	"filippo.io/nistec"

	"github.com/bytemare/ecc/internal/nist/fiat"
	"github.com/bytemare/ecc/internal/nist/sswu"
)

const (
	// H2CP256 is the RFC 9380 hash-to-curve ciphersuite identifier for P-256.
	H2CP256 = "P256_XMD:SHA-256_SSWU_RO_"
	// E2CP256 is the RFC 9380 encode-to-curve ciphersuite identifier for P-256.
	E2CP256 = "P256_XMD:SHA-256_SSWU_NU_"

	fieldLength   = 32
	uniformLength = 48
)

var (
	initOnce sync.Once
	engine   sswu.Engine[*fiat.P256Element, *nistec.P256Point]
)

// HashToCurve returns the RFC 9380 random-oracle mapping for P-256.
func HashToCurve(input, dst []byte) (*nistec.P256Point, error) {
	initOnce.Do(initEngine)
	return engine.HashToCurve(input, dst)
}

// EncodeToCurve returns the RFC 9380 non-uniform mapping for P-256.
func EncodeToCurve(input, dst []byte) (*nistec.P256Point, error) {
	initOnce.Do(initEngine)
	return engine.EncodeToCurve(input, dst)
}

// initEngine materializes the shared P-256 SSWU engine from precomputed
// field constants.
func initEngine() {
	engine = sswu.Engine[*fiat.P256Element, *nistec.P256Point]{
		Hash:          crypto.SHA256,
		FieldLength:   fieldLength,
		UniformLength: uniformLength,
		One:           fiat.P256One(),
		A:             fiat.P256A(),
		B:             fiat.P256B(),
		Z:             fiat.P256Z(),
		Two64:         fiat.P256Two64(),
		NewElement: func() *fiat.P256Element {
			return new(fiat.P256Element)
		},
		Sqrt:    p256Sqrt,
		ToPoint: toPoint,
		AddPoints: func(p, q *nistec.P256Point) *nistec.P256Point {
			return p.Add(p, q)
		},
	}
}

// toPoint converts affine P-256 coordinates into an uncompressed SEC 1 point
// and lets nistec validate the encoding.
func toPoint(x, y *fiat.P256Element) *nistec.P256Point {
	var in [65]byte
	in[0] = 4
	copy(in[1:33], x.Bytes())
	copy(in[33:], y.Bytes())
	p, err := nistec.NewP256Point().SetBytes(in[:])
	if err != nil {
		panic(err)
	}
	return p
}

// p256Sqrt sets e to a square root of x if one exists and returns 1 on
// success. The addition chain is adapted from filippo.io/nistec.
func p256Sqrt(e, x *fiat.P256Element) int {
	t0 := new(fiat.P256Element)
	t1 := new(fiat.P256Element)
	p256Square(t0, x, 1)
	t0.Mul(x, t0)
	p256Square(t1, t0, 2)
	t0.Mul(t0, t1)
	p256Square(t1, t0, 4)
	t0.Mul(t0, t1)
	p256Square(t1, t0, 8)
	t0.Mul(t0, t1)
	p256Square(t1, t0, 16)
	t0.Mul(t0, t1)
	p256Square(t0, t0, 32)
	t0.Mul(x, t0)
	p256Square(t0, t0, 96)
	t0.Mul(x, t0)
	p256Square(t0, t0, 94)
	t1.Square(t0)
	e.Set(t0)
	return t1.Equal(x)
}

// p256Square sets e = x^(2^n).
func p256Square(e, x *fiat.P256Element, n int) {
	e.Square(x)
	for i := 1; i < n; i++ {
		e.Square(e)
	}
}
