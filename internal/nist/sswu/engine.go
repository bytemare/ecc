// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package sswu implements the shared constant-time Simplified SWU engine used
// by the NIST curve wrappers. Curve-specific square-root chains and point
// encoders remain local to each curve package so the main review surface stays
// explicit.
package sswu

import (
	"crypto"

	"github.com/bytemare/ecc/hash2curve"
)

const maxFieldLength = 66

// FieldElement captures the field operations required by the shared SSWU
// engine.
type FieldElement[E any] interface {
	One() E
	Set(E) E
	SetBytes([]byte) (E, error)
	Bytes() []byte
	Add(E, E) E
	Sub(E, E) E
	Mul(E, E) E
	Square(E) E
	Invert(E) E
	Select(E, E, int) E
	Equal(E) int
	IsZero() int
}

// Engine implements the shared hash-to-curve and encode-to-curve logic for the
// NIST curves over a concrete field element and point type.
type Engine[E FieldElement[E], P any] struct {
	One           E
	A             E
	B             E
	Z             E
	Two64         E
	NewElement    func() E
	Sqrt          func(dst, x E) int
	ToPoint       func(x, y E) P
	AddPoints     func(p, q P) P
	Hash          crypto.Hash
	FieldLength   int
	UniformLength int
}

// HashToCurve returns the RFC 9380 random-oracle encoding for the configured
// curve.
func (e *Engine[E, P]) HashToCurve(input, dst []byte) (P, error) {
	length := 2 * e.UniformLength
	var uniform [196]byte // 196 is 2*98, the highest value we would use, for P521.

	// Pre-allocate a larger buffer but slice it to length. This spares a dedicated allocation.
	if err := hash2curve.ExpandXMDTo(e.Hash, uniform[:length], input, dst); err != nil {
		return *new(P), err
	}

	q0 := e.mapToCurve(e.reduceUniform(uniform[:e.UniformLength]))
	q1 := e.mapToCurve(e.reduceUniform(uniform[e.UniformLength:length]))

	return e.AddPoints(q0, q1), nil
}

// EncodeToCurve returns the RFC 9380 non-uniform encoding for the configured
// curve.
func (e *Engine[E, P]) EncodeToCurve(input, dst []byte) (P, error) {
	var uniform [98]byte // 98 is the highest value we would use, for P521.

	// Pre-allocate a larger buffer but slice it to length. This spares a dedicated allocation.
	if err := hash2curve.ExpandXMDTo(e.Hash, uniform[:e.UniformLength], input, dst); err != nil {
		return *new(P), err
	}

	return e.mapToCurve(e.reduceUniform(uniform[:e.UniformLength])), nil
}

// reduceUniform reduces expanded XMD bytes into a field element by Horner
// evaluation over 64-bit chunks.
func (e *Engine[E, P]) reduceUniform(uniform []byte) E {
	acc := e.NewElement()
	remaining := uniform
	if rem := len(remaining) % 8; rem != 0 {
		acc = e.elementFromUint64(decodeWord(remaining[:rem]))
		remaining = remaining[rem:]
	}

	for len(remaining) > 0 {
		chunk := e.elementFromUint64(decodeWord(remaining[:8]))
		acc.Mul(acc, e.Two64)
		acc.Add(acc, chunk)
		remaining = remaining[8:]
	}

	return acc
}

// mapToCurve applies the shared SSWU map over the configured field.
func (e *Engine[E, P]) mapToCurve(u E) P {
	tv1 := e.NewElement().Square(u)
	tv1.Mul(tv1, e.Z)
	tv2 := e.NewElement().Square(tv1)
	tv2.Add(tv2, tv1)
	tv3 := e.NewElement().Add(tv2, e.One)
	tv3.Mul(tv3, e.B)
	negTv2 := e.NewElement().Sub(e.NewElement(), tv2)
	tv4 := e.NewElement().Select(negTv2, e.Z, 1-tv2.IsZero())
	tv4.Mul(tv4, e.A)
	tv2.Square(tv3)
	tv6 := e.NewElement().Square(tv4)
	tv5 := e.NewElement().Mul(e.A, tv6)
	tv2.Add(tv2, tv5)
	tv2.Mul(tv2, tv3)
	tv6.Mul(tv6, tv4)
	tv5.Mul(e.B, tv6)
	tv2.Add(tv2, tv5)
	x := e.NewElement().Mul(tv1, tv3)
	y1, isSquare := e.sqrtRatio(tv2, tv6)
	y := e.NewElement().Mul(tv1, u)
	y.Mul(y, y1)
	x.Select(tv3, x, isSquare)
	y.Select(y1, y, isSquare)
	negY := e.NewElement().Sub(e.NewElement(), y)
	y.Select(y, negY, equalBit(e.sgn0(u), e.sgn0(y)))
	tv4.Invert(tv4)
	x.Mul(x, tv4)
	return e.ToPoint(x, y)
}

// sqrtRatio returns sqrt(u/v) when it exists, or sqrt(Z*u/v) otherwise, along
// with a flag indicating whether u/v was square.
func (e *Engine[E, P]) sqrtRatio(u, v E) (E, int) {
	inv := e.NewElement().Invert(v)
	quotient := e.NewElement().Mul(inv, u)
	y1 := e.NewElement()
	isSquare := e.Sqrt(y1, quotient)
	candidate := e.NewElement().Mul(quotient, e.Z)
	y2 := e.NewElement()
	_ = e.Sqrt(y2, candidate)
	return e.NewElement().Select(y1, y2, isSquare), isSquare
}

func (e *Engine[E, P]) mustSetBytes(in []byte) E {
	v, err := e.NewElement().SetBytes(in)
	if err != nil {
		panic(err)
	}
	return v
}

func (e *Engine[E, P]) elementFromUint64(v uint64) E {
	var in [maxFieldLength]byte
	start := len(in) - e.FieldLength
	for i := range 8 {
		in[len(in)-1-i] = byte(v)
		v >>= 8
	}
	return e.mustSetBytes(in[start:])
}

func (e *Engine[E, P]) sgn0(x E) int {
	return int(x.Bytes()[e.FieldLength-1] & 1)
}

func decodeWord(in []byte) uint64 {
	var out uint64
	for _, b := range in {
		out = (out << 8) | uint64(b)
	}
	return out
}

func equalBit(x, y int) int {
	return 1 ^ (x ^ y)
}
