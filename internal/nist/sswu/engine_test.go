// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package sswu

import (
	"encoding/binary"
	"math/big"
	"testing"
)

const (
	mockFieldLength = 16
	mockModulus     = 1000003
)

type mockElement struct {
	v uint64
}

// One sets e to the multiplicative identity in the mock field.
func (e *mockElement) One() *mockElement {
	e.v = 1
	return e
}

// Set copies t into e.
func (e *mockElement) Set(t *mockElement) *mockElement {
	e.v = t.v
	return e
}

// SetBytes reduces the big-endian input modulo the mock field.
func (e *mockElement) SetBytes(in []byte) (*mockElement, error) {
	value := new(big.Int).SetBytes(in)
	value.Mod(value, big.NewInt(mockModulus))
	e.v = value.Uint64()
	return e, nil
}

// Bytes returns the canonical big-endian encoding of e.
func (e *mockElement) Bytes() []byte {
	out := make([]byte, mockFieldLength)
	binary.BigEndian.PutUint64(out[mockFieldLength-8:], e.v)
	return out
}

// Add sets e to t1+t2 modulo the mock field.
func (e *mockElement) Add(t1, t2 *mockElement) *mockElement {
	e.v = (t1.v + t2.v) % mockModulus
	return e
}

// Sub sets e to t1-t2 modulo the mock field.
func (e *mockElement) Sub(t1, t2 *mockElement) *mockElement {
	e.v = (t1.v + mockModulus - t2.v%mockModulus) % mockModulus
	return e
}

// Mul sets e to t1*t2 modulo the mock field.
func (e *mockElement) Mul(t1, t2 *mockElement) *mockElement {
	e.v = (t1.v * t2.v) % mockModulus
	return e
}

// Square sets e to t^2 modulo the mock field.
func (e *mockElement) Square(t *mockElement) *mockElement {
	e.v = (t.v * t.v) % mockModulus
	return e
}

// Invert sets e to the multiplicative inverse of t in the mock field.
func (e *mockElement) Invert(t *mockElement) *mockElement {
	inverse := new(big.Int).ModInverse(big.NewInt(int64(t.v)), big.NewInt(mockModulus))
	if inverse == nil {
		panic("mock inverse does not exist")
	}
	e.v = inverse.Uint64()
	return e
}

// Select sets e to a when cond is 1 and to b otherwise.
func (e *mockElement) Select(a, b *mockElement, cond int) *mockElement {
	if cond == 1 {
		e.v = a.v
	} else {
		e.v = b.v
	}
	return e
}

// Equal returns 1 if e and t hold the same mock-field value and 0 otherwise.
func (e *mockElement) Equal(t *mockElement) int {
	if e.v == t.v {
		return 1
	}
	return 0
}

// IsZero returns 1 if e is zero in the mock field and 0 otherwise.
func (e *mockElement) IsZero() int {
	if e.v == 0 {
		return 1
	}
	return 0
}

func newMockEngine() *Engine[*mockElement, int] {
	two64 := new(big.Int).Lsh(big.NewInt(1), 64)
	two64.Mod(two64, big.NewInt(mockModulus))

	return &Engine[*mockElement, int]{
		FieldLength:   mockFieldLength,
		UniformLength: 19,
		One:           &mockElement{v: 1},
		A:             &mockElement{v: mockModulus - 3},
		B:             &mockElement{v: 7},
		Z:             &mockElement{v: mockModulus - 5},
		Two64:         &mockElement{v: two64.Uint64()},
		NewElement: func() *mockElement {
			return &mockElement{}
		},
		Sqrt: func(dst, x *mockElement) int {
			dst.Set(x)
			return 1
		},
		ToPoint: func(x, y *mockElement) int {
			return int(x.v + y.v)
		},
		AddPoints: func(p, q int) int {
			return p + q
		},
	}
}

func reduceReference(input []byte) uint64 {
	modulus := big.NewInt(mockModulus)
	two64 := new(big.Int).Lsh(big.NewInt(1), 64)
	two64.Mod(two64, modulus)
	acc := new(big.Int)
	remaining := input
	if rem := len(remaining) % 8; rem != 0 {
		acc.SetUint64(decodeWord(remaining[:rem]))
		acc.Mod(acc, modulus)
		remaining = remaining[rem:]
	}

	for len(remaining) > 0 {
		acc.Mul(acc, two64)
		acc.Add(acc, new(big.Int).SetUint64(decodeWord(remaining[:8])))
		acc.Mod(acc, modulus)
		remaining = remaining[8:]
	}

	return acc.Uint64()
}

// TestReduceUniformHandlesFullChunks tests that reduceUniform handles inputs made only of 64-bit chunks.
func TestReduceUniformHandlesFullChunks(t *testing.T) {
	engine := newMockEngine()
	input := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	if got, want := engine.reduceUniform(input).v, reduceReference(input); got != want {
		t.Fatalf("unexpected reduction result: got %d, want %d", got, want)
	}
}

// TestReduceUniformHandlesLeadingPartialChunk tests that reduceUniform handles inputs with a leading partial chunk.
func TestReduceUniformHandlesLeadingPartialChunk(t *testing.T) {
	engine := newMockEngine()
	input := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18}
	if got, want := engine.reduceUniform(input).v, reduceReference(input); got != want {
		t.Fatalf("unexpected reduction result: got %d, want %d", got, want)
	}
}
