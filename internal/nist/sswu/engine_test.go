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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	mockFieldLength = 16
	mockModulus     = 1000003
)

type mockElement struct {
	v uint64
}

func (e *mockElement) One() *mockElement {
	e.v = 1
	return e
}

func (e *mockElement) Set(t *mockElement) *mockElement {
	e.v = t.v
	return e
}

func (e *mockElement) SetBytes(in []byte) (*mockElement, error) {
	value := new(big.Int).SetBytes(in)
	value.Mod(value, big.NewInt(mockModulus))
	e.v = value.Uint64()
	return e, nil
}

func (e *mockElement) Bytes() []byte {
	out := make([]byte, mockFieldLength)
	binary.BigEndian.PutUint64(out[mockFieldLength-8:], e.v)
	return out
}

func (e *mockElement) Add(t1, t2 *mockElement) *mockElement {
	e.v = (t1.v + t2.v) % mockModulus
	return e
}

func (e *mockElement) Sub(t1, t2 *mockElement) *mockElement {
	e.v = (t1.v + mockModulus - t2.v%mockModulus) % mockModulus
	return e
}

func (e *mockElement) Mul(t1, t2 *mockElement) *mockElement {
	e.v = (t1.v * t2.v) % mockModulus
	return e
}

func (e *mockElement) Square(t *mockElement) *mockElement {
	e.v = (t.v * t.v) % mockModulus
	return e
}

func (e *mockElement) Invert(t *mockElement) *mockElement {
	inverse := new(big.Int).ModInverse(big.NewInt(int64(t.v)), big.NewInt(mockModulus))
	if inverse == nil {
		panic("mock inverse does not exist")
	}
	e.v = inverse.Uint64()
	return e
}

func (e *mockElement) Select(a, b *mockElement, cond int) *mockElement {
	if cond == 1 {
		e.v = a.v
	} else {
		e.v = b.v
	}
	return e
}

func (e *mockElement) Equal(t *mockElement) int {
	if e.v == t.v {
		return 1
	}
	return 0
}

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

func TestReduceUniformHandlesFullChunks(t *testing.T) {
	engine := newMockEngine()
	input := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	if got, want := engine.reduceUniform(input).v, reduceReference(input); got != want {
		t.Fatalf("unexpected reduction result: got %d, want %d", got, want)
	}
}

func TestReduceUniformHandlesLeadingPartialChunk(t *testing.T) {
	engine := newMockEngine()
	input := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18}
	if got, want := engine.reduceUniform(input).v, reduceReference(input); got != want {
		t.Fatalf("unexpected reduction result: got %d, want %d", got, want)
	}
}

func TestCurvePackagesUseSharedEngine(t *testing.T) {
	files := []string{
		filepath.Join("..", "p256", "p256.go"),
		filepath.Join("..", "p384", "p384.go"),
		filepath.Join("..", "p521", "p521.go"),
	}
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		text := string(content)
		for _, forbidden := range []string{"func mapToCurve(", "func reduceUniform(", "func sqrtRatio("} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s still defines %s", file, forbidden)
			}
		}
	}
}
