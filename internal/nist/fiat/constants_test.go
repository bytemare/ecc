// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package fiat

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func canonicalUint64Bytes(length int, value uint64) []byte {
	out := make([]byte, length)
	for i := range 8 {
		out[length-1-i] = byte(value)
		value >>= 8
	}
	return out
}

func two64Bytes(length int) []byte {
	out := make([]byte, length)
	out[length-9] = 1
	return out
}

func mustDecodeHex(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
}

// TestP256PrecomputedConstants tests that the checked-in P-256 field constants match runtime-derived values.
func TestP256PrecomputedConstants(t *testing.T) {
	one := new(P256Element).One().Bytes()
	if got := P256One().Bytes(); !bytes.Equal(got, one) {
		t.Fatal("P256One mismatch")
	}

	three, err := new(P256Element).SetBytes(canonicalUint64Bytes(p256ElementLen, 3))
	if err != nil {
		t.Fatalf("set three: %v", err)
	}
	if got := P256A().Bytes(); !bytes.Equal(got, new(P256Element).Sub(new(P256Element), three).Bytes()) {
		t.Fatal("P256A mismatch")
	}
	if got := P256B().Bytes(); !bytes.Equal(
		got,
		mustDecodeHex(t, "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
	) {
		t.Fatal("P256B mismatch")
	}
	ten, err := new(P256Element).SetBytes(canonicalUint64Bytes(p256ElementLen, 10))
	if err != nil {
		t.Fatalf("set ten: %v", err)
	}
	if got := P256Z().Bytes(); !bytes.Equal(got, new(P256Element).Sub(new(P256Element), ten).Bytes()) {
		t.Fatal("P256Z mismatch")
	}
	two64, err := new(P256Element).SetBytes(two64Bytes(p256ElementLen))
	if err != nil {
		t.Fatalf("set 2^64: %v", err)
	}
	if got := P256Two64().Bytes(); !bytes.Equal(got, two64.Bytes()) {
		t.Fatal("P256Two64 mismatch")
	}
	minusOne := new(P256Element).Sub(new(P256Element), new(P256Element).One()).Bytes()
	if !bytes.Equal(p256MinusOneEncoding[:], minusOne) {
		t.Fatal("p256 minus-one encoding mismatch")
	}
}

// TestP384PrecomputedConstants tests that the checked-in P-384 field constants match runtime-derived values.
func TestP384PrecomputedConstants(t *testing.T) {
	one := new(P384Element).One().Bytes()
	if got := P384One().Bytes(); !bytes.Equal(got, one) {
		t.Fatal("P384One mismatch")
	}

	three, err := new(P384Element).SetBytes(canonicalUint64Bytes(p384ElementLen, 3))
	if err != nil {
		t.Fatalf("set three: %v", err)
	}
	if got := P384A().Bytes(); !bytes.Equal(got, new(P384Element).Sub(new(P384Element), three).Bytes()) {
		t.Fatal("P384A mismatch")
	}
	if got := P384B().Bytes(); !bytes.Equal(
		got,
		mustDecodeHex(
			t,
			"b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
		),
	) {
		t.Fatal("P384B mismatch")
	}
	twelve, err := new(P384Element).SetBytes(canonicalUint64Bytes(p384ElementLen, 12))
	if err != nil {
		t.Fatalf("set twelve: %v", err)
	}
	if got := P384Z().Bytes(); !bytes.Equal(got, new(P384Element).Sub(new(P384Element), twelve).Bytes()) {
		t.Fatal("P384Z mismatch")
	}
	two64, err := new(P384Element).SetBytes(two64Bytes(p384ElementLen))
	if err != nil {
		t.Fatalf("set 2^64: %v", err)
	}
	if got := P384Two64().Bytes(); !bytes.Equal(got, two64.Bytes()) {
		t.Fatal("P384Two64 mismatch")
	}
	minusOne := new(P384Element).Sub(new(P384Element), new(P384Element).One()).Bytes()
	if !bytes.Equal(p384MinusOneEncoding[:], minusOne) {
		t.Fatal("p384 minus-one encoding mismatch")
	}
}

// TestP521PrecomputedConstants tests that the checked-in P-521 field constants match runtime-derived values.
func TestP521PrecomputedConstants(t *testing.T) {
	one := new(P521Element).One().Bytes()
	if got := P521One().Bytes(); !bytes.Equal(got, one) {
		t.Fatal("P521One mismatch")
	}

	three, err := new(P521Element).SetBytes(canonicalUint64Bytes(p521ElementLen, 3))
	if err != nil {
		t.Fatalf("set three: %v", err)
	}
	if got := P521A().Bytes(); !bytes.Equal(got, new(P521Element).Sub(new(P521Element), three).Bytes()) {
		t.Fatal("P521A mismatch")
	}
	if got := P521B().Bytes(); !bytes.Equal(
		got,
		mustDecodeHex(
			t,
			"0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
		),
	) {
		t.Fatal("P521B mismatch")
	}
	four, err := new(P521Element).SetBytes(canonicalUint64Bytes(p521ElementLen, 4))
	if err != nil {
		t.Fatalf("set four: %v", err)
	}
	if got := P521Z().Bytes(); !bytes.Equal(got, new(P521Element).Sub(new(P521Element), four).Bytes()) {
		t.Fatal("P521Z mismatch")
	}
	two64, err := new(P521Element).SetBytes(two64Bytes(p521ElementLen))
	if err != nil {
		t.Fatalf("set 2^64: %v", err)
	}
	if got := P521Two64().Bytes(); !bytes.Equal(got, two64.Bytes()) {
		t.Fatal("P521Two64 mismatch")
	}
	minusOne := new(P521Element).Sub(new(P521Element), new(P521Element).One()).Bytes()
	if !bytes.Equal(p521MinusOneEncoding[:], minusOne) {
		t.Fatal("p521 minus-one encoding mismatch")
	}
}
