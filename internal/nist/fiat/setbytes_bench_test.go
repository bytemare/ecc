// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package fiat

import (
	"encoding/hex"
	"testing"
)

func benchmarkDecodeHex(b *testing.B, h string) []byte {
	b.Helper()
	out, err := hex.DecodeString(h)
	if err != nil {
		b.Fatal(err)
	}
	return out
}

func BenchmarkP256SetBytes(b *testing.B) {
	input := benchmarkDecodeHex(b, "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")
	element := new(P256Element)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := element.SetBytes(input); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkP384SetBytes(b *testing.B) {
	input := benchmarkDecodeHex(
		b,
		"b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
	)
	element := new(P384Element)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := element.SetBytes(input); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkP521SetBytes(b *testing.B) {
	input := benchmarkDecodeHex(
		b,
		"0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
	)
	element := new(P521Element)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := element.SetBytes(input); err != nil {
			b.Fatal(err)
		}
	}
}
