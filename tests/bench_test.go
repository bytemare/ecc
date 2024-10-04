// SPDX-License-Group: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package ecc_test

import (
	"bytes"
	"testing"
)

func benchAll(b *testing.B, f func(*testing.B, *testGroup)) {
	for _, group := range testTable {
		b.Run(group.name, func(t *testing.B) {
			f(t, group)
		})
	}
}

func BenchmarkPow(b *testing.B) {
	benchAll(b, func(b *testing.B, group *testGroup) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			base := group.group.NewScalar().Random()
			exp := group.group.NewScalar().Random()
			res := base.Pow(exp)
			res.Equal(base)
		}
	})
}

func BenchmarkHashToGroup(b *testing.B) {
	msg := make([]byte, 256)
	dst := make([]byte, 10)
	benchAll(b, func(b *testing.B, group *testGroup) {
		b.SetBytes(int64(len(msg)))
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			group.group.HashToGroup(msg, dst)
		}
	})
}

func BenchmarkSubtraction(b *testing.B) {
	benchAll(b, func(b *testing.B, group *testGroup) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			base := group.group.Base()
			base.Subtract(base)
		}
	})
}

func BenchmarkScalarBaseMult(b *testing.B) {
	benchAll(b, func(b *testing.B, group *testGroup) {
		priv := group.group.NewScalar().Random()
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = group.group.Base().Multiply(priv)
			// to do : Prevent the compiler from optimizing out the operation.
		}
	})
}

func BenchmarkScalarMult(b *testing.B) {
	benchAll(b, func(b *testing.B, group *testGroup) {
		priv := group.group.NewScalar().Random()
		pub := group.group.Base().Multiply(group.group.NewScalar().Random())
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			pub = pub.Multiply(priv)
		}
	})
}

func BenchmarkMarshalUnmarshal(b *testing.B) {
	benchAll(b, func(b *testing.B, group *testGroup) {
		pub := group.group.Base().Multiply(group.group.NewScalar().Random())
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf := pub.Encode()
			pk := group.group.NewElement()
			if err := pk.Decode(buf); err != nil {
				b.Fatal(err)
			}
			if !bytes.Equal(buf, pk.Encode()) {
				b.Error("Unmarshal output different from Marshal input")
			}
		}
	})
}
