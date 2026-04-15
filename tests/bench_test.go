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

	"github.com/bytemare/ecc/hash2curve"
)

// BenchmarkPow benchmarks scalar exponentiation across all groups.
func BenchmarkPow(b *testing.B) {
	testAllGroups(b, func(group *testGroup) {
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

// BenchmarkHashToScalar benchmarks hashing arbitrary input to scalars across all groups.
func BenchmarkHashToScalar(b *testing.B) {
	msg := []byte("benchmark message")
	dst := []byte("benchmark-dst")

	testAllGroups(b, func(group *testGroup) {
		b.SetBytes(int64(len(msg) + len(dst)))
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = group.group.HashToScalar(msg, dst)
		}
	})
}

// BenchmarkHashToGroup benchmarks hashing arbitrary input to group elements across all groups.
func BenchmarkHashToGroup(b *testing.B) {
	msg := []byte("benchmark message")
	dst := []byte("benchmark-dst")

	testAllGroups(b, func(group *testGroup) {
		b.SetBytes(int64(len(msg) + len(dst)))
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = group.group.HashToGroup(msg, dst)
		}
	})
}

// BenchmarkEncodeToGroup benchmarks non-uniform encoding of arbitrary input to group elements across all groups.
func BenchmarkEncodeToGroup(b *testing.B) {
	msg := []byte("benchmark message")
	dst := []byte("benchmark-dst")

	testAllGroups(b, func(group *testGroup) {
		b.SetBytes(int64(len(msg) + len(dst)))
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = group.group.EncodeToGroup(msg, dst)
		}
	})
}

// BenchmarkSubtraction benchmarks element subtraction across all groups.
func BenchmarkSubtraction(b *testing.B) {
	testAllGroups(b, func(group *testGroup) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			base := group.group.Base()
			base.Subtract(base)
		}
	})
}

// BenchmarkScalarBaseMult benchmarks base-point scalar multiplication across all groups.
func BenchmarkScalarBaseMult(b *testing.B) {
	testAllGroups(b, func(group *testGroup) {
		priv := group.group.NewScalar().Random()
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = group.group.Base().Multiply(priv)
			// to do : Prevent the compiler from optimizing out the operation.
		}
	})
}

// BenchmarkScalarMult benchmarks arbitrary-point scalar multiplication across all groups.
func BenchmarkScalarMult(b *testing.B) {
	testAllGroups(b, func(group *testGroup) {
		priv := group.group.NewScalar().Random()
		pub := group.group.Base().Multiply(group.group.NewScalar().Random())
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			pub = pub.Multiply(priv)
		}
	})
}

// BenchmarkScalarEqual benchmarks scalar equality checks across all groups.
func BenchmarkScalarEqual(b *testing.B) {
	testAllGroups(b, func(group *testGroup) {
		left, _ := group.group.HashToScalar([]byte("benchmark left"), []byte("benchmark-dst-left"))
		right, _ := group.group.HashToScalar([]byte("benchmark right"), []byte("benchmark-dst-right"))
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = left.Equal(right)
		}
	})
}

// BenchmarkScalarLessOrEqual benchmarks scalar ordering checks across all groups.
func BenchmarkScalarLessOrEqual(b *testing.B) {
	testAllGroups(b, func(group *testGroup) {
		left, _ := group.group.HashToScalar([]byte("benchmark left"), []byte("benchmark-dst-left"))
		right, _ := group.group.HashToScalar([]byte("benchmark right"), []byte("benchmark-dst-right"))
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = left.LessOrEqual(right)
		}
	})
}

// BenchmarkMarshalUnmarshal benchmarks scalar binary round-tripping across all groups.
func BenchmarkMarshalUnmarshalScalar(b *testing.B) {
	testAllGroups(b, func(group *testGroup) {
		s := group.group.NewScalar().Random()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			buf := s.Encode()

			pk := group.group.NewScalar()
			if err := pk.Decode(buf); err != nil {
				b.Fatal(err)
			}

			if !bytes.Equal(buf, pk.Encode()) {
				b.Error("Unmarshal output different from Marshal input")
			}
		}
	})
}

// BenchmarkMarshalUnmarshal benchmarks element binary round-tripping across all groups.
func BenchmarkMarshalUnmarshalElement(b *testing.B) {
	testAllGroups(b, func(group *testGroup) {
		pub := group.group.Base().Multiply(group.group.NewScalar().Random())
		b.ReportAllocs()
		b.ResetTimer()
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

// BenchmarkExpandXMD benchmarks allocating XMD expansion for representative suite lengths.
func BenchmarkExpandXMD(b *testing.B) {
	input := []byte("benchmark input")
	dst := []byte("benchmark-dst")

	testAllGroups(b, func(group *testGroup) {
		b.ReportAllocs()
		b.SetBytes(int64(len(input) + len(dst)))
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, _ = hash2curve.ExpandXMD(group.hash, input, dst, group.hashToCurve.securityLength)
		}
	})
}

// BenchmarkExpandXMDTo benchmarks sink-style XMD expansion for representative suite lengths.
func BenchmarkExpandXMDTo(b *testing.B) {
	input := []byte("benchmark input")
	dst := []byte("benchmark-dst")

	testAllGroups(b, func(group *testGroup) {
		b.ReportAllocs()
		b.SetBytes(int64(len(input) + len(dst)))
		b.ResetTimer()
		out := make([]byte, group.hashToCurve.securityLength)

		for i := 0; i < b.N; i++ {
			_ = hash2curve.ExpandXMDTo(group.hash, out, input, dst)
		}
	})
}
