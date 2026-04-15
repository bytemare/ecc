// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package ecc_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"math/big"
	"math/rand"
	"slices"
	"testing"

	"github.com/bytemare/ecc"
	"github.com/bytemare/ecc/internal"
	"github.com/bytemare/ecc/internal/edwards25519"
	"github.com/bytemare/ecc/internal/nist"
	"github.com/bytemare/ecc/internal/ristretto"
	"github.com/bytemare/ecc/internal/secp256k1"

	libsecp256k1 "github.com/bytemare/secp256k1"
)

const scalarCompareIterations = 256

// TestScalar_Group tests that each scalar reports its owning group.
func TestScalar_Group(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		s := group.group.NewScalar()
		if s.Group() != group.group {
			t.Fatal(errWrongGroup)
		}
	})
}

// TestScalar_WrongInput tests that scalar operations panic on wrong-group and wrong-field inputs.
func TestScalar_WrongInput(t *testing.T) {
	exec := func(f func(*ecc.Scalar) *ecc.Scalar, arg *ecc.Scalar) func() {
		return func() {
			f(arg)
		}
	}

	equal := func(f func(*ecc.Scalar) bool, arg *ecc.Scalar) func() {
		return func() {
			f(arg)
		}
	}

	testAllGroups(t, func(group *testGroup) {
		scalar := group.group.NewScalar()
		methods := []func(arg *ecc.Scalar) *ecc.Scalar{
			scalar.Add, scalar.Subtract, scalar.Multiply, scalar.Set,
		}

		var wrongGroup ecc.Group

		switch group.group {
		// The following is arbitrary, and simply aims at confusing identifiers
		case ecc.Ristretto255Sha512, ecc.Edwards25519Sha512, ecc.Secp256k1Sha256:
			wrongGroup = ecc.P256Sha256
		case ecc.P256Sha256, ecc.P384Sha384, ecc.P521Sha512:
			wrongGroup = ecc.Ristretto255Sha512

			// Add a special test for nist groups, using a different field
			wrongfield := ((group.group + 1) % 3) + 3
			expectPanic(t, "wrong field", internal.ErrWrongField, exec(scalar.Add, wrongfield.NewScalar()))
		default:
			t.Fatalf("Invalid group id %d", group.group)
		}

		for _, f := range methods {
			expectPanic(t, "wrong group", internal.ErrWrongGroup, exec(f, wrongGroup.NewScalar()))
		}

		expectPanic(t, "wrong group", internal.ErrWrongGroup, equal(scalar.Equal, wrongGroup.NewScalar()))
	})
}

func testScalarCopySet(t *testing.T, scalar, other *ecc.Scalar) {
	// Verify they don't point to the same thing
	if &scalar == &other {
		t.Fatalf("Pointer to the same scalar")
	}

	// Verify whether they are equivalent
	if !scalar.Equal(other) {
		t.Fatalf("Expected equality")
	}

	// Verify than operations on one don't affect the other
	scalar.Add(scalar)
	if scalar.Equal(other) {
		t.Fatalf(errUnExpectedEquality)
	}

	other.Invert()
	if scalar.Equal(other) {
		t.Fatalf(errUnExpectedEquality)
	}

	// Verify setting to nil sets to 0
	if !scalar.Set(nil).Equal(other.Zero()) {
		t.Error(errExpectedEquality)
	}
}

// TestScalar_Copy tests that Copy duplicates a scalar without aliasing it.
func TestScalar_Copy(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		random := group.group.NewScalar().Random()
		cpy := random.Copy()
		testScalarCopySet(t, random, cpy)
	})
}

// TestScalar_Set tests that Set copies a scalar value without aliasing it.
func TestScalar_Set(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		random := group.group.NewScalar().Random()
		other := group.group.NewScalar()
		other.Set(random)
		testScalarCopySet(t, random, other)
	})
}

func parseScalar(s *ecc.Scalar) ([]byte, bool) {
	b := s.Encode()
	b3 := b[8:]
	b4 := byte(0)
	for _, bx := range b3 {
		b4 |= bx
	}
	return b[:8], b4 == 0
}

func testScalarUInt64(t *testing.T, s *ecc.Scalar, expectedValue uint64, expectedError error) {
	t.Helper()
	i, err := s.UInt64()

	if err == nil {
		if expectedError != nil {
			t.Fatalf("expected error %q", expectedError)
		}
	} else {
		if expectedError == nil {
			t.Fatalf("unexpected error %q", err)
		} else if !errors.Is(err, expectedError) {
			t.Fatalf("expected error %q, got %q", expectedError, err)
		}
	}

	if expectedError == nil && i != expectedValue {
		t.Fatalf("expected %d, got %d", expectedValue, i)
	}
}

// TestScalar_UInt64 tests conversion of scalars to uint64 across valid and overflowing values.
func TestScalar_UInt64(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		// 0
		testScalarUInt64(t, group.group.NewScalar(), 0, nil)

		// 1
		testScalarUInt64(t, group.group.NewScalar().One(), 1, nil)

		// Max Uint64
		testScalarUInt64(t, group.group.NewScalar().SetUInt64(math.MaxUint64), math.MaxUint64, nil)

		// Max Uint64+1 fails
		s := group.group.NewScalar().SetUInt64(math.MaxUint64).Add(group.group.NewScalar().One())
		testScalarUInt64(t, s, 0, internal.ErrUInt64TooBig)

		// Order - 1 fails
		s = group.group.NewScalar().Subtract(group.group.NewScalar().One())
		testScalarUInt64(t, s, 0, internal.ErrUInt64TooBig)
	})
}

// TestScalar_SetUInt64 tests uint64-to-scalar conversion across all groups.
func TestScalar_SetUInt64(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		s := group.group.NewScalar().SetUInt64(0)
		if !s.IsZero() {
			t.Fatal("expected 0")
		}

		s.SetUInt64(1)
		if !s.Equal(group.group.NewScalar().One()) {
			t.Fatal("expected 1")
		}

		// uint64 max badValue is 18,446,744,073,709,551,615
		s.SetUInt64(math.MaxUint64)
		ref := make([]byte, group.group.ScalarLength())

		switch group.group {
		case ecc.Ristretto255Sha512, ecc.Edwards25519Sha512:
			binary.LittleEndian.PutUint64(ref, math.MaxUint64)
		default:
			binary.BigEndian.PutUint64(ref[group.group.ScalarLength()-8:], math.MaxUint64)
		}

		if bytes.Compare(ref, s.Encode()) != 0 {
			t.Fatalf("expected %q, got %q", hex.EncodeToString(ref), s.Hex())
		}
	})
}

// TestScalar_EncodedLength tests that encoded scalars have the expected byte length.
func TestScalar_EncodedLength(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		encodedScalar := group.group.NewScalar().Random().Encode()
		if len(encodedScalar) != group.scalarLength {
			t.Fatalf(
				"Encode() is expected to return %d bytes, but returned %d bytes",
				group.scalarLength,
				encodedScalar,
			)
		}
	})
}

func decodeWithReductionInputLength(g ecc.Group) int {
	switch g {
	case ecc.Ristretto255Sha512, ecc.Edwards25519Sha512, ecc.P521Sha512:
		return 64
	default:
		return g.ScalarLength()
	}
}

func isLittleEndianScalarGroup(g ecc.Group) bool {
	switch g {
	case ecc.Ristretto255Sha512, ecc.Edwards25519Sha512:
		return true
	default:
		return false
	}
}

func reductionOrder(g ecc.Group) *big.Int {
	order := slices.Clone(g.Order())
	if g == ecc.Ristretto255Sha512 {
		slices.Reverse(order)
	}

	return new(big.Int).SetBytes(order)
}

func encodeReductionInput(g ecc.Group, value *big.Int) []byte {
	input := make([]byte, decodeWithReductionInputLength(g))
	value.FillBytes(input)

	if isLittleEndianScalarGroup(g) {
		slices.Reverse(input)
	}

	return input
}

func expectedReducedScalar(t *testing.T, g ecc.Group, input []byte) *ecc.Scalar {
	t.Helper()

	s := g.NewScalar()

	if g == ecc.P521Sha512 {
		encoded := make([]byte, g.ScalarLength())
		copy(encoded[len(encoded)-len(input):], input)

		if err := s.Decode(encoded); err != nil {
			t.Fatal(err)
		}

		return s
	}

	buf := slices.Clone(input)
	if isLittleEndianScalarGroup(g) {
		slices.Reverse(buf)
	}

	value := new(big.Int).SetBytes(buf)
	value.Mod(value, reductionOrder(g))

	encoded := make([]byte, g.ScalarLength())
	value.FillBytes(encoded)
	if isLittleEndianScalarGroup(g) {
		slices.Reverse(encoded)
	}

	if err := s.Decode(encoded); err != nil {
		t.Fatal(err)
	}

	return s
}

// TestScalar_DecodeWithReduction_InvalidInputLength tests that DecodeWithReduction rejects invalid input lengths.
func TestScalar_DecodeWithReduction_InvalidInputLength(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		g := group.group
		inputLength := decodeWithReductionInputLength(g)
		expectedError := internal.ErrParamInvalidInputLength
		if g == ecc.Secp256k1Sha256 {
			expectedError = libsecp256k1.ErrParamInvalidInputLength
		}

		cases := []struct {
			name  string
			input []byte
		}{
			{name: "nil", input: nil},
			{name: "empty", input: []byte{}},
			{name: "short", input: make([]byte, inputLength-1)},
			{name: "long", input: make([]byte, inputLength+1)},
		}

		if g == ecc.P521Sha512 {
			cases = append(cases, struct {
				name  string
				input []byte
			}{
				name:  "canonical-length",
				input: make([]byte, g.ScalarLength()),
			})
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				err := g.NewScalar().DecodeWithReduction(tc.input)
				if err == nil {
					t.Fatal("expected error on invalid reduction input length")
				}

				if !errors.Is(err, ecc.ErrDecodeScalar) {
					t.Fatalf("expected wrapped scalar decoding error, got %v", err)
				}

				if !errors.Is(err, expectedError) {
					t.Fatalf("expected invalid input length, got %v", err)
				}
			})
		}
	})
}

// TestScalar_DecodeWithReduction_Edges tests DecodeWithReduction on edge-case inputs around each group order.
func TestScalar_DecodeWithReduction_Edges(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		g := group.group
		order := reductionOrder(g)

		type testCase struct {
			canonicalErr error
			name         string
			input        []byte
		}

		cases := []testCase{
			{name: "zero", input: make([]byte, decodeWithReductionInputLength(g))},
			{name: "one", input: encodeReductionInput(g, big.NewInt(1))},
		}

		if g == ecc.P521Sha512 {
			topBitSet := make([]byte, decodeWithReductionInputLength(g))
			topBitSet[0] = 0x80

			cases = append(cases,
				testCase{name: "top-bit-set", input: topBitSet},
				testCase{name: "all-ff", input: bytes.Repeat([]byte{0xff}, decodeWithReductionInputLength(g))},
			)
		} else {
			canonicalErr := internal.ErrParamScalarInvalidEncoding
			if isLittleEndianScalarGroup(g) {
				canonicalErr = nil
			}

			cases = append(cases,
				testCase{
					name:  "order-minus-one",
					input: encodeReductionInput(g, new(big.Int).Sub(order, big.NewInt(1))),
				},
				testCase{
					name:         "order",
					input:        encodeReductionInput(g, new(big.Int).Set(order)),
					canonicalErr: canonicalErr,
				},
				testCase{
					name:         "order-plus-one",
					input:        encodeReductionInput(g, new(big.Int).Add(new(big.Int).Set(order), big.NewInt(1))),
					canonicalErr: canonicalErr,
				},
				testCase{
					name:         "all-ff",
					input:        bytes.Repeat([]byte{0xff}, decodeWithReductionInputLength(g)),
					canonicalErr: canonicalErr,
				},
			)
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got := g.NewScalar().One()
				if err := got.DecodeWithReduction(tc.input); err != nil {
					t.Fatal(err)
				}

				want := expectedReducedScalar(t, g, tc.input)
				if !got.Equal(want) {
					t.Fatalf("unexpected reduction for %s: want %s, got %s", tc.name, want.Hex(), got.Hex())
				}

				if g == ecc.P521Sha512 {
					padded := make([]byte, g.ScalarLength())
					copy(padded[len(padded)-len(tc.input):], tc.input)

					expected := g.NewScalar()
					if err := expected.Decode(padded); err != nil {
						t.Fatal(err)
					}

					if !got.Equal(expected) {
						t.Fatalf(
							"P-521 reduction must match zero-padded canonical decode: want %s, got %s",
							expected.Hex(),
							got.Hex(),
						)
					}
				}

				if tc.canonicalErr != nil {
					expectErrors(t,
						func() error { return g.NewScalar().Decode(tc.input) },
						ecc.ErrDecodeScalar,
						tc.canonicalErr,
					)
				}
			})
		}
	})
}

// TestScalar_DecodeWithReduction_Properties tests the reduction and canonical round-trip properties of DecodeWithReduction.
func TestScalar_DecodeWithReduction_Properties(t *testing.T) {
	const iterations = 16

	testAllGroups(t, func(group *testGroup) {
		g := group.group
		inputLength := decodeWithReductionInputLength(g)
		rng := rand.New(rand.NewSource(int64(g)))

		for range iterations {
			input := make([]byte, inputLength)
			if _, err := rng.Read(input); err != nil {
				t.Fatal(err)
			}

			want := expectedReducedScalar(t, g, input)
			got := g.NewScalar()
			if err := got.DecodeWithReduction(input); err != nil {
				t.Fatal(err)
			}

			if !got.Equal(want) {
				t.Fatalf(
					"unexpected reduction: want %s, got %s (input %s)",
					want.Hex(),
					got.Hex(),
					hex.EncodeToString(input),
				)
			}

			roundTrip := g.NewScalar()
			if err := roundTrip.Decode(got.Encode()); err != nil {
				t.Fatal(err)
			}

			if !roundTrip.Equal(got) {
				t.Fatalf("canonical round-trip mismatch: want %s, got %s", got.Hex(), roundTrip.Hex())
			}

			if g == ecc.P521Sha512 {
				padded := make([]byte, g.ScalarLength())
				copy(padded[len(padded)-len(input):], input)

				paddedScalar := g.NewScalar()
				if err := paddedScalar.Decode(padded); err != nil {
					t.Fatal(err)
				}

				if !got.Equal(paddedScalar) {
					t.Fatalf(
						"P-521 reduction must match zero-padded canonical decode: want %s, got %s",
						paddedScalar.Hex(),
						got.Hex(),
					)
				}
			}
		}

		if g == ecc.P521Sha512 {
			return
		}

		order := reductionOrder(g)
		maxInput := new(big.Int).Lsh(big.NewInt(1), uint(8*inputLength))
		limit := new(big.Int).Sub(maxInput, order)
		buf := make([]byte, len(limit.Bytes()))

		for range iterations {
			if _, err := rng.Read(buf); err != nil {
				t.Fatal(err)
			}

			x := new(big.Int).SetBytes(buf)
			x.Mod(x, limit)

			left := g.NewScalar()
			if err := left.DecodeWithReduction(encodeReductionInput(g, x)); err != nil {
				t.Fatal(err)
			}

			right := g.NewScalar()
			x.Add(x, order)
			if err := right.DecodeWithReduction(encodeReductionInput(g, x)); err != nil {
				t.Fatal(err)
			}

			if !left.Equal(right) {
				t.Fatalf("expected x and x+order to reduce equally: %s != %s", left.Hex(), right.Hex())
			}
		}
	})
}

// TestScalar_Internal_NilOperations tests the internal nil-input contracts for scalar operations.
func TestScalar_Internal_NilOperations(t *testing.T) {
	var nilScalar internal.Scalar

	cases := []struct {
		scalar internal.Scalar
		name   string
	}{
		{scalar: edwards25519.New().NewScalar(), name: "Edwards"},
		{scalar: ristretto.New().NewScalar(), name: "Ristretto"},
		{scalar: secp256k1.New().NewScalar(), name: "Secp256k1"},
		{scalar: nist.P256().NewScalar(), name: "NistP256"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := tc.scalar
			s.One()

			if s.Add(nilScalar) != s {
				t.Fatal("Add should return receiver when scalar nil")
			}

			s.One()
			if s.Subtract(nilScalar) != s {
				t.Fatal("Subtract should return receiver when scalar nil")
			}

			s.One()
			if s.Equal(nilScalar) != 0 {
				t.Fatal("Equal should return 0 when compared to nil")
			}

			s.One()
			s.Multiply(nilScalar)

			if !s.IsZero() {
				t.Fatal("Multiply with nil scalar should zero the receiver")
			}

			s.One()
			s.Set(nilScalar)

			if !s.IsZero() {
				t.Fatal("Set with nil scalar should zero the receiver")
			}
		})
	}
}

// TestScalar_Arithmetic tests the core scalar arithmetic identities across all groups.
func TestScalar_Arithmetic(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		scalarTestZero(t, group.group)
		scalarTestOne(t, group.group)
		scalarTestMinusOne(t, group.group)
		scalarTestEqual(t, group.group)
		scalarTestLessOrEqual(t, group.group)
		scalarTestRandom(t, group.group)
		scalarTestAdd(t, group.group)
		scalarTestSubtract(t, group.group)
		scalarTestMultiply(t, group.group)
		scalarTestPow(t, group.group)
		scalarTestInvert(t, group.group)
	})
}

func scalarTestZero(t *testing.T, g ecc.Group) {
	zero := g.NewScalar()
	if !zero.IsZero() {
		t.Fatal("expected zero scalar")
	}

	s := g.NewScalar().Random()
	if !s.Subtract(s).IsZero() {
		t.Fatal("expected zero scalar")
	}

	s = g.NewScalar().Random()
	if !s.Add(zero).Equal(s) {
		t.Fatal("expected no change in adding zero scalar")
	}

	s = g.NewScalar().Random()
	if !s.Add(zero).Equal(s) {
		t.Fatal("not equal")
	}
}

func scalarTestOne(t *testing.T, g ecc.Group) {
	one := g.NewScalar().One()
	m := one.Copy()
	if !one.Equal(m.Multiply(m)) {
		t.Fatal(errExpectedEquality)
	}
}

func scalarTestMinusOne(t *testing.T, g ecc.Group) {
	m1 := g.NewScalar().MinusOne()
	one := g.NewScalar().One()
	if !m1.Add(one).IsZero() {
		t.Fatal(errExpectedEquality)
	}
}

func scalarTestRandom(t *testing.T, g ecc.Group) {
	r := g.NewScalar().Random()
	if r.Equal(g.NewScalar().Zero()) {
		t.Fatalf("random scalar is zero: %v", r.Hex())
	}
}

func scalarTestEqual(t *testing.T, g ecc.Group) {
	zero := g.NewScalar().Zero()
	zero2 := g.NewScalar().Zero()

	if g.NewScalar().Random().Equal(nil) {
		t.Fatal(errUnExpectedEquality)
	}

	if !zero.Equal(zero2) {
		t.Fatal(errExpectedEquality)
	}

	random := g.NewScalar().Random()
	cpy := random.Copy()
	if !random.Equal(cpy) {
		t.Fatal(errExpectedEquality)
	}

	random2 := g.NewScalar().Random()
	if random.Equal(random2) {
		t.Fatal(errUnExpectedEquality)
	}
}

func scalarTestLessOrEqual(t *testing.T, g ecc.Group) {
	zero := g.NewScalar().Zero()
	one := g.NewScalar().One()
	two := g.NewScalar().One().Add(one)

	if g.NewScalar().Random().LessOrEqual(nil) {
		t.Fatal(errUnExpectedEquality)
	}

	if !zero.LessOrEqual(one) {
		t.Fatal("expected 0 < 1")
	}

	if !one.LessOrEqual(two) {
		t.Fatal("expected 1 < 2")
	}

	if one.LessOrEqual(zero) {
		t.Fatal("expected 1 > 0")
	}

	if two.LessOrEqual(one) {
		t.Fatal("expected 2 > 1")
	}

	if !two.LessOrEqual(two) {
		t.Fatal("expected 2 == 2")
	}

	// Randomize property testing
	// scalarTestLessOrEqualRandomizedProperty(t, g)
}

func scalarTestLessOrEqualRandomizedProperty(t *testing.T, g ecc.Group) {
	rng := newDeterministicTestRand()

	for i := range scalarCompareIterations {
		left := deterministicReducedScalar(t, rng, g)
		right := deterministicReducedScalar(t, rng, g)

		want := false
		iLeft := new(big.Int).SetBytes(left.Encode())
		iRight := new(big.Int).SetBytes(right.Encode())

		if iLeft.Cmp(iRight) <= 0 {
			want = true
		}

		if got := left.LessOrEqual(right); got != want {
			t.Fatalf("case %d: expected %v, got %v", i, want, got)
		}
	}
}

// newDeterministicTestRand returns a reproducible RNG for randomized-but-stable tests.
func newDeterministicTestRand() *rand.Rand {
	return rand.New(rand.NewSource(1))
}

// deterministicReducedScalar decodes a reproducible random scalar reduced modulo the group order.
func deterministicReducedScalar(t *testing.T, rng *rand.Rand, g ecc.Group) *ecc.Scalar {
	t.Helper()

	input := make([]byte, g.HashFunc().Size())
	if _, err := rng.Read(input); err != nil {
		t.Fatal(err)
	}

	s := g.NewScalar()
	if err := s.DecodeWithReduction(input); err != nil {
		t.Fatal(err)
	}

	return s
}

func scalarTestAdd(t *testing.T, g ecc.Group) {
	r := g.NewScalar().Random()
	cpy := r.Copy()
	if !r.Add(nil).Equal(cpy) {
		t.Fatal(errExpectedEquality)
	}
}

func scalarTestSubtract(t *testing.T, g ecc.Group) {
	r := g.NewScalar().Random()
	cpy := r.Copy()
	if !r.Subtract(nil).Equal(cpy) {
		t.Fatal(errExpectedEquality)
	}
}

func scalarTestMultiply(t *testing.T, g ecc.Group) {
	s := g.NewScalar().Random()
	if !s.Multiply(nil).IsZero() {
		t.Fatal("expected zero")
	}
}

func scalarTestPow(t *testing.T, g ecc.Group) {
	// s**nil = 1
	s := g.NewScalar().Random()
	if !s.Pow(nil).Equal(g.NewScalar().One()) {
		t.Fatal("expected s**nil = 1")
	}

	// s**0 = 1
	s = g.NewScalar().Random()
	zero := g.NewScalar().Zero()
	if !s.Pow(zero).Equal(g.NewScalar().One()) {
		t.Fatal("expected s**0 = 1")
	}

	// s**1 = s
	s = g.NewScalar().Random()
	exp := g.NewScalar().One()
	if !s.Copy().Pow(exp).Equal(s) {
		t.Fatal("expected s**1 = s")
	}

	// s**2 = s*s
	s = g.NewScalar().One()
	s.Add(s.Copy().One())
	s2 := s.Copy().Multiply(s)
	exp.SetUInt64(2)

	if !s.Pow(exp).Equal(s2) {
		t.Fatal("expected s**2 = s*s")
	}

	// s**3 = s*s*s
	s = g.NewScalar().Random()
	s3 := s.Copy().Multiply(s)
	s3.Multiply(s)
	exp.SetUInt64(3)

	if !s.Pow(exp).Equal(s3) {
		t.Fatal("expected s**3 = s*s*s")
	}

	// 5**7 = 78125 = 00000000 00000001 00110001 00101101 = 1 49 45
	result := g.NewScalar().SetUInt64(uint64(math.Pow(5, 7)))
	s.SetUInt64(5)
	exp.SetUInt64(7)

	res := s.Pow(exp)
	if !res.Equal(result) {
		t.Fatal("expected 5**7 = 78125")
	}

	// 3**255 = 11F1B08E87EC42C5D83C3218FC83C41DCFD9F4428F4F92AF1AAA80AA46162B1F71E981273601F4AD1DD4709B5ACA650265A6AB
	iBase := big.NewInt(3)
	iExp := big.NewInt(255)
	result = bigIntExp(t, g, iBase, iExp)

	s.SetUInt64(3)
	exp.SetUInt64(255)

	res = s.Pow(exp)
	if !res.Equal(result) {
		t.Fatal(
			"expected 3**255 = " +
				"11F1B08E87EC42C5D83C3218FC83C41DCFD9F4428F4F92AF1AAA80AA46162B1F71E981273601F4AD1DD4709B5ACA650265A6AB",
		)
	}

	// 7945232487465**513
	iBase.SetInt64(7945232487465)
	iExp.SetInt64(513)
	result = bigIntExp(t, g, iBase, iExp)

	s.SetUInt64(7945232487465)
	exp.SetUInt64(513)

	res = s.Pow(exp)
	if !res.Equal(result) {
		t.Fatal("expect equality on 7945232487465**513")
	}

	// random**random
	s.Random()
	exp.Random()

	switch g {
	// These are in little-endian
	case ecc.Ristretto255Sha512, ecc.Edwards25519Sha512:
		e := s.Encode()
		for i, j := 0, len(e)-1; i < j; i++ {
			e[i], e[j] = e[j], e[i]
			j--
		}
		iBase.SetBytes(e)

		e = exp.Encode()
		for i, j := 0, len(e)-1; i < j; i++ {
			e[i], e[j] = e[j], e[i]
			j--
		}
		iExp.SetBytes(e)

	default:
		iBase.SetBytes(s.Encode())
		iExp.SetBytes(exp.Encode())
	}

	result = bigIntExp(t, g, iBase, iExp)

	if !s.Pow(exp).Equal(result) {
		t.Fatal("expected equality on random numbers")
	}
}

func bigIntExp(t *testing.T, g ecc.Group, base, exp *big.Int) *ecc.Scalar {
	orderBytes := g.Order()

	if g == ecc.Ristretto255Sha512 {
		slices.Reverse(orderBytes)
	}

	order := new(big.Int).SetBytes(orderBytes)
	r := new(big.Int).Exp(base, exp, order)

	b := make([]byte, g.ScalarLength())
	r.FillBytes(b)

	if g == ecc.Ristretto255Sha512 || g == ecc.Edwards25519Sha512 {
		slices.Reverse(b)
	}

	result := g.NewScalar()
	if err := result.Decode(b); err != nil {
		t.Fatal(err)
	}

	return result
}

func scalarTestInvert(t *testing.T, g ecc.Group) {
	s := g.NewScalar().Random()
	sqr := s.Copy().Multiply(s)

	i := s.Copy().Invert().Multiply(sqr)
	if !i.Equal(s) {
		t.Fatal(errExpectedEquality)
	}

	s = g.NewScalar().Random()
	square := s.Copy().Multiply(s)
	inv := square.Copy().Invert()
	if !s.One().Equal(square.Multiply(inv)) {
		t.Fatal(errExpectedEquality)
	}
}
