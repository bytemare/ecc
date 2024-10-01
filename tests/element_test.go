// SPDX-License-Group: MIT
//
// Copyright (C) 2020-2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package group_test

import (
	"encoding/hex"
	"errors"
	"log"
	"math/big"
	"testing"

	"github.com/bytemare/crypto"
	"github.com/bytemare/crypto/internal"
)

const (
	errUnExpectedEquality = "unexpected equality"
	errExpectedEquality   = "expected equality"
	errExpectedIdentity   = "expected identity"
	errWrongGroup         = "wrong group"
)

func testElementCopySet(t *testing.T, element, other *crypto.Element) {
	// Verify they don't point to the same thing
	if &element == &other {
		t.Fatalf("Pointer to the same scalar")
	}

	// Verify whether they are equivalent
	if element.Equal(other) != 1 {
		t.Fatalf("Expected equality")
	}

	// Verify than operations on one don't affect the other
	element.Add(element)
	if element.Equal(other) == 1 {
		t.Fatalf(errUnExpectedEquality)
	}

	other.Double().Double()
	if element.Equal(other) == 1 {
		t.Fatalf(errUnExpectedEquality)
	}

	// Verify setting to nil sets to identity
	if element.Set(nil).Equal(other.Identity()) != 1 {
		t.Error(errExpectedEquality)
	}
}

func TestElement_Group(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		e := group.group.NewElement()
		if e.Group() != group.group {
			t.Fatal(errWrongGroup)
		}
	})
}

func TestElement_Copy(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		base := group.group.Base()
		cpy := base.Copy()
		testElementCopySet(t, base, cpy)
	})
}

func TestElement_Set(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		base := group.group.Base()
		other := group.group.NewElement()
		other.Set(base)
		testElementCopySet(t, base, other)
	})
}

func TestElement_WrongInput(t *testing.T) {
	exec := func(f func(*crypto.Element) *crypto.Element, arg *crypto.Element) func() {
		return func() {
			_ = f(arg)
		}
	}

	equal := func(f func(*crypto.Element) int, arg *crypto.Element) func() {
		return func() {
			f(arg)
		}
	}

	mult := func(f func(*crypto.Scalar) *crypto.Element, arg *crypto.Scalar) func() {
		return func() {
			f(arg)
		}
	}

	testAllGroups(t, func(group *testGroup) {
		element := group.group.NewElement()
		var alternativeGroup crypto.Group

		switch group.group {
		// The following is arbitrary, and simply aims at confusing identifiers
		case crypto.Ristretto255Sha512, crypto.Edwards25519Sha512:
			alternativeGroup = crypto.P256Sha256
		case crypto.P256Sha256, crypto.P384Sha384, crypto.P521Sha512, crypto.Secp256k1:
			alternativeGroup = crypto.Ristretto255Sha512
		default:
			t.Fatalf("Invalid group id %d", group.group)
		}

		if err := testPanic(errWrongGroup, internal.ErrCastElement,
			exec(element.Add, alternativeGroup.NewElement())); err != nil {
			t.Fatal(err)
		}

		if err := testPanic(errWrongGroup, internal.ErrCastElement,
			exec(element.Subtract, alternativeGroup.NewElement())); err != nil {
			t.Fatal(err)
		}

		if err := testPanic(errWrongGroup, internal.ErrCastElement,
			exec(element.Set, alternativeGroup.NewElement())); err != nil {
			t.Fatal(err)
		}

		if err := testPanic(errWrongGroup, internal.ErrCastElement,
			equal(element.Equal, alternativeGroup.NewElement())); err != nil {
			t.Fatal(err)
		}
	})

	// Specifically test Ristretto
	if err := testPanic(errWrongGroup, internal.ErrCastScalar,
		mult(crypto.Ristretto255Sha512.NewElement().Multiply, crypto.P384Sha384.NewScalar())); err != nil {
		t.Fatal(err)
	}
}

func TestElement_EncodedLength(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		id := group.group.NewElement().Identity().Encode()
		if len(id) != group.elementLength {
			t.Fatalf(
				"Encode() of the identity element is expected to return %d bytes, but returned %d bytes",
				group.elementLength,
				len(id),
			)
		}

		encodedID := hex.EncodeToString(id)
		if encodedID != group.identity {
			t.Fatalf(
				"Encode() of the identity element is unexpected.\n\twant: %v\n\tgot : %v",
				group.identity,
				encodedID,
			)
		}

		encodedElement := group.group.NewElement().Base().Multiply(group.group.NewScalar().Random()).Encode()
		if len(encodedElement) != group.elementLength {
			t.Fatalf(
				"Encode() is expected to return %d bytes, but returned %d bytes",
				group.elementLength,
				encodedElement,
			)
		}
	})
}

func TestElement_Decode_OutOfBounds(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		decodeErr := "element Decode: "
		unmarshallBinaryErr := "element UnmarshalBinary: "
		errMessage := ""
		switch group.group {
		case crypto.Ristretto255Sha512:
			errMessage = "invalid Ristretto encoding"
		case crypto.P256Sha256:
			errMessage = "invalid P256 element encoding"
		case crypto.P384Sha384:
			errMessage = "invalid P384Element encoding"
		case crypto.P521Sha512:
			errMessage = "invalid P521Element encoding"
		case crypto.Edwards25519Sha512:
			errMessage = "edwards25519: invalid point encoding"
		case crypto.Secp256k1:
			errMessage = "invalid point encoding"
		}

		decodeErr += errMessage
		unmarshallBinaryErr += errMessage

		encoded := make([]byte, group.group.ElementLength())

		y := big.NewInt(0)

		x, ok := new(big.Int).SetString(group.fieldOrder, 0)
		if !ok {
			t.Fatalf("setting int in base %d failed: %v", 0, group.fieldOrder)
		}

		// x exceeds the order
		x.Add(x, big.NewInt(1))

		switch group.group {
		case crypto.Ristretto255Sha512, crypto.Edwards25519Sha512:
			x.FillBytes(encoded)
		case crypto.P256Sha256, crypto.P384Sha384, crypto.P521Sha512, crypto.Secp256k1:
			encoded[0] = byte(2 | y.Bit(0)&1)
			x.FillBytes(encoded[1:])
		default:
			t.Fatalf("non registered group %s", group.group)
		}

		expected := errors.New(decodeErr)
		if err := group.group.NewElement().Decode(encoded[:]); err == nil || err.Error() != expected.Error() {
			t.Errorf("expected error %q, got %v", expected, err)
		}

		expected = errors.New(unmarshallBinaryErr)
		if err := group.group.NewElement().UnmarshalBinary(encoded[:]); err == nil || err.Error() != expected.Error() {
			t.Errorf("expected error %q, got %v", expected, err)
		}
	})
}

func TestElement_XCoordinate(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		baseX := hex.EncodeToString(group.group.Base().XCoordinate())
		refLen := len(baseX) / 2 // hexadecimal length is 2 times byt length

		if baseX != group.basePointX {
			t.Error(errExpectedEquality)
		}

		zero := hex.EncodeToString(make([]byte, refLen))
		id := hex.EncodeToString(group.group.NewElement().XCoordinate())

		if zero != id {
			t.Error(errExpectedEquality)
		}
	})
}

func TestElement_Vectors_Add(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		base := group.group.Base()
		acc := group.group.Base()

		for _, mult := range group.multBase {
			e := decodeElement(t, group.group, mult)
			if e.Equal(acc) != 1 {
				t.Fatal("expected equality")
			}

			acc.Add(base)
		}

		base.Add(group.group.NewElement())
		if base.Equal(group.group.Base()) != 1 {
			t.Fatal(errExpectedEquality)
		}

		if group.group.NewElement().Add(base).Equal(base) != 1 {
			t.Fatal(errExpectedEquality)
		}
	})
}

func TestElement_Vectors_Double(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		tables := [][]int{
			{1, 2, 4, 8},
			{3, 6, 12},
			{5, 10},
			{7, 14},
		}

		for _, table := range tables {
			e := decodeElement(t, group.group, group.multBase[table[0]-1])
			for _, multiple := range table[1:] {
				e.Double()

				v := decodeElement(t, group.group, group.multBase[multiple-1])
				if v.Equal(e) != 1 {
					t.Fatalf("expected equality for %d", multiple)
				}
			}
		}
	})
}

func TestElement_Vectors_Mult(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		s := group.group.NewScalar()
		base := group.group.Base()

		for i, mult := range group.multBase {
			e := decodeElement(t, group.group, mult)
			if e.Equal(base) != 1 {
				t.Fatalf("expected equality for %d", i)
			}

			s.SetUInt64(uint64(i + 2))
			base.Base().Multiply(s)
		}
	})
}

func TestElement_Arithmetic(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		elementTestEqual(t, group.group)
		elementTestAdd(t, group.group)
		elementTestDouble(t, group.group)
		elementTestNegate(t, group.group)
		elementTestSubstract(t, group.group)
		elementTestMultiply(t, group.group)
		elementTestIdentity(t, group.group)
	})
}

func elementTestEqual(t *testing.T, g crypto.Group) {
	base := g.Base()
	base2 := g.Base()

	if base.Equal(nil) != 0 {
		t.Fatal(errUnExpectedEquality)
	}

	if base.Equal(base2) != 1 {
		t.Fatal(errExpectedEquality)
	}

	random := g.NewElement().Multiply(g.NewScalar().Random())
	cpy := random.Copy()
	if random.Equal(cpy) != 1 {
		t.Fatal()
	}
}

func elementTestAdd(t *testing.T, g crypto.Group) {
	// Verify whether add yields the same element when given nil
	base := g.Base()
	cpy := base.Copy()
	if cpy.Add(nil).Equal(base) != 1 {
		t.Fatal(errExpectedEquality)
	}

	// Verify whether add yields the same element when given identity
	base = g.Base()
	cpy = base.Copy()
	cpy.Add(g.NewElement())
	if cpy.Equal(base) != 1 {
		t.Fatal(errExpectedEquality)
	}

	// Verify whether add yields the same when adding to identity
	base = g.Base()
	identity := g.NewElement()
	if identity.Add(base).Equal(base) != 1 {
		t.Fatal(errExpectedEquality)
	}

	// Verify whether add yields the identity given the negative
	base = g.Base()
	negative := g.Base().Negate()
	identity = g.NewElement()
	if base.Add(negative).Equal(identity) != 1 {
		t.Fatal(errExpectedEquality)
	}

	// Verify whether add yields the double when adding to itself
	base = g.Base()
	double := g.Base().Double()
	if base.Add(base).Equal(double) != 1 {
		t.Fatal(errExpectedEquality)
	}

	// Verify whether 3*base = base + base + base
	three := g.NewScalar().One()
	three.Add(three)
	three.Add(g.NewScalar().One())

	mult := g.Base().Multiply(three)
	e := g.Base().Add(g.Base()).Add(g.Base())

	if e.Equal(mult) != 1 {
		t.Fatal(errExpectedEquality)
	}
}

func elementTestNegate(t *testing.T, g crypto.Group) {
	// 0 = -0
	id := g.NewElement().Identity()
	negId := g.NewElement().Identity().Negate()

	if id.Equal(negId) != 1 {
		t.Fatal("expected equality when negating identity element")
	}

	// b + (-b) = 0
	b := g.NewElement().Base()
	negB := g.NewElement().Base().Negate()
	b.Add(negB)

	if !b.IsIdentity() {
		t.Fatal("expected identity for b + (-b)")
	}

	// -(-b) = b
	b = g.NewElement().Base()
	negB = g.NewElement().Base().Negate().Negate()

	if b.Equal(negB) != 1 {
		t.Fatal("expected equality -(-b) = b")
	}
}

func elementTestDouble(t *testing.T, g crypto.Group) {
	// Verify whether double works like adding
	base := g.Base()
	double := g.Base().Add(g.Base())
	if double.Equal(base.Double()) != 1 {
		t.Fatal(errExpectedEquality)
	}

	two := g.NewScalar().One().Add(g.NewScalar().One())
	mult := g.Base().Multiply(two)
	if mult.Equal(double) != 1 {
		t.Fatal(errExpectedEquality)
	}
}

func elementTestSubstract(t *testing.T, g crypto.Group) {
	base := g.Base()

	// Verify whether subtracting yields the same element when given nil.
	if base.Subtract(nil).Equal(base) != 1 {
		t.Fatal(errExpectedEquality)
	}

	// Verify whether subtracting and then adding yields the same element.
	base2 := base.Add(base).Subtract(base)
	if base.Equal(base2) != 1 {
		t.Fatal(errExpectedEquality)
	}
}

func elementTestMultiply(t *testing.T, g crypto.Group) {
	scalar := g.NewScalar()

	// base = base * 1
	base := g.Base()
	mult := g.Base().Multiply(scalar.One())
	if base.Equal(mult) != 1 {
		t.Fatal(errExpectedEquality)
	}

	// Random scalar mult must not yield identity
	scalar = g.NewScalar().Random()
	m := g.Base().Multiply(scalar)
	if m.IsIdentity() {
		t.Fatal("random scalar multiplication is identity")
	}

	// 2 * base = base + base
	twoG := g.Base().Add(g.Base())
	two := g.NewScalar().One().Add(g.NewScalar().One())
	mult = g.Base().Multiply(two)

	if mult.Equal(twoG) != 1 {
		t.Fatal(errExpectedEquality)
	}

	// base * 0 = id
	if !g.Base().Multiply(scalar.Zero()).IsIdentity() {
		t.Fatal(errExpectedIdentity)
	}

	// base * nil = id
	if !g.Base().Multiply(nil).IsIdentity() {
		t.Fatal(errExpectedIdentity)
	}
}

func elementTestIdentity(t *testing.T, g crypto.Group) {
	id := g.NewElement()
	if !id.IsIdentity() {
		t.Fatal(errExpectedIdentity)
	}

	base := g.Base()
	if id.Equal(base.Subtract(base)) != 1 {
		log.Printf("id : %v", id.Encode())
		log.Printf("ba : %v", base.Encode())
		t.Fatal(errExpectedIdentity)
	}

	sub1 := g.Base().Double().Negate().Add(g.Base().Double())
	sub2 := g.Base().Subtract(g.Base())
	if sub1.Equal(sub2) != 1 {
		t.Fatal(errExpectedEquality)
	}

	if id.Equal(base.Multiply(nil)) != 1 {
		t.Fatal(errExpectedIdentity)
	}

	if id.Equal(base.Multiply(g.NewScalar().Zero())) != 1 {
		t.Fatal(errExpectedIdentity)
	}

	base = g.Base()
	neg := base.Copy().Negate()
	base.Add(neg)
	if id.Equal(base) != 1 {
		t.Fatal(errExpectedIdentity)
	}
}
