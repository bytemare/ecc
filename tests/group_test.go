// SPDX-License-Group: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package ecc_test

import (
	"encoding/hex"
	"testing"

	"github.com/bytemare/ecc"
	"github.com/bytemare/ecc/hash2curve"
	"github.com/bytemare/ecc/internal"
)

const consideredAvailableFmt = "%v is considered available when it must not"

// TestAvailability tests that all supported groups report themselves as available.
func TestAvailability(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		if !group.group.Available() {
			t.Errorf("'%s' is not available, but should be", group.group.String())
		}
	})
}

// TestNonAvailability tests that unsupported and out-of-range groups report unavailable and panic on String.
func TestNonAvailability(t *testing.T) {
	oob := ecc.Group(0)
	if oob.Available() {
		t.Errorf(consideredAvailableFmt, oob)
	}

	d := ecc.Group(2) // decaf448
	if d.Available() {
		t.Errorf(consideredAvailableFmt, d)
	}

	expectPanic(t, "decaf availability", internal.ErrInvalidGroup, func() { _ = d.String() })

	oob = ecc.Secp256k1Sha256 + 1
	if oob.Available() {
		t.Errorf(consideredAvailableFmt, oob)
	}

	expectPanic(t, "oob availability", internal.ErrInvalidGroup, func() { _ = oob.String() })

	oob++
	expectPanic(t, "oob availability", internal.ErrInvalidGroup, func() { _ = oob.String() })
}

// TestGroup_Base tests that each group returns the expected canonical generator.
func TestGroup_Base(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		if group.group.Base().Hex() != group.basePoint {
			t.Fatalf("Got wrong base element\n\tgot : %s\n\twant: %s",
				group.group.Base().Hex(),
				group.basePoint)
		}
	})
}

// TestDST tests that MakeDST builds the expected application and ciphersuite-specific DST.
func TestDST(t *testing.T) {
	app := "app"
	version := uint8(1)
	tests := map[ecc.Group]string{
		ecc.Ristretto255Sha512: app + "-V01-CS01-",
		ecc.P256Sha256:         app + "-V01-CS03-",
		ecc.P384Sha384:         app + "-V01-CS04-",
		ecc.P521Sha512:         app + "-V01-CS05-",
		ecc.Edwards25519Sha512: app + "-V01-CS06-",
		ecc.Secp256k1Sha256:    app + "-V01-CS07-",
	}

	testAllGroups(t, func(group *testGroup) {
		res := string(group.group.MakeDST(app, version))
		test := tests[group.group] + group.hashToCurve.h2c
		if res != test {
			t.Errorf("Wrong DST. want %q, got %q", res, test)
		}
	})
}

// TestGroup_String tests that String returns the RFC 9380 ciphersuite identifier.
func TestGroup_String(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		res := group.group.String()
		ref := group.hashToCurve.h2c
		if res != ref {
			t.Errorf("Wrong DST. want %q, got %q", ref, res)
		}
	})
}

// TestGroup_NewScalar tests that NewScalar returns the zero scalar for each group.
func TestGroup_NewScalar(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		s := group.group.NewScalar().Encode()
		for _, b := range s {
			if b != 0 {
				t.Fatalf("expected zero scalar, but got %v", hex.EncodeToString(s))
			}
		}
	})
}

// TestGroup_NewElement tests that NewElement returns the identity element for each group.
func TestGroup_NewElement(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		e := hex.EncodeToString(group.group.NewElement().Encode())
		ref := group.identity

		if e != ref {
			t.Fatalf("expected identity element %v, but got %v", ref, e)
		}
	})
}

// TestGroup_ScalarLength tests that ScalarLength matches the expected encoded scalar size.
func TestGroup_ScalarLength(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		if int(group.group.ScalarLength()) != group.scalarLength {
			t.Fatalf("expected encoded scalar length %d, but got %d", group.scalarLength, group.group.ScalarLength())
		}
	})
}

// TestGroup_ElementLength tests that ElementLength matches the expected encoded element size.
func TestGroup_ElementLength(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		if group.group.ElementLength() != group.elementLength {
			t.Fatalf("expected encoded element length %d, but got %d", group.elementLength, group.group.ElementLength())
		}
	})
}

// TestHashFunc tests that each group exposes the expected hash function.
func TestHashFunc(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		if group.group.HashFunc() != group.hash {
			t.Errorf("%s: %q vs. %q", errExpectedEquality, group.group.HashFunc(), group.hash)
		}
	})
}

// TestHashToScalar tests that HashToScalar matches the per-group reference vectors.
func TestHashToScalar(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		sv := decodeScalar(t, group.group, group.hashToCurve.hashToScalar)

		s, err := group.group.HashToScalar(group.hashToCurve.input, group.hashToCurve.dst)
		if err != nil {
			t.Fatal(err)
		}

		if !s.Equal(sv) {
			t.Error(errExpectedEquality)
		}
	})
}

// TestHashToScalar_NoDST tests that HashToScalar rejects nil and empty DST values.
func TestHashToScalar_NoDST(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		data := []byte("input data")

		// Nil DST
		expectErrors(t, func() error {
			_, err := group.group.HashToScalar(data, nil)
			return err
		}, hash2curve.ErrZeroLengthDST)

		// Zero length DST
		expectErrors(t, func() error {
			_, err := group.group.HashToScalar(data, []byte{})
			return err
		}, hash2curve.ErrZeroLengthDST)
	})
}

// TestHashToGroup tests that HashToGroup matches the per-group reference vectors.
func TestHashToGroup(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		ev := decodeElement(t, group.group, group.hashToCurve.hashToGroup)

		e, err := group.group.HashToGroup(group.hashToCurve.input, group.hashToCurve.dst)
		if err != nil {
			t.Fatal(err)
		}

		if !e.Equal(ev) {
			t.Error(errExpectedEquality)
		}
	})
}

// TestHashToGroup_NoDST tests that HashToGroup rejects nil and empty DST values.
func TestHashToGroup_NoDST(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		data := []byte("input data")

		// Nil DST
		expectErrors(t, func() error {
			_, err := group.group.HashToGroup(data, nil)
			return err
		}, hash2curve.ErrZeroLengthDST)

		// Zero length DST
		expectErrors(t, func() error {
			_, err := group.group.HashToGroup(data, []byte{})
			return err
		}, hash2curve.ErrZeroLengthDST)
	})
}

// TestEncodeToGroup_NoDST tests that EncodeToGroup rejects nil and empty DST values.
func TestEncodeToGroup_NoDST(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		data := []byte("input data")

		// Nil DST
		expectErrors(t, func() error {
			_, err := group.group.EncodeToGroup(data, nil)
			return err
		}, hash2curve.ErrZeroLengthDST)

		// Zero length DST
		expectErrors(t, func() error {
			_, err := group.group.EncodeToGroup(data, []byte{})
			return err
		}, hash2curve.ErrZeroLengthDST)
	})
}

// TestGroup_Order tests that each group returns the expected encoded scalar field order.
func TestGroup_Order(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		h := hex.EncodeToString(group.group.Order())
		if h != group.groupOrder {
			t.Error(errExpectedEquality)
		}
	})
}
