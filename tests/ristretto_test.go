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
	"crypto"
	"encoding/hex"
	"testing"

	"github.com/bytemare/ecc/internal/ristretto"
)

const (
	goodRistrettoScalar = "243170e83a77812893c234314116e1c007671adfe23325011e3827c1b2ff8d0a"
	ristrettoBasePoint  = "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"

	testApp     = "testRistretto255"
	testVersion = "0.0"
)

type ristrettoTest struct {
	name    string
	app     string
	version string
	scalar  string // hex encoding
	element string // hex encoding
	hashID  crypto.Hash
	scal    bool // says whether the scalar is supposed to be valid
	elem    bool // says whether the element is supposed to be valid
}

var ristrettoTests = []ristrettoTest{
	{
		name:    "Valid element (base point), valid scalar",
		hashID:  crypto.SHA512,
		app:     testApp,
		version: testVersion,
		scalar:  goodRistrettoScalar,
		element: ristrettoBasePoint,
		scal:    true,
		elem:    true,
	},
	{
		name:    "Valid element (base point), bad scalar (size)",
		hashID:  crypto.SHA512,
		app:     testApp,
		version: testVersion,
		scalar:  "243170e83a77812893c234314116e1c007671adfe23325011e3827c1b2ff8d",
		element: ristrettoBasePoint,
		scal:    false,
		elem:    true,
	},
	{
		name:    "Valid element (base point), bad scalar (encoding)",
		hashID:  crypto.SHA512,
		app:     testApp,
		version: testVersion,
		scalar:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		element: ristrettoBasePoint,
		scal:    false,
		elem:    true,
	},
	{
		name:    "Valid scalar, bad element",
		hashID:  crypto.SHA512,
		app:     testApp,
		version: testVersion,
		scalar:  goodRistrettoScalar,
		element: "2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08",
		scal:    true,
		elem:    false,
	},
	{
		name:    "Nil scalar, bad element",
		hashID:  crypto.SHA512,
		app:     testApp,
		version: testVersion,
		scalar:  "",
		element: "2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08",
		scal:    false,
		elem:    false,
	},
	{
		name:    "Nil scalar, nil element",
		hashID:  crypto.SHA512,
		app:     testApp,
		version: testVersion,
		scalar:  "",
		element: "",
		scal:    false,
		elem:    false,
	},
}

func TestRistrettoScalar(t *testing.T) {
	for _, tt := range ristrettoTests {
		t.Run(tt.name, func(t *testing.T) {
			// Grab the bytes of the encoding
			s := ristretto.Group{}.NewScalar()
			err := s.DecodeHex(tt.scalar)

			if tt.scal == false {
				if err == nil {
					t.Fatalf("expected error for %s", tt.name)
				}

				return
			}

			if err != nil {
				t.Fatalf("%s : unexpected error, got %v", tt.name, err)
			}

			if s == nil {
				t.Fatal("scalar is nil, should not happen")
			}

			if len(s.Encode()) != 32 {
				t.Fatalf(
					"invalid random scalar length. Expected %d, got %d",
					32,
					len(s.Encode()),
				)
			}

			cpy := s.Copy()
			cpy = cpy.Invert()
			if bytes.Equal(cpy.Encode(), s.Encode()) {
				t.Fatal("scalar inversion resulted in same scalar")
			}
		})
	}
}

func TestRistrettoElement(t *testing.T) {
	// Test if the element in the test is the base point
	bp := ristretto.Group{}.NewElement().(*ristretto.Element).Base()

	// Grab the bytes of the encoding
	encoding, err := hex.DecodeString(ristrettoTests[0].element)
	if err != nil {
		t.Fatalf("%s: bad hex encoding in test vector: %v", ristrettoTests[0].name, err)
	}

	if !bytes.Equal(bp.Encode(), encoding) {
		t.Fatalf("%s: element doesn't decode to basepoint", ristrettoTests[0].name)
	}

	for _, tt := range ristrettoTests {
		t.Run(tt.name, func(t *testing.T) {
			// Test decoding
			e := ristretto.Group{}.NewElement()
			err = e.DecodeHex(tt.element)

			if tt.elem == false {
				if err == nil {
					t.Fatalf("expected error for %s", tt.name)
				}

				return
			}

			if err != nil {
				t.Fatalf("%s : unexpected error, got %v", tt.name, err)
			}

			if e == nil {
				t.Fatalf("%s : element is nil but should not have failed on decoding", tt.name)
			}

			// Test encoding
			if !bytes.Equal(encoding, e.Encode()) {
				t.Fatalf("%s : Decoding and encoding doesn't return the same bytes", tt.name)
			}
		})
	}
}
