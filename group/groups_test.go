// SPDX-License-Group: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package group

import (
	"encoding/hex"
	"github.com/bytemare/crypto/group/curve25519"
	"github.com/bytemare/crypto/group/edwards25519"
	"github.com/bytemare/crypto/group/old"
	"github.com/bytemare/crypto/group/ristretto"
	"testing"
)

type group struct {
	name string
	h2c  string
	id   Group
}

func testGroups() []*group {
	return []*group{
		{"Ristretto255", ristretto.H2C, Ristretto255Sha512},
		{"P256", old.H2CP256, P256Sha256},
		{"P384", old.H2CP384, P384Sha384},
		{"P521", old.H2CP521, P521Sha512},
		{"Curve25519", curve25519.H2C, Curve25519Sha512},
		{"Edwards25519", edwards25519.H2C, Edwards25519Sha512},
		//{"Curve448", string(h2c.Curve448_XOFSHAKE256_ELL2_RO_), Curve448Shake256},
		//{"Edwards448", string(h2c.Edwards448_XOFSHAKE256_ELL2_RO_), Edwards448Shake256},
	}
}

func testAll(t *testing.T, f func(*testing.T, *group)) {
	for _, test := range testGroups() {
		t.Run(test.name, func(t *testing.T) {
			f(t, test)
		})
	}
}

func TestAvailability(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *group) {
		if !group.id.Available() {
			t.Errorf("'%s' is not available, but should be", group.id.String())
		}
	})
}

func TestNonAvailability(t *testing.T) {
	oob := Group(0)
	if oob.Available() {
		t.Errorf("%v is considered available when it must not", oob)
	}

	oob = maxID
	if oob.Available() {
		t.Errorf("%v is considered available when it must not", oob)
	}
}

func TestDST(t *testing.T) {
	app := "app"
	version := uint8(1)
	tests := map[Group]string{
		Ristretto255Sha512: "app-V01-CS01-ristretto255_XMD:SHA-512_R255MAP_RO_",
		P256Sha256:         "app-V01-CS03-P256_XMD:SHA-256_SSWU_RO_",
		P384Sha384:         "app-V01-CS04-P384_XMD:SHA-384_SSWU_RO_",
		P521Sha512:         "app-V01-CS05-P521_XMD:SHA-512_SSWU_RO_",
		Curve25519Sha512:   "app-V01-CS06-curve25519_XMD:SHA-512_ELL2_RO_",
		Edwards25519Sha512: "app-V01-CS07-edwards25519_XMD:SHA-512_ELL2_RO_",
		//Curve448Shake256:   "app-V01-CS08-curve448_XOF:SHAKE256_ELL2_RO_",
		//Edwards448Shake256: "app-V01-CS09-edwards448_XOF:SHAKE256_ELL2_RO_",
	}

	testAll(t, func(t2 *testing.T, group *group) {
		res := string(group.id.MakeDST(app, version))
		test := tests[group.id]
		if res != test {
			t.Errorf("Wrong DST. want %q, got %q", res, test)
		}
	})
}

func TestGroup_String(t *testing.T) {
	tests := map[Group]string{
		Ristretto255Sha512: "ristretto255_XMD:SHA-512_R255MAP_RO_",
		P256Sha256:         "P256_XMD:SHA-256_SSWU_RO_",
		P384Sha384:         "P384_XMD:SHA-384_SSWU_RO_",
		P521Sha512:         "P521_XMD:SHA-512_SSWU_RO_",
		Curve25519Sha512:   "curve25519_XMD:SHA-512_ELL2_RO_",
		Edwards25519Sha512: "edwards25519_XMD:SHA-512_ELL2_RO_",
		//Curve448Shake256:   "curve448_XOF:SHAKE256_ELL2_RO_",
		//Edwards448Shake256: "edwards448_XOF:SHAKE256_ELL2_RO_",
	}

	testAll(t, func(t2 *testing.T, group *group) {
		res := group.id.String()
		test := tests[group.id]
		if res != test {
			t.Errorf("Wrong DST. want %q, got %q", res, test)
		}
	})
}

func TestGroup_NewScalar(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *group) {
		s := group.id.NewScalar().Bytes()
		for _, b := range s {
			if b != 0 {
				t.Fatalf("expected zero scalar, but got %v", hex.EncodeToString(s))
			}
		}
	})
}

func TestGroup_NewElement(t *testing.T) {
	identity := map[Group]string{
		Ristretto255Sha512: "0000000000000000000000000000000000000000000000000000000000000000",
		P256Sha256:         "020000000000000000000000000000000000000000000000000000000000000000",
		P384Sha384:         "02000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		P521Sha512:         "02000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		Curve25519Sha512:   "0000000000000000000000000000000000000000000000000000000000000000",
		Edwards25519Sha512: "0100000000000000000000000000000000000000000000000000000000000000",
		//Curve448Shake256:   "010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		//Edwards448Shake256: "010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	}

	testAll(t, func(t2 *testing.T, group *group) {
		e := hex.EncodeToString(group.id.NewElement().Bytes())
		ref := identity[group.id]

		if e != ref {
			t.Fatalf("expected identity element %v, but got %v", ref, e)
		}
	})
}

func TestGroup_ElementLength(t *testing.T) {
	length := map[Group]uint{
		Ristretto255Sha512: 32,
		P256Sha256:         33,
		P384Sha384:         49,
		P521Sha512:         67,
		Curve25519Sha512:   32,
		Edwards25519Sha512: 32,
		//Curve448Shake256:   57,
		//Edwards448Shake256: 57,
	}

	testAll(t, func(t2 *testing.T, group *group) {
		if group.id.ElementLength() != length[group.id] {
			t.Fatalf("expected encoded element length %d, but got %d", length[group.id], group.id.ElementLength())
		}
	})
}

func TestGroup_Base(t *testing.T) {
	base := map[Group]string{
		Ristretto255Sha512: "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
		P256Sha256:         "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
		P384Sha384:         "03aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
		P521Sha512:         "0200c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
		Curve25519Sha512:   "0900000000000000000000000000000000000000000000000000000000000000",
		Edwards25519Sha512: "5866666666666666666666666666666666666666666666666666666666666666",
		//Curve448Shake256:   "1a5b7b453d22d76ff77a6750b1c41213210d4346237e02b8edf6f38dc25df760d04555f5345daecbce6f32586eab986cf6b1f595125d237d80",
		//Edwards448Shake256: "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900",
	}

	testAll(t, func(t2 *testing.T, group *group) {
		if hex.EncodeToString(group.id.Base().Bytes()) != base[group.id] {
			t.Fatalf("Got wrong base element %s", hex.EncodeToString(group.id.Base().Bytes()))
		}
	})
}
