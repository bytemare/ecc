// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package nist

import (
	"crypto"
	"encoding/hex"
	"testing"
)

func deriveScalarParams(
	identifier byte,
	length, reductionLength int,
	hashToScalarLength uint,
	hash crypto.Hash,
	zeroPadReduction bool,
	orderHex string,
	rr [scalarMaxLimbs]uint64,
	n0inv uint64,
) *scalarParams {
	p := &scalarParams{
		identifier:         identifier,
		length:             length,
		reductionLength:    reductionLength,
		hashToScalarLength: hashToScalarLength,
		hash:               hash,
		zeroPadReduction:   zeroPadReduction,
		n0inv:              n0inv,
		rr:                 rr,
	}

	order, err := hex.DecodeString(orderHex)
	if err != nil {
		panic(err)
	}
	copy(p.orderBytes[:], order)
	parseBigEndianToLimbs(order, &p.order)
	p.limbs = (length + 7) / 8
	copy(p.minusTwoBytes[:], order)
	subtractBigEndianSmall(p.minusTwoBytes[:length], 2)

	var one [scalarMaxLimbs]uint64
	one[0] = 1
	p.toMontgomery(&p.oneMont, &one)

	minusOne := p.order
	subtractLimbsSmall(&minusOne, p.limbs, 1)
	p.toMontgomery(&p.minusOneMont, &minusOne)

	var two64 [scalarMaxLimbs]uint64
	two64[1] = 1
	p.toMontgomery(&p.two64Mont, &two64)

	return p
}

// TestStaticP256ScalarParams tests that the static P-256 scalar parameters match derived reference values.
func TestStaticP256ScalarParams(t *testing.T) {
	want := deriveScalarParams(
		IdentifierP256,
		32,
		32,
		48,
		crypto.SHA256,
		false,
		"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
		[scalarMaxLimbs]uint64{0x83244c95be79eea2, 0x4699799c49bd6fa6, 0x2845b2392b6bec59, 0x66e12d94f3d95620},
		0xccd1c8aaee00bc4f,
	)
	if *p256ScalarParams != *want {
		t.Fatal("p256 scalar params do not match derived values")
	}
}

// TestStaticP384ScalarParams tests that the static P-384 scalar parameters match derived reference values.
func TestStaticP384ScalarParams(t *testing.T) {
	want := deriveScalarParams(
		IdentifierP384,
		48,
		48,
		72,
		crypto.SHA384,
		false,
		"ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
		[scalarMaxLimbs]uint64{
			0x2d319b2419b409a9,
			0xff3d81e5df1aa419,
			0xbc3e483afcb82947,
			0xd40d49174aab1cc5,
			0x3fb05b7a28266895,
			0x0c84ee012b39bf21,
		},
		0x6ed46089e88fdc45,
	)
	if *p384ScalarParams != *want {
		t.Fatal("p384 scalar params do not match derived values")
	}
}

// TestStaticP521ScalarParams tests that the static P-521 scalar parameters match derived reference values.
func TestStaticP521ScalarParams(t *testing.T) {
	want := deriveScalarParams(
		IdentifierP521,
		66,
		64,
		98,
		crypto.SHA512,
		true,
		"01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
		[scalarMaxLimbs]uint64{
			0x137cd04dcf15dd04,
			0xf707badce5547ea3,
			0x12a78d38794573ff,
			0xd3721ef557f75e06,
			0xdd6e23d82e49c7db,
			0xcff3d142b7756e3e,
			0x5bcc6d61a8e567bc,
			0x2d8e03d1492d0d45,
			0x3d,
		},
		0x1d2f5ccd79a995c7,
	)
	if *p521ScalarParams != *want {
		t.Fatal("p521 scalar params do not match derived values")
	}
}
