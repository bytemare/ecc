// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package edwards25519

import (
	"crypto"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"

	"github.com/bytemare/ecc/hash2curve"
)

const (
	// H2C represents the hash-to-curve string identifier.
	H2C = "edwards25519_XMD:SHA-512_ELL2_RO_"

	// E2C represents the encode-to-curve string identifier.
	E2C = "edwards25519_XMD:SHA-512_ELL2_NU_"

	// p25519 is the prime 2^255 - 19 for the field.
	// = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed.
	// p25519 = "57896044618658097711785492504343953926634992332820282019728792003956564819949".
)

func fe() *field.Element {
	return new(field.Element)
}

// HashToEdwards25519Field implements hash-to-scalar mapping modulo the order of Edwards25519 using input with dst.
func HashToEdwards25519Field(input, dst []byte) (*edwards25519.Scalar, error) {
	var uniform [48]byte
	if err := hash2curve.ExpandXMDTo(crypto.SHA512, uniform[:], input, dst); err != nil {
		return nil, err
	}

	var wide [64]byte
	expandAndReverse64(&wide, uniform[:])

	s, err := edwards25519.NewScalar().SetUniformBytes(wide[:])
	if err != nil {
		// Unreachable: result is of the required fixed length.
		// A failure indicates a regression in ristretto255.edwards25519.
		panic(err)
	}

	return s, nil
}

// HashToEdwards25519 implements hash-to-curve mapping to Edwards25519 of input with dst.
func HashToEdwards25519(input, dst []byte) (*edwards25519.Point, error) {
	var uniform [2 * 48]byte
	if err := hash2curve.ExpandXMDTo(crypto.SHA512, uniform[:], input, dst); err != nil {
		return nil, err
	}

	var u1, u2 [64]byte
	expandAndReverse64(&u1, uniform[0:48])
	expandAndReverse64(&u2, uniform[48:])
	q0, _ := new(field.Element).SetWideBytes(u1[:]) //nolint:errcheck // always succeeds
	q1, _ := new(field.Element).SetWideBytes(u2[:]) //nolint:errcheck // always succeeds
	p0 := Elligator2Edwards(q0)
	p1 := Elligator2Edwards(q1)
	p0.Add(p0, p1)
	p0.MultByCofactor(p0)

	return p0, nil
}

// EncodeToEdwards25519 implements encode-to-curve mapping to Edwards25519 of input with dst.
func EncodeToEdwards25519(input, dst []byte) (*edwards25519.Point, error) {
	var uniform [48]byte
	if err := hash2curve.ExpandXMDTo(crypto.SHA512, uniform[:], input, dst); err != nil {
		return nil, err
	}

	var u [64]byte
	expandAndReverse64(&u, uniform[0:48])
	b, _ := new(field.Element).SetWideBytes(u[:]) //nolint:errcheck // always succeeds
	p0 := Elligator2Edwards(b)
	p0.MultByCofactor(p0)

	return p0, nil
}

// Elligator2Edwards maps the field element to a point on Edwards25519.
func Elligator2Edwards(e *field.Element) *edwards25519.Point {
	u, v := Elligator2Montgomery(e)
	x, y := MontgomeryToEdwards(u, v)

	return AffineToEdwards(x, y)
}

// Elligator2Montgomery implements the Elligator2 mapping to Curve25519.
func Elligator2Montgomery(e *field.Element) (x, y *field.Element) {
	a, _ := fe().SetBytes([]byte{ //nolint:errcheck // always succeeds
		6, 109, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	})
	minA := fe().Negate(a)
	one := fe().One()
	minusOne := fe().Negate(one)
	two := fe().Add(one, one)

	t1 := fe().Square(e)     // u^2
	t1.Multiply(t1, two)     // t1 = 2u^2
	e1 := t1.Equal(minusOne) //
	t1.Swap(fe().Zero(), e1) // if 2u^2 == -1, t1 = 0

	x1 := fe().Add(t1, one) // t1 + 1
	x1.Invert(x1)           // 1 / (t1 + 1)
	x1.Multiply(x1, minA)   // x1 = -A / (t1 + 1)

	gx1 := fe().Add(x1, a) // x1 + A
	gx1.Multiply(gx1, x1)  // x1 * (x1 + A)
	gx1.Add(gx1, one)      // x1 * (x1 + A) + 1
	gx1.Multiply(gx1, x1)  // x1 * (x1 * (x1 + A) + 1)

	x2 := fe().Negate(x1) // -x1
	x2.Subtract(x2, a)    // -x2 - A

	gx2 := fe().Multiply(t1, gx1) // t1 * gx1

	root1, _isSquare := fe().SqrtRatio(gx1, one) // root1 = (+) sqrt(gx1)
	negRoot1 := fe().Negate(root1)               // negRoot1 = (-) sqrt(gx1)
	root2, _ := fe().SqrtRatio(gx2, one)         // root2 = (+) sqrt(gx2)

	// if gx1 is square, set the point to (x1, -root1)
	// if not, set the point to (x2, +root2)
	if _isSquare == 1 {
		x = x1
		y = negRoot1 // set sgn0(y) == 1, i.e. negative
	} else {
		x = x2
		y = root2 // set sgn0(y) == 0, i.e. positive
	}

	return x, y
}

// AffineToEdwards takes the affine coordinates of an Edwards25519 and returns a pointer to Point represented in
// extended projective coordinates.
func AffineToEdwards(x, y *field.Element) *edwards25519.Point {
	t := fe().Multiply(x, y)

	p, err := new(edwards25519.Point).SetExtendedCoordinates(x, y, fe().One(), t)
	if err != nil {
		// Construction failures imply a bug in edwards25519.
		panic(err)
	}

	return p
}

// MontgomeryToEdwards lifts a Curve25519 point (u, v) to its Edwards25519 equivalent (x, y).
func MontgomeryToEdwards(u, v *field.Element) (x, y *field.Element) {
	invsqrtD, _ := fe().SetBytes([]byte{ //nolint:errcheck // always succeeds
		6, 126, 69, 255, 170, 4, 110, 204, 130, 26, 125, 75, 209, 211, 161, 197,
		126, 79, 252, 3, 220, 8, 123, 210, 187, 6, 160, 96, 244, 237, 38, 15,
	})

	x = fe().Invert(v)
	x.Multiply(x, u)
	x.Multiply(x, invsqrtD)

	y = MontgomeryUToEdwardsY(u)

	return x, y
}

// MontgomeryUToEdwardsY transforms a Curve25519 x (or u) coordinate to an Edwards25519 y coordinate.
func MontgomeryUToEdwardsY(u *field.Element) *field.Element {
	one := fe().One()
	u1 := fe().Subtract(u, one)
	u2 := fe().Add(u, one)

	return u1.Multiply(u1, u2.Invert(u2))
}

// expandAndReverse64 writes the reversed input into out and pads the remaining bytes with 0s.
func expandAndReverse64(out *[64]byte, in []byte) {
	clear(out[:])
	for i := range in {
		out[i] = in[len(in)-1-i]
	}
}
