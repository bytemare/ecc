// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package fiat

var p384MinusOneEncoding = [p384ElementLen]byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xfe,
}

var p384OneMontgomery = p384MontgomeryDomainFieldElement{
	0xffffffff00000001, 0x00000000ffffffff, 0x0000000000000001,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
}

var p384AMontgomery = p384MontgomeryDomainFieldElement{
	0x00000003fffffffc, 0xfffffffc00000000, 0xfffffffffffffffb,
	0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
}

var p384BMontgomery = p384MontgomeryDomainFieldElement{
	0x081188719d412dcc, 0xf729add87a4c32ec, 0x77f2209b1920022e,
	0xe3374bee94938ae2, 0xb62b21f41f022094, 0xcd08114b604fbff9,
}

var p384ZMontgomery = p384MontgomeryDomainFieldElement{
	0x0000000cfffffff3, 0xfffffff300000000, 0xfffffffffffffff2,
	0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
}

var p384Two64Montgomery = p384MontgomeryDomainFieldElement{
	0x0000000000000000, 0xffffffff00000001, 0x00000000ffffffff,
	0x0000000000000001, 0x0000000000000000, 0x0000000000000000,
}

// P384One returns 1 in the P-384 base field.
func P384One() *P384Element {
	return &P384Element{x: p384OneMontgomery}
}

// P384A returns the P-384 SSWU A coefficient, which is -3.
func P384A() *P384Element {
	return &P384Element{x: p384AMontgomery}
}

// P384B returns the P-384 curve coefficient B.
func P384B() *P384Element {
	return &P384Element{x: p384BMontgomery}
}

// P384Z returns the P-384 SSWU Z parameter.
func P384Z() *P384Element {
	return &P384Element{x: p384ZMontgomery}
}

// P384Two64 returns 2^64 reduced in the P-384 base field.
func P384Two64() *P384Element {
	return &P384Element{x: p384Two64Montgomery}
}
