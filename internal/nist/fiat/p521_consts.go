// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package fiat

var p521MinusOneEncoding = [p521ElementLen]byte{
	0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xfe,
}

var p521OneMontgomery = p521MontgomeryDomainFieldElement{
	0x0080000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
}

var p521AMontgomery = p521MontgomeryDomainFieldElement{
	0xfe7fffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
	0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
	0xffffffffffffffff, 0xffffffffffffffff, 0x00000000000001ff,
}

var p521BMontgomery = p521MontgomeryDomainFieldElement{
	0x8014654fae586387, 0x78f7a28fea35a81f, 0x839ab9efc41e961a,
	0xbd8b29605e9dd8df, 0xf0ab0c9ca8f63f49, 0xf9dc5a44c8c77884,
	0x77516d392dccd98a, 0x0fc94d10d05b42a0, 0x000000000000004d,
}

var p521ZMontgomery = p521MontgomeryDomainFieldElement{
	0xfdffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
	0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
	0xffffffffffffffff, 0xffffffffffffffff, 0x00000000000001ff,
}

var p521Two64Montgomery = p521MontgomeryDomainFieldElement{
	0x0000000000000000, 0x0080000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
}

// P521One returns 1 in the P-521 base field.
func P521One() *P521Element {
	return &P521Element{x: p521OneMontgomery}
}

// P521A returns the P-521 SSWU A coefficient, which is -3.
func P521A() *P521Element {
	return &P521Element{x: p521AMontgomery}
}

// P521B returns the P-521 curve coefficient B.
func P521B() *P521Element {
	return &P521Element{x: p521BMontgomery}
}

// P521Z returns the P-521 SSWU Z parameter.
func P521Z() *P521Element {
	return &P521Element{x: p521ZMontgomery}
}

// P521Two64 returns 2^64 reduced in the P-521 base field.
func P521Two64() *P521Element {
	return &P521Element{x: p521Two64Montgomery}
}
