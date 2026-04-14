// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package fiat

var p256MinusOneEncoding = [p256ElementLen]byte{
	0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
}

var p256OneMontgomery = p256MontgomeryDomainFieldElement{
	0x0000000000000001, 0xffffffff00000000, 0xffffffffffffffff, 0x00000000fffffffe,
}

var p256AMontgomery = p256MontgomeryDomainFieldElement{
	0xfffffffffffffffc, 0x00000003ffffffff, 0x0000000000000000, 0xfffffffc00000004,
}

var p256BMontgomery = p256MontgomeryDomainFieldElement{
	0xd89cdf6229c4bddf, 0xacf005cd78843090, 0xe5a220abf7212ed6, 0xdc30061d04874834,
}

var p256ZMontgomery = p256MontgomeryDomainFieldElement{
	0xfffffffffffffff5, 0x0000000affffffff, 0x0000000000000000, 0xfffffff50000000b,
}

var p256Two64Montgomery = p256MontgomeryDomainFieldElement{
	0x00000000ffffffff, 0x0000000100000001, 0xfffffffeffffffff, 0xfffffffe00000000,
}

// P256One returns 1 in the P-256 base field.
func P256One() *P256Element {
	return &P256Element{x: p256OneMontgomery}
}

// P256A returns the P-256 SSWU A coefficient, which is -3.
func P256A() *P256Element {
	return &P256Element{x: p256AMontgomery}
}

// P256B returns the P-256 curve coefficient B.
func P256B() *P256Element {
	return &P256Element{x: p256BMontgomery}
}

// P256Z returns the P-256 SSWU Z parameter.
func P256Z() *P256Element {
	return &P256Element{x: p256ZMontgomery}
}

// P256Two64 returns 2^64 reduced in the P-256 base field.
func P256Two64() *P256Element {
	return &P256Element{x: p256Two64Montgomery}
}
