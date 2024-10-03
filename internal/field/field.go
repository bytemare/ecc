// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package field provides modular operations over very high integers.
package field

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// String2Int returns a big.Int representation of the integer s.
func String2Int(s string) big.Int {
	if p, _ := new(big.Int).SetString(s, 0); p != nil {
		return *p
	}

	panic("invalid string to convert")
}

// Field represents a Galois Field.
type Field struct {
	order       *big.Int
	pMinus1div2 *big.Int // used in IsSquare
	pMinus2     *big.Int // used for Field big.Int inversion
	exp         *big.Int
	byteLen     int
}

// NewField returns a newly instantiated field for the given prime order.
func NewField(prime *big.Int) Field {
	// pMinus1div2 is used to determine whether a big Int is a quadratic square.
	pMinus1div2 := big.NewInt(1)
	pMinus1div2.Sub(prime, pMinus1div2)
	pMinus1div2.Rsh(pMinus1div2, 1)

	// pMinus2 is used for modular inversion.
	pMinus2 := big.NewInt(2)
	pMinus2.Sub(prime, pMinus2)

	// precompute e = (p + 1) / 4
	exp := big.NewInt(1)
	exp.Add(prime, exp)
	exp.Rsh(exp, 2)

	return Field{
		order:       prime,
		pMinus1div2: pMinus1div2,
		pMinus2:     pMinus2,
		exp:         exp,
		byteLen:     (prime.BitLen() + 7) / 8,
	}
}

// Random sets res to a random big.Int in the Field.
func (f Field) Random(res *big.Int) *big.Int {
	tmp, err := rand.Int(rand.Reader, f.order)
	if err != nil {
		// We can as well not panic and try again in a loop
		panic(fmt.Errorf("unexpected error in generating random bytes : %w", err))
	}

	res.Set(tmp)

	return res
}

// Order returns the size of the Field.
func (f Field) Order() *big.Int {
	return f.order
}

// PMinusOne returns p-1, the greatest integer below the order.
func (f Field) PMinusOne() *big.Int {
	return new(big.Int).Sub(f.order, big.NewInt(1))
}

// ByteLen returns the length of the field order in bytes.
func (f Field) ByteLen() int {
	return f.byteLen
}

// IsZero returns whether the big.Int is equivalent to zero.
func (f Field) IsZero(e *big.Int) bool {
	return e.Sign() == 0
}

// Inv sets res to the modular inverse of x mod field order.
func (f Field) Inv(res, x *big.Int) {
	f.Exponent(res, x, f.pMinus2)
}

// Exponent returns x^n mod field order.
func (f Field) Exponent(res, x, n *big.Int) *big.Int {
	return res.Exp(x, n, f.order)
}

// IsEqual returns whether the two fields have the same order.
func (f Field) IsEqual(f2 *Field) bool {
	return f.order.Cmp(f2.order) == 0
}

// Mod reduces x modulo the field order.
func (f Field) Mod(x *big.Int) *big.Int {
	return x.Mod(x, f.order)
}

// Add sets res to x + y modulo the field order.
func (f Field) Add(res, x, y *big.Int) {
	f.Mod(res.Add(x, y))
}

// Sub sets res to x - y modulo the field order.
func (f Field) Sub(res, x, y *big.Int) *big.Int {
	return f.Mod(res.Sub(x, y))
}

// Mul sets res to the multiplication of x and y modulo the field order.
func (f Field) Mul(res, x, y *big.Int) {
	f.Mod(res.Mul(x, y))
}
