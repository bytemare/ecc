// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package ecc_test

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
	"testing"
)

var errParamNotOnCurve = errors.New("point is not on curve")

// TestNistInvalidCoordinates tests big.Int values that are not valid field elements
// (negative or bigger than P). They are expected to return false from
// IsOnCurve, all other behavior is undefined.
func TestNistInvalidCoordinates(t *testing.T) {
	tests := []struct {
		curve elliptic.Curve
		name  string
	}{
		{elliptic.P256(), "P256"},
		{elliptic.P384(), "P384"},
		{elliptic.P521(), "P521"},
	}

	for _, test := range tests {
		curve := test.curve
		t.Run(test.name, func(tt *testing.T) {
			testInvalidCoordinates(tt, test.name, curve)
		})
	}
}

func solveP256(x *big.Int) *big.Int {
	p, _ := new(big.Int).SetString("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10)
	b, _ := new(big.Int).SetString("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)

	return solveNist(x, b, p)
}

func solveP384(x *big.Int) *big.Int {
	p, _ := new(big.Int).SetString("394020061963944792122790401001436138050797392704654"+
		"46667948293404245721771496870329047266088258938001861606973112319", 10)
	b, _ := new(big.Int).SetString("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088"+
		"f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16)

	return solveNist(x, b, p)
}

func solveP521(x *big.Int) *big.Int {
	p, _ := new(big.Int).SetString("68647976601306097149819007990813932172694353001433"+
		"0540939446345918554318339765605212255964066145455497729631139148"+
		"0858037121987999716643812574028291115057151", 10)
	b, _ := new(big.Int).SetString("0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8"+
		"b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef"+
		"451fd46b503f00", 16)

	return solveNist(x, b, p)
}

func solveNist(x, b, order *big.Int) *big.Int {
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	threeX := new(big.Int).Lsh(x, 1)
	threeX.Add(threeX, x)

	x3.Sub(x3, threeX)
	x3.Add(x3, b)
	x3.Mod(x3, order)

	return x3
}

type solver func(x *big.Int) *big.Int

func isOnCurve(x, y, order *big.Int, solve solver) error {
	// Reject integers below 0 or higher than the field order.
	if x.Sign() < 0 || x.Cmp(order) >= 0 ||
		y.Sign() < 0 || y.Cmp(order) >= 0 {
		return errParamNotOnCurve
	}

	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, order)

	if solve(x).Cmp(y2) != 0 {
		return errParamNotOnCurve
	}

	return nil
}

func testInvalidCoordinates(t *testing.T, curveName string, curve elliptic.Curve) {
	checkIsOnCurveFalse := func(name string, x, y, order *big.Int, solver solver) {
		if err := isOnCurve(x, y, order, solver); err == nil {
			t.Errorf("expected error for IsOnCurve(%s), but call returned no error", name)
		}
	}

	var solver solver
	switch curveName {
	case "P256":
		solver = solveP256
	case "P384":
		solver = solveP384
	case "P521":
		solver = solveP521
	default:
		panic("invalid nist group")
	}

	p := curve.Params().P
	_, x, y, _ := elliptic.GenerateKey(curve, rand.Reader)
	xx, yy := new(big.Int), new(big.Int)

	// Check if the sign is getting dropped.
	xx.Neg(x)
	checkIsOnCurveFalse("-x, y", xx, y, p, solver)
	yy.Neg(y)
	checkIsOnCurveFalse("x, -y", x, yy, p, solver)

	// Check if negative values are reduced modulo P.
	xx.Sub(x, p)
	checkIsOnCurveFalse("x-P, y", xx, y, p, solver)
	yy.Sub(y, p)
	checkIsOnCurveFalse("x, y-P", x, yy, p, solver)

	// Check if positive values are reduced modulo P.
	xx.Add(x, p)
	checkIsOnCurveFalse("x+P, y", xx, y, p, solver)
	yy.Add(y, p)
	checkIsOnCurveFalse("x, y+P", x, yy, p, solver)

	// Check if the overflow is dropped.
	xx.Add(x, new(big.Int).Lsh(big.NewInt(1), 535))
	checkIsOnCurveFalse("x+2⁵³⁵, y", xx, y, p, solver)
	yy.Add(y, new(big.Int).Lsh(big.NewInt(1), 535))
	checkIsOnCurveFalse("x, y+2⁵³⁵", x, yy, p, solver)

	// Check if P is treated like zero (if possible).
	// y^2 = x^3 - 3x + B
	// y = mod_sqrt(x^3 - 3x + B)
	// y = mod_sqrt(B) if x = 0
	// If there is no modsqrt, there is no point with x = 0, can't test x = P.
	if yy := new(big.Int).ModSqrt(curve.Params().B, p); yy != nil {
		if !curve.IsOnCurve(big.NewInt(0), yy) {
			t.Fatal("(0, mod_sqrt(B)) is not on the curve?")
		}
		checkIsOnCurveFalse("P, y", p, yy, p, solver)
	}
}
