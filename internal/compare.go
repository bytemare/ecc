// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package internal

import "crypto/subtle"

func constantTimeCompareStep(lt, gt int, x, y byte) (int, int) {
	eq := subtle.ConstantTimeByteEq(x, y)
	neq := 1 ^ eq

	xlt := subtle.ConstantTimeLessOrEq(int(x), int(y)) & neq
	xgt := subtle.ConstantTimeLessOrEq(int(y), int(x)) & neq

	undecided := 1 ^ (lt | gt)
	lt |= undecided & xlt
	gt |= undecided & xgt

	return lt, gt
}

// ConstantTimeLessOrEqBytes returns 1 when x <= y and 0 otherwise.
// When littleEndian is true, x and y are interpreted as little-endian integers.
func ConstantTimeLessOrEqBytes(x, y []byte, littleEndian bool) int {
	if len(x) != len(y) {
		panic(ErrParamScalarLength)
	}

	lt := 0
	gt := 0

	if littleEndian {
		for i := len(x) - 1; i >= 0; i-- {
			lt, gt = constantTimeCompareStep(lt, gt, x[i], y[i])
		}
	} else {
		for i := range x {
			lt, gt = constantTimeCompareStep(lt, gt, x[i], y[i])
		}
	}

	return 1 ^ gt
}
