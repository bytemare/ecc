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
	"math/big"
)

type mapping[point nistECPoint[point]] struct {
	hashToScalar hashToScalar[point]
	hashToCurve  hashToCurve[point]
	mapToCurve   mapToCurve[point]
	hash         crypto.Hash
}

type (
	hashToScalar[point nistECPoint[point]] func(input, dst []byte) *big.Int
	hashToCurve[point nistECPoint[point]]  func(input, dst []byte) point
	mapToCurve[point nistECPoint[point]]   func(input, dst []byte) point
)

func (m *mapping[point]) setMapping(
	hash crypto.Hash,
	h2s hashToScalar[point],
	h2c hashToCurve[point],
	m2c mapToCurve[point],
) {
	m.hash = hash
	m.hashToScalar = h2s
	m.hashToCurve = h2c
	m.mapToCurve = m2c
}
