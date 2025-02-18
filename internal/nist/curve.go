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

	"github.com/bytemare/ecc/internal/field"
)

type mapping[point nistECPoint[point]] struct {
	HashToScalar hashToScalar[point]
	HashToCurve  hashToCurve[point]
	MapToCurve   mapToCurve[point]
	hash         crypto.Hash
}

type curve[point nistECPoint[point]] struct {
	NewPoint func() point
	field    field.Field
	b        big.Int
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
	m.HashToScalar = h2s
	m.HashToCurve = h2c
	m.MapToCurve = m2c
}

func (c *curve[point]) setCurveParams(prime *big.Int, b string, newPoint func() point) {
	c.field = field.NewField(prime)
	c.b = field.String2Int(b)
	c.NewPoint = newPoint
}
