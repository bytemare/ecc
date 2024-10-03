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

	"github.com/bytemare/hash2curve"

	"github.com/bytemare/ecc/internal/field"
)

type mapping struct {
	z         big.Int
	hash      crypto.Hash
	secLength uint
}

type curve[point nistECPoint[point]] struct {
	field    field.Field
	b        big.Int
	NewPoint func() point
	mapping
}

func (c *curve[point]) setMapping(hash crypto.Hash, z string, secLength uint) {
	c.mapping.hash = hash
	c.mapping.secLength = secLength
	c.mapping.z = field.String2Int(z)
}

func (c *curve[point]) setCurveParams(prime *big.Int, b string, newPoint func() point) {
	c.field = field.NewField(prime)
	c.b = field.String2Int(b)
	c.NewPoint = newPoint
}

func (c *curve[point]) encodeXMD(input, dst []byte) point {
	u := hash2curve.HashToFieldXMD(c.hash, input, dst, 1, 1, c.secLength, c.field.Order())
	q := c.map2curve(u[0])
	// We can save cofactor clearing because it is 1.
	return q
}

func (c *curve[point]) hashXMD(input, dst []byte) point {
	u := hash2curve.HashToFieldXMD(c.hash, input, dst, 2, 1, c.secLength, c.field.Order())
	q0 := c.map2curve(u[0])
	q1 := c.map2curve(u[1])
	// We can save cofactor clearing because it is 1.
	return q0.Add(q0, q1)
}

func (c *curve[point]) map2curve(fe *big.Int) point {
	x, y := hash2curve.MapToCurveSSWU(&nistWa, &c.b, &c.z, fe, c.field.Order())
	return c.affineToPoint(x, y)
}

var (
	decompressed256 = [65]byte{0x04}
	decompressed384 = [97]byte{0x04}
	decompressed521 = [133]byte{0x04}
)

func (c *curve[point]) affineToPoint(pxc, pyc *big.Int) point {
	var decompressed []byte

	byteLen := c.field.ByteLen()
	switch byteLen {
	case 32:
		decompressed = decompressed256[:]
	case 48:
		decompressed = decompressed384[:]
	case 66:
		decompressed = decompressed521[:]
	default:
		panic("invalid byte length")
	}

	decompressed[0] = 0x04
	pxc.FillBytes(decompressed[1 : 1+byteLen])
	pyc.FillBytes(decompressed[1+byteLen:])

	p, err := c.NewPoint().SetBytes(decompressed)
	if err != nil {
		panic(err)
	}

	return p
}
