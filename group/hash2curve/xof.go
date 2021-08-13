// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package hash2curve provides hash-to-curve compatible input expansion.
package hash2curve

import (
	"math"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hash"
)

// expandMessage XOF implements https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve#section-5.4.2.
func expandXOF(x hash.Extensible, input, dst []byte, length int) []byte {
	dst = vetXofDST(x, dst)
	len2o := encoding.I2OSP(length, 2)
	dstLen2o := encoding.I2OSP(len(dst), 1)

	return x.Get().Hash(length, input, len2o, dst, dstLen2o)
}

// If the tag length exceeds 255 bytes, compute a shorter tag by hashing it.
func vetXofDST(x hash.Extensible, dst []byte) []byte {
	if len(dst) <= dstMaxLength {
		return dst
	}

	k := x.SecurityLevel()
	size := int(math.Ceil(float64(2*k) / float64(8)))

	return x.Get().Hash(size, []byte(dstLongPrefix), dst)
}