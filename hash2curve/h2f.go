// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package hash2curve

import (
	"crypto"
	"math/big"

	"github.com/bytemare/hash"
)

// HashToFieldXOF hashes the input with the domain separation tag (dst) to an integer under modulo, using an
// extensible output function (e.g. SHAKE).
// - dst MUST be non-nil and its length longer than 0. It's recommended that DST at least 16 bytes long.
// - count * ext * securityLength must be positive integers higher than 32.
func HashToFieldXOF(
	id *hash.ExtendableHash,
	input, dst []byte,
	count, ext, securityLength uint,
	modulo *big.Int,
) []*big.Int {
	expLength := count * ext * securityLength // elements * ext * security length
	uniform := ExpandXOF(id, input, dst, expLength)

	return reduceUniform(uniform, count, securityLength, modulo)
}

// HashToFieldXMD hashes the input with the domain separation tag (dst) to an integer under modulo, using a
// merkle-damgard based expander (e.g. SHA256).
// - dst MUST be non-nil, longer than 0 and lower than 256. It's recommended that DST at least 16 bytes long.
// - count * ext * securityLength must be a positive integer lower than 255 * (size of digest).
func HashToFieldXMD(id crypto.Hash, input, dst []byte, count, ext, securityLength uint, modulo *big.Int) []*big.Int {
	expLength := count * ext * securityLength // elements * ext * security length
	uniform := ExpandXMD(id, input, dst, expLength)

	return reduceUniform(uniform, count, securityLength, modulo)
}

func reduceUniform(uniform []byte, count, securityLength uint, modulo *big.Int) []*big.Int {
	res := make([]*big.Int, count)

	for i := range count {
		offset := i * securityLength
		res[i] = reduce(uniform[offset:offset+securityLength], modulo)
	}

	return res
}

func reduce(input []byte, modulo *big.Int) *big.Int {
	/*
		Interpret the input as a big-endian encoded unsigned integer of the field, and reduce it modulo the prime.
	*/
	i := new(big.Int).SetBytes(input)
	i.Mod(i, modulo)

	return i
}
