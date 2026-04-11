// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package hash2curve Hashing to Elliptic Curves as specified in RFC 9380 (https://datatracker.ietf.org/doc/rfc9380).
package hash2curve

import (
	"crypto"
	"errors"

	"github.com/bytemare/hash"

	"github.com/bytemare/ecc/hash2curve/internal"
)

const (
	minLength            = 0
	recommendedMinLength = 16
)

var errZeroLenDST = errors.New("zero-length DST")

func checkDST(dst []byte) {
	if len(dst) < recommendedMinLength {
		if len(dst) == minLength {
			panic(errZeroLenDST)
		}
	}
}

// ExpandXMD expands the input and dst using the given fixed length hash function.
// - dst MUST be non-nil, longer than 0 and lower than 256. It's recommended that DST at least 16 bytes long.
// - length must be a positive integer lower than 255 * (size of digest).
func ExpandXMD(id crypto.Hash, input, dst []byte, length uint) []byte {
	checkDST(dst)
	return internal.ExpandXMD(id, input, dst, length)
}

// ExpandXOF expands the input and dst using the given extendable output hash function.
// - dst MUST be non-nil and its length longer than 0. It's recommended that DST at least 16 bytes long.
// - length must be a positive integer higher than 32.
func ExpandXOF(ext *hash.ExtendableHash, input, dst []byte, length uint) []byte {
	checkDST(dst)
	return internal.ExpandXOF(ext, input, dst, length)
}
