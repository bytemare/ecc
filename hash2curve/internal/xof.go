// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package internal values, structures, and functions that are not part of the public API.
package internal

import (
	"errors"
	"math"

	"github.com/bytemare/hash"

	"github.com/bytemare/ecc/encoding"
)

var errXOFHighOutput = errors.New("XOF dst hashing is too long")

// ExpandXOF implements expand_message_xof as specified in RFC 9380 section 5.3.2.
func ExpandXOF(ext *hash.ExtendableHash, input, dst []byte, length uint) []byte {
	if length > math.MaxUint16 {
		panic(errLengthTooLarge)
	}

	dst = VetXofDST(ext, dst)
	len2o := encoding.I2OSP(int(length), 2)
	dstLen2o := encoding.I2OSP(len(dst), 1)

	ext.SetOutputSize(int(length))

	return ext.Hash(input, len2o, dst, dstLen2o)
}

// VetXofDST computes a shorter tag for dst if the tag length exceeds 255 bytes.
func VetXofDST(x *hash.ExtendableHash, dst []byte) []byte {
	if len(dst) <= dstMaxLength {
		return dst
	}

	size := checkXOFSecurityLevel(x)
	x.SetOutputSize(size)

	return x.Hash([]byte(dstLongPrefix), dst)
}

// checkXOFSecurityLength return the desired output length to shorten the DST, or panics if the XOFs security level is
// too high for the expected output length.
func checkXOFSecurityLevel(x *hash.ExtendableHash) int {
	k := x.Algorithm().SecurityLevel()

	size := int(math.Ceil(float64(2*k) / float64(8)))
	if size > x.Size()*8 {
		panic(errXOFHighOutput)
	}

	return size
}
