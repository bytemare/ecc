// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package internal

import (
	cryptorand "crypto/rand"
	"encoding"
	"errors"
	"fmt"
)

var (
	// ErrInvalidGroup indicates usage of an unavailable or invalid group.
	ErrInvalidGroup = errors.New("invalid group")

	// ErrParamNilScalar indicates a forbidden nil or empty scalar.
	ErrParamNilScalar = errors.New("nil or empty scalar")

	// ErrParamScalarLength indicates an invalid scalar length.
	ErrParamScalarLength = errors.New("invalid scalar length")

	// ErrParamNilPoint indicated a forbidden nil or empty point.
	ErrParamNilPoint = errors.New("nil or empty point")

	// ErrParamInvalidPointEncoding indicates an invalid point encoding has been provided.
	ErrParamInvalidPointEncoding = errors.New("invalid point encoding")

	// ErrCastElement indicates a failed attempt to cast to a point.
	ErrCastElement = errors.New("could not cast to same group element (wrong group ?)")

	// ErrCastScalar indicates a failed attempt to cast to a scalar.
	ErrCastScalar = errors.New("could not cast to same group scalar (wrong group ?)")

	// ErrWrongField indicates an incompatible field has been encountered.
	ErrWrongField = errors.New("incompatible fields")

	// ErrIdentity indicates that the identity point (or point at infinity) has been encountered.
	ErrIdentity = errors.New("infinity/identity point")

	// ErrBigIntConversion reports an error in converting to a *big.int.
	ErrBigIntConversion = errors.New("conversion error")

	// ErrParamNegScalar reports an error when the input scalar is negative.
	ErrParamNegScalar = errors.New("negative scalar")

	// ErrParamScalarTooBig reports an error when the input scalar is too big.
	ErrParamScalarTooBig = errors.New("scalar too big")

	// ErrParamScalarInvalidEncoding indicates an invalid scalar encoding has been provided, or that it's too big.
	ErrParamScalarInvalidEncoding = errors.New("invalid scalar encoding")

	// ErrUInt64TooBig indicates that the scalar is higher than the allowed values for uint64.
	ErrUInt64TooBig = errors.New("scalar is too big to be uint64")

	// ErrDecodingInvalidLength indicates an invalid encoding length.
	ErrDecodingInvalidLength = errors.New("invalid encoding length")

	// ErrDecodingInvalidJSONEncoding indicates an invalid JSON encoding.
	ErrDecodingInvalidJSONEncoding = errors.New("invalid JSON encoding")
)

// An Encoder can encode itself to machine or human-readable forms.
type Encoder interface {
	// Encode returns the compressed byte encoding.
	Encode() []byte

	// Hex returns the fixed-sized hexadecimal encoding.
	Hex() string

	// BinaryMarshaler implementation.
	encoding.BinaryMarshaler
}

// A Decoder can encode itself to machine or human-readable forms.
type Decoder interface {
	// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
	Decode(data []byte) error

	// DecodeHex sets the receiver to the decoding of the hex encoded input.
	DecodeHex(h string) error

	// BinaryUnmarshaler implementation.
	encoding.BinaryUnmarshaler
}

// RandomBytes returns random bytes of length len (wrapper for crypto/rand).
func RandomBytes(length int) []byte {
	random := make([]byte, length)
	if _, err := cryptorand.Read(random); err != nil {
		// We can as well not panic and try again in a loop
		panic(fmt.Errorf("unexpected error in generating random bytes : %w", err))
	}

	return random
}
