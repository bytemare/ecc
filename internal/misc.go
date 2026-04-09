// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package internal

import (
	"encoding"
	"errors"
	"fmt"
	"reflect"

	cryptorand "crypto/rand"
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

	// ErrWrongGroup indicates an operation has been attempted between incompatible EC groups.
	ErrWrongGroup = errors.New("wrong group")

	// ErrWrongField indicates an incompatible field has been encountered.
	ErrWrongField = errors.New("incompatible fields")

	// ErrIdentity indicates that the identity point (or point at infinity) has been encountered.
	ErrIdentity = errors.New("infinity/identity point")

	// ErrBigIntConversion reports an error in converting to a *big.int.
	ErrBigIntConversion = errors.New("conversion error")

	// ErrParamScalarInvalidEncoding indicates an invalid scalar encoding has been provided, or that it's too big.
	ErrParamScalarInvalidEncoding = errors.New("invalid scalar encoding")

	// ErrUInt64TooBig indicates that the scalar is higher than the allowed values for uint64.
	ErrUInt64TooBig = errors.New("scalar is too big to be uint64")

	// ErrParamInvalidInputLength indicates the input length is invalid.
	ErrParamInvalidInputLength = errors.New("invalid input length")
)

// WrongGroupError returns an error indicating a group mismatch.
func WrongGroupError(expected, got reflect.Type) error {
	return errors.Join(ErrWrongGroup, fmt.Errorf("expected %v, got %v", expected, got)) //nolint:err113 // it's ok.
}

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
	_, _ = cryptorand.Read(random)

	return random
}
