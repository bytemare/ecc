// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package internal defines simple and abstract APIs to group Elements and Scalars.
package internal

// Scalar interface abstracts common operations on scalars in a prime-order Group.
type Scalar interface {
	// Group returns the group's Identifier.
	Group() byte

	// Zero sets the scalar to 0, and returns it.
	Zero() Scalar

	// One sets the scalar to 1, and returns it.
	One() Scalar

	// MinusOne sets the scalar to order-1, and returns it.
	MinusOne() Scalar

	// Random sets the current scalar to a new random scalar and returns it.
	// The random source is crypto/rand, and this functions is guaranteed to return a non-zero scalar.
	Random() Scalar

	// Add sets the receiver to the sum of the input and the receiver, and returns the receiver.
	Add(Scalar) Scalar

	// Subtract subtracts the input from the receiver, and returns the receiver.
	Subtract(Scalar) Scalar

	// Multiply multiplies the receiver with the input, and returns the receiver.
	Multiply(Scalar) Scalar

	// Pow sets s to s**scalar modulo the group order, and returns s. If scalar is nil, it returns 1.
	Pow(scalar Scalar) Scalar

	// Invert sets the receiver to the scalar's modular inverse ( 1 / scalar ), and returns it.
	Invert() Scalar

	// Equal returns 1 if the scalars are equal, and 0 otherwise.
	Equal(Scalar) int

	// LessOrEqual returns 1 if s <= scalar, and 0 otherwise.
	LessOrEqual(scalar Scalar) int

	// IsZero returns whether the scalar is 0.
	IsZero() bool

	// Set sets the receiver to the value of the argument scalar, and returns the receiver.
	Set(Scalar) Scalar

	// SetUInt64 sets s to i modulo the field order, and returns an error if one occurs.
	SetUInt64(i uint64) Scalar

	// UInt64 returns the uint64 representation of the scalar,
	// or an error if its value is higher than the authorized limit for uint64.
	UInt64() (uint64, error)

	// Copy returns a copy of the receiver.
	Copy() Scalar

	// Encode returns the compressed byte encoding of the scalar.
	Encode() []byte

	// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
	Decode(in []byte) error

	// Hex returns the fixed-sized hexadecimal encoding of s.
	Hex() string

	// DecodeHex sets s to the decoding of the hex encoded scalar.
	DecodeHex(h string) error
}
