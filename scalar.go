// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package ecc

import (
	"fmt"
	"strings"

	"github.com/bytemare/ecc/internal"
)

// Scalar represents a scalar in the prime-order group.
type Scalar struct {
	_ disallowEqual
	internal.Scalar
}

func newScalar(s internal.Scalar) *Scalar {
	return &Scalar{Scalar: s}
}

// Group returns the group's Identifier.
func (s *Scalar) Group() Group {
	return Group(s.Scalar.Group())
}

// Zero sets the scalar to 0, and returns it.
func (s *Scalar) Zero() *Scalar {
	s.Scalar.Zero()
	return s
}

// One sets the scalar to 1, and returns it.
func (s *Scalar) One() *Scalar {
	s.Scalar.One()
	return s
}

// MinusOne sets the scalar to order-1, and returns it.
func (s *Scalar) MinusOne() *Scalar {
	s.Scalar.MinusOne()
	return s
}

// Random sets the current scalar to a new random scalar and returns it.
// The random source is crypto/rand, and this functions is guaranteed to return a non-zero scalar.
func (s *Scalar) Random() *Scalar {
	s.Scalar.Random()
	return s
}

// Add sets the receiver to the sum of the input and the receiver, and returns the receiver.
func (s *Scalar) Add(scalar *Scalar) *Scalar {
	if scalar == nil {
		return s
	}

	s.Scalar.Add(scalar.Scalar)

	return s
}

// Subtract subtracts the input from the receiver, and returns the receiver.
func (s *Scalar) Subtract(scalar *Scalar) *Scalar {
	if scalar == nil {
		return s
	}

	s.Scalar.Subtract(scalar.Scalar)

	return s
}

// Multiply multiplies the receiver with the input, and returns the receiver.
func (s *Scalar) Multiply(scalar *Scalar) *Scalar {
	if scalar == nil {
		return s.Zero()
	}

	s.Scalar.Multiply(scalar.Scalar)

	return s
}

// Pow sets s to s**scalar modulo the group order, and returns s. If scalar is nil, it returns 1.
func (s *Scalar) Pow(scalar *Scalar) *Scalar {
	if scalar == nil {
		return s.One()
	}

	s.Scalar.Pow(scalar.Scalar)

	return s
}

// Invert sets the receiver to the scalar's modular inverse ( 1 / scalar ), and returns it.
func (s *Scalar) Invert() *Scalar {
	s.Scalar.Invert()
	return s
}

// Equal returns true if the elements are equivalent, and false otherwise.
func (s *Scalar) Equal(scalar *Scalar) bool {
	if scalar == nil {
		return false
	}

	return s.Scalar.Equal(scalar.Scalar) == 1
}

// LessOrEqual returns 1 if s <= scalar, and 0 otherwise.
func (s *Scalar) LessOrEqual(scalar *Scalar) bool {
	if scalar == nil {
		return false
	}

	return s.Scalar.LessOrEqual(scalar.Scalar) == 1
}

// IsZero returns whether the scalar is 0.
func (s *Scalar) IsZero() bool {
	return s.Scalar.IsZero()
}

// Set sets the receiver to the value of the argument scalar, and returns the receiver.
func (s *Scalar) Set(scalar *Scalar) *Scalar {
	if scalar == nil {
		return s.Zero()
	}

	s.Scalar.Set(scalar.Scalar)

	return s
}

// SetUInt64 sets s to i modulo the field order, and returns an error if one occurs.
func (s *Scalar) SetUInt64(i uint64) *Scalar {
	s.Scalar.SetUInt64(i)
	return s
}

// UInt64 returns the uint64 representation of the scalar,
// or an error if its value is higher than the authorized limit for uint64.
func (s *Scalar) UInt64() (uint64, error) {
	i, err := s.Scalar.UInt64()
	if err != nil {
		return 0, fmt.Errorf("%w", err)
	}

	return i, nil
}

// Copy returns a copy of the receiver.
func (s *Scalar) Copy() *Scalar {
	return &Scalar{Scalar: s.Scalar.Copy()}
}

// Encode returns the compressed byte encoding of the scalar.
func (s *Scalar) Encode() []byte {
	return s.Scalar.Encode()
}

// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
func (s *Scalar) Decode(data []byte) error {
	if err := s.Scalar.Decode(data); err != nil {
		return fmt.Errorf("scalar Decode: %w", err)
	}

	return nil
}

// Hex returns the fixed-sized hexadecimal encoding of s.
func (s *Scalar) Hex() string {
	return s.Scalar.Hex()
}

// DecodeHex sets s to the decoding of the hex encoded scalar.
func (s *Scalar) DecodeHex(h string) error {
	if err := s.Scalar.DecodeHex(h); err != nil {
		return fmt.Errorf("scalar DecodeHex: %w", err)
	}

	return nil
}

// MarshalJSON marshals the scalar into valid JSON.
func (s *Scalar) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%q", s.Hex())), nil
}

// UnmarshalJSON unmarshals the input into the scalar.
func (s *Scalar) UnmarshalJSON(data []byte) error {
	j := strings.ReplaceAll(string(data), "\"", "")
	return s.DecodeHex(j)
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (s *Scalar) MarshalBinary() ([]byte, error) {
	return s.Scalar.Encode(), nil
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (s *Scalar) UnmarshalBinary(data []byte) error {
	if err := s.Scalar.Decode(data); err != nil {
		return fmt.Errorf("scalar UnmarshalBinary: %w", err)
	}

	return nil
}
