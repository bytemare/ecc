// SPDX-License-Identifier: MIT
//
// Copyright (C)2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secp256k1

import (
	"encoding/binary"
	"fmt"

	"github.com/bytemare/secp256k1"

	"github.com/bytemare/ecc/internal"
)

// Scalar implements the Scalar interface for Edwards25519 group scalars.
type Scalar struct {
	scalar *secp256k1.Scalar
}

func newScalar() *Scalar {
	return &Scalar{scalar: secp256k1.NewScalar()}
}

func assert(scalar internal.Scalar) *Scalar {
	sc, ok := scalar.(*Scalar)
	if !ok {
		panic(internal.ErrCastScalar)
	}

	return sc
}

// Group returns the group's Identifier.
func (s *Scalar) Group() byte {
	return Identifier
}

// Zero sets the scalar to 0, and returns it.
func (s *Scalar) Zero() internal.Scalar {
	s.scalar.Zero()
	return s
}

// One sets the scalar to 1, and returns it.
func (s *Scalar) One() internal.Scalar {
	s.scalar.One()
	return s
}

// MinusOne sets the scalar to order-1, and returns it.
func (s *Scalar) MinusOne() internal.Scalar {
	s.scalar.MinusOne()
	return s
}

// Random sets the current scalar to a new random scalar and returns it.
// The random source is crypto/rand, and this functions is guaranteed to return a non-zero scalar.
func (s *Scalar) Random() internal.Scalar {
	s.scalar.Random()
	return s
}

// Add sets the receiver to the sum of the input and the receiver, and returns the receiver.
func (s *Scalar) Add(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s
	}

	sc := assert(scalar)
	s.scalar.Add(sc.scalar)

	return s
}

// Subtract subtracts the input from the receiver, and returns the receiver.
func (s *Scalar) Subtract(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s
	}

	sc := assert(scalar)
	s.scalar.Subtract(sc.scalar)

	return s
}

// Multiply multiplies the receiver with the input, and returns the receiver.
func (s *Scalar) Multiply(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s.Zero()
	}

	sc := assert(scalar)
	s.scalar.Multiply(sc.scalar)

	return s
}

// Pow sets s to s**scalar modulo the group order, and returns s. If scalar is nil, it returns 1.
func (s *Scalar) Pow(scalar internal.Scalar) internal.Scalar {
	if scalar == nil || scalar.IsZero() {
		return s.One()
	}

	if scalar.Equal(newScalar().One()) == 1 {
		return s
	}

	sc := assert(scalar)
	s.scalar.Pow(sc.scalar)

	return s
}

// Invert sets the receiver to its modular inverse ( 1 / s ), and returns it.
func (s *Scalar) Invert() internal.Scalar {
	s.scalar.Invert()
	return s
}

// Equal returns 1 if the scalars are equal, and 0 otherwise.
func (s *Scalar) Equal(scalar internal.Scalar) int {
	if scalar == nil {
		return 0
	}

	sc := assert(scalar)

	return s.scalar.Equal(sc.scalar)
}

// LessOrEqual returns 1 if s <= scalar and 0 otherwise.
func (s *Scalar) LessOrEqual(scalar internal.Scalar) int {
	sc := assert(scalar)
	return int(s.scalar.LessOrEqual(sc.scalar)) //nolint:gosec // LessOrEqual returns 0 or 1, we're fine.
}

// IsZero returns whether the scalar is 0.
func (s *Scalar) IsZero() bool {
	return s.scalar.IsZero()
}

// Set sets the receiver to the value of the argument scalar, and returns the receiver.
func (s *Scalar) Set(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s.Zero()
	}

	sc := assert(scalar)
	s.scalar.Set(sc.scalar)

	return s
}

// SetUInt64 sets s to i modulo the field order, and returns an error if one occurs.
func (s *Scalar) SetUInt64(i uint64) internal.Scalar {
	s.scalar.SetUInt64(i)
	return s
}

// UInt64 returns the uint64 representation of the scalar,
// or an error if its value is higher than the authorized limit for uint64.
func (s *Scalar) UInt64() (uint64, error) {
	b := s.scalar.Encode()
	overflows := byte(0)

	for _, bx := range b[:scalarLength-8] {
		overflows |= bx
	}

	if overflows != 0 {
		return 0, internal.ErrUInt64TooBig
	}

	return binary.BigEndian.Uint64(b[scalarLength-8:]), nil
}

// Copy returns a copy of the receiver.
func (s *Scalar) Copy() internal.Scalar {
	return &Scalar{scalar: s.scalar.Copy()}
}

// Encode returns the compressed byte encoding of the scalar.
func (s *Scalar) Encode() []byte {
	return s.scalar.Encode()
}

// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
func (s *Scalar) Decode(in []byte) error {
	if err := s.scalar.Decode(in); err != nil {
		if err.Error() == "scalar too big" {
			return internal.ErrParamScalarInvalidEncoding
		}

		return fmt.Errorf("%w", err)
	}

	return nil
}

// Hex returns the fixed-sized hexadecimal encoding of s.
func (s *Scalar) Hex() string {
	return s.scalar.Hex()
}

// DecodeHex sets s to the decoding of the hex encoded scalar.
func (s *Scalar) DecodeHex(h string) error {
	if err := s.scalar.DecodeHex(h); err != nil {
		return fmt.Errorf("%w", err)
	}

	return nil
}
