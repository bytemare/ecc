// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package nist

import (
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/bytemare/ecc/internal"
	"github.com/bytemare/ecc/internal/field"
)

// Scalar implements the Scalar interface for group scalars.
type Scalar struct {
	field  *field.Field
	scalar big.Int
}

func newScalar(f *field.Field) *Scalar {
	s := &Scalar{
		field:  f,
		scalar: big.Int{},
	}

	return s
}

func (s *Scalar) assert(scalar internal.Scalar) *Scalar {
	_sc, ok := scalar.(*Scalar)
	if !ok {
		panic(internal.ErrCastScalar)
	}

	if !s.field.IsEqual(_sc.field) {
		panic(internal.ErrWrongField)
	}

	return _sc
}

// Group returns the group's Identifier.
func (s *Scalar) Group() byte {
	switch *s.field {
	case p256.scalarField:
		return IdentifierP256
	case p384.scalarField:
		return IdentifierP384
	case p521.scalarField:
		return IdentifierP521
	}

	panic("invalid field order for scalar" + s.field.Order().String())
}

// Zero sets s to 0, and returns it.
func (s *Scalar) Zero() internal.Scalar {
	s.scalar.Set(big.NewInt(0))
	return s
}

// One sets s to 1, and returns it.
func (s *Scalar) One() internal.Scalar {
	s.scalar.Set(big.NewInt(1))
	return s
}

// MinusOne sets the scalar to order-1, and returns it.
func (s *Scalar) MinusOne() internal.Scalar {
	s.scalar.Set(s.field.PMinusOne())
	return s
}

// Random sets s to a new random scalar and returns it.
// The random source is crypto/rand, and this functions is guaranteed to return a non-zero scalar.
func (s *Scalar) Random() internal.Scalar {
	for {
		s.field.Random(&s.scalar)

		if !s.IsZero() {
			return s
		}
	}
}

// Add sets the receiver to the sum of the input and the receiver, and returns the receiver.
func (s *Scalar) Add(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s
	}

	sc := s.assert(scalar)
	s.field.Add(&s.scalar, &s.scalar, &sc.scalar)

	return s
}

// Subtract subtracts the input from the receiver, and returns the receiver.
func (s *Scalar) Subtract(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s
	}

	sc := s.assert(scalar)
	s.field.Sub(&s.scalar, &s.scalar, &sc.scalar)

	return s
}

// Multiply multiplies the receiver with the input, and returns the receiver.
func (s *Scalar) Multiply(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s.Zero()
	}

	sc := s.assert(scalar)
	s.field.Mul(&s.scalar, &s.scalar, &sc.scalar)

	return s
}

// Pow sets s to s**scalar modulo the group order, and returns s. If scalar is nil, it returns 1.
func (s *Scalar) Pow(scalar internal.Scalar) internal.Scalar {
	if scalar == nil || scalar.IsZero() {
		return s.One()
	}

	if scalar.Equal(newScalar(s.field).One()) == 1 {
		return s
	}

	sc := s.assert(scalar)
	s.field.Exponent(&s.scalar, &s.scalar, &sc.scalar)

	return s
}

// Invert sets the receiver to its modular inverse ( 1 / s ), and returns it.
func (s *Scalar) Invert() internal.Scalar {
	s.field.Inv(&s.scalar, &s.scalar)
	return s
}

// Equal returns 1 if the scalars are equal, and 0 otherwise.
func (s *Scalar) Equal(scalar internal.Scalar) int {
	if scalar == nil {
		return 0
	}

	sc := s.assert(scalar)

	return subtle.ConstantTimeCompare(s.scalar.Bytes(), sc.scalar.Bytes())
}

// LessOrEqual returns 1 if s <= scalar, and 0 otherwise.
func (s *Scalar) LessOrEqual(scalar internal.Scalar) int {
	sc := s.assert(scalar)

	ienc := s.Encode()
	jenc := sc.Encode()

	leni := len(ienc)
	if leni != len(jenc) {
		panic(internal.ErrParamScalarLength)
	}

	var res bool

	for i := range leni {
		res = res || (ienc[i] > jenc[i])
	}

	if res {
		return 0
	}

	return 1
}

// IsZero returns whether the scalar is 0.
func (s *Scalar) IsZero() bool {
	return s.field.IsZero(&s.scalar)
}

// Set sets the receiver to the value of the argument scalar, and returns the receiver.
func (s *Scalar) Set(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s.Zero()
	}

	ec := s.assert(scalar)
	s.scalar.Set(&ec.scalar)

	return s
}

// SetUInt64 sets s to i modulo the field order, and returns an error if one occurs.
func (s *Scalar) SetUInt64(i uint64) internal.Scalar {
	s.scalar.SetUint64(i)
	return s
}

// UInt64 returns the uint64 representation of the scalar,
// or an error if its value is higher than the authorized limit for uint64.
func (s *Scalar) UInt64() (uint64, error) {
	b := s.Encode()
	overflows := byte(0)
	scalarLength := s.field.ByteLen()

	for _, bx := range b[:scalarLength-8] {
		overflows |= bx
	}

	if overflows != 0 {
		return 0, internal.ErrUInt64TooBig
	}

	return binary.BigEndian.Uint64(b[scalarLength-8:]), nil
}

// Copy returns a copy of the Scalar.
func (s *Scalar) Copy() internal.Scalar {
	cpy := newScalar(s.field)
	cpy.scalar.Set(&s.scalar)

	return cpy
}

// Encode returns the compressed byte encoding of the scalar.
func (s *Scalar) Encode() []byte {
	scalar := make([]byte, s.field.ByteLen())
	return s.scalar.FillBytes(scalar)
}

// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
func (s *Scalar) Decode(in []byte) error {
	switch len(in) {
	case 0:
		return internal.ErrParamNilScalar
	case s.field.ByteLen():
		break
	default:
		return internal.ErrParamScalarLength
	}

	// warning - SetBytes interprets the input as a non-signed integer, so this will always be false
	// 	if tmp.Sign() < 0 {
	//		return internal.ErrParamNegScalar
	//	}
	tmp := new(big.Int).SetBytes(in)

	if s.field.Order().Cmp(tmp) <= 0 {
		return internal.ErrParamScalarInvalidEncoding
	}

	s.scalar.Set(tmp)

	return nil
}

// Hex returns the fixed-sized hexadecimal encoding of s.
func (s *Scalar) Hex() string {
	return hex.EncodeToString(s.Encode())
}

// DecodeHex sets s to the decoding of the hex encoded scalar.
func (s *Scalar) DecodeHex(h string) error {
	b, err := hex.DecodeString(h)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	return s.Decode(b)
}
