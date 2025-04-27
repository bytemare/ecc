// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package edwards25519

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/bytemare/ecc/internal"

	ed "filippo.io/edwards25519"
)

const inputLength = 64

var (
	scZero     Scalar
	scOne      Scalar
	order      big.Int
	scMinusOne = []byte{
		236, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16,
	}
	orderBytes = []byte{
		237, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16,
	}
)

func init() {
	scZero = Scalar{*ed.NewScalar()}
	if err := scZero.Decode([]byte{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}); err != nil {
		panic(err)
	}

	scOne = Scalar{*ed.NewScalar()}
	if err := scOne.Decode([]byte{
		1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}); err != nil {
		panic(err)
	}

	if _, ok := order.SetString(orderPrime, 10); !ok {
		panic(internal.ErrBigIntConversion)
	}
}

// Scalar implements the Scalar interface for Edwards25519 group scalars.
type Scalar struct {
	scalar ed.Scalar
}

func assert(scalar internal.Scalar) *Scalar {
	sc, ok := scalar.(*Scalar)
	if !ok {
		panic(internal.ErrCastScalar)
	}

	return &Scalar{*ed.NewScalar().Set(&sc.scalar)}
}

// Group returns the group's Identifier.
func (s *Scalar) Group() byte {
	return Identifier
}

// Zero sets the scalar to 0, and returns it.
func (s *Scalar) Zero() internal.Scalar {
	s.scalar = *ed.NewScalar()
	return s
}

// One sets the scalar to 1, and returns it.
func (s *Scalar) One() internal.Scalar {
	s.set(&scOne.scalar)
	return s
}

// MinusOne sets the scalar to order-1, and returns it.
func (s *Scalar) MinusOne() internal.Scalar {
	_ = s.decodeScalar(scMinusOne) //nolint:errcheck // always succeeds
	return s
}

// Random sets the current scalar to a new random scalar and returns it.
// The random source is crypto/rand, and this functions is guaranteed to return a non-zero scalar.
func (s *Scalar) Random() internal.Scalar {
	for {
		random := internal.RandomBytes(inputLength)
		if _, err := s.scalar.SetUniformBytes(random); err != nil {
			panic(err)
		}

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

	sc := assert(scalar)
	s.scalar.Add(&s.scalar, &sc.scalar)

	return s
}

// Subtract subtracts the input from the receiver, and returns the receiver.
func (s *Scalar) Subtract(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s
	}

	sc := assert(scalar)
	s.scalar.Subtract(&s.scalar, &sc.scalar)

	return s
}

// Multiply multiplies the receiver with the input, and returns the receiver.
func (s *Scalar) Multiply(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s.Zero()
	}

	sc := assert(scalar)
	s.multiply(sc)

	return s
}

func getMSBit(in byte) int {
	for i := 7; i >= 0; i-- {
		mask := byte(1 << uint(i))
		if in&mask != 0 {
			return i
		}
	}

	return 0
}

func getMSByte(in []byte) int {
	msb := 0

	for i, b := range in {
		if b != 0 {
			msb = i
		}
	}

	return msb
}

// Pow sets s to s**scalar modulo the group order, and returns s. If scalar is nil, it returns 1.
func (s *Scalar) Pow(scalar internal.Scalar) internal.Scalar {
	s1 := s.copy()
	s2 := s.copy()
	s2.square()

	bytes := assert(scalar).scalar.Bytes()
	msbyte := getMSByte(bytes)
	msbit := getMSBit(bytes[msbyte])

	// First round over the most significant byte
	b := bytes[msbyte]
	for j := msbit - 1; j >= 0; j-- {
		bit := b & byte(1<<byte(j))
		if bit == 0 {
			s2.multiply(s1)
			s1.square()
		} else {
			s1.multiply(s2)
			s2.square()
		}
	}

	for i := msbyte - 1; i >= 0; i-- {
		b = bytes[i]
		for j := 7; j >= 0; j-- {
			bit := b & byte(1<<byte(j))
			if bit == 0 {
				s2.multiply(s1)
				s1.square()
			} else {
				s1.multiply(s2)
				s2.square()
			}
		}
	}

	if scalar.IsZero() {
		s1.One()
	} else {
		s2.One()
	}

	s.set(&s1.scalar)

	return s
}

// Invert sets the receiver to the scalar's modular inverse ( 1 / scalar ), and returns it.
func (s *Scalar) Invert() internal.Scalar {
	s.scalar.Invert(&s.scalar)
	return s
}

// Equal returns 1 if the scalars are equal, and 0 otherwise.
func (s *Scalar) Equal(scalar internal.Scalar) int {
	if scalar == nil {
		return 0
	}

	sc := assert(scalar)

	return s.scalar.Equal(&sc.scalar)
}

// LessOrEqual returns 1 if s <= scalar and 0 otherwise.
func (s *Scalar) LessOrEqual(scalar internal.Scalar) int {
	sc := assert(scalar)

	ienc := s.Encode()
	jenc := sc.Encode()

	i := len(ienc)
	if i != len(jenc) {
		panic(internal.ErrParamScalarLength)
	}

	var res bool

	for i--; i >= 0; i-- {
		res = res || (ienc[i] > jenc[i])
	}

	if res {
		return 0
	}

	return 1
}

// IsZero returns whether the scalar is 0.
func (s *Scalar) IsZero() bool {
	return s.scalar.Equal(ed.NewScalar()) == 1
}

// Set sets the receiver to the value of the argument scalar, and returns the receiver.
func (s *Scalar) Set(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s.Zero()
	}

	ec := assert(scalar)
	s.scalar = ec.scalar

	return s
}

// SetUInt64 sets s to i modulo the field order, and returns an error if one occurs.
func (s *Scalar) SetUInt64(i uint64) internal.Scalar {
	encoded := make([]byte, canonicalEncodingLength)
	binary.LittleEndian.PutUint64(encoded, i)

	if err := s.decodeScalar(encoded); err != nil {
		// This cannot happen, since any uint64 is smaller than the order.
		panic(fmt.Sprintf("unexpected decoding of uint64 scalar: %s", err))
	}

	return s
}

// UInt64 returns the uint64 representation of the scalar,
// or an error if its value is higher than the authorized limit for uint64.
func (s *Scalar) UInt64() (uint64, error) {
	b := s.scalar.Bytes()
	overflows := byte(0)

	for _, bx := range b[8:] {
		overflows |= bx
	}

	if overflows != 0 {
		return 0, internal.ErrUInt64TooBig
	}

	return binary.LittleEndian.Uint64(b[:8]), nil
}

// Copy returns a copy of the receiver.
func (s *Scalar) Copy() internal.Scalar {
	return &Scalar{*ed.NewScalar().Set(&s.scalar)}
}

// Encode returns the compressed byte encoding of the scalar.
func (s *Scalar) Encode() []byte {
	return s.scalar.Bytes()
}

// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
func (s *Scalar) Decode(in []byte) error {
	return s.decodeScalar(in)
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

func (s *Scalar) set(scalar *ed.Scalar) {
	s.scalar = *scalar
}

func (s *Scalar) multiply(scalar *Scalar) {
	s.scalar.Multiply(&s.scalar, &scalar.scalar)
}

func (s *Scalar) square() {
	s.scalar.Multiply(&s.scalar, &s.scalar)
}

func (s *Scalar) copy() *Scalar {
	return &Scalar{*ed.NewScalar().Set(&s.scalar)}
}

func (s *Scalar) decodeScalar(scalar []byte) error {
	if len(scalar) == 0 {
		return internal.ErrParamNilScalar
	}

	if len(scalar) != canonicalEncodingLength {
		return internal.ErrParamScalarLength
	}

	if _, err := s.scalar.SetCanonicalBytes(scalar); err != nil {
		return fmt.Errorf("%w", err)
	}

	return nil
}
