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
	"encoding/hex"
	"fmt"
	"reflect"

	"filippo.io/nistec"

	"github.com/bytemare/ecc/internal"
)

const (
	p256CompressedEncodingLength = 33
	p384CompressedEncodingLength = 49
	p521CompressedEncodingLength = 67
)

// Element implements the Element interface for group elements over NIST curves.
type Element[Point nistECPoint[Point]] struct {
	p   Point
	new func() Point
}

func checkElement[Point nistECPoint[Point]](element internal.Element) *Element[Point] {
	if element == nil {
		panic(internal.ErrParamNilPoint)
	}

	ec, ok := element.(*Element[Point])
	if !ok {
		panic(internal.ErrCastElement)
	}

	return ec
}

// Group returns the group's Identifier.
func (e *Element[Point]) Group() byte {
	switch any(e.p).(type) {
	case *nistec.P256Point:
		return IdentifierP256
	case *nistec.P384Point:
		return IdentifierP384
	case *nistec.P521Point:
		return IdentifierP521
	}

	panic(fmt.Sprintf("invalid point type %v", reflect.TypeFor[Point]()))
}

// Base sets the element to the group's base point a.k.a. canonical generator.
func (e *Element[Point]) Base() internal.Element {
	e.p.SetGenerator()
	return e
}

// Identity sets the element to the point at infinity of the Group's underlying curve.
func (e *Element[Point]) Identity() internal.Element {
	e.p = e.new()
	return e
}

// Add sets the receiver to the sum of the input and the receiver, and returns the receiver.
func (e *Element[Point]) Add(element internal.Element) internal.Element {
	ec := checkElement[Point](element)
	e.p.Add(e.p, ec.p)

	return e
}

// Double sets the receiver to its double, and returns it.
func (e *Element[Point]) Double() internal.Element {
	e.p.Double(e.p)
	return e
}

// negateSmall returns the compressed byte encoding of the negated element e with 5 allocations in 13000 ns/op.
func (e *Element[Point]) negateSmall() []byte {
	enc := e.p.BytesCompressed()

	if e.IsIdentity() {
		return enc
	}

	switch enc[0] {
	case 2:
		enc[0] = 0x03
	case 3:
		enc[0] = 0x02
	default:
		panic("invalid encoding header")
	}

	return enc
}

// Negate sets the receiver to its negation, and returns it.
func (e *Element[P]) Negate() internal.Element {
	_, err := e.p.SetBytes(e.negateSmall())
	if err != nil {
		panic(err)
	}

	return e
}

// Subtract subtracts the input from the receiver, and returns the receiver.
func (e *Element[P]) Subtract(element internal.Element) internal.Element {
	ec := checkElement[P](element).negateSmall()

	p, err := e.new().SetBytes(ec)
	if err != nil {
		panic(err)
	}

	e.p.Add(e.p, p)

	return e
}

func (e *Element[P]) isGenerator() bool {
	b := e.new().SetGenerator().BytesCompressed()
	return subtle.ConstantTimeCompare(b, e.Encode()) == 1
}

// Multiply sets the receiver to the scalar multiplication of the receiver with the given Scalar, and returns it.
func (e *Element[P]) Multiply(scalar internal.Scalar) internal.Element {
	if e.isGenerator() {
		if _, err := e.p.ScalarBaseMult(scalar.Encode()); err != nil {
			panic(err)
		}
	} else {
		if _, err := e.p.ScalarMult(e.p, scalar.Encode()); err != nil {
			panic(err)
		}
	}

	return e
}

// Equal returns 1 if the elements are equivalent, and 0 otherwise.
func (e *Element[Point]) Equal(element internal.Element) int {
	ec := checkElement[Point](element)

	return subtle.ConstantTimeCompare(e.p.Bytes(), ec.p.Bytes())
}

// IsIdentity returns whether the Element is the point at infinity of the Group's underlying curve.
func (e *Element[P]) IsIdentity() bool {
	b := e.p.BytesCompressed()
	i := e.new().BytesCompressed()

	return subtle.ConstantTimeCompare(b, i) == 1
}

// Set sets the receiver to the value of the argument, and returns the receiver.
func (e *Element[P]) Set(element internal.Element) internal.Element {
	if element == nil {
		return e.Identity()
	}

	ec, ok := element.(*Element[P])
	if !ok {
		panic(internal.ErrCastElement)
	}

	e.p.Set(ec.p)

	return e
}

// Copy returns a copy of the receiver.
func (e *Element[P]) Copy() internal.Element {
	return &Element[P]{
		p:   e.new().Set(e.p),
		new: e.new,
	}
}

// Encode returns the compressed byte encoding of the element.
func (e *Element[P]) Encode() []byte {
	if e.IsIdentity() {
		return encodeInfinity(e)
	}

	return e.p.BytesCompressed()
}

func encodeInfinity[Point nistECPoint[Point]](element *Element[Point]) []byte {
	var encodedLength int

	_, err := element.p.BytesX()
	switch err.Error()[:4] {
	case "P256":
		encodedLength = p256CompressedEncodingLength
	case "P384":
		encodedLength = p384CompressedEncodingLength
	case "P521":
		encodedLength = p521CompressedEncodingLength
	default:
		panic("could not infer nist curve")
	}

	return make([]byte, encodedLength)
}

// XCoordinate returns the encoded x coordinate of the element.
func (e *Element[P]) XCoordinate() []byte {
	if e.IsIdentity() {
		inf := encodeInfinity(e)
		return inf[:len(inf)-1]
	}

	b, err := e.p.BytesX()
	if err != nil {
		panic("encountered infinity point failing IsIdentity()")
	}

	return b
}

// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
func (e *Element[P]) Decode(data []byte) error {
	if _, err := e.p.SetBytes(data); err != nil {
		return fmt.Errorf("%w", err)
	}

	return nil
}

// Hex returns the fixed-sized hexadecimal encoding of e.
func (e *Element[P]) Hex() string {
	return hex.EncodeToString(e.Encode())
}

// DecodeHex sets e to the decoding of the hex encoded element.
func (e *Element[P]) DecodeHex(h string) error {
	b, err := hex.DecodeString(h)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	return e.Decode(b)
}
