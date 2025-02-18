// SPDX-License-Identifier: MIT
//
// Copyright (C)2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in theg
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secp256k1

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/bytemare/secp256k1"

	"github.com/bytemare/ecc/internal"
)

var errIdentityEncoding = errors.New("invalid secp256k1 encoding: invalid point encoding")

// Element implements the Element interface for the Secp256k1 group element.
type Element struct {
	element *secp256k1.Element
}

// newElement returns a new element set to the point at infinity.
func newElement() *Element {
	return &Element{element: secp256k1.NewElement()}
}

func assertElement(element internal.Element) *Element {
	if element == nil {
		panic(internal.ErrParamNilPoint)
	}

	ec, ok := element.(*Element)
	if !ok {
		panic(internal.ErrCastElement)
	}

	return ec
}

// Group returns the group's Identifier.
func (e *Element) Group() byte {
	return Identifier
}

// Base sets the element to the group's base point a.k.a. canonical generator.
func (e *Element) Base() internal.Element {
	e.element.Base()
	return e
}

// Identity sets the element to the point at infinity of the Group's underlying curve.
func (e *Element) Identity() internal.Element {
	e.element.Identity()
	return e
}

// Add sets the receiver to the sum of the input and the receiver, and returns the receiver.
func (e *Element) Add(element internal.Element) internal.Element {
	q := assertElement(element)
	e.element.Add(q.element)

	return e
}

// Double sets the receiver to its double, and returns it.
func (e *Element) Double() internal.Element {
	e.element.Double()
	return e
}

// Negate sets the receiver to its negation, and returns it.
func (e *Element) Negate() internal.Element {
	e.element.Negate()
	return e
}

// Subtract subtracts the input from the receiver, and returns the receiver.
func (e *Element) Subtract(element internal.Element) internal.Element {
	q := assertElement(element)
	e.element.Subtract(q.element)

	return e
}

// Multiply sets the receiver to the scalar multiplication of the receiver with the given Scalar, and returns it.
func (e *Element) Multiply(scalar internal.Scalar) internal.Element {
	s := assert(scalar)
	e.element.Multiply(s.scalar)

	return e
}

// Equal returns 1 if the elements are equivalent, and 0 otherwise.
func (e *Element) Equal(element internal.Element) int {
	q := assertElement(element)
	return e.element.Equal(q.element)
}

// IsIdentity returns whether the Element is the point at infinity of the Group's underlying curve.
func (e *Element) IsIdentity() bool {
	return e.element.IsIdentity()
}

// Set sets the receiver to the value of the argument, and returns the receiver.
func (e *Element) Set(element internal.Element) internal.Element {
	if element == nil {
		return e.Identity()
	}

	q := assertElement(element)
	e.element.Set(q.element)

	return e
}

// Copy returns a copy of the receiver.
func (e *Element) Copy() internal.Element {
	return &Element{element: e.element.Copy()}
}

// Encode returns the compressed byte encoding of the element.
func (e *Element) Encode() []byte {
	zero := make([]byte, 33)
	enc := e.element.Encode()

	if e.IsIdentity() {
		return zero
	}

	return enc
}

// XCoordinate returns the encoded x coordinate of the element, which is the same as Encode().
func (e *Element) XCoordinate() []byte {
	return e.element.XCoordinate()
}

// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
func (e *Element) Decode(data []byte) error {
	if len(data) != 33 {
		return errIdentityEncoding
	}

	if err := e.element.Decode(data); err != nil {
		return fmt.Errorf("invalid secp256k1 encoding: %w", err)
	}

	return nil
}

// Hex returns the fixed-sized hexadecimal encoding of e.
func (e *Element) Hex() string {
	return hex.EncodeToString(e.Encode())
}

// DecodeHex sets e to the decoding of the hex encoded element.
func (e *Element) DecodeHex(h string) error {
	b, err := hex.DecodeString(h)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	return e.Decode(b)
}
