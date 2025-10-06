// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package ristretto allows simple and abstracted operations in the Ristretto255 group.
package ristretto

import (
	"encoding/hex"
	"errors"
	"reflect"

	"github.com/gtank/ristretto255"

	"github.com/bytemare/ecc/internal"
)

// ErrDecodeElement is returned when decoding an invalid byte slice.
var ErrDecodeElement = errors.New("invalid ristretto255 element encoding")

// Element implements the Element interface for the Ristretto255 group element.
type Element struct {
	element ristretto255.Element
}

func checkElement(element internal.Element) *Element {
	if element == nil {
		panic(internal.ErrParamNilPoint)
	}

	ec, ok := element.(*Element)
	if !ok {
		panic(internal.WrongGroupError(reflect.TypeFor[*Element](), reflect.TypeOf(element)))
	}

	return ec
}

// Group returns the group's Identifier.
func (e *Element) Group() byte {
	return Identifier
}

// Base sets the element to the group's base point a.k.a. canonical generator.
func (e *Element) Base() internal.Element {
	e.element.Set(ristretto255.NewGeneratorElement())
	return e
}

// Identity sets the element to the point at infinity of the Group's underlying curve.
func (e *Element) Identity() internal.Element {
	e.element.Set(ristretto255.NewIdentityElement())
	return e
}

// Add sets the receiver to the sum of the input and the receiver, and returns the receiver.
func (e *Element) Add(element internal.Element) internal.Element {
	ec := checkElement(element)
	e.element.Add(&e.element, &ec.element)

	return e
}

// Double sets the receiver to its double, and returns it.
func (e *Element) Double() internal.Element {
	e.element.Add(&e.element, &e.element)
	return e
}

// Negate sets the receiver to its negation, and returns it.
func (e *Element) Negate() internal.Element {
	e.element.Negate(&e.element)
	return e
}

// Subtract subtracts the input from the receiver, and returns the receiver.
func (e *Element) Subtract(element internal.Element) internal.Element {
	ec := checkElement(element)
	e.element.Subtract(&e.element, &ec.element)

	return e
}

// Multiply sets the receiver to the scalar multiplication of the receiver with the given Scalar, and returns it.
func (e *Element) Multiply(scalar internal.Scalar) internal.Element {
	if scalar == nil {
		e.element.Set(ristretto255.NewIdentityElement())
		return e
	}

	sc := assert(scalar)

	// Optimization for multiplying the base point.
	if e.element.Equal(ristretto255.NewGeneratorElement()) == 1 {
		e.element.ScalarBaseMult(&sc.scalar)
	} else {
		e.element.ScalarMult(&sc.scalar, &e.element)
	}

	return e
}

// Equal returns 1 if the elements are equivalent, and 0 otherwise.
func (e *Element) Equal(element internal.Element) int {
	ec := checkElement(element)
	return e.element.Equal(&ec.element)
}

// IsIdentity returns whether the Element is the point at infinity of the Group's underlying curve.
func (e *Element) IsIdentity() bool {
	id := ristretto255.NewIdentityElement()
	return e.element.Equal(id) == 1
}

// Set sets the receiver to the value of the argument, and returns the receiver.
func (e *Element) Set(element internal.Element) internal.Element {
	if element == nil {
		return e.Identity()
	}

	ec, ok := element.(*Element)
	if !ok {
		panic(internal.WrongGroupError(reflect.TypeFor[*Element](), reflect.TypeOf(element)))
	}

	*e = *ec

	return e
}

// Copy returns a copy of the receiver.
func (e *Element) Copy() internal.Element {
	n, err := ristretto255.NewIdentityElement().SetCanonicalBytes(e.element.Bytes())
	if err != nil {
		// Canonical encodings are guaranteed. A failure indicates a regression in ristretto255.
		panic(err)
	}

	return &Element{element: *n}
}

// Encode returns the compressed byte encoding of the element.
func (e *Element) Encode() []byte {
	return e.element.Bytes()
}

// XCoordinate returns the encoded x coordinate of the element, which is the same as Encode().
func (e *Element) XCoordinate() []byte {
	return e.Encode()
}

// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
func (e *Element) Decode(data []byte) error {
	if len(data) == 0 {
		return ErrDecodeElement
	}

	res, err := ristretto255.NewIdentityElement().SetCanonicalBytes(data)
	if err != nil {
		return ErrDecodeElement
	}

	// superfluous identity check // todo: check if it's covered
	if res.Equal(ristretto255.NewIdentityElement()) == 1 {
		return errors.Join(ErrDecodeElement, internal.ErrIdentity)
	}

	e.element = *res

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
		return errors.Join(ErrDecodeElement, err)
	}

	return e.Decode(b)
}
