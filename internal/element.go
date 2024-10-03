// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package internal defines simple and abstract APIs to group Elements and Scalars.
package internal

// Element interface abstracts common operations on an Element in a prime-order Group.
type Element interface {
	// Group returns the group's Identifier.
	Group() byte

	// Base sets the element to the group's base point a.k.a. canonical generator.
	Base() Element

	// Identity sets the element to the point at infinity of the Group's underlying curve.
	Identity() Element

	// Add sets the receiver to the sum of the input and the receiver, and returns the receiver.
	Add(Element) Element

	// Double sets the receiver to its double, and returns it.
	Double() Element

	// Negate sets the receiver to its negation, and returns it.
	Negate() Element

	// Subtract subtracts the input from the receiver, and returns the receiver.
	Subtract(Element) Element

	// Multiply sets the receiver to the scalar multiplication of the receiver with the given Scalar, and returns it.
	Multiply(Scalar) Element

	// Equal returns 1 if the elements are equivalent, and 0 otherwise.
	Equal(Element) int

	// IsIdentity returns whether the Element is the point at infinity of the Group's underlying curve.
	IsIdentity() bool

	// Set sets the receiver to the value of the argument, and returns the receiver.
	Set(Element) Element

	// Copy returns a copy of the receiver.
	Copy() Element

	// Encode returns the compressed byte encoding of the element.
	Encode() []byte

	// XCoordinate returns the encoded x coordinate of the element.
	XCoordinate() []byte

	// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
	Decode(data []byte) error

	// Hex returns the fixed-sized hexadecimal encoding of e.
	Hex() string

	// DecodeHex sets e to the decoding of the hex encoded element.
	DecodeHex(h string) error
}
