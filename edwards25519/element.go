// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package edwards25519 wraps filippo.io/edwards25519 and exposes a simple prime-order group API with hash-to-curve.
package edwards25519

import (
	"fmt"

	"filippo.io/edwards25519"

	"github.com/bytemare/crypto/internal"
)

// Element represents an Edwards25519 point.
// It wraps an Edwards25519 implementation to leverage its optimized operations.
type Element struct {
	element *edwards25519.Point
}

// Add returns the sum of the Elements, and does not change the receiver.
func (e *Element) Add(element internal.Element) internal.Element {
	if element == nil {
		panic(internal.ErrParamNilPoint)
	}

	ele, ok := element.(*Element)
	if !ok {
		panic(internal.ErrCastElement)
	}

	return &Element{edwards25519.NewIdentityPoint().Add(e.element, ele.element)}
}

// Sub returns the difference between the Elements, and does not change the receiver.
func (e *Element) Sub(element internal.Element) internal.Element {
	if element == nil {
		panic(internal.ErrParamNilPoint)
	}

	ele, ok := element.(*Element)
	if !ok {
		panic(internal.ErrCastElement)
	}

	return &Element{edwards25519.NewIdentityPoint().Subtract(e.element, ele.element)}
}

// Mult returns the scalar multiplication of the receiver element with the given scalar.
func (e *Element) Mult(scalar internal.Scalar) internal.Element {
	if scalar == nil {
		panic(internal.ErrParamNilScalar)
	}

	sc, ok := scalar.(*Scalar)
	if !ok {
		panic(internal.ErrCastElement)
	}

	return &Element{edwards25519.NewIdentityPoint().ScalarMult(sc.scalar, e.element)}
}

// IsIdentity returns whether the element is the Group's identity element.
func (e *Element) IsIdentity() bool {
	id := edwards25519.NewIdentityPoint()
	return e.element.Equal(id) == 1
}

// Copy returns a copy of the element.
func (e *Element) Copy() internal.Element {
	n := edwards25519.NewIdentityPoint()
	if _, err := n.SetBytes(e.element.Bytes()); err != nil {
		panic(err)
	}

	return &Element{element: n}
}

// Decode decodes the input an sets the current element to its value, and returns it.
func (e *Element) Decode(in []byte) (internal.Element, error) {
	if len(in) == 0 {
		return nil, internal.ErrParamNilPoint
	}

	if _, err := e.element.SetBytes(in); err != nil {
		return nil, fmt.Errorf("decoding element : %w", err)
	}

	if e.IsIdentity() {
		return nil, internal.ErrIdentity
	}

	return e, nil
}

// Bytes returns the compressed byte encoding of the element.
func (e *Element) Bytes() []byte {
	return e.element.Bytes()
}