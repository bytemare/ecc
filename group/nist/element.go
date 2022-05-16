// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package old

import (
	"github.com/bytemare/crypto/group/internal"
	nist "github.com/bytemare/crypto/group/old/internal"
)

// Point implements the Point interface for group elements over NIST curves.
type Point struct {
	group *nist.Group
	point *nist.Point
}

func (p *Point) newPoint(point *nist.Point) *Point {
	return &Point{p.group, point}
}

// Add returns the sum of the Elements, and does not change the receiver.
func (p *Point) Add(element internal.Element) internal.Element {
	if element == nil {
		panic(internal.ErrParamNilPoint)
	}

	e, ok := element.(*Point)
	if !ok {
		panic(internal.ErrCastElement)
	}

	return p.newPoint(p.group.NewPoint().Add(p.point, e.point))
}

// Sub returns the difference between the Elements, and does not change the receiver.
func (p *Point) Sub(element internal.Element) internal.Element {
	if element == nil {
		panic(internal.ErrParamNilPoint)
	}

	ele, ok := element.(*Point)
	if !ok {
		panic(internal.ErrCastElement)
	}

	return p.newPoint(p.group.NewPoint().Sub(p.point, ele.point))
}

// Mult returns the scalar multiplication of the receiver element with the given scalar, and does not change the receiver.
func (p *Point) Mult(scalar internal.Scalar) internal.Element {
	if scalar == nil {
		panic(internal.ErrParamNilScalar)
	}

	sc, ok := scalar.(*Scalar)
	if !ok {
		panic(internal.ErrCastElement)
	}

	return p.newPoint(p.group.NewPoint().Mult(sc.scalar, p.point))
}

// InvertMult returns the scalar multiplication of the receiver element with the inverse of the given scalar, and does not change the receiver.
func (p *Point) InvertMult(scalar internal.Scalar) internal.Element {
	if scalar == nil {
		panic(internal.ErrParamNilScalar)
	}

	return p.Mult(scalar.Invert())
}

// IsIdentity returns whether the element is the Group's identity element.
func (p *Point) IsIdentity() bool {
	return p.point.IsIdentity()
}

// Copy returns a copy of the element.
func (p *Point) Copy() internal.Element {
	return p.newPoint(p.point.Copy())
}

// Decode sets p to the value of the decoded input, and returns p.
func (p *Point) Decode(in []byte) (internal.Element, error) {
	_, err := p.point.Decode(in)
	if err != nil {
		return nil, err
	}

	return p, nil
}

// Bytes returns the compressed byte encoding of the element.
func (p *Point) Bytes() []byte {
	return p.point.Bytes()
}
