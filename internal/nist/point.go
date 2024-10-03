// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package nist

type nistECPoint[point any] interface {
	Add(p1, p2 point) point
	Negate(p point) point
	BytesCompressed() []byte
	BytesX() ([]byte, error)
	Double(p point) point
	ScalarBaseMult(scalar []byte) (point, error)
	ScalarMult(p point, scalar []byte) (point, error)
	Bytes() []byte
	Select(p1, p2 point, cond int) point
	Set(p point) point
	SetBytes(b []byte) (point, error)
	SetGenerator() point
}
