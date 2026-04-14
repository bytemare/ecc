// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package nist

import "crypto"

type mapping[point nistECPoint[point]] struct {
	hashToCurve func(input, dst []byte) (point, error)
	mapToCurve  func(input, dst []byte) (point, error)
	hash        crypto.Hash
}

func (m *mapping[point]) setMapping(
	hash crypto.Hash,
	h2c func(input, dst []byte) (point, error),
	m2c func(input, dst []byte) (point, error),
) {
	m.hash = hash
	m.hashToCurve = h2c
	m.mapToCurve = m2c
}
