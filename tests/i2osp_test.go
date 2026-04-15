// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package ecc_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/bytemare/ecc/encoding"
)

type I2ospTest struct {
	encoded []byte
	value   int
	size    uint16
}

var I2OSPVectors = []I2ospTest{
	{
		[]byte{0}, 0, 1,
	},
	{
		[]byte{1}, 1, 1,
	},
	{
		[]byte{0xff}, 255, 1,
	},
	{
		[]byte{0x01, 0x00}, 256, 2,
	},
	{
		[]byte{0xff, 0xff}, 65535, 2,
	},
	{
		[]byte{0xff, 0xe3, 0xd0}, 16770000, 3,
	},
	{
		[]byte{0xff, 0xff, 0xe3, 0x80}, 4294960000, 4,
	},
}

// TestI2osp tests I2OSP against known vectors and boundary conditions.
func TestI2osp(t *testing.T) {
	for i, v := range I2OSPVectors {
		t.Run(fmt.Sprintf("%d - %d - %v", v.value, v.size, v.encoded), func(t *testing.T) {
			r := encoding.I2OSP(v.value, v.size)

			if !bytes.Equal(r, v.encoded) {
				t.Fatalf(
					"invalid encoding for %d. Expected '%s', got '%v'",
					i,
					hex.EncodeToString(v.encoded),
					hex.EncodeToString(r),
				)
			}
		})
	}

	length := 0

	expectPanic(t, "expected panic with with 0 length", encoding.ErrLengthNegativeOrZero, func() {
		_ = encoding.I2OSP(1, uint16(length))
	})

	length = 5

	expectPanic(t, "expected panic with length too big", encoding.ErrLengthTooBig, func() {
		_ = encoding.I2OSP(1, uint16(length))
	})

	tooLarge := 1 << 32
	length = 1

	expectPanic(t, "expected panic with exceeding value for the length", encoding.ErrInputLarge, func() {
		_ = encoding.I2OSP(tooLarge, uint16(length))
	})

	lengths := map[int]int{
		100:           1,
		1 << 8:        2,
		1 << 16:       3,
		(1 << 32) - 1: 4,
	}

	for k, v := range lengths {
		r := encoding.I2OSP(k, uint16(v))

		if len(r) != v {
			t.Fatalf("invalid length for %d. Expected '%d', got '%d' (%v)", k, v, len(r), r)
		}
	}
}
