// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
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

	"github.com/bytemare/ecc/internal/ristretto"
)

type ristrettoH2gTestBytes struct {
	input, dst, encodedElement []byte
}

type ristrettoH2gTest struct {
	input          string
	dst            string
	encodedElement string
}

func (h *ristrettoH2gTest) decode() (*ristrettoH2gTestBytes, error) {
	b := &ristrettoH2gTestBytes{}
	var err error

	b.input, err = hex.DecodeString(h.input)
	if err != nil {
		return nil, err
	}

	b.dst, err = hex.DecodeString(h.dst)
	if err != nil {
		return nil, err
	}

	b.encodedElement, err = hex.DecodeString(h.encodedElement)
	if err != nil {
		return nil, err
	}

	return b, err
}

var ristrettoH2gTests = []ristrettoH2gTest{
	{
		input:          "68656c6c6f",
		dst:            "564f50524630362d48617368546f47726f75702d000001",
		encodedElement: "723c88cc59988d39889aa607b6696d423e7718a36d4825e0f940b3c3a534396a",
	},
	{
		input:          "776f726c64",
		dst:            "564f50524630362d48617368546f47726f75702d000001",
		encodedElement: "a47c0a13c42a26ab06e60d2e251ba591334a289f4fdfe3b17ed3321a9527f44c",
	},
}

func TestRistretto_HashToGroup(t *testing.T) {
	for i, test := range ristrettoH2gTests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			v, err := test.decode()
			if err != nil {
				t.Fatalf("%d : %v", i, err)
			}

			e := ristretto.Group{}.HashToGroup(v.input, v.dst)

			if !bytes.Equal(e.Encode(), v.encodedElement) {
				t.Fatalf(
					"Mappings do not match.\n\tExpected: %v\n\tActual: %v\n",
					hex.EncodeToString(v.encodedElement),
					e.Hex(),
				)
			}
		})
	}
}
