// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package ecc_test

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/bytemare/ecc"
	"github.com/bytemare/ecc/internal"
)

func replaceStringInBytes(data []byte, old, new string) []byte {
	s := string(data)
	s = strings.Replace(s, old, new, 1)

	return []byte(s)
}

type jsonTesterBaddie struct {
	receiver      serde
	expectedError error
	name          string
	key           string
	badValue      string
}

func testJSONBaddie(t *testing.T, baddie jsonTesterBaddie) {
	data, err := json.Marshal(baddie.receiver)
	if err != nil {
		t.Fatal(err)
	}

	// Replace the good value with the bad value that should trigger an error
	data = replaceStringInBytes(data, baddie.key, baddie.badValue)
	err = json.Unmarshal(data, baddie.receiver)

	if err == nil {
		t.Fatal("expected an error but got none")
	}

	var (
		syntaxErr *json.SyntaxError
		typeErr   *json.UnmarshalTypeError
	)
	if errors.As(err, &syntaxErr) || errors.As(err, &typeErr) {
		if !strings.Contains(err.Error(), baddie.expectedError.Error()) {
			t.Log(string(data))
			t.Fatalf("expected error %q, got %q", baddie.expectedError, err)
		}

		return
	}

	expectErrors(t, func() error { return err }, baddie.expectedError)
}

func TestDecode_Group_Fail(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		// Mismatched group should fail.
		var bad ecc.Group
		switch group.group {
		case ecc.Ristretto255Sha512:
			bad = ecc.P256Sha256
		default:
			bad = ecc.Ristretto255Sha512
		}

		tests := []jsonTesterBaddie{
			// Different group than receiver
			{
				receiver:      group.group.NewScalar(),
				name:          "Scalar - different group",
				key:           "\"group\"",
				badValue:      "\"group\":" + strconv.Itoa(int(bad)) + ", \"oldGroup\"",
				expectedError: internal.ErrInvalidGroup,
			},

			// Different group than receiver
			{
				receiver:      group.group.NewElement(),
				name:          "Element - different group",
				key:           "\"group\"",
				badValue:      "\"group\":" + strconv.Itoa(int(bad)) + ", \"oldGroup\"",
				expectedError: internal.ErrInvalidGroup,
			},

			// JSON: bad json
			{
				receiver:      group.group.NewScalar(),
				name:          "Scalar - bad json",
				key:           "\"group\"",
				badValue:      "bad",
				expectedError: errors.New("invalid character 'b' looking for beginning of object key string"),
			},

			// JSON: bad json
			{
				receiver:      group.group.NewElement(),
				name:          "Element - bad json",
				key:           "\"group\"",
				badValue:      "bad",
				expectedError: errors.New("invalid character 'b' looking for beginning of object key string"),
			},

			// UnmarshallJSON: bad group
			{
				receiver:      group.group.NewScalar(),
				name:          "Scalar - bad group",
				key:           "\"group\"",
				badValue:      "\"group\":2, \"oldGroup\"",
				expectedError: internal.ErrInvalidGroup,
			},

			// UnmarshallJSON: bad group
			{
				receiver:      group.group.NewElement(),
				name:          "Element - bad group",
				key:           "\"group\"",
				badValue:      "\"group\":2, \"oldGroup\"",
				expectedError: internal.ErrInvalidGroup,
			},

			// UnmarshallJSON: bad ciphersuite
			{
				receiver:      group.group.NewScalar(),
				name:          "Scalar - bad ciphersuite",
				key:           "\"group\"",
				badValue:      "\"group\":70, \"oldGroup\"",
				expectedError: internal.ErrInvalidGroup,
			},

			// UnmarshallJSON: bad ciphersuite
			{
				receiver:      group.group.NewElement(),
				name:          "Element - bad ciphersuite",
				key:           "\"group\"",
				badValue:      "\"group\":70, \"oldGroup\"",
				expectedError: internal.ErrInvalidGroup,
			},

			// UnmarshallJSON: bad ciphersuite
			{
				receiver: group.group.NewScalar(),
				name:     "Scalar - bad group (negative)",
				key:      "\"group\"",
				badValue: "\"group\":-1, \"oldGroup\"",
				expectedError: errors.New(
					"json: cannot unmarshal number -1 into Go struct field jsonScalar.group of type ecc.Group",
				),
			},

			// UnmarshallJSON: bad ciphersuite
			{
				receiver: group.group.NewElement(),
				name:     "Element - bad group (negative)",
				key:      "\"group\"",
				badValue: "\"group\":-1, \"oldGroup\"",
				expectedError: errors.New(
					"json: cannot unmarshal number -1 into Go struct field jsonElement.group of type ecc.Group",
				),
			},

			// UnmarshallJSON: bad ciphersuite
			{
				receiver: group.group.NewScalar(),
				name:     "Scalar - bad group (too big)",
				key:      "\"group\"",
				badValue: "\"group\":" + "9223372036854775808" + ", \"oldGroup\"", // MaxInt64 + 1
				expectedError: errors.New(
					"json: cannot unmarshal number 9223372036854775808 into Go struct field jsonScalar.group of type ecc.Group",
				),
			},

			// UnmarshallJSON: bad ciphersuite
			{
				receiver: group.group.NewElement(),
				name:     "Element - bad group (too big)",
				key:      "\"group\"",
				badValue: "\"group\":" + "9223372036854775808" + ", \"oldGroup\"", // MaxInt64 + 1
				expectedError: errors.New(
					"json: cannot unmarshal number 9223372036854775808 into Go struct field jsonElement.group of type ecc.Group",
				),
			},

			// UnmarshallJSON: bad value
			{
				receiver:      group.group.NewScalar(),
				name:          "Scalar - bad value",
				key:           "\"data\"",
				badValue:      "\"data\":" + "123^" + ", \"oldData\"", // MaxInt64 + 1
				expectedError: errors.New("invalid character"),
			},

			// UnmarshallJSON: bad value
			{
				receiver:      group.group.NewElement(),
				name:          "Element - bad value",
				key:           "\"data\"",
				badValue:      "\"data\":" + "123}" + ", \"oldData\"", // MaxInt64 + 1
				expectedError: errors.New("invalid character"),
			},
		}

		for _, baddie := range tests {
			t.Run(baddie.name, func(t *testing.T) {
				testJSONBaddie(t, baddie)
			})
		}
	})
}
