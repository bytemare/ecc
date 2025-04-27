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
	"fmt"
	"strings"
	"testing"

	"github.com/bytemare/ecc"
	"github.com/bytemare/ecc/internal"

	eccEncoding "github.com/bytemare/ecc/encoding"
)

func replaceStringInBytes(data []byte, old, new string) []byte {
	s := string(data)
	s = strings.Replace(s, old, new, 1)

	return []byte(s)
}

type jsonTesterBaddie struct {
	key, value, expectedError string
}

func testJSONBaddie(in any, baddie jsonTesterBaddie) error {
	data, err := json.Marshal(in)
	if err != nil {
		return err
	}

	data = replaceStringInBytes(data, baddie.key, baddie.value)

	_, err = eccEncoding.JSONReGetGroup(string(data))

	if len(baddie.expectedError) != 0 { // we're expecting an error
		if err == nil ||
			!strings.HasPrefix(err.Error(), baddie.expectedError) {
			return fmt.Errorf("expected error %q, got %q", baddie.expectedError, err)
		}
	} else {
		if err != nil {
			return fmt.Errorf("unexpected error %q", err)
		}
	}

	return nil
}

func jsonTester(badJSONErr string, in any) error {
	// JSON: bad json
	baddie := jsonTesterBaddie{
		key:           "\"group\"",
		value:         "bad",
		expectedError: "invalid character 'b' looking for beginning of object key string",
	}

	if err := testJSONBaddie(in, baddie); err != nil {
		// return err
	}

	// UnmarshallJSON: bad group
	baddie = jsonTesterBaddie{
		key:           "\"group\"",
		value:         "\"group\":2, \"oldGroup\"",
		expectedError: internal.ErrInvalidGroup.Error(),
	}

	if err := testJSONBaddie(in, baddie); err != nil {
		return err
	}

	// UnmarshallJSON: bad ciphersuite
	baddie = jsonTesterBaddie{
		key:           "\"group\"",
		value:         "\"group\":70, \"oldGroup\"",
		expectedError: internal.ErrInvalidGroup.Error(),
	}

	if err := testJSONBaddie(in, baddie); err != nil {
		return err
	}

	// UnmarshallJSON: bad ciphersuite
	baddie = jsonTesterBaddie{
		key:           "\"group\"",
		value:         "\"group\":-1, \"oldGroup\"",
		expectedError: badJSONErr,
	}

	if err := testJSONBaddie(in, baddie); err != nil {
		return err
	}

	// UnmarshallJSON: bad ciphersuite
	overflow := "9223372036854775808" // MaxInt64 + 1
	baddie = jsonTesterBaddie{
		key:           "\"group\"",
		value:         "\"group\":" + overflow + ", \"oldGroup\"",
		expectedError: "failed to read Group: strconv.Atoi: parsing \"9223372036854775808\": value out of range",
	}

	if err := testJSONBaddie(in, baddie); err != nil {
		return err
	}

	return nil
}

func TestJSONReGetGroup_BadString(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		test := struct {
			Group ecc.Group `json:"group"`
			Int   int       `json:"int"`
		}{
			Group: group.group,
			Int:   1,
		}

		// JSON: bad json
		errInvalidJSON := "invalid JSON encoding"
		if err := jsonTester(errInvalidJSON, test); err != nil {
			t.Fatal(err)
		}
	})
}
