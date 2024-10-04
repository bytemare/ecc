// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package ecc_test

import (
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/bytemare/ecc"
)

var (
	errNoPanic        = errors.New("no panic")
	errNoPanicMessage = errors.New("panic but no message")
	errZeroLenDST     = errors.New("zero-length DST")
	errWrapGroup      = "%s: %w"
)

func hasPanic(f func()) (has bool, err error) {
	defer func() {
		var report any
		if report = recover(); report != nil {
			has = true
			err = fmt.Errorf("%v", report)
		}
	}()

	f()

	return has, err
}

// testPanic executes the function f with the expectation to recover from a panic. If no panic occurred or if the
// panic message is not the one expected, ExpectPanic returns an error.
func testPanic(s string, expectedError error, f func()) error {
	hasPanic, err := hasPanic(f)

	// if there was no panic
	if !hasPanic {
		return errNoPanic
	}

	// panic, and we don't expect a particular message
	if expectedError == nil {
		return nil
	}

	// panic, but the panic value is empty
	if err == nil {
		return errNoPanicMessage
	}

	// panic, but the panic value is not what we expected
	if err.Error() != expectedError.Error() {
		return fmt.Errorf("expected panic on %s with message %q, got %q", s, expectedError, err)
	}

	return nil
}

func decodeScalar(t *testing.T, g ecc.Group, input string) *ecc.Scalar {
	b, err := hex.DecodeString(input)
	if err != nil {
		t.Error(err)
	}

	s := g.NewScalar()
	if err := s.Decode(b); err != nil {
		t.Error(err)
	}

	return s
}

func decodeElement(t *testing.T, g ecc.Group, input string) *ecc.Element {
	b, err := hex.DecodeString(input)
	if err != nil {
		t.Error(err)
	}

	e := g.NewElement()
	if err = e.Decode(b); err != nil {
		t.Error(err)
	}

	return e
}
