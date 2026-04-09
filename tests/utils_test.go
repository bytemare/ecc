// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package ecc_test

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/bytemare/ecc"
	"github.com/bytemare/ecc/internal/field"
)

var (
	errNoPanic        = errors.New("no panic")
	errNoPanicMessage = errors.New("panic but no message")
)

// hasPanic runs f and recovers from a panic if any occurred, and returns whether it did and the panic message as an
// error.
func hasPanic(f func()) (has bool, err error) {
	defer func() {
		var report any
		if report = recover(); report != nil {
			has = true
			// Preserve the original error if the panic badValue is an error so that errors.Is / errors.As work
			if e, ok := report.(error); ok {
				err = e
			} else {
				// Fallback: format non-error panic values (string, etc.) as error
				err = fmt.Errorf("%v", report)
			}
		}
	}()

	f()

	return has, err
}

// expectPanic executes the function f with the expectation to recover from a panic. If no panic occurred or if the
// panic message is not the one expected, ExpectPanic returns an error.
func expectPanic(t *testing.T, s string, expectedError error, f func()) {
	t.Helper()
	hasPanic, err := hasPanic(f)

	// if there was no panic
	if !hasPanic {
		t.Fatal(errNoPanic)
	}

	// panic, and we don't expect a particular message
	if expectedError == nil {
		return
	}

	// panic, but the panic badValue is empty
	if err == nil {
		t.Fatal(errNoPanicMessage)
	}

	// panic, but the panic badValue is not what we expected
	if !errors.Is(err, expectedError) {
		t.Fatal(fmt.Errorf("expected panic on %s with message %q, got %q", s, expectedError, err))
	}

	return
}

func expectErrors(t *testing.T, f func() error, expected ...error) {
	t.Helper()
	if err := f(); err == nil {
		t.Fatal("expected error, got nil")
	} else {
		for _, e := range expected {
			if !errors.Is(err, e) {
				t.Fatalf("expected error %q not present in error %q", e, err)
			}
		}
	}
}

func decodeScalar(t *testing.T, g ecc.Group, input string) *ecc.Scalar {
	t.Helper()

	s := g.NewScalar()
	if err := s.DecodeHex(input); err != nil {
		t.Error(err)
	}

	return s
}

func decodeElement(t *testing.T, g ecc.Group, input string) *ecc.Element {
	t.Helper()

	e := g.NewElement()
	if err := e.DecodeHex(input); err != nil {
		t.Error(err)
	}

	return e
}

func testDecodeEmpty(t *testing.T, s serde) {
	if err := s.Decode(nil); err == nil {
		t.Fatal("expected error on Decode() with nil input")
	}

	if err := s.Decode([]byte{}); err == nil {
		t.Fatal("expected error on Decode() with empty input")
	}

	if err := s.(encoding.BinaryUnmarshaler).UnmarshalBinary(nil); err == nil {
		t.Fatal("expected error on UnmarshalBinary() with nil input")
	}

	if err := s.(encoding.BinaryUnmarshaler).UnmarshalBinary([]byte{}); err == nil {
		t.Fatal("expected error on UnmarshalBinary() with empty input")
	}

	if err := s.DecodeHex(""); err == nil {
		t.Fatal("expected error on empty string")
	}

	if err := json.Unmarshal(nil, s); err == nil {
		t.Fatal("expected error")
	}

	if err := json.Unmarshal([]byte{}, s); err == nil {
		t.Fatal("expected error")
	}
}

func TestFieldString2Int_Invalid(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()

	field.String2Int("not-a-number")
}
