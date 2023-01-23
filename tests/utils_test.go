// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package group_test

import (
	"bytes"
	"encoding"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

var (
	errNoPanic        = errors.New("no panic")
	errNoPanicMessage = errors.New("panic but no message")
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

type serde interface {
	Encode() []byte
	Decode(data []byte) error
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

func testEncoding(t *testing.T, thing1, thing2 serde) {
	encoded := thing1.Encode()
	marshalled, _ := thing1.MarshalBinary()

	if !bytes.Equal(encoded, marshalled) {
		t.Fatalf("Encode() and MarshalBinary() are expected to have the same output."+
			"\twant: %v\tgot : %v", encoded, marshalled)
	}

	if err := thing2.Decode(nil); err == nil {
		t.Fatal("expected error on Decode() with nil input")
	}

	if err := thing2.Decode(encoded); err != nil {
		t.Fatalf("Decode() failed on a valid encoding: %v. Value: %v", err, hex.EncodeToString(encoded))
	}

	if err := thing2.UnmarshalBinary(encoded); err != nil {
		t.Fatalf("UnmarshalBinary() failed on a valid encoding: %v", err)
	}
}

func TestEncoding(t *testing.T) {
	testAll(t, func(t *testing.T, group *testGroup) {
		g := group.group
		scalar := g.NewScalar().Random()
		testEncoding(t, scalar, g.NewScalar())

		scalar = g.NewScalar().Random()
		element := g.Base().Multiply(scalar)
		testEncoding(t, element, g.NewElement())
	})
}
