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
	"encoding"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/bytemare/ecc"

	eccEncoding "github.com/bytemare/ecc/encoding"
)

type serde interface {
	Encode() []byte
	Decode(data []byte) error
	Hex() string
	DecodeHex(h string) error
	MarshalJSON() ([]byte, error)
	UnmarshalJSON(data []byte) error
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

type (
	byteEncoder    func() ([]byte, error)
	byteDecoder    func([]byte) error
	makeEncodeTest func(t *encodingTest) *encodingTest
)

var encodeTesters = []makeEncodeTest{
	encodeTest,
	binaryTest,
	hexTest,
	jsonTest,
}

func toEncoder(s serde) byteEncoder {
	return func() ([]byte, error) {
		return s.Encode(), nil
	}
}

func hexToEncoder(s serde) byteEncoder {
	return func() ([]byte, error) {
		return []byte(s.Hex()), nil
	}
}

func hexToDecoder(s serde) byteDecoder {
	return func(d []byte) error {
		return s.DecodeHex(string(d))
	}
}

type encodingTest struct {
	source, receiver serde
	sourceEncoder    byteEncoder
	receiverDecoder  byteDecoder
	receiverEncoder  byteEncoder
}

func newEncodingTest(source, receiver serde) *encodingTest {
	return &encodingTest{source: source, receiver: receiver}
}

func encodeTest(t *encodingTest) *encodingTest {
	t.sourceEncoder = toEncoder(t.source)
	t.receiverDecoder = t.receiver.Decode
	t.receiverEncoder = toEncoder(t.receiver)

	return t
}

func binaryTest(t *encodingTest) *encodingTest {
	t.sourceEncoder = t.source.MarshalBinary
	t.receiverDecoder = t.receiver.UnmarshalBinary
	t.receiverEncoder = t.receiver.MarshalBinary

	return t
}

func hexTest(t *encodingTest) *encodingTest {
	t.sourceEncoder = hexToEncoder(t.source)
	t.receiverDecoder = hexToDecoder(t.receiver)
	t.receiverEncoder = hexToEncoder(t.receiver)

	return t
}

func jsonTest(t *encodingTest) *encodingTest {
	t.sourceEncoder = t.source.MarshalJSON
	t.receiverDecoder = t.receiver.UnmarshalJSON
	t.receiverEncoder = t.receiver.MarshalJSON

	return t
}

func (t *encodingTest) run() error {
	encoded, err := t.sourceEncoder()
	if err != nil {
		return err
	}

	if err = t.receiverDecoder(encoded); err != nil {
		return fmt.Errorf("%v. Value: %v", err, hex.EncodeToString(encoded))
	}

	encoded2, err := t.receiverEncoder()
	if err != nil {
		return err
	}

	if !bytes.Equal(encoded, encoded2) {
		return fmt.Errorf("re-decoding of same source does not yield the same results.\n\twant: %v\n\tgot : %s\n",
			encoded, encoded2)
	}

	return nil
}

func testScalarEncodings(g ecc.Group, f makeEncodeTest) error {
	source, receiver := g.NewScalar().Random(), g.NewScalar()
	t := newEncodingTest(source, receiver)

	if err := f(t).run(); err != nil {
		return err
	}

	if !source.Equal(receiver) {
		return errors.New(errExpectedEquality)
	}

	return nil
}

func testElementEncodings(g ecc.Group, f makeEncodeTest) error {
	source, receiver := g.Base(), g.NewElement()
	t := newEncodingTest(source, receiver)

	if err := f(t).run(); err != nil {
		return err
	}

	if !source.Equal(receiver) {
		return errors.New(errExpectedEquality)
	}

	return nil
}

func TestScalar_Encoding(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		g := group.group
		testDecodeEmpty(t, group.group.NewScalar().Random())
		for _, tester := range encodeTesters {
			if err := testScalarEncodings(g, tester); err != nil {
				t.Fatal()
			}
		}
	})
}

func TestElement_Encoding(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		g := group.group
		testDecodeEmpty(t, group.group.Base())
		for _, tester := range encodeTesters {
			if err := testElementEncodings(g, tester); err != nil {
				t.Fatal()
			}
		}
	})
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

func testDecodingHexFails(t *testing.T, thing1, thing2 serde) {
	// empty string
	if err := thing2.DecodeHex(""); err == nil {
		t.Fatal("expected error on empty string")
	}

	// malformed string
	hexed := thing1.Hex()
	malformed := []rune(hexed)
	malformed[0] = []rune("_")[0]

	if err := thing2.DecodeHex(string(malformed)); err == nil {
		t.Fatal("expected error on malformed string")
	} else if !strings.HasSuffix(err.Error(), "DecodeHex: encoding/hex: invalid byte: U+005F '_'") {
		t.Fatalf("unexpected error: %q", err)
	}
}

func TestEncoding_Hex_Fails(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		g := group.group
		scalar := g.NewScalar().Random()
		element := g.Base().Multiply(scalar)

		// Hex fails
		testDecodingHexFails(t, scalar, g.NewScalar())
		testDecodingHexFails(t, element, g.NewElement())

		// Doesn't yield the same decoded result
		scalar = g.NewScalar().Random()
		s := g.NewScalar()
		if err := s.DecodeHex(scalar.Hex()); err != nil {
			t.Fatalf("unexpected error on valid encoding: %s", err)
		}

		if !s.Equal(scalar) {
			t.Fatal(errExpectedEquality)
		}

		element = g.Base().Multiply(scalar)
		e := g.NewElement()
		if err := e.DecodeHex(element.Hex()); err != nil {
			t.Fatalf("unexpected error on valid encoding: %s", err)
		}

		if !e.Equal(element) {
			t.Fatal(errExpectedEquality)
		}
	})
}

func TestJSONReGetGroup(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		test := struct {
			Group ecc.Group `json:"group"`
			Int   int       `json:"int"`
		}{
			Group: group.group,
			Int:   1,
		}

		enc, err := json.Marshal(test)
		if err != nil {
			t.Fatal(err)
		}

		g, err := eccEncoding.JSONReGetGroup(string(enc))
		if err != nil {
			t.Fatal(err)
		}

		if g != group.group {
			t.Fatal(errExpectedEquality)
		}
	})
}
