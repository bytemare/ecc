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
	"github.com/bytemare/ecc/debug"
	"github.com/bytemare/ecc/internal/edwards25519"
	"github.com/bytemare/ecc/internal/nist"
	"github.com/bytemare/ecc/internal/ristretto"
	"github.com/bytemare/ecc/internal/secp256k1"
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

func testDecodeBad(t *testing.T, group ecc.Group, s serde, bad []byte, expectedErrors ...error) {
	expectErrors(t, func() error { return s.Decode(bad) }, expectedErrors...)
	expectErrors(t, func() error { return s.UnmarshalBinary(bad) }, expectedErrors...)
	expectErrors(t, func() error { return s.DecodeHex(hex.EncodeToString(bad)) }, expectedErrors...)

	fakeJson := jsonSerDe{Group: group, Data: string(bad)}
	badJson, err := json.Marshal(fakeJson)
	if err != nil {
		t.Fatal(err)
	}

	expectErrors(t, func() error { return s.UnmarshalJSON(badJson) }, expectedErrors...)
}

func TestScalar_Encoding(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		g := group.group
		testDecodeEmpty(t, group.group.NewScalar().Random())
		for _, tester := range encodeTesters {
			if err := testScalarEncodings(g, tester); err != nil {
				t.Fatal(err)
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
				t.Fatal(err)
			}
		}
	})
}

func TestScalar_Decoding_Fails(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		g := group.group

		// Invalid length
		bad := []byte{0, 1}
		testDecodeBad(t, g, g.NewScalar(), bad, ecc.ErrDecodeScalar)

		// Decode a scalar higher than order
		bad = debug.BadScalarHigh(group.group)
		testDecodeBad(t, g, g.NewScalar(), bad, ecc.ErrDecodeScalar)
	})
}

func TestElement_Decoding_Fails(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		g := group.group

		var errMessage error
		switch group.group {
		case ecc.Ristretto255Sha512:
			errMessage = ristretto.ErrDecodeElement
		case ecc.P256Sha256:
			errMessage = nist.ErrDecodeElementP256
		case ecc.P384Sha384:
			errMessage = nist.ErrDecodeElementP384
		case ecc.P521Sha512:
			errMessage = nist.ErrDecodeElementP521
		case ecc.Edwards25519Sha512:
			errMessage = edwards25519.ErrDecodeElement
		case ecc.Secp256k1Sha256:
			errMessage = secp256k1.ErrDecodeElement
		}

		// off curve
		bad := debug.BadElementOffCurve(group.group)
		testDecodeBad(t, g, g.NewElement(), bad, ecc.ErrDecodeElement, errMessage)

		// bad encoding, e.g. sign
		bad = debug.BadElementEncoding(group.group)
		testDecodeBad(t, g, g.NewElement(), bad, ecc.ErrDecodeElement, errMessage)
	})
}

// jsonSerDe mirrors the current JSON object format emitted by Scalar/Element.
type jsonSerDe struct {
	Data  string    `json:"data"`
	Group ecc.Group `json:"group"`
}

func testDecodingHexFails(t *testing.T, thing1, thing2 serde, expectedError error) {
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
	} else if !errors.Is(err, expectedError) || !strings.Contains(err.Error(), "encoding/hex: invalid byte: U+005F '_'") {
		t.Fatalf("unexpected error: %q", err)
	}
}

func TestEncoding_Hex_Scalar_Fails(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		g := group.group
		scalar := g.NewScalar().Random()
		testDecodingHexFails(t, scalar, g.NewScalar(), ecc.ErrDecodeScalar)
	})
}

func TestEncoding_Hex_Element_Fails(t *testing.T) {
	testAllGroups(t, func(group *testGroup) {
		g := group.group
		scalar := g.NewScalar().Random()
		element := g.Base().Multiply(scalar)
		testDecodingHexFails(t, element, g.NewElement(), ecc.ErrDecodeElement)
	})
}
