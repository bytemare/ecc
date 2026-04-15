// SPDX-License-Group: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package ecc_test

import (
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"

	"github.com/bytemare/ecc"
)

const hashToCurveVectorsFileLocation = "vectors/h2c"

type h2cVectors struct {
	Ciphersuite string `json:"ciphersuite"`
	Mode        string
	Curve       string      `json:"curve"`
	Dst         string      `json:"dst"`
	Vectors     []h2cVector `json:"vectors"`
	group       ecc.Group
}

type h2cVector struct {
	*h2cVectors
	P struct {
		X string `json:"x"`
		Y string `json:"y"`
	} `json:"P"`
	Q0 struct {
		X string `json:"x"`
		Y string `json:"y"`
	} `json:"Q0"`
	Q1 struct {
		X string `json:"x"`
		Y string `json:"y"`
	} `json:"Q1"`
	Msg string   `json:"msg"`
	U   []string `json:"u"`
}

func vectorToBig(x, y string) (*big.Int, *big.Int) {
	xb, ok := new(big.Int).SetString(x, 0)
	if !ok {
		panic("invalid x")
	}

	yb, ok := new(big.Int).SetString(y, 0)
	if !ok {
		panic("invalid y")
	}

	return xb, yb
}

func affineToEdwardsFromStrings(t *testing.T, a string) *field.Element {
	aBytes, err := hex.DecodeString(a[2:])
	if err != nil {
		t.Fatal(err)
	}

	// reverse
	for i, j := 0, len(aBytes)-1; j > i; i++ {
		aBytes[i], aBytes[j] = aBytes[j], aBytes[i]
		j--
	}

	u := &field.Element{}
	if _, err := u.SetBytes(aBytes); err != nil {
		t.Fatal(err)
	}

	return u
}

func affineToEdwards(x, y *field.Element) *edwards25519.Point {
	t := new(field.Element).Multiply(x, y)

	p, err := new(edwards25519.Point).SetExtendedCoordinates(x, y, new(field.Element).One(), t)
	if err != nil {
		panic(err)
	}

	return p
}

func vectorToEdwards25519(t *testing.T, x, y string) *edwards25519.Point {
	u, v := affineToEdwardsFromStrings(t, x), affineToEdwardsFromStrings(t, y)
	return affineToEdwards(u, v)
}

func vectorToSecp256k1(x, y string) []byte {
	var output [33]byte

	yb, _ := hex.DecodeString(y[2:])
	yint := new(big.Int).SetBytes(yb)
	output[0] = byte(2 | yint.Bit(0)&1)

	xb, _ := hex.DecodeString(x[2:])
	copy(output[1:], xb)

	return output[:]
}

func (v *h2cVectors) runCiphersuite(t *testing.T) {
	for _, vector := range v.Vectors {
		vector.h2cVectors = v
		t.Run(v.Ciphersuite, vector.run)
	}
}

func ecFromGroup(g ecc.Group) elliptic.Curve {
	switch g {
	case ecc.P256Sha256:
		return elliptic.P256()
	case ecc.P384Sha384:
		return elliptic.P384()
	case ecc.P521Sha512:
		return elliptic.P521()
	default:
		panic("invalid nist group")
	}
}

func (v *h2cVector) run(t *testing.T) {
	var expectedElement string

	// Decode the vector coordinates into the canonical encoding
	switch v.group {
	case ecc.P256Sha256, ecc.P384Sha384, ecc.P521Sha512:
		e := ecFromGroup(v.group)
		x, y := vectorToBig(v.P.X, v.P.Y)
		expectedElement = hex.EncodeToString(elliptic.MarshalCompressed(e, x, y))
	case ecc.Edwards25519Sha512:
		p := vectorToEdwards25519(t, v.P.X, v.P.Y)
		expectedElement = hex.EncodeToString(p.Bytes())
	case ecc.Secp256k1Sha256:
		expectedElement = hex.EncodeToString(vectorToSecp256k1(v.P.X, v.P.Y))
	default:
		t.Fatal("ciphersuite not recognized")
	}

	// Verify HashTo and EncodeTo
	v.verifyHashingToElement(t, expectedElement)
}

func (v *h2cVector) verifyElement(p *ecc.Element, function, expected string) error {
	p2 := v.group.NewElement()
	if err := p2.DecodeHex(expected); err != nil {
		return err
	}

	if !p.Equal(p2) {
		return fmt.Errorf("Unexpected %s output.\n\tExpected %q\n\tgot %q",
			function,
			expected,
			p.Hex(),
		)
	}

	return nil
}

func (v *h2cVector) verifyHashingToElement(t *testing.T, expectedElement string) {
	var p *ecc.Element
	var err error
	var function string

	switch v.Mode {
	case "RO_":
		function = "HashToGroup"

		p, err = v.group.HashToGroup([]byte(v.Msg), []byte(v.Dst))
		if err != nil {
			t.Fatal(err)
		}
	case "NU_":
		function = "EncodeToGroup"

		p, err = v.group.EncodeToGroup([]byte(v.Msg), []byte(v.Dst))
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("ciphersuite not recognized")
	}

	if err := v.verifyElement(p, function, expectedElement); err != nil {
		t.Fatal(err)
	}
}

// for a given ciphersuite string, return the corresponding group identifier.
func getGroup(ciphersuite string) (ecc.Group, bool) {
	for _, group := range testTable {
		if group.hashToCurve.h2c == ciphersuite || group.hashToCurve.e2c == ciphersuite {
			return group.group, true
		}
	}

	return 0, false
}

// TestHashToCurveVectors tests the bundled hash-to-curve vector files against the public group APIs.
func TestHashToCurveVectors(t *testing.T) {
	if err := filepath.Walk(hashToCurveVectorsFileLocation,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			file, errOpen := os.Open(path)
			if errOpen != nil {
				t.Fatal(errOpen)
			}

			defer func(file *os.File) {
				err := file.Close()
				if err != nil {
					t.Logf("error closing file: %v", err)
				}
			}(file)

			val, errRead := io.ReadAll(file)
			if errRead != nil {
				t.Fatal(errRead)
			}

			var v h2cVectors
			errJSON := json.Unmarshal(val, &v)
			if errJSON != nil {
				t.Fatal(errJSON)
			}

			group, ok := getGroup(v.Ciphersuite)
			if !ok {
				t.Logf("Unsupported ciphersuite. Got %q", v.Ciphersuite)
				return nil
			}

			v.group = group
			v.Mode = v.Ciphersuite[len(v.Ciphersuite)-3:]
			t.Run(v.Ciphersuite, v.runCiphersuite)

			return nil
		}); err != nil {
		t.Fatalf("error opening vector files: %v", err)
	}
}
