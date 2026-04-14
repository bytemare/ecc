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
	"crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/bytemare/hash"

	"github.com/bytemare/ecc/encoding"
	"github.com/bytemare/ecc/hash2curve"
)

const expandMessageVectorFiles = "vectors/expand"

func TestExpander_ZeroDST(t *testing.T) {
	msg := []byte("test")
	zeroDST := []byte("")
	length := uint(32)

	defer func() {
		recover()
	}()

	xmd1 := crypto.SHA256

	expectErrors(t, func() error {
		_, err := hash2curve.ExpandXMD(xmd1, msg, zeroDST, length)
		return err
	}, hash2curve.ErrZeroLengthDST)

	xof1 := hash.SHAKE128

	expectErrors(t, func() error {
		_, err := hash2curve.ExpandXOF(xof1.GetXOF(), msg, zeroDST, length)
		return err
	}, hash2curve.ErrZeroLengthDST)
}

func TestExpander_LongDST(t *testing.T) {
	msg := []byte("test")
	longDST := []byte(
		"a255_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	)
	length := uint(32)

	xmd1 := crypto.SHA256
	if _, err := hash2curve.ExpandXMD(xmd1, msg, longDST, length); err != nil {
		t.Fatalf("expandXMD failed: %v", err)
	}

	xof1 := hash.SHAKE128
	if _, err := hash2curve.ExpandXOF(xof1.GetXOF(), msg, longDST, length); err != nil {
		t.Fatalf("expandXMD failed: %v", err)
	}
}

func TestExpander_XMDHighLength(t *testing.T) {
	defer func() {
		recover()
	}()

	length := uint(9000)

	expectErrors(t, func() error {
		_, err := hash2curve.ExpandXMD(crypto.SHA256, []byte("input"), []byte("dst"), length)
		return err
	}, hash2curve.ErrLengthTooHigh)
}

func TestExpander_XOFHighLength(t *testing.T) {
	defer func() {
		recover()
	}()

	length := uint(math.MaxUint16 + 1)

	expectErrors(t, func() error {
		_, err := hash2curve.ExpandXOF(hash.SHAKE128.GetXOF(), []byte("input"), []byte("dst"), length)
		return err
	}, hash2curve.ErrLengthTooHigh)
}

type expanderVector struct {
	dstPrime     []byte
	msg          []byte
	msgPrime     []byte
	uniformBytes []byte
	lenInBytes   uint
}

type expanderVectorStrings struct {
	DSTPrime     string `json:"DST_prime"`
	LenInBytes   string `json:"len_in_bytes"`
	Msg          string `json:"msg"`
	MsgPrime     string `json:"msg_prime"`
	UniformBytes string `json:"uniform_bytes"`
}

func (vs *expanderVectorStrings) decode() (*expanderVector, error) {
	v := &expanderVector{}
	var err error

	v.dstPrime, err = hex.DecodeString(vs.DSTPrime)
	if err != nil {
		return nil, err
	}

	length, err := strconv.ParseUint(vs.LenInBytes[2:], 16, 32)
	if err != nil {
		return nil, err
	}

	v.lenInBytes = uint(length)
	v.msg = []byte(vs.Msg)

	v.msgPrime, err = hex.DecodeString(vs.MsgPrime)
	if err != nil {
		return nil, err
	}

	v.uniformBytes, err = hex.DecodeString(vs.UniformBytes)
	if err != nil {
		return nil, err
	}

	return v, err
}

type expanderSet struct {
	DST   string                  `json:"DST"`
	Hash  string                  `json:"hash"`
	Name  string                  `json:"name"`
	Tests []expanderVectorStrings `json:"tests"`
	K     int                     `json:"k"`
}

func mapHash(name string) hash.Hash {
	switch name {
	case "SHA256":
		return hash.SHA256
	case "SHA512":
		return hash.SHA512
	case "SHAKE128":
		return hash.SHAKE128
	case "SHAKE256":
		return hash.SHAKE256
	default:
		panic("unknown hash type")
		return 0
	}
}

func mapXMD(name string) crypto.Hash {
	switch name {
	case "SHA256":
		return crypto.SHA256
	case "SHA512":
		return crypto.SHA512
	default:
		panic(nil)
	}
}

func mapXOF(name string) hash.Hash {
	switch name {
	case "SHAKE128":
		return hash.SHAKE128
	case "SHAKE256":
		return hash.SHAKE256
	default:
		panic(nil)
	}
}

func isXMD(id string) bool {
	return id == "SHA256" || id == "SHA512"
}

func concatenate(input ...[]byte) []byte {
	length := 0
	for _, b := range input {
		length += len(b)
	}

	buf := make([]byte, 0, length)

	for _, in := range input {
		buf = append(buf, in...)
	}

	return buf
}

// dstPrime length-suffix-encodes dst.
func dstPrime(dst []byte) []byte {
	return append(dst, encoding.I2OSP(len(dst), 1)[0])
}

func msgPrime(h hash.Hash, input, dst []byte, length uint) []byte {
	lib := encoding.I2OSP(int(length), 2)
	dstPrime := dstPrime(dst)

	if h.Type() == hash.ExtendableOutputFunction {
		return concatenate(input, lib, dstPrime)
	}

	zPad := make([]byte, h.BlockSize())
	zeroByte := []byte{0}

	return concatenate(zPad, input, lib, zeroByte, dstPrime)
}

func (s *expanderSet) run(t *testing.T) {
	var dst []byte
	var err error

	if isXMD(s.Hash) {
		h := mapXMD(s.Hash)
		dst, err = hash2curve.VetDSTXMD(h, []byte(s.DST))
		if err != nil {
			t.Fatalf("invalid DST: %v", err)
		}
	} else {
		h := mapXOF(s.Hash)
		dst, err = hash2curve.VetDSTXOF(h.GetXOF(), []byte(s.DST))
		if err != nil {
			t.Fatalf("invalid DST: %v", err)
		}
	}

	id := mapHash(s.Hash)

	for i, test := range s.Tests {
		t.Run(fmt.Sprintf("%s : Vector %d", s.Hash, i), func(t *testing.T) {
			v, err := test.decode()
			if err != nil {
				t.Fatalf("%d : %v", i, err)
			}

			dstPrime := dstPrime(dst)
			if !bytes.Equal(v.dstPrime, dstPrime) {
				t.Fatalf("%d : invalid DST prime.\ngot : %v\nwant: %v", i, dstPrime, v.dstPrime)
			}

			msgPrime := msgPrime(id, v.msg, dst, v.lenInBytes)
			if !bytes.Equal(v.msgPrime, msgPrime) {
				t.Fatalf("%d : invalid msg prime.", i)
			}

			var x []byte
			if isXMD(s.Hash) {
				x, err = hash2curve.ExpandXMD(mapXMD(s.Hash), v.msg, dst, v.lenInBytes)
				if err != nil {
					t.Fatalf("%d : %v", i, err)
				}
			} else {
				x, err = hash2curve.ExpandXOF(mapXOF(s.Hash).GetXOF(), v.msg, dst, v.lenInBytes)
				if err != nil {
					t.Fatalf("%d : %v", i, err)
				}
			}

			if !bytes.Equal(v.uniformBytes, x) {
				t.Fatalf(
					"%d : invalid hash (length %d vs %d). expected %q, got %q",
					i,
					len(x),
					v.lenInBytes,
					v.uniformBytes,
					x,
				)
			}
		})
	}
}

func TestExpander_Vectors(t *testing.T) {
	if err := filepath.Walk(expandMessageVectorFiles,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			file, errOpen := os.Open(path)
			if errOpen != nil {
				return errOpen
			}

			defer func(file *os.File) {
				err := file.Close()
				if err != nil {
				}
			}(file)

			val, errRead := io.ReadAll(file)
			if errRead != nil {
				return errRead
			}

			var s expanderSet
			errJSON := json.Unmarshal(val, &s)
			if errJSON != nil {
				return errJSON
			}

			s.run(t)

			return nil
		}); err != nil {
		t.Fatalf("error opening expanderSet expanderVectorStrings: %v", err)
	}
}
