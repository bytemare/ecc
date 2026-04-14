// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package hash2curve

import (
	"crypto"
	"encoding/binary"
	"errors"
	"hash"
	"log/slog"
	"math"

	"github.com/bytemare/ecc/encoding"

	xHash "github.com/bytemare/hash"
)

const (
	minLength            = 0
	recommendedMinLength = 16

	dstMaxLength  = math.MaxUint8
	dstLongPrefix = "H2C-OVERSIZE-DST-"

	xmdMaxDigestSize = 64
	xmdMaxBlockSize  = 128
	xmdMaxDSTPrime   = dstMaxLength + 1
)

var (
	// ErrZeroLengthDST is returned when a group could not be decoded.
	ErrZeroLengthDST = errors.New("the provided domain separation tag is empty")

	// ErrLengthTooHigh is returned when the requested output length is too large for the hash function or the DST.
	ErrLengthTooHigh = errors.New("requested byte length is too high")

	// ErrXMDOutputSizeTooBig is returned when the provided hash function returns too many bytes.
	ErrXMDOutputSizeTooBig = errors.New("the hash function's output size is too big")

	errXOFHighOutput = errors.New("XOF dst hashing is too long")
)

// CheckDST returns an error for invalid DST lengths.
func CheckDST(dst []byte) error {
	// placeholder for warning about short DST, we don't enforce minimum length, yet.
	if len(dst) < recommendedMinLength {
		if len(dst) == minLength {
			slog.Debug("empty dst")
			return ErrZeroLengthDST
		}
	}

	return nil
}

// ExpandXMD expands the input and dst using the given fixed length hash function. It implements
// expand_message_xmd as specified in RFC 9380 section 5.3.1.
// - dst MUST be non-nil, longer than 0 and lower than 256. It's recommended that DST is at least 16 bytes long.
// - length must be a positive integer lower than 255 * (size of digest).
func ExpandXMD(id crypto.Hash, input, dst []byte, length uint) ([]byte, error) {
	out := make([]byte, length)

	if err := ExpandXMDTo(id, out, input, dst); err != nil {
		return nil, err
	}

	return out, nil
}

// ExpandXMDTo does that same than [ExpandXMD] but writes the output to the provided slice.
// The output slice must be of the desired length, and an error is returned if the length is too high for the hash function or the DST.
func ExpandXMDTo(id crypto.Hash, out, input, dst []byte) error {
	dst, err := VetDSTXMD(id, dst)
	if err != nil {
		return err
	}

	var dstPrimeArray [xmdMaxDSTPrime]byte
	dstPrimeLen := copy(dstPrimeArray[:], dst)
	dstPrimeArray[dstPrimeLen] = byte(len(dst))
	dstPrime := dstPrimeArray[:dstPrimeLen+1]

	// ell indicates how many hash chunks we need.
	length := len(out)
	b := id.Size()
	ell := (length + b - 1) / b // equivalent to math.Ceil(float64(length) / float64(b))
	if ell > 255 || length > math.MaxUint16 || len(dst) > math.MaxUint8 {
		return ErrLengthTooHigh
	}

	var lib [2]byte
	var zeroByte [1]byte

	binary.BigEndian.PutUint16(lib[:], uint16(length))
	h := id.New()
	blockSize := h.BlockSize()

	var b0, b1, zPad []byte

	if h.Size() <= xmdMaxDigestSize && blockSize <= xmdMaxBlockSize {
		var zPadBuf [xmdMaxBlockSize]byte
		zPad = zPadBuf[:blockSize]

		var buf0 [xmdMaxDigestSize]byte
		b0 = buf0[:]

		var buf1 [xmdMaxDigestSize]byte
		b1 = buf1[:]
	} else {
		zPad = make([]byte, blockSize)
		b0 = make([]byte, h.Size())
		b1 = make([]byte, h.Size())
	}

	b0 = hashTo(h, b0, zPad, input, lib[:], zeroByte[:], dstPrime)
	b1 = hashTo(h, b1, b0, []byte{1}, dstPrime)
	offset := copy(out, b1[:id.Size()])

	// ell < 2 means the hash function's output length is sufficient.
	if ell < 2 {
		return nil
	}

	// Only if we need to expand the hash output, we keep on hashing.
	xmd(h, out, b0[:], b1[:], dstPrime, ell, offset)

	return nil
}

// xmd expands the message digest until it reaches the desirable length.
func xmd(h hash.Hash, out, b0, b1, dstPrime []byte, ell, offset int) {
	var bi []byte
	if h.Size() <= xmdMaxDigestSize && h.BlockSize() <= xmdMaxBlockSize {
		var bufi [xmdMaxDigestSize]byte
		bi = bufi[:]
	} else {
		bi = make([]byte, h.Size())
	}

	copy(bi[:h.Size()], b1[:h.Size()])

	for i := 2; i <= ell; i++ {
		for j := 0; j < h.Size(); j++ {
			bi[j] ^= b0[j]
		}

		bi = hashTo(h, bi[:], bi[:h.Size()], []byte{byte(i)}, dstPrime)
		offset += copy(out[offset:], bi[:h.Size()])
	}
}

// VerifyDSTXMD returns an error if the DST or hash function are not compliant.
func VerifyDSTXMD(id crypto.Hash, dst []byte) error {
	if err := CheckDST(dst); err != nil {
		return err
	}

	if len(dst) <= dstMaxLength {
		return nil
	}

	// The DST is too long, so we need to hash it down under 256 bytes.
	// If the hash function's output size is too big, we can't shorten the DST, and we return an error.
	if id.Size() > dstMaxLength {
		return ErrXMDOutputSizeTooBig
	}

	return nil
}

// VetDSTXMD computes a shorter tag for dst if the tag length exceeds 255 bytes.
// If the DST or the hash function are not compliant, an error is returned.
func VetDSTXMD(id crypto.Hash, dst []byte) ([]byte, error) {
	if err := VerifyDSTXMD(id, dst); err != nil {
		return nil, err
	}

	if len(dst) <= dstMaxLength {
		return dst, nil
	}

	// If the tag length exceeds 255 bytes, compute a shorter tag by hashing it
	out := make([]byte, id.Size())
	return hashTo(id.New(), out, []byte(dstLongPrefix), dst), nil
}

func hashTo(h hash.Hash, out []byte, input ...[]byte) []byte {
	h.Reset()

	for _, i := range input {
		_, _ = h.Write(i)
	}

	return h.Sum(out[:0])
}

// ExpandXOF expands the input and dst using the given extendable output hash function. It implements
// expand_message_xof as specified in RFC 9380 section 5.3.2.
// - dst MUST be non-nil and its length longer than 0. It's recommended that DST is at least 16 bytes long.
// - length must be a positive integer higher than 32.
func ExpandXOF(ext *xHash.ExtendableHash, input, dst []byte, length uint) ([]byte, error) {
	dst, err := VetDSTXOF(ext, dst)
	if err != nil {
		return nil, err
	}

	if length > math.MaxUint16 {
		return nil, ErrLengthTooHigh
	}

	len2o := encoding.I2OSP(int(length), 2)
	dstLen2o := encoding.I2OSP(len(dst), 1)

	ext.SetOutputSize(int(length))

	return ext.Hash(input, len2o, dst, dstLen2o), nil
}

// VerifyDSTXOF returns an error if the DST or hash function are not compliant.
func VerifyDSTXOF(x *xHash.ExtendableHash, dst []byte) error {
	if err := CheckDST(dst); err != nil {
		return err
	}

	_, err := checkXOFSecurityLevel(x)
	if err != nil {
		return err
	}

	return nil
}

// VetDSTXOF computes a shorter tag for dst if the tag length exceeds 255 bytes.
// If the DST or the hash function are not compliant, an error is returned.
func VetDSTXOF(x *xHash.ExtendableHash, dst []byte) ([]byte, error) {
	if err := VerifyDSTXOF(x, dst); err != nil {
		return nil, err
	}

	if len(dst) <= dstMaxLength {
		return dst, nil
	}

	size, err := checkXOFSecurityLevel(x)
	if err != nil {
		return nil, err
	}

	x.SetOutputSize(size)

	return x.Hash([]byte(dstLongPrefix), dst), nil
}

// checkXOFSecurityLevel returns the desired output length to shorten the DST, or returns an error
// if the XOFs security level is too high for the expected output length.
func checkXOFSecurityLevel(x *xHash.ExtendableHash) (int, error) {
	k := x.Algorithm().SecurityLevel()

	size := int(math.Ceil(float64(2*k) / float64(8)))
	if size > x.Size()*8 {
		return 0, errXOFHighOutput
	}

	return size, nil
}
