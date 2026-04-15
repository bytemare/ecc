// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package nist

import (
	"crypto"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
	"reflect"

	"github.com/bytemare/ecc/hash2curve"
	"github.com/bytemare/ecc/internal"

	cryptorand "crypto/rand"
	cryptosubtle "crypto/subtle"
)

const scalarMaxLimbs = 9

type scalarParams struct {
	order              [scalarMaxLimbs]uint64
	two64Mont          [scalarMaxLimbs]uint64
	minusOneMont       [scalarMaxLimbs]uint64
	oneMont            [scalarMaxLimbs]uint64
	rr                 [scalarMaxLimbs]uint64
	reductionLength    int
	n0inv              uint64
	limbs              int
	hashToScalarLength uint
	hash               crypto.Hash
	length             int
	orderBytes         [66]byte
	minusTwoBytes      [66]byte
	zeroPadReduction   bool
	identifier         byte
}

// The NIST scalar parameter tables are static so unused curves do not pay
// constructor work during package initialization.
var (
	p256ScalarParams = &scalarParams{
		hash:               crypto.SHA256,
		identifier:         IdentifierP256,
		length:             32,
		reductionLength:    32,
		hashToScalarLength: 48,
		limbs:              4,
		zeroPadReduction:   false,
		n0inv:              0xccd1c8aaee00bc4f,
		order: [scalarMaxLimbs]uint64{
			0xf3b9cac2fc632551, 0xbce6faada7179e84, 0xffffffffffffffff,
			0xffffffff00000000,
		},
		rr: [scalarMaxLimbs]uint64{
			0x83244c95be79eea2, 0x4699799c49bd6fa6, 0x2845b2392b6bec59,
			0x66e12d94f3d95620,
		},
		oneMont: [scalarMaxLimbs]uint64{
			0x0c46353d039cdaaf, 0x4319055258e8617b, 0x0000000000000000,
			0x00000000ffffffff,
		},
		minusOneMont: [scalarMaxLimbs]uint64{
			0xe7739585f8c64aa2, 0x79cdf55b4e2f3d09, 0xffffffffffffffff,
			0xfffffffe00000001,
		},
		two64Mont: [scalarMaxLimbs]uint64{
			0xf756a571fc632551, 0x22159165b6faae70, 0x431905529c0166cd,
			0xfffffffe00000001,
		},
		orderBytes: [66]byte{
			0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
			0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
		},
		minusTwoBytes: [66]byte{
			0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
			0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x4f,
		},
	}

	p384ScalarParams = &scalarParams{
		hash:               crypto.SHA384,
		identifier:         IdentifierP384,
		length:             48,
		reductionLength:    48,
		hashToScalarLength: 72,
		limbs:              6,
		zeroPadReduction:   false,
		n0inv:              0x6ed46089e88fdc45,
		order: [scalarMaxLimbs]uint64{
			0xecec196accc52973, 0x581a0db248b0a77a, 0xc7634d81f4372ddf,
			0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
		},
		rr: [scalarMaxLimbs]uint64{
			0x2d319b2419b409a9, 0xff3d81e5df1aa419, 0xbc3e483afcb82947,
			0xd40d49174aab1cc5, 0x3fb05b7a28266895, 0x0c84ee012b39bf21,
		},
		oneMont: [scalarMaxLimbs]uint64{
			0x1313e695333ad68d, 0xa7e5f24db74f5885, 0x389cb27e0bc8d220,
		},
		minusOneMont: [scalarMaxLimbs]uint64{
			0xd9d832d5998a52e6, 0xb0341b6491614ef5, 0x8ec69b03e86e5bbe,
			0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
		},
		two64Mont: [scalarMaxLimbs]uint64{
			0x0000000000000000, 0x1313e695333ad68d, 0xa7e5f24db74f5885,
			0x389cb27e0bc8d220,
		},
		orderBytes: [66]byte{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2,
			0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73,
		},
		minusTwoBytes: [66]byte{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2,
			0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x71,
		},
	}

	p521ScalarParams = &scalarParams{
		hash:               crypto.SHA512,
		identifier:         IdentifierP521,
		length:             66,
		reductionLength:    64,
		hashToScalarLength: 98,
		limbs:              9,
		zeroPadReduction:   true,
		n0inv:              0x1d2f5ccd79a995c7,
		order: [scalarMaxLimbs]uint64{
			0xbb6fb71e91386409, 0x3bb5c9b8899c47ae, 0x7fcc0148f709a5d0,
			0x51868783bf2f966b, 0xfffffffffffffffa, 0xffffffffffffffff,
			0xffffffffffffffff, 0xffffffffffffffff, 0x00000000000001ff,
		},
		rr: [scalarMaxLimbs]uint64{
			0x137cd04dcf15dd04, 0xf707badce5547ea3, 0x12a78d38794573ff,
			0xd3721ef557f75e06, 0xdd6e23d82e49c7db, 0xcff3d142b7756e3e,
			0x5bcc6d61a8e567bc, 0x2d8e03d1492d0d45, 0x000000000000003d,
		},
		oneMont: [scalarMaxLimbs]uint64{
			0xfb80000000000000, 0x28a2482470b763cd, 0x17e2251b23bb31dc,
			0xca4019ff5b847b2d, 0x02d73cbc3e206834,
		},
		minusOneMont: [scalarMaxLimbs]uint64{
			0xbfefb71e91386409, 0x1313819418e4e3e0, 0x67e9dc2dd34e73f4,
			0x87466d8463ab1b3e, 0xfd28c343c1df97c5, 0xffffffffffffffff,
			0xffffffffffffffff, 0xffffffffffffffff, 0x00000000000001ff,
		},
		two64Mont: [scalarMaxLimbs]uint64{
			0x0000000000000000, 0xfb80000000000000, 0x28a2482470b763cd,
			0x17e2251b23bb31dc, 0xca4019ff5b847b2d, 0x02d73cbc3e206834,
		},
		orderBytes: [66]byte{
			0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfa, 0x51, 0x86,
			0x87, 0x83, 0xbf, 0x2f, 0x96, 0x6b, 0x7f, 0xcc, 0x01, 0x48, 0xf7, 0x09,
			0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c, 0x47, 0xae, 0xbb, 0x6f,
			0xb7, 0x1e, 0x91, 0x38, 0x64, 0x09,
		},
		minusTwoBytes: [66]byte{
			0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfa, 0x51, 0x86,
			0x87, 0x83, 0xbf, 0x2f, 0x96, 0x6b, 0x7f, 0xcc, 0x01, 0x48, 0xf7, 0x09,
			0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c, 0x47, 0xae, 0xbb, 0x6f,
			0xb7, 0x1e, 0x91, 0x38, 0x64, 0x07,
		},
	}
)

// Scalar implements the Scalar interface for group scalars.
type Scalar struct {
	params *scalarParams
	x      [scalarMaxLimbs]uint64
}

func newScalar(params *scalarParams) *Scalar {
	return &Scalar{params: params}
}

func hashToScalar(params *scalarParams, input, dst []byte) (internal.Scalar, error) {
	length := int(params.hashToScalarLength)
	var uniform [98]byte // 98 is the highest value we would use, for P521.

	// Pre-allocate a larger buffer but slice it to length. This spares a dedicated allocation.
	if err := hash2curve.ExpandXMDTo(params.hash, uniform[:length], input, dst); err != nil {
		return nil, err
	}

	s := newScalar(params)
	s.reduceBytes(uniform[:length])

	return s, nil
}

func (s *Scalar) assert(scalar internal.Scalar) *Scalar {
	sc, ok := scalar.(*Scalar)
	if !ok {
		panic(internal.WrongGroupError(reflect.TypeFor[*Scalar](), reflect.TypeOf(scalar)))
	}

	if sc.params != s.params {
		panic(internal.ErrWrongField)
	}

	return sc
}

// Group returns the group's Identifier.
func (s *Scalar) Group() byte {
	return s.params.identifier
}

// Zero sets s to 0, and returns it.
func (s *Scalar) Zero() internal.Scalar {
	clearWords(&s.x)
	return s
}

// One sets s to 1, and returns it.
func (s *Scalar) One() internal.Scalar {
	s.x = s.params.oneMont
	return s
}

// MinusOne sets the scalar to order-1, and returns it.
func (s *Scalar) MinusOne() internal.Scalar {
	s.x = s.params.minusOneMont
	return s
}

// Random sets s to a new random scalar and returns it.
// The random source is crypto/rand, and this functions is guaranteed to return a non-zero scalar.
func (s *Scalar) Random() internal.Scalar {
	buf := make([]byte, s.params.length)
	for {
		// We use rejection sampling instead of reducing wide input.
		_, _ = cryptorand.Read(buf)
		if err := s.Decode(buf); err == nil && !s.IsZero() {
			return s
		}
	}
}

// Add sets the receiver to the sum of the input and the receiver, and returns the receiver.
func (s *Scalar) Add(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s
	}

	sc := s.assert(scalar)
	addMontgomery(s.params, &s.x, &s.x, &sc.x)
	return s
}

// Subtract subtracts the input from the receiver, and returns the receiver.
func (s *Scalar) Subtract(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s
	}

	sc := s.assert(scalar)
	subMontgomery(s.params, &s.x, &s.x, &sc.x)

	return s
}

// Multiply multiplies the receiver with the input, and returns the receiver.
func (s *Scalar) Multiply(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s.Zero()
	}

	sc := s.assert(scalar)
	montgomeryMul(s.params, &s.x, &s.x, &sc.x)

	return s
}

// Pow sets s to s**scalar modulo the group order, and returns s. If scalar is nil, it returns 1.
func (s *Scalar) Pow(scalar internal.Scalar) internal.Scalar {
	if scalar == nil || scalar.IsZero() {
		return s.One()
	}

	sc := s.assert(scalar)
	s.pow(sc.Encode())

	return s
}

// Invert sets the receiver to its modular inverse ( 1 / s ), and returns it.
func (s *Scalar) Invert() internal.Scalar {
	// TODO: isn't there a more efficient trick to invert rather than doing this?
	s.pow(s.params.minusTwoBytes[:s.params.length])
	return s
}

// Equal returns 1 if the scalars are equal, and 0 otherwise.
func (s *Scalar) Equal(scalar internal.Scalar) int {
	if scalar == nil {
		return 0
	}

	sc := s.assert(scalar)
	var diff uint64
	for i := 0; i < s.params.limbs; i++ {
		diff |= s.x[i] ^ sc.x[i]
	}

	return cryptosubtle.ConstantTimeEq(int32(diff>>32), 0) & cryptosubtle.ConstantTimeEq(int32(diff), 0)
}

// LessOrEqual returns 1 if s <= scalar, and 0 otherwise.
func (s *Scalar) LessOrEqual(scalar internal.Scalar) int {
	sc := s.assert(scalar)
	var left, right [scalarMaxLimbs]uint64
	s.params.fromMontgomery(&left, &s.x)
	sc.params.fromMontgomery(&right, &sc.x)

	return lessOrEqualNormalLimbs(&left, &right, s.params.limbs)
}

// IsZero returns whether the scalar is 0.
func (s *Scalar) IsZero() bool {
	var acc uint64

	for i := range s.params.limbs {
		acc |= s.x[i]
	}

	return acc == 0
}

// Set sets the receiver to the value of the argument scalar, and returns the receiver.
func (s *Scalar) Set(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s.Zero()
	}

	sc := s.assert(scalar)
	s.x = sc.x

	return s
}

// SetUInt64 sets s to i modulo the field order, and returns an error if one occurs.
func (s *Scalar) SetUInt64(i uint64) internal.Scalar {
	var normal [scalarMaxLimbs]uint64
	normal[0] = i
	s.params.toMontgomery(&s.x, &normal)

	return s
}

// UInt64 returns the uint64 representation of the scalar,
// or an error if its value is higher than the authorized limit for uint64.
func (s *Scalar) UInt64() (uint64, error) {
	var normal [scalarMaxLimbs]uint64
	s.params.fromMontgomery(&normal, &s.x)

	var overflow uint64
	for i := 1; i < s.params.limbs; i++ {
		overflow |= normal[i]
	}

	if overflow != 0 {
		return 0, internal.ErrUInt64TooBig
	}

	return normal[0], nil
}

// Copy returns a copy of the Scalar.
func (s *Scalar) Copy() internal.Scalar {
	return new(*s)
}

// Encode returns the compressed byte encoding of the scalar.
func (s *Scalar) Encode() []byte {
	var normal [scalarMaxLimbs]uint64
	s.params.fromMontgomery(&normal, &s.x)
	out := make([]byte, s.params.length)
	encodeLimbsBigEndian(out, &normal, s.params.limbs)

	return out
}

// Decode sets s to a big-endian byte decoding of x.
// If x is not a canonical encoding of s, Decode returns an error.
func (s *Scalar) Decode(data []byte) error {
	if len(data) != s.params.length {
		return internal.ErrParamScalarLength
	}

	var normal [scalarMaxLimbs]uint64
	parseBigEndianToLimbs(data, &normal)

	if !lessThanLimbs(&normal, &s.params.order, s.params.limbs) {
		return internal.ErrParamScalarInvalidEncoding
	}

	s.params.toMontgomery(&s.x, &normal)

	return nil
}

// DecodeWithReduction sets s to x modulo the group order. If x is nil or
// not of the correct input length, DecodeWithReduction returns an error.
func (s *Scalar) DecodeWithReduction(data []byte) error {
	if len(data) != s.params.reductionLength {
		return internal.ErrParamInvalidInputLength
	}

	if s.params.zeroPadReduction {
		buf := make([]byte, s.params.length)
		copy(buf[s.params.length-len(data):], data)
		return s.Decode(buf)
	}

	s.reduceBytes(data)

	return nil
}

// Hex returns the fixed-sized hexadecimal encoding of s.
func (s *Scalar) Hex() string {
	return hex.EncodeToString(s.Encode())
}

// DecodeHex sets s to the decoding of the hex encoded scalar.
func (s *Scalar) DecodeHex(h string) error {
	b, err := hex.DecodeString(h)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	return s.Decode(b)
}

func (s *Scalar) pow(exponent []byte) {
	base := s.x
	result := s.params.oneMont
	var squared, multiplied [scalarMaxLimbs]uint64

	for _, bt := range exponent {
		for bit := 7; bit >= 0; bit-- {
			montgomeryMul(s.params, &squared, &result, &result)
			montgomeryMul(s.params, &multiplied, &squared, &base)
			selectWords(&result, &multiplied, &squared, int((bt>>uint(bit))&1), s.params.limbs)
		}
	}

	s.x = result
}

func (s *Scalar) reduceBytes(input []byte) {
	clearWords(&s.x)
	if len(input) == 0 {
		return
	}

	remaining := input
	if rem := len(remaining) % 8; rem != 0 {
		var chunk [scalarMaxLimbs]uint64
		chunk[0] = decodeWord(remaining[:rem])
		s.params.toMontgomery(&s.x, &chunk)
		remaining = remaining[rem:]
	}

	for len(remaining) > 0 {
		var chunk [scalarMaxLimbs]uint64
		var chunkMont, tmp [scalarMaxLimbs]uint64
		chunk[0] = binary.BigEndian.Uint64(remaining[:8])
		s.params.toMontgomery(&chunkMont, &chunk)
		montgomeryMul(s.params, &tmp, &s.x, &s.params.two64Mont)
		addMontgomery(s.params, &s.x, &tmp, &chunkMont)
		remaining = remaining[8:]
	}
}

func clearWords(x *[scalarMaxLimbs]uint64) {
	clear(x[:])
}

func decodeWord(in []byte) uint64 {
	var out uint64

	for _, b := range in {
		out = (out << 8) | uint64(b)
	}

	return out
}

func parseBigEndianToLimbs(in []byte, out *[scalarMaxLimbs]uint64) {
	clearWords(out)
	remaining := len(in)
	for i := 0; i < scalarMaxLimbs && remaining > 0; i++ {
		start := max(remaining-8, 0)
		out[i] = decodeWord(in[start:remaining])
		remaining = start
	}
}

func encodeLimbsBigEndian(out []byte, x *[scalarMaxLimbs]uint64, limbs int) {
	var tmp [scalarMaxLimbs * 8]byte

	for i := range limbs {
		start := len(tmp) - 8*(i+1)
		binary.BigEndian.PutUint64(tmp[start:start+8], x[i])
	}

	copy(out, tmp[len(tmp)-len(out):])
}

func subtractBigEndianSmall(out []byte, value byte) {
	borrow := uint16(value)
	for i := len(out) - 1; i >= 0; i-- {
		v := uint16(out[i])
		if v >= borrow {
			out[i] = byte(v - borrow)
			borrow = 0
			break
		}
		out[i] = byte(0x100 + v - borrow)
		borrow = 1
	}
	if borrow != 0 {
		panic("underflow in big-endian subtraction")
	}
}

func subtractLimbsSmall(x *[scalarMaxLimbs]uint64, limbs int, value uint64) {
	borrow := value
	for i := range limbs {
		x[i], borrow = bits.Sub64(x[i], borrow, 0)
		if borrow == 0 {
			break
		}
		borrow = 1
	}
}

func lessThanLimbs(x, y *[scalarMaxLimbs]uint64, limbs int) bool {
	for i := limbs - 1; i >= 0; i-- {
		if x[i] < y[i] {
			return true
		}
		if x[i] > y[i] {
			return false
		}
	}

	return false
}

func lessOrEqualNormalLimbs(x, y *[scalarMaxLimbs]uint64, limbs int) int {
	lt := 0
	gt := 0

	for i := limbs - 1; i >= 0; i-- {
		eq := cryptosubtle.ConstantTimeEq(int32(x[i]>>32), int32(y[i]>>32)) &
			cryptosubtle.ConstantTimeEq(int32(x[i]), int32(y[i]))
		neq := 1 ^ eq
		_, xlt := bits.Sub64(x[i], y[i], 0)
		_, xgt := bits.Sub64(y[i], x[i], 0)
		undecided := 1 ^ (lt | gt)
		lt |= undecided & (int(xlt) & neq)
		gt |= undecided & (int(xgt) & neq)
	}

	return 1 ^ gt
}

func selectWords(dst, a, b *[scalarMaxLimbs]uint64, cond, limbs int) {
	mask := uint64(0) - uint64(cond)

	for i := range limbs {
		dst[i] = (a[i] & mask) | (b[i] &^ mask)
	}
}

func addMontgomery(p *scalarParams, dst, x, y *[scalarMaxLimbs]uint64) {
	var sum [scalarMaxLimbs]uint64
	var carry uint64

	for i := 0; i < p.limbs; i++ {
		sum[i], carry = bits.Add64(x[i], y[i], carry)
	}

	subtractModulus(p, dst, &sum, carry)
}

func subMontgomery(p *scalarParams, dst, x, y *[scalarMaxLimbs]uint64) {
	var borrow uint64
	for i := 0; i < p.limbs; i++ {
		dst[i], borrow = bits.Sub64(x[i], y[i], borrow)
	}

	mask := uint64(0) - borrow
	var carry uint64

	for i := 0; i < p.limbs; i++ {
		addend := p.order[i] & mask
		dst[i], carry = bits.Add64(dst[i], addend, carry)
	}
}

func subtractModulus(p *scalarParams, dst, x *[scalarMaxLimbs]uint64, extra uint64) {
	var diff [scalarMaxLimbs]uint64
	var borrow uint64

	for i := 0; i < p.limbs; i++ {
		diff[i], borrow = bits.Sub64(x[i], p.order[i], borrow)
	}

	_, borrow = bits.Sub64(extra, 0, borrow)
	mask := uint64(borrow) - 1

	for i := 0; i < p.limbs; i++ {
		dst[i] = (diff[i] & mask) | (x[i] &^ mask)
	}
}

func montgomeryMul(p *scalarParams, dst, x, y *[scalarMaxLimbs]uint64) {
	var t [scalarMaxLimbs*2 + 1]uint64
	limit := 2*p.limbs + 1

	for i := 0; i < p.limbs; i++ {
		for j := 0; j < p.limbs; j++ {
			addMulWord(t[:limit], i+j, x[i], y[j])
		}
	}

	for i := 0; i < p.limbs; i++ {
		m := t[i] * p.n0inv
		for j := 0; j < p.limbs; j++ {
			addMulWord(t[:limit], i+j, m, p.order[j])
		}
	}

	var candidate [scalarMaxLimbs]uint64

	for i := 0; i < p.limbs; i++ {
		candidate[i] = t[p.limbs+i]
	}

	subtractModulus(p, dst, &candidate, t[2*p.limbs])
}

func addMulWord(t []uint64, start int, a, b uint64) {
	hi, lo := bits.Mul64(a, b)
	var carry uint64
	var c1 uint64
	var c2 uint64
	t[start], carry = bits.Add64(t[start], lo, 0)
	sum, c1 := bits.Add64(hi, 0, carry)
	t[start+1], c2 = bits.Add64(t[start+1], sum, 0)
	carryWord := c1 + c2

	for i := start + 2; i < len(t); i++ {
		t[i], carry = bits.Add64(t[i], carryWord, 0)
		carryWord = carry
	}
}

func (p *scalarParams) toMontgomery(dst, normal *[scalarMaxLimbs]uint64) {
	montgomeryMul(p, dst, normal, &p.rr)
}

func (p *scalarParams) fromMontgomery(dst, mont *[scalarMaxLimbs]uint64) {
	var one [scalarMaxLimbs]uint64
	one[0] = 1
	montgomeryMul(p, dst, mont, &one)
}
