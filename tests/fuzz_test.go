// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package ecc_test

import (
	"crypto"
	"errors"
	"math"
	"testing"

	"github.com/bytemare/hash"

	"github.com/bytemare/ecc"
	"github.com/bytemare/ecc/hash2curve"
	"github.com/bytemare/ecc/internal"
)

func FuzzGroup(f *testing.F) {
	f.Fuzz(func(t *testing.T, group byte, h2Input, h2DST []byte, dstApp string, dstVersion uint8) {
		if panicked, err := hasPanic(func() {
			g := ecc.Group(group)

			if len(g.MakeDST(dstApp, dstVersion)) == 0 {
				t.Fatal("unexpected 0 length dst")
			}

			if len(h2DST) != 0 {
				one := g.NewScalar().SetUInt64(1)
				s, err := g.HashToScalar(h2Input, h2DST)
				if err != nil {
					t.Fatal(err)
				}

				if s.IsZero() || s.Equal(one) {
					t.Fatal("HashToScalar yielded 0 or 1")
				}

				e, err := g.HashToGroup(h2Input, h2DST)
				if err != nil {
					t.Fatal(err)
				}

				if e.IsIdentity() || e.Equal(g.Base()) {
					t.Fatal("HashToGroup yielded identity or generator")
				}

				e, err = g.EncodeToGroup(h2Input, h2DST)
				if err != nil {
					t.Fatal(err)
				}

				if e.IsIdentity() || e.Equal(g.Base()) {
					t.Fatal("HashToGroup yielded identity or generator")
				}
			}
		}); panicked && !errors.Is(err, internal.ErrInvalidGroup) {
			t.Fatal(err)
		}
	})
}

func FuzzScalar(f *testing.F) {
	f.Fuzz(func(t *testing.T, group byte, input []byte, i uint64) {
		if panicked, err := hasPanic(func() {
			g := ecc.Group(group)
			s := g.NewScalar()

			s.SetUInt64(i)
			_ = s.Decode(input)
			_ = s.DecodeHex(string(input))
			_ = s.UnmarshalJSON(input)
			_ = s.UnmarshalBinary(input)
		}); panicked && !errors.Is(err, internal.ErrInvalidGroup) {
			t.Fatal(err)
		}
	})
}

func FuzzElement(f *testing.F) {
	f.Fuzz(func(t *testing.T, group byte, input []byte) {
		if panicked, err := hasPanic(func() {
			g := ecc.Group(group)
			s := g.NewScalar()

			_ = s.Decode(input)
			_ = s.DecodeHex(string(input))
			_ = s.UnmarshalJSON(input)
			_ = s.UnmarshalBinary(input)
		}); panicked && !errors.Is(err, internal.ErrInvalidGroup) {
			t.Fatal(err)
		}
	})
}

func fuzzTestSkipInput(t *testing.T, dst []byte, length uint) {
	if len(dst) == 0 {
		t.Skip("zero length dst")
	}

	if length < 0 {
		t.Skip("requested length is negative")
	}

	if length > math.MaxUint16 {
		t.Skip("requested length too big")
	}
}

func fuzzTestSkipXMDInput(t *testing.T, h uint, dst []byte, length uint) {
	fuzzTestSkipInput(t, dst, length)

	hid := crypto.Hash(h)

	if !hid.Available() {
		t.Skip("unavailable hash")
	}

	if len(dst) > math.MaxUint8 {
		t.Skip("dst too long")
	}

	if length > uint(255*hid.Size()) {
		t.Skip("requested length too big")
	}
}

func FuzzExpandXMD(f *testing.F) {
	f.Fuzz(func(t *testing.T, h uint, input, dst []byte, length uint) {
		fuzzTestSkipXMDInput(t, h, dst, length)
		_, _ = hash2curve.ExpandXMD(crypto.Hash(h), input, dst, length)
	})
}

func fuzzTestSkipXOFInput(t *testing.T, h uint, dst []byte, length uint) {
	fuzzTestSkipInput(t, dst, length)

	if hash.Hash(h) < hash.SHAKE128 || hash.Hash(h) > hash.BLAKE2XS {
		t.Skip()
	}

	if length < 32 {
		t.Skip("length too small")
	}

	if !hash.Hash(h).Available() {
		t.Skip()
	}
}

func FuzzExpandXOF(f *testing.F) {
	f.Fuzz(func(t *testing.T, h uint, input, dst []byte, length uint) {
		fuzzTestSkipXOFInput(t, h, dst, length)
		_, _ = hash2curve.ExpandXOF(hash.Hash(h).GetXOF(), input, dst, length)
	})
}
