// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package ecc_test

import (
	"testing"

	"github.com/bytemare/ecc"
	"github.com/bytemare/ecc/encoding"
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
				if s := g.HashToScalar(h2Input, h2DST); s.IsZero() || s.Equal(one) {
					t.Fatal("HashToScalar yielded 0 or 1")
				}

				if e := g.HashToGroup(h2Input, h2DST); e.IsIdentity() || e.Equal(g.Base()) {
					t.Fatal("HashToGroup yielded identity or generator")
				}

				if e := g.EncodeToGroup(h2Input, h2DST); e.IsIdentity() || e.Equal(g.Base()) {
					t.Fatal("HashToGroup yielded identity or generator")
				}
			}
		}); panicked && err.Error() != internal.ErrInvalidGroup.Error() {
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
		}); panicked && err.Error() != internal.ErrInvalidGroup.Error() {
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
		}); panicked && err.Error() != internal.ErrInvalidGroup.Error() {
			t.Fatal(err)
		}
	})
}

func FuzzJSONReGetGroup(f *testing.F) {
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = encoding.JSONReGetGroup(input)
	})
}
