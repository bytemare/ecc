// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package encoding provides serde utilities.
package encoding

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/bytemare/ecc"
	"github.com/bytemare/ecc/internal"
)

func jsonReGetField(key, s, catch string) (string, error) {
	r := fmt.Sprintf(`%q:%s`, regexp.QuoteMeta(key), catch)
	re := regexp.MustCompile(r)
	matches := re.FindStringSubmatch(s)

	if len(matches) != 2 {
		return "", internal.ErrDecodingInvalidJSONEncoding
	}

	return matches[1], nil
}

// JSONReGetGroup attempts to find the group JSON encoding in s.
func JSONReGetGroup(s string) (ecc.Group, error) {
	f, err := jsonReGetField("group", s, `(\w+)`)
	if err != nil {
		return 0, err
	}

	i, err := strconv.Atoi(f)
	if err != nil {
		return 0, fmt.Errorf("failed to read Group: %w", err)
	}

	if i < 0 || i > 63 {
		return 0, internal.ErrInvalidGroup
	}

	c := ecc.Group(i)
	if !c.Available() {
		return 0, internal.ErrInvalidGroup
	}

	return c, nil
}
