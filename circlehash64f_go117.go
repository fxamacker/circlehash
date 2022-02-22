// Copyright 2021-2022 Faye Amacker
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Reference implementation of CircleHash64 is maintained at
// https://github.com/fxamacker/circlehash

// This file is for Go versions >= 1.17.
//go:build go1.17
// +build go1.17

package circlehash

import (
	"unsafe"
)

// circle64fShortInput produces a digest from input with length up to 64 bytes.
// WARNING: The caller MUST check the input length before calling this function.
// WARNING: This function must not be exported without adding error handling.
func circle64fShortInput(p unsafe.Pointer, seed uint64, dlen uint64) uint64 {

	startingLength := dlen
	currentState := seed ^ pi0

	// We have at most 64 bytes to process.
	// Process chunks of 16 bytes
	for ; dlen > 16; dlen -= 16 {
		a := readUnaligned64(p)
		b := readUnaligned64(add(p, 8))

		currentState = mix64(a^pi1, b^currentState)

		p = add(p, 16)
	}

	// We have at most 16 bytes to process.

	// a and b are 0 for default case of dlen == 0
	a := uint64(0)
	b := uint64(0)

	switch {
	case dlen > 8:
		// We have 9-16 bytes to process.
		// a and b might overlap.
		a = readUnaligned64(p)
		b = readUnaligned64(add(p, uintptr(dlen-8)))

	case dlen > 3:
		// We have 4-8 bytes to process.
		// a and b might overlap.
		a = uint64(readUnaligned32(p))
		b = uint64(readUnaligned32(add(p, uintptr(dlen-4))))

	case dlen > 0:
		// We have 1-3 bytes to process.
		a = uint64(*(*byte)(p)) << 16
		a |= uint64(*(*byte)(add(p, uintptr(dlen>>1)))) << 8
		a |= uint64(*(*byte)(add(p, uintptr(dlen-1))))
		// b is 0, so we don't need to set it to 0 again
	}

	// We use pi1 and pi4 during finalization (abseil and wyhash reuses same const)
	w := mix64(a^pi1, b^currentState)
	z := pi4 ^ startingLength
	return mix64(w, z)
}
