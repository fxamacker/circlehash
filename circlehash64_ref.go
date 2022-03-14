// Copyright 2021-2022 Faye Amacker
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This file is for Go versions older than 1.17.
//go:build !go1.17
// +build !go1.17

package circlehash

import (
	"unsafe"
)

// Hash64 returns a 64-bit digest of data.
// Digest is compatible with CircleHash64f.
func Hash64(b []byte, seed uint64) uint64 {
	return uint64(circle64f(*(*unsafe.Pointer)(unsafe.Pointer(&b)), seed, uint64(len(b))))
}

// Hash64String returns a 64-bit digest of s.
// Digest is compatible with Hash64.
func Hash64String(s string, seed uint64) uint64 {
	return uint64(circle64f(*(*unsafe.Pointer)(unsafe.Pointer(&s)), seed, uint64(len(s))))
}

// Hash64Uint64x2 returns a 64-bit digest of a and b.
// Digest is compatible with Hash64 with byte slice of len 16.
func Hash64Uint64x2(a uint64, b uint64, seed uint64) uint64 {
	return circle64fUint64x2(a, b, seed)
}

// circle64f is the unoptimized reference implementation of CircleHash64
func circle64f(p unsafe.Pointer, seed uint64, dlen uint64) uint64 {

	startingLength := dlen
	currentState := seed ^ pi0

	if dlen > 64 {
		// Process chunks of 64 bytes.
		duplicatedState := currentState

		for ; dlen > 64; dlen -= 64 {
			a := readUnaligned64(p)
			b := readUnaligned64(add(p, 8))
			c := readUnaligned64(add(p, 16))
			d := readUnaligned64(add(p, 24))
			e := readUnaligned64(add(p, 32))
			f := readUnaligned64(add(p, 40))
			g := readUnaligned64(add(p, 48))
			h := readUnaligned64(add(p, 56))

			cs0 := mix64(a^pi1, b^currentState)
			cs1 := mix64(c^pi2, d^currentState)
			currentState = (cs0 ^ cs1)

			ds0 := mix64(e^pi3, f^duplicatedState)
			ds1 := mix64(g^pi4, h^duplicatedState)
			duplicatedState = (ds0 ^ ds1)

			p = add(p, 64)
		}

		currentState = currentState ^ duplicatedState
	}

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

// circle64fUint64x2 produces a 64-bit digest from a, b, and seed.
// Digest is compatible with circlehash64f with byte slice of len 16.
func circle64fUint64x2(a uint64, b uint64, seed uint64) uint64 {
	const dataLen = uint64(16)
	currentState := seed ^ pi0
	w := mix64(a^pi1, b^currentState)
	z := pi4 ^ dataLen
	return mix64(w, z)
}
