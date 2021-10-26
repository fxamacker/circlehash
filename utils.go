// Copyright 2021 Faye Amacker
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

package circlehash

import (
	"math/bits"
	"unsafe"
)

func add(p unsafe.Pointer, x uintptr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(p) + x)
}

// readUnaligned32 uses LittleEndian (from Go 1.17)
func readUnaligned32(p unsafe.Pointer) uint32 {
	q := (*[4]byte)(p)
	return uint32(q[0]) | uint32(q[1])<<8 | uint32(q[2])<<16 | uint32(q[3])<<24
}

// readUnaligned64 uses LittleEndian (from Go 1.17)
func readUnaligned64(p unsafe.Pointer) uint64 {
	q := (*[8]byte)(p)
	return uint64(q[0]) | uint64(q[1])<<8 | uint64(q[2])<<16 | uint64(q[3])<<24 | uint64(q[4])<<32 | uint64(q[5])<<40 | uint64(q[6])<<48 | uint64(q[7])<<56
}

func mix64(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	return hi ^ lo
}

/*
// Used by CircleHash64s
func mix64x(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	return a ^ b ^ hi ^ lo // mitigate multiplication by zero
}
*/
