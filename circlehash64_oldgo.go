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
