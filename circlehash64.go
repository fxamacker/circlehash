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

// Hash64 returns a 64-bit digest of data.
func Hash64(b []byte, seed uint64) uint64 {
	return uint64(circle64f(*(*ptr)(ptr(&b)), seed, uint64(len(b))))
}

// HashString64 returns a 64-bit digest of string s.
func HashString64(s string, seed uint64) uint64 {
	return uint64(circle64f(*(*ptr)(ptr(&s)), seed, uint64(len(s))))
}
