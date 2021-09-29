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
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
)

func decodeHexOrPanic(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("bad hex string: %s", err))
	}
	return b
}

func TestHash64(t *testing.T) {

	data00 := make([]byte, 256)
	for i := 0; i < len(data00); i++ {
		data00[i] = 0
	}

	data55 := make([]byte, 256)
	for i := 0; i < len(data55); i++ {
		data55[i] = 0x55
	}

	data80 := make([]byte, 256)
	for i := 0; i < len(data80); i++ {
		data80[i] = 0x80
	}

	dataAA := make([]byte, 256)
	for i := 0; i < len(dataAA); i++ {
		dataAA[i] = 0xaa
	}

	dataFF := make([]byte, 256)
	for i := 0; i < len(dataFF); i++ {
		dataFF[i] = 0xff
	}

	data00FF := make([]byte, 256)
	for i := 0; i < len(data00FF); i++ {
		data00FF[i] = uint8(i)
	}

	testCases := []struct {
		name           string
		seed           uint64
		data           []byte
		expectedDigest []byte
	}{
		/*
			// These are SHA384 results for 1,536 different Abseil-compatible digests (256 digests each)
			{"00", uint64(0x0000000000000000), data00, decodeHexOrPanic("671adad39c36eb415712103bd6120e5400d88cad815edecc0879dc29bb207a1f38ad76acc610cf9888f262ed942a4604")},

			{"55", uint64(0x5555555555555555), data55, decodeHexOrPanic("f27fb9f14f639b6c2642f235e87eb422ef5b01201d07babb9e6ba1e9cd544fbc3f9d83391ce5b414420c5847c93deb88")},

			{"aa", uint64(0xaaaaaaaaaaaaaaaa), dataAA, decodeHexOrPanic("8f979fa390694fc8932a686e9f4d01bcc01d278cff0220b58fbef16754816e362d95f64788f330c2f20e1610d810343b")},

			{"80", uint64(0x8080808080808080), data80, decodeHexOrPanic("626e65cec12993f8b20d487c9a946959ab2f23125822af26a1087083fdfe67ba799f36fc67a615f38ee3b947b6d4f6ae")},

			{"ff", uint64(0xffffffffffffffff), dataFF, decodeHexOrPanic("2786da14eb751de04da7c9838dc98d483a01f7948f97e4234ea1eebb9bbb9a7289afabb0535ae7c004287c562496185b")},

			{"00ff", uint64(0x0123456789ABCDEF), data00FF, decodeHexOrPanic("8219f8c46a86a5f393c8f7fae9b0a11621894591b8d094b7ec727a28acbbb4599da80ccad714fed794af5ed848dea57e")},
		*/

		// These are SHA384 results for 1,536 CircleHash64f digests (256 digests each)
		{"00", uint64(0x0000000000000000), data00, decodeHexOrPanic("62d57be0c889c0e50e5b5c225ffcd30e46c5ace73f5fdf97f78eb3893c8fe3bcfb0aa9858d89830172bb7c417256be81")},

		{"55", uint64(0x5555555555555555), data55, decodeHexOrPanic("4c94dd841e6547a20f9c83470f34beea48f7fc9e737714eef736bb343acbf0822d72c8cf4e9c7a6fd3a5aa7b254be5b5")},

		{"aa", uint64(0xaaaaaaaaaaaaaaaa), dataAA, decodeHexOrPanic("704164484daaa9d7236b0bfa836755074496e5f84bb5939a11c2b1d9179f6f083826d4d80134df30445c8e61912b2569")},

		{"80", uint64(0x8080808080808080), data80, decodeHexOrPanic("ab16308e15428ec5807d69646d9c4c9a99fa64b3dd55a73b711192948b5752e019fabfb9a56e61e6941ab43b6cd1aa28")},

		{"ff", uint64(0xffffffffffffffff), dataFF, decodeHexOrPanic("690755c949c92918780ecab6f8f23aacac7ae49ad2eab6c070e1c866ebe43b61668d7c47d790115ba982e6e0381ebd54")},

		{"00-ff", uint64(0x0123456789ABCDEF), data00FF, decodeHexOrPanic("796ddd4981b6e7a9ade46eba606437953e56239619e8e468ad6e24dc4d11be90bbe4fcc23cb5a1c0acd53a55589e202d")},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf(tc.name), func(t *testing.T) {

			sha384 := sha512.New384()

			b := make([]byte, 8)
			for i := 0; i < len(tc.data); i++ {
				digest := Hash64(tc.data[0:i], tc.seed)

				binary.LittleEndian.PutUint64(b, digest)

				sha384.Write(b)
			}

			actual := sha384.Sum(nil)

			if !bytes.Equal(tc.expectedDigest, actual) {
				t.Errorf("sha384(d0, ..., d255) returned %s, want %s", hex.EncodeToString(actual), tc.expectedDigest)
			}
		})
	}
}
