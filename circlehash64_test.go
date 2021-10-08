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
	"hash"
	"testing"
)

// CircleHash64 uses CircleHash64f as default hash. Expected SHA-512 checksums are
// from the C++ and Go CircleHash reference implementations by Faye Amacker.
// SHA-512 is used because it's included in Go and available in many languages.
//
// Compatibility tests check CircleHash64 digests produced by hashing
// input sizes of various lengths (0-16384 bytes).
//
// Tests for input sizes greater than 128 bytes can help future implementations
// that rely on input size to determine which optimized version to execute.
//
// Passing these compatibility tests inherits non-benchmark SMHasher test results.
// CircleHash64 passes important tests not included in this file. For example:
// all SMHasher tests such as Strict Avalanche Criterion, Bit Independence Criterion,
// and etc. using demerphq/smhasher, rurban/smhasher, and a custom smhasher that
// is harder to pass.

const (
	// nums are nothing-up-my-sleeve numbers
	numsAllZeros = uint64(0x0000000000000000)
	numsAll55s   = uint64(0x5555555555555555) // alternating 1 and 0 bit
	numsAllAAs   = uint64(0xAAAAAAAAAAAAAAAA) // alternating 0 and 1 bit
	numsAllFFs   = uint64(0xFFFFFFFFFFFFFFFF)

	numsGoldenRatio    = uint64(0x9E3779B97F4A7C15) // https://en.wikipedia.org/wiki/Golden_ratio
	numsGoldenRatioInv = numsGoldenRatio ^ numsAllFFs
)

var countCircleHash64f uint64 // count calls to Hash64 (doesn't include calls to HashString64)
var collisions = make(map[uint64]uint64)

func TestCircleHash64EmptyInputs(t *testing.T) {

	data := make([]byte, 0)

	testCases := []struct {
		name string
		seed uint64
		want uint64
	}{
		{"seed 00s", numsAllZeros, uint64(0x53097B8ED678AF76)},
		{"seed 55s", numsAll55s, uint64(0xD4F32E198DB2CE67)},
		{"seed AAs", numsAllAAs, uint64(0x5B872DFE1FC33E91)},
		{"seed FFs", numsAllFFs, uint64(0x687B6E5DE386D50D)},
		{"seed GR", numsGoldenRatio, uint64(0x153AF508A10A0825)},
		{"seed GRI", numsGoldenRatioInv, uint64(0x4ECA726E323FC429)},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf(tc.name), func(t *testing.T) {

			got := countedCircleHash64(t, data, tc.seed)
			if got != tc.want {
				t.Errorf("CircleHash64(%v, %v) = 0x%016x; want 0x%016x", data, tc.seed, got, tc.want)
			}

		})
	}
}

func TestCircleHash64UniformBitPatternInputs(t *testing.T) {

	testCases := []struct {
		name string
		seed uint64
		want []byte
	}{
		{"seed 00s", numsAllZeros, decodeHexOrPanic("69813d042f48e95fbfad434c5755852cf35aa3b06d5e9aeca3f8d21a1064f292ef708ec30420d195922e349eb5c981995f215b68c573aa89740f37e00b6af6cd")},
		{"seed 55s", numsAll55s, decodeHexOrPanic("fff6aafb5b4213ac122d82da3028ca60714df2ecb5ed2a7bd8f9d8ef1989502327ee3f29787001120efd9200d7440cd6bc089e68acc2752dc2425ec04be2b92a")},
		{"seed AAs", numsAllAAs, decodeHexOrPanic("7d48a7571d3656c478b88064fef50389ef63558f720cc8673d367d567c1eb42fcf78acd3dfa4fca107e4341a3ceaa665e9cae06403a6834a03eac68a216add01")},
		{"seed FFs", numsAllFFs, decodeHexOrPanic("9c9ddb1ccf928838ee3ea4a0f076b15c02ccbaee33110a838e91190a69389dc19530098f1b825ef619b8acc9e60e7b774cf1752bbe11371374af811f52b93666")},
		{"seed GR", numsGoldenRatio, decodeHexOrPanic("dbd8e1ab0191bafc45f1b9b4eca732d4b7dd8bb583a99988e5cc8af4e64144e5f44e40c56ef100f11704d64b47c0850e7afe3cdd2e626a69d03e4c500d365b6a")},
		{"seed GRI", numsGoldenRatioInv, decodeHexOrPanic("becb85458437bb618fb835d33ad019c84f966395f2c505758a8249c7a26473a05cd38a35e54bbd4a676d534d926737fef75766f139fd2f632b59b5cf965dd21c")},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf(tc.name), func(t *testing.T) {

			got := checksumUniformBitPatternInputs(t, tc.seed)

			if !bytes.Equal(got, tc.want) {
				t.Errorf("checksumUniformBitPatternInputs(seed 0x%016x) = 0x%x; want 0x%x",
					tc.seed, got, tc.want)
			}

		})
	}

}

func TestCircleHash64NonUniformBitPatternInputs(t *testing.T) {

	// Create 16 KiB of test data from SHA-512 using the simplest
	// form of SHA-512 feedback loop (nothing-up-my-sleeve).
	data := nonUniformBytes16KiB()

	// Verify CircleHash64 digests produced from hashing portions of
	// data using different seed values. Input sizes vary from
	// 1 to 16384 bytes by varing starting pos and ending pos.

	testCases := []struct {
		name                     string
		seed                     uint64
		wantSHA512VaringStartPos []byte
		wantSHA512VaringEndPos   []byte
	}{
		{
			"seed 00s",
			numsAllZeros,
			decodeHexOrPanic("8fc041d09087f9f3108ed86422ee6562f4eaf1ad0b1d83ede3f69b14f3798b8a5c80518ea7041f0803882ced33bce34351c5415469957e40ddd806d618742a71"),
			decodeHexOrPanic("80348e245dec5e09c424411c4dfa9fbbad1cbf68495707e3579bec8c7e7e010f6ff441b6b3987e4da28be39ccd355ae545ca0329284fa39a0d630b941e83355a"),
		},

		{
			"seed 55s",
			numsAll55s,
			decodeHexOrPanic("714733e2f758328f07556e849cc96b371dba28ed8c6c934f6591a7e4ea90a02dc93bb858639ed62b3aacc26932efe3a47aa4e5b713a8f1c2a5375988fb3fcf05"),
			decodeHexOrPanic("90ac86e7e8ce973ad402d1db741c7ee320b330ffbbe391c9b20eb9ce07385c66df3f40efd0865ee18894b559cde70f38ec7b01319b2ef2f3f61c64cc8abeca12"),
		},

		{
			"seed AAs",
			numsAllAAs,
			decodeHexOrPanic("710f68717bf5144e703e10236d9d2cda2b7e8e503aacf4168a088a1be51d3ffe83cf19908e238be15883f6cd25a2c7c71e715173e19fc73f5707ad7626c3b944"),
			decodeHexOrPanic("042037e4dfaf0072c5048c8043fa6ac1f197f8b3c2140d97ccfe9abd69f7ef6fb6739e0728c40bff272dbd6a0c82f7f04f95a0ca64cdfe73c080b691bd58214e"),
		},

		{
			"seed FFs",
			numsAllAAs,
			decodeHexOrPanic("710f68717bf5144e703e10236d9d2cda2b7e8e503aacf4168a088a1be51d3ffe83cf19908e238be15883f6cd25a2c7c71e715173e19fc73f5707ad7626c3b944"),
			decodeHexOrPanic("042037e4dfaf0072c5048c8043fa6ac1f197f8b3c2140d97ccfe9abd69f7ef6fb6739e0728c40bff272dbd6a0c82f7f04f95a0ca64cdfe73c080b691bd58214e"),
		},

		{
			"seed GR",
			numsGoldenRatio,
			decodeHexOrPanic("A19151170F5A8E92A98416FFF407F35317D458CD8F47A3D28B9A2DDCB277D6D0FF895A1B06F6AA5F25C67B71C74D9F6705FFBFE27EDD1237EE990395F61842F2"),
			decodeHexOrPanic("B853718A24F4B46E0E3D1B4CF497637AF09B5AA061496707B1839F824B9B4F4294113976765A72B9DFD916D8A56CC434A7F12116CFF8406C8B3FFD8A8ACD80D3"),
		},

		{
			"seed GRI",
			numsGoldenRatioInv,
			decodeHexOrPanic("E18B76BB467BBBAB91DEEB42307964FD92DB5AC6BF5718DA12BA391C3A89C6F0F7C6379DCF6C7676EB1BBC8C8D240919B154086BFBA65FC4D0E468B67E474195"),
			decodeHexOrPanic("626CBB08E12D6988BC7D8F75E9571961D4E46240E5EF682562F7010D8916A7B104B988F6749B67F59F5E7CB4147017842D78CE17B7C9443813B92C0E198B62E2"),
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf(tc.name), func(t *testing.T) {

			h := sha512.New()

			checksumVaryingStartPos(t, h, tc.seed, data)
			got := h.Sum(nil)
			if !bytes.Equal(got, tc.wantSHA512VaringStartPos) {
				t.Errorf("checksumVaryingStartPos(nonuniform16KiB) = 0x%0128x; want 0x%0128x",
					got,
					tc.wantSHA512VaringStartPos)
			}

			h.Reset()

			checksumVaryingEndPos(t, h, tc.seed, data)
			got = h.Sum(nil)
			if !bytes.Equal(got, tc.wantSHA512VaringEndPos) {
				t.Errorf("checksumVaryingEndPos(nonuniform16KiB) = 0x%0128x; want 0x%0128x",
					got,
					tc.wantSHA512VaringEndPos)
			}
		})
	}

	/* TODO: (Optional) Repeat tests after inverting the input data.
	// Create 16 KiB of test data with every bit of data inverted,
	// to make tests cover all 131072 bits as both 0 and 1.
	datainv := nonUniformBytes16KiB()
	for i := 0; i < len(datainv); i++ {
		datainv[i] ^= uint8(0xFF)
	}
	*/

}

// checksumUniformBitPatternInputs returns SHA-512 checksum of 65536 CircleHash64
// digests using input of repeated byte values (0x00 to 0xFF).
// Input sizes range from 1 to 256 bytes.
func checksumUniformBitPatternInputs(t *testing.T, seed uint64) []byte {
	sha512 := sha512.New()

	// Check 65536 digests on uniform byte fills (0x00-0xFF) of varying lengths
	for pattern := 0; pattern <= 255; pattern++ {

		data := make([]byte, 256)
		for i := 0; i < len(data); i++ {
			data[i] = byte(pattern)
		}

		for i := uint64(1); i <= uint64(len(data)); i++ {
			digest := countedCircleHash64(t, data[0:i], seed)

			b := make([]byte, 8)
			binary.LittleEndian.PutUint64(b, digest)

			// Feed CircleHash64 result into SHA-512.
			sha512.Write(b)
		}
	}

	return sha512.Sum(nil)
}

// checksumVaryingStartPos updates cryptoHash512 with
// concatenated CircleHash64 digests. E.g. passing in data containing
// 128 bytes will use 128 CircleHash64 digests ending at
// the last byte and incrementing the start position of data.
func checksumVaryingStartPos(t *testing.T, cryptoHash512 hash.Hash, seed uint64, data []byte) {

	// vary the starting position and keep the ending position
	for i := uint64(0); i < uint64(len(data)); i++ {

		digest := countedCircleHash64(t, data[i:], seed)

		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, digest)

		// Feed CircleHash64 result into SHA-512, SHA3-512, etc.
		cryptoHash512.Write(b)
	}
}

// checksumVaryingEndPos updates cryptoHash512 with
// concatenated CircleHash64 digests. E.g. passing in data containing
// 128 bytes will use 128 CircleHash64 digests always starting at
// the first byte and incrementing the length of input size.
func checksumVaryingEndPos(t *testing.T, cryptoHash512 hash.Hash, seed uint64, data []byte) {

	// keep the starting position at zero and increment the length
	for i := uint64(1); i <= uint64(len(data)); i++ {
		digest := countedCircleHash64(t, data[0:i], seed)

		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, digest)

		// Feed CircleHash64 result into SHA-512, SHA3-512, etc.
		cryptoHash512.Write(b)
	}
}

// nonUniformBytes16Kib returns 16384 bytes of non-uniform bytes
// produced from SHA-512 in a feedback loop. SHA-512 is used instead
// of SHAKE-256 XOF or a stream cipher because SHA-512 is bundled with
// Go and is available in most languages. One reason a simple PRNG
// isn't used here is because different implementions in different
// programming languages are sometimes incompatible due to errors
// (like SplitMix64). SHA-512 will be compatible everywhere.
// SHA-512 of the returned 16384-byte slice is:
// 412895CDFDF6FD60181CD709B6AED89CCE63EDE8402531185C969DE50EB04AE3
// 5D042D7B2758D02F97C6B13B1A397E2FBECA7CEB07C606F3602BED97984F99C6
func nonUniformBytes16KiB() []byte {
	b := make([]byte, 0, 256*64) // length=0, capacity=16384

	// Each input to SHA-512 is 64 bytes. First 64-byte input is zeros.
	// The next input to SHA-512 is the 64-byte output of SHA-512.
	// Each output of SHA-512 is appended to the returned byte slice.
	d := make([]byte, 64)
	for i := 0; i < 256; i++ {
		a := sha512.Sum512(d)
		d = a[:]
		b = append(b, d...)
	}

	return b
}

// countedCircleHash64 calls Hash64 and increments countCircleHash64.
func countedCircleHash64(t *testing.T, data []byte, seed uint64) uint64 {
	digest := Hash64(data, seed)
	digest2 := HashString64(string(data), seed)
	if digest != digest2 {
		t.Errorf("Hash64() 0x%x != HashString64() 0x%x", digest, digest2)
	}

	collisions[digest]++
	countCircleHash64f++
	return digest
}

func decodeHexOrPanic(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("bad hex string: %s", err))
	}
	return b
}
