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

// Official reference implementation of CircleHash64 is maintained in
// circlehash64_ref.go at
//
//     https://github.com/fxamacker/circlehash

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

// CircleHash64 uses CircleHash64f as default hash. Expected SHA-512 digests are
// from the C++ and Go CircleHash reference implementations by Faye Amacker.
// SHA-512 is used because it's included in Go and available in many languages.
//
// Compatibility tests check nearly 600000 CircleHash64 digests produced by hashing
// input sizes of various lengths (0-16384 bytes) and using different seeds.
//
// Tests for input sizes greater than 128 bytes can verify future hash implementations
// that rely on larger input sizes to determine which optimized code path is executed.
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
			numsAllFFs,
			decodeHexOrPanic("e275ac0f2df55036ac844f7cbf6375fbad8b4c7fbac98296e5d0fbfbdb294534c5a45058883220572bff8145c3e2f191950f0cad2841c9bd50babe3b907469c4"),
			decodeHexOrPanic("12864d73da4f64ef97b988b400566f9b89ebaeee87629208ac7029a6cc6a57759025f83efd0480b1675fb4b06d128439c03ac300ce0c1fbd35dfaa9a91e233ac"),
		},

		{
			"seed GR",
			numsGoldenRatio,
			decodeHexOrPanic("a19151170f5a8e92a98416fff407f35317d458cd8f47a3d28b9a2ddcb277d6d0ff895a1b06f6aa5f25c67b71c74d9f6705ffbfe27edd1237ee990395f61842f2"),
			decodeHexOrPanic("b853718a24f4b46e0e3d1b4cf497637af09b5aa061496707b1839f824b9b4f4294113976765a72b9dfd916d8a56cc434a7f12116cff8406c8b3ffd8a8acd80d3"),
		},

		{
			"seed GRI",
			numsGoldenRatioInv,
			decodeHexOrPanic("e18b76bb467bbbab91deeb42307964fd92db5ac6bf5718da12ba391c3a89c6f0f7c6379dcf6c7676eb1bbc8c8d240919b154086bfba65fc4d0e468b67e474195"),
			decodeHexOrPanic("626cbb08e12d6988bc7d8f75e9571961d4e46240e5ef682562f7010d8916a7b104b988f6749b67f59f5e7cb4147017842d78ce17b7c9443813b92c0e198b62e2"),
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf(tc.name), func(t *testing.T) {

			h := sha512.New()

			// verify hash of 1-16384 bytes of test data by varying start pos
			checksumVaryingStartPos(t, h, tc.seed, data)
			got := h.Sum(nil)
			if !bytes.Equal(got, tc.wantSHA512VaringStartPos) {
				t.Errorf("checksumVaryingStartPos(nonuniform16KiB) = 0x%0128x; want 0x%0128x",
					got,
					tc.wantSHA512VaringStartPos)
			}

			h.Reset()

			// verify hash of 1-16384 bytes of test data by varying end pos
			checksumVaryingEndPos(t, h, tc.seed, data)
			got = h.Sum(nil)
			if !bytes.Equal(got, tc.wantSHA512VaringEndPos) {
				t.Errorf("checksumVaryingEndPos(nonuniform16KiB) = 0x%0128x; want 0x%0128x",
					got,
					tc.wantSHA512VaringEndPos)
			}
		})
	}

	// Repeat tests using inverted input data.

	// Create the same 16 KiB of test data with each bit inverted.
	datainv := nonUniformBytes16KiB()
	for i := 0; i < len(datainv); i++ {
		datainv[i] ^= uint8(0xFF)
	}

	invertedTestCases := []struct {
		name                     string
		seed                     uint64
		wantSHA512VaringStartPos []byte
		wantSHA512VaringEndPos   []byte
	}{
		{
			"inv seed 00s",
			numsAllZeros,
			decodeHexOrPanic("5de228628eb602cc3e9cad7f2c9698a17589aabbbc4426fe5db7e8779f9d7510739c7f5a6a0f011a0071922410bddc3f912754f9f52c1fcfab9f067b2e135924"),
			decodeHexOrPanic("f20a0bc89a8c3a9547c708e17520d8c3fd58dae9026d623849b6d4f096f7641fc78dc3cc5fcba8de498ffa7124aacf369e9c26b8578fffcb2e6ef3fb5334f626"),
		},

		{
			"inv seed 55s",
			numsAll55s,
			decodeHexOrPanic("32613848874a93e43ea3db6ec6c160b052d80c86831262162ba413bdf3da9107bb367e8d69d1c7b5086493ea101f059694943174e25cb269b6fe66cc0ba92f08"),
			decodeHexOrPanic("1459a581c50a7eaaf95980ec186217e8073152810373499aa65da81055421eb506d558ce632e70b92882e02490843d36967c75fc807d95d2f302a1968e72b2ba"),
		},

		{
			"inv seed AAs",
			numsAllAAs,
			decodeHexOrPanic("0e3bfed4a9d6bfc1f63276d1b0664b391484f18274bf36c2a206d7a36af74c3f6fd418dda361ba0558546c8e1cd384abeec7362822f1d43c406120655843cd44"),
			decodeHexOrPanic("210f1daec1051da6bc08520c670b9cb0823106212abbc97912b005903597fc8822663ac82855ba7bebdaac4c2fc53d95abdc11d64c2a8a9473f4bb16cd62d026"),
		},

		{
			"inv seed FFs",
			numsAllFFs,
			decodeHexOrPanic("2bb421510b20803d47d81616e01a5e9fec80455ba4c2790f5e913fa2ff4cca9c87f0e00ec1f90ddc93cb2803f438945eda5f25c4b7ae076e4b63e6d80c3c2fe7"),
			decodeHexOrPanic("37bd28edff26adf06bd915d5b13261301c4e9ac1b8cd3f6c1072f9515b1182beabec5e186bf607d04ac950264b497e5c3dea03ec2f6042e74bd608b98fff2223"),
		},

		{
			"inv seed GR",
			numsGoldenRatio,
			decodeHexOrPanic("18d7a3c93ec537ab3223cd8144d2ef613b2a8cec5ac5cd9ce4952c4f67448fd99a01ee813f78584da05dd536c11052e974d346359f4e845470d344c2f0ac209a"),
			decodeHexOrPanic("2cd2944d539ef7ef08d0d1d40d05141928131e51fe5f4dc714d0992da77c461af2930dda506beb17fa81e2b94ebe8285f46046354a40c08b2bab2ae60b0c038d"),
		},

		{
			"inv seed GRI",
			numsGoldenRatioInv,
			decodeHexOrPanic("977c8d171582b8dd41b6ad5909af7a45d8c62a5b16b32c2fc2d83986e98c2dca0e62748660ff68de89ec14ceed7fdddf29d99441870259be32f940c01202597f"),
			decodeHexOrPanic("a9bb403ffa62c5eb65dccf9017233383c23f12a1c82957e1f630a48f3785ef53b2637da91369dbeb8ec52865ec44fba175021d1eea6c87c4ed6cd2fee33dc363"),
		},
	}

	for _, tc := range invertedTestCases {
		t.Run(fmt.Sprintf(tc.name), func(t *testing.T) {

			h := sha512.New()

			// verify hash of 1-16384 bytes of test data by varying start pos
			checksumVaryingStartPos(t, h, tc.seed, datainv)
			got := h.Sum(nil)
			if !bytes.Equal(got, tc.wantSHA512VaringStartPos) {
				t.Errorf("checksumVaryingStartPos(nonuniform16KiB) = 0x%0128x; want 0x%0128x",
					got,
					tc.wantSHA512VaringStartPos)
			}

			h.Reset()

			// verify hash of 1-16384 bytes of test data by varying end pos
			checksumVaryingEndPos(t, h, tc.seed, datainv)
			got = h.Sum(nil)
			if !bytes.Equal(got, tc.wantSHA512VaringEndPos) {
				t.Errorf("checksumVaryingEndPos(nonuniform16KiB) = 0x%0128x; want 0x%0128x",
					got,
					tc.wantSHA512VaringEndPos)
			}
		})
	}

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
// 412895cdfdf6fd60181cd709b6aed89cce63ede8402531185c969de50eb04ae3
// 5d042d7b2758d02f97c6b13b1a397e2fbeca7ceb07c606f3602bed97984f99c6
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
	digest2 := Hash64String(string(data), seed)
	if digest != digest2 {
		t.Errorf("Hash64() 0x%x != Hash64String() 0x%x", digest, digest2)
	}

	if len(data) == 16 {
		a := binary.LittleEndian.Uint64(data)
		b := binary.LittleEndian.Uint64(data[8:])
		digest3 := Hash64Uint64x2(a, b, seed)
		if digest != digest3 {
			t.Errorf("Hash64() 0x%x != Hash64Uint64x2() 0x%x", digest, digest3)
		}
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
