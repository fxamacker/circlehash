<p align="center">
  <img height="120" src="https://user-images.githubusercontent.com/33205765/158502446-f96d007e-2b58-46af-88a0-895a475af958.png" />
<p/>

<p align="center">
  <a href="https://github.com/fxamacker/circlehash/actions?query=workflow%3ACI">
    <img src="https://github.com/fxamacker/circlehash/workflows/CI/badge.svg" />
  </a>
  <a href="https://github.com/fxamacker/circlehash/actions?query=workflow%3Alinters">
    <img src="https://github.com/fxamacker/circlehash/workflows/linters/badge.svg" />
  </a> 
  <a href="https://github.com/fxamacker/circlehash/actions/workflows/codeql-analysis.yml">
    <img src="https://github.com/fxamacker/circlehash/actions/workflows/codeql-analysis.yml/badge.svg" />
  </a>
  <a href="https://github.com/fxamacker/circlehash/actions?query=workflow%3A%22cover+100%25%22">
    <img src="https://github.com/fxamacker/circlehash/workflows/cover%20100%25/badge.svg" />
  </a>
</p>

# CircleHash

CircleHash is a family of modern non-cryptographic hash functions.

CircleHash64 is a 64-bit hash with a 64-bit seed.  It's fast, simple, and easy to audit.  It uses fractional digits of **π** as default constants ([nothing up my sleeve](https://en.wikipedia.org/wiki/Nothing-up-my-sleeve_number)).  It balances speed, digest quality, and maintainability.

CircleHash64 is based on [Google's Abseil C++ library](https://abseil.io/about/) internal hash.  It passes every test in SMHasher (demerphq/smhasher, rurban/smhasher, and my stricter test suite).  Tests passed include  Bit Independence Criterion, [Strict Avalanche Criterion](https://en.wikipedia.org/wiki/Avalanche_effect#Strict_avalanche_criterion), etc.

Three CircleHash64 functions are currently used in production (on linux_amd64):

```Go
func Hash64(b []byte, seed uint64) uint64
func Hash64String(s string, seed uint64) uint64
func Hash64Uint64x2(a uint64, b uint64, seed uint64) uint64 
```

ℹ️ Non-cryptographic hashes should only be used in software designed to properly handle hash collisions.  If you require a secure hash, please use a cryptographic hash (like the ones in SHA-3 standard).

## Comparisons

### Strict Avalanche Criterion (SAC)

|                | CircleHash64 | Abseil C++ | SipHash-2-4 | xxh64 |
| :---           | :---:         | :---:  | :---: | :---: |
| SAC worst-bit <br/> 0-128 byte inputs <br/> (lower % is better) | 0.791% 🥇 <br/> w/ 99 bytes | 0.862% <br/> w/ 67 bytes | 0.852% <br/> w/ 125 bytes | 0.832% <br/> w/ 113 bytes |

☝️ Using demerphq/smhasher updated to test all input sizes 0-128 bytes (SAC test will take hours longer to run).

### Speed: Hash Short Inputs with 64-bit Seed
|              | CircleHash64 | XXH3 | XXH64 <br/>(w/o seed) | SipHash |
|:-------------|:---:|:---:|:---:|:---:|
| 4 bytes | 1.34 GB/s | 1.21 GB/s| 0.877 GB/s | 0.361 GB/s |
| 8 bytes | 2.70 GB/s | 2.41 GB/s | 1.68 GB/s | 0.642 GB/s |
| 16 bytes | 5.48 GB/s | 5.21 GB/s | 2.94 GB/s | 1.03 GB/s |
| 32 bytes | 8.01 GB/s | 7.08 GB/s | 3.33 GB/s | 1.46 GB/s |
| 64 bytes | 10.3 GB/s | 9.33 GB/s | 5.47 GB/s | 1.83 GB/s |
| 128 bytes | 12.8 GB/s | 11.6 GB/s | 8.22 GB/s | 2.09 GB/s |
| 192 bytes | 14.2 GB/s | 9.86 GB/s | 9.71 GB/s | 2.17 GB/s |
| 256 bytes | 15.0 GB/s | 8.19 GB/s | 10.2 GB/s | 2.22 GB/s |

- Go 1.17.7, darwin_amd64, i7-1068N7 CPU.
- Fastest XXH64 (written in Go+Assembly) doesn't support seed.

## Why CircleHash?

I wanted a fast, maintainable, and easy-to-audit 64-bit hash function that's free of backdoors and bugs.  It needed to be very fast at hashing short inputs with a  64-bit seed.

It also needed to pass all tests in demerphq/smhasher, rurban/smhasher, and my test suite.  And have sufficiently explained choice of default constants and avoid over-optimizations that increase risk of being affected by bad seeds or efficient seed-independent attacks.

Existing non-cryptographic hash libraries in Go either failed SMhasher tests, didn't support seeds, were too slow, were overly complicated, lacked sufficient explanation for their default constants, lacked sufficient tests, or appeared to be unmaintained.

## CircleHash Design

After testing and evaluations, I chose a slightly more conservative design than Go 1.17 internal hash and wyhash_final3 variants.  CircleHash64 functions are based primarily on [Abseil's](https://abseil.io/about/) internal hash (which was based on an older wyhash).

> Abseil is an open source collection of C++ libraries drawn from the most fundamental pieces of Google’s internal codebase. These libraries are the nuts-and-bolts that underpin almost everything Google runs. [...] Abseil encompasses the most basic building blocks of Google’s codebase: code that is production-tested and will be fully maintained for years to come.

CircleHash64 comes in two flavors:

- 🛡️ **CircleHash64fx** (unlike Abseil's internal hash) shields against losing accumulated state from potential multiplication by zero. It's a bit slower than CircleHash64f but remains among the fastest for short inputs. Users who don't mind giving up this protection in exchange for speed can choose CircleHash64f.

- 🚀 **CircleHash64f** can be configured to produce same digests as Abseil LTS 20210324.2.  By default, CircleHash64f uses two different 64-bit constants rather than using the same 64-bit constant twice at finalization.  And unlike internal hashes, CircleHash64f offers backward compatibility (SemVer 2.0).

CircleHash64 uses CircleHash64f by default and supports 64-bit seeds.  It was created when I needed a very fast seeded hash for inputs mostly <= 128 bytes.

## Benchmarks

CircleHash64 is ideal for input sizes <= 512 bytes.  Larger inputs can be hashed faster using other CircleHash designs (not yet published).

For best results, it's better to run your own benchmarks on your own hardware with your most common data sizes.

Until detailed benchmarks are published, please view [Comparisons](README.md#Comparisons) for some preliminary results.

## Status

CircleHash64 is currently used in production on linux_amd64.  Other platforms may work but they are not officially supported yet.

The most important files are:

- circlehash64_ref.go -- reference implementation used by Go 1.16 and older versions.
- circlehash64.go -- faster implementation used by Go 1.17 and newer versions.
- circlehash64_test.go -- tests that verify digests with expected results for various input sizes using different seeds.  Rather than port SMHasher and other test suites to Go, the C++ implementation is used for those additional tests.

A more extensive and idiomatic API is being considered.  However, currently exported CircleHash64 functions are unlikely to be affected.

CircleHash64fx has not yet been published because CircleHash64f (aka CircleHash64) is faster and there hasn't been a need.

## Release Policy

This project uses Semantic Versioning 2.0.  

As an exception, some variants of CircleHash may be declared stable before this repo reaches v1.0.  I.e. given the same input data, the hash function will always produce the same digest.  Such declarations will be noted in the README and applicable release notes.

CircleHash64f is stable.  Given the same input data and seed, it will always produce the same digest in future versions.

## Contributing

Please read [contributing guide](CONTRIBUTING.md) if you would like to contribute to CircleHash.

## Special Thanks and Credits
  - Go Team for making programming more fun and productive.
  - Abseil team for producing some of the best and cleanest C++ code I've ever seen.
  - Reini Urban and Yves Orton for publishing their SMHasher improvements in rurban/smhasher and demerphq/smhasher.
  - Montgomery Edwards⁴⁴⁸ for proof-reading my draft README and offering helpful suggestions.

## License

The CircleHash library is licensed under the terms of the Apache license. See [LICENSE](LICENSE) for more information.

Copyright © 2021-2022 Faye Amacker.
