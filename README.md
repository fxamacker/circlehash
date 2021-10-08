# CircleHash

[![](https://github.com/fxamacker/circlehash/workflows/CI/badge.svg)](https://github.com/fxamacker/circlehash/actions?query=workflow%3ACI)
[![](https://github.com/fxamacker/circlehash/workflows/cover%20100%25/badge.svg)](https://github.com/fxamacker/circlehash/actions?query=workflow%3A%22cover+100%25%22)
[![](https://github.com/fxamacker/circlehash/workflows/linters/badge.svg)](https://github.com/fxamacker/circlehash/actions?query=workflow%3Alinters)

CircleHash is a family of non-cryptographic hash functions that pass every test in SMHasher (demerphq/smhasher, rurban/smhasher, and mine).  Tests passed include Strict Avalanche Criterion, Bit Independence Criterion, and many others.

CircleHash64 uses the fractional digits of **π** as default constants ([nothing up my sleeve](https://en.wikipedia.org/wiki/Nothing-up-my-sleeve_number)). The code is simple and easy to audit.  I tried to balance competing factors such as speed, digest quality, and maintainability.

CircleHash64 is based on [Google's Abseil C++ library](https://abseil.io/about/) internal hash.  🚀  Unoptimized CircleHash64 in C++ is fast as Abseil C++ internal hash.  CircleHash64 has good results for [Strict Avalanche Criterion (SAC)](https://en.wikipedia.org/wiki/Avalanche_effect#Strict_avalanche_criterion).

|                | CircleHash64 | Abseil C++ | SipHash-2-4 |
| :---           | :---:         | :---:  | :---: |
| SAC worst-bit <br/> 0-32 byte inputs <br/> (lower % is better) | 0.754% <br/> w/ 29 bytes | 0.829% <br/> w/ 22 bytes | 0.768% <br/> w/ 29 bytes |

☝️ Using demerphq/smhasher updated to test all input sizes 0-32 bytes (tests will take much longer to finish).

ℹ️ Non-cryptographic hashes should only be used in software designed to properly handle hash collisions.  If you require a secure hash, please use a cryptographic hash (like the ones in SHA-3 standard).

## Why CircleHash?

I wanted a very fast, maintainable, and easy-to-audit hash function that's free of backdoors and bugs.

It needed to pass all tests in demerphq/smhasher, rurban/smhasher, and my test suite.  It also needed to have sufficiently explained choice of default constants and avoid over-optimizations that increase risk of being affected by bad seeds or efficient seed-independent attacks.

Existing non-cryptographic hash libraries in Go either failed SMhasher tests, didn't support seeds, were too slow, were overly complicated, lacked sufficient explanation for their default constants, lacked sufficient tests, or appeared to be unmaintained.

## CircleHash Design

After testing and evaluations, I chose a slightly more conservative design than Go 1.17 internal hash and wyhash_final3 variants.  CircleHash64 functions are based primarily on [Abseil's](https://abseil.io/about/) internal hash (which was based on an older wyhash).

> Abseil is an open source collection of C++ libraries drawn from the most fundamental pieces of Google’s internal codebase. These libraries are the nuts-and-bolts that underpin almost everything Google runs. [...] Abseil encompasses the most basic building blocks of Google’s codebase: code that is production-tested and will be fully maintained for years to come.

CircleHash64 comes in two flavors:

- 🛡️ **CircleHash64fx** (unlike Abseil's internal hash) shields against losing accumulated state from potential multiplication by zero. It's a bit slower than CircleHash64f but remains among the fastest for short inputs. Users who don't mind giving up this protection in exchange for speed can choose CircleHash64f.

- 🚀 **CircleHash64f** can be configured to produce same digests as Abseil LTS 20210324.2.  By default, CircleHash64f uses two different 64-bit constants rather than using the same 64-bit constant twice at finalization.  And unlike internal hashes, CircleHash64f offers backward compatibility (SemVer 2.0).

CircleHash64 uses CircleHash64f by default and supports 64-bit seeds.

## CircleHash Speed in Go and C++

CircleHash64 is among the fastest hashes for short inputs. Unoptimized CircleHash64 in Go is faster than optimized XXH64 in Go+Assembly.

CircleHash64 is faster than executing this assignment just once in a Go program:

```Go 
     foo = uint64_a % uint64_b  // slower than CircleHash64f and CircleHash64fx on Haswell Xeon
```

Speeds were compared using Go 1.16.8 on linux_amd64 (Haswell CPU) with unoptimized CircleHash64. On newer Intel CPUs the modulus can be slightly faster.

## Benchmarks

Coming soon... For best results, it's better to do your own benchmarks using your own hardware and your most common data sizes.

## Status [DRAFT]
  - [x] dependable release policy: all tests must pass and enforce Semantic Versioning 2.0
  - [x] readable and easy-to-audit code with nothing-up-my-sleeve constants
  - [x] faster than Go 1.16 compiled program executing `foo = uint64_a % uint64_b` on Haswell Xeon CPU
  - [x] pass all tests
      - [x] rurban/smhasher
      - [x] demerphq/smhasher
      - [x] custom (harder to pass) version of SMHasher 
      - [x] CircleHash64f configured for compatibility with Abseil LTS 20210324.2
      - [x] CircleHash64f configured for improved entropy in finalization
      - [ ] CircleHash64f and CircleHash64fx compatibility tests
          - [x] Go 1.15, 1.16, 1.17 on linux_amd64
          - [x] Go 1.15, 1.16, 1.17 on darwin_amd64
          - [x] C++ (g++ 9.3) on linux x86_64
          - [ ] Go 1.15, 1.16, 1.17 on linux_arm64
      - [ ] Additional tests
          - [ ] additional 64-bit archs
          - [ ] 32-bit archs
          - [ ] long-running collision tests (need big server 256 GB RAM)
  - [x] publish reference code for CircleHash64f in Go
  - [ ] publish reference code for CircleHash64fx in Go
  - [ ] publish compatibility test vectors for CircleHash64f
  - [ ] publish benchmarks for unoptimized CircleHash64 reference implementation (Go)
  - [ ] provide implementations in other languages
  - [ ] provide optional functions for creating high quality seeds
  - [ ] provide optional functions for creating high quality constants (to override **π**)

## Release Policy

This project uses Semantic Versioning 2.0.

## Special Thanks and Credits
  - Go Team for making programming more fun and productive.
  - Abseil team for producing some of the best and cleanest C++ code I've ever seen.
  - Reini Urban and Yves Orton for publishing their SMHasher improvements in rurban/smhasher and demerphq/smhasher.
  - Montgomery Edwards⁴⁴⁸ for proof-reading my draft README and offering helpful suggestions.

## License

The CircleHash library is licensed under the terms of the Apache license. See [LICENSE](LICENSE) for more information.

Copyright © 2021 Faye Amacker.
