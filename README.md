# CircleHash

[![](https://github.com/fxamacker/circlehash/workflows/CI/badge.svg)](https://github.com/fxamacker/circlehash/actions?query=workflow%3ACI)
[![](https://github.com/fxamacker/circlehash/workflows/cover%20%E2%89%A598%25/badge.svg)](https://github.com/fxamacker/circlehash/actions?query=workflow%3A%22cover+%E2%89%A598%25%22)
[![](https://github.com/fxamacker/circlehash/workflows/linters/badge.svg)](https://github.com/fxamacker/circlehash/actions?query=workflow%3Alinters)

CircleHash is a family of non-cryptographic hash functions that pass every test in SMHasher (both rurban/smhasher and demerphq/smhasher).  Tests passed include [Strict Avalanche Criterion](https://en.wikipedia.org/wiki/Avalanche_effect#Strict_avalanche_criterion), Bit Independence Criterion, and many others.

CircleHash uses the fractional digits of **π** as default constants ([nothing up my sleeve](https://en.wikipedia.org/wiki/Nothing-up-my-sleeve_number)). The code is simple and easy to audit.  I tried to balance competing factors such as speed, digest quality, and maintainability.

CircleHash64 variants produce 64-bit digests and support 64-bit seeds.  They are very fast and guaranteed to produce compatible digests within the same major release (SemVer 2.0).  

## Why CircleHash?

I wanted a very fast, maintainable, and easy-to-audit hash function that's free of backdoors and bugs.

It needed to pass all tests in both demerphq/smhasher and rurban/smhasher.  It also needed to have sufficiently explained choice of default constants and avoid over-optimizations that increase risk of being affected by bad seeds or efficient seed-independent attacks.

Existing non-cryptographic hash libraries in Go either failed SMhasher tests, didn't support seeds, were too slow, were overly complicated, lacked sufficient explanation for their default constants, lacked sufficient tests, or appeared to be unmaintained.  

## CircleHash Design

After testing and evaluations, I chose a slightly more conservative design than Go 1.17 internal hash and wyhash_final3 variants.  CircleHash64 functions are based primarily on [Abseil's](https://abseil.io/about/) internal hash (which was based on an older wyhash).

> Abseil is an open source collection of C++ libraries drawn from the most fundamental pieces of Google’s internal codebase. These libraries are the nuts-and-bolts that underpin almost everything Google runs. [...] Abseil encompasses the most basic building blocks of Google’s codebase: code that is production-tested and will be fully maintained for years to come.

CircleHash comes in two flavors:

- 🛡️ **CircleHash64s** (unlike Abseil's internal hash) shields against losing accumulated state from potential multiplication by zero. It's a bit slower than CircleHash64f but remains among the fastest for short inputs. Users who don't mind giving up this protection in exchange for speed can choose CircleHash64f.

- 🚀 **CircleHash64f** can be configured to produce same digests as Abseil LTS 20210324.2.  By default, CircleHash64f uses two different 64-bit constants rather than using the same 64-bit constant twice at finalization.  And unlike internal hashes, CircleHash64f offers backward compatibility (SemVer 2.0).

👉 Non-cryptographic hashes should only be used in software designed to properly handle hash collisions.  If you require a secure hash, please use a cryptographic hash (like the ones in SHA-3 standard).

## CircleHash Speed in Go and C++

CircleHash64f and CircleHash64s are extremely fast 64-bit hashes that support a 64-bit seed and an optional salt (320 bits).

:rocket: CircleHash64f and CircleHash64s are faster than executing this assignment just once in a Go program:

```Go 
     foo = uint64_a % uint64_b  // slower than CircleHash64f and CircleHash64s on Haswell Xeon
```

Speeds were compared using Go 1.16.8 on linux_amd64 (Haswell CPU) with CircleHash written in plain Go (no assembly).

When compiled with g++ 9.3 on linux_amd64 (Haswell CPU), CircleHash64f and CircleHash64s are among the fastest hashes for short inputs.

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
      - [x] CircleHash64f and CircleHash64s internal tests
          - [x] Go 16.8 on linux_amd64
          - [x] g++ 9.3 on linux x86_64
          - [ ] Go 16.8 on linux_arm64
          - [ ] additional systems
          - [ ] additional versions of Go
          - [ ] tidy up and publish internal test code
          - [ ] long-running collision tests (need big server 256 GB RAM)
  - [ ] publish compatibility test vectors
  - [ ] publish Go reference code for CircleHash64f
  - [ ] publish Go reference code for CircleHash64s
  - [ ] publish C++ version
  - [ ] release tag
  - [ ] detailed benchmarks and comparisons for every input size 0-64 bytes (and more)
  - [ ] provide implementations in other languages
  - [ ] provide optional functions for creating high quality seeds
  - [ ] provide optional functions for creating high quality constants (to override **π**)
  - [ ] maybe if time allows, test and support big-endian systems

## Comparisons

Coming...  

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
