# noble-curves

Minimal, zero-dependency JS implementation of elliptic curve cryptography.

- Short Weierstrass, Edwards, Montgomery curves
- ECDSA, EdDSA, Schnorr, BLS signature schemes
- ECDH key agreement
- [hash to curve](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/) algorithms for encoding or hashing an arbitrary string to a point on an elliptic curve
- Auditable, [fast](#speed)
- 🔻 Helps JS bundlers with lack of entry point, ensures small size of your app
- 🔍 Unique tests ensure correctness. Wycheproof vectors included

To keep the package minimal, no curve definitions are provided out-of-box. Use `micro-curve-definitions` module:

- It provides P192, P224, P256, P384, P521, secp256k1, stark, bn254, pasta (pallas/vesta), ed25519, ed448 & bls12-381 curves
- Main reason for separate package is the fact hashing library (like @noble/hashes) is required for full functionality
- We may reconsider merging packages in future, when a stable version would be ready

The goal for the near future is to update previous packages
([secp256k1](https://github.com/paulmillr/noble-secp256k1),
[ed25519](https://github.com/paulmillr/noble-ed25519),
[bls12-381](https://github.com/paulmillr/noble-bls12-381)) with lean UMD builds based on noble-curves. This would improve compatibility & allow having one codebase for everything.

### This library belongs to _noble_ crypto

> **noble-crypto** — high-security, easily auditable set of contained cryptographic libraries and tools.

- No dependencies, small files
- Easily auditable TypeScript/JS code
- Supported in all major browsers and stable node.js versions
- All releases are signed with PGP keys
- Check out [homepage](https://paulmillr.com/noble/) & all libraries:
  [curves](https://github.com/paulmillr/noble-curves) ([secp256k1](https://github.com/paulmillr/noble-secp256k1),
  [ed25519](https://github.com/paulmillr/noble-ed25519),
  [bls12-381](https://github.com/paulmillr/noble-bls12-381)),
  [hashes](https://github.com/paulmillr/noble-hashes)

## Usage

Use NPM in node.js / browser, or include single file from
[GitHub's releases page](https://github.com/paulmillr/noble-curves/releases):

> npm install @noble/curves

The library does not have an entry point. It allows you to select specific primitives and drop everything else. If you only want to use secp256k1, just use the library with rollup or other bundlers. This is done to make your bundles tiny.

```ts
import { weierstrass } from '@noble/curves/weierstrass'; // Short Weierstrass curve
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { concatBytes, randomBytes } from '@noble/hashes/utils';

const secp256k1 = weierstrass({
  a: 0n,
  b: 7n,
  P: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
  n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
  Gx: 55066263022277343669578718895168534326250603453777594175500187360389116729240n,
  Gy: 32670510020758816978083085130507043184471273380659243275938904335757337482424n,
  hash: sha256,
  hmac: (k: Uint8Array, ...msgs: Uint8Array[]) => hmac(sha256, key, concatBytes(...msgs)),
});

const key = secp256k1.utils.randomPrivateKey();
const pub = secp256k1.getPublicKey(key);
const msg = randomBytes(32);
const sig = secp256k1.sign(msg, key);
secp256k1.verify(sig, msg, pub); // true
sig.recoverPublicKey(msg); // == pub
const someonesPubkey = secp256k1.getPublicKey(secp256k1.utils.randomPrivateKey());
const shared = secp256k1.getSharedSecret(key, someonesPubkey);
```

## API

- [Overview](#overview)
- [edwards: Twisted Edwards curve](#edwards-twisted-edwards-curve)
- [montgomery: Montgomery curve](#montgomery-montgomery-curve)
- [weierstrass: Short Weierstrass curve](#weierstrass-short-weierstrass-curve)
- [modular](#modular)
- [utils](#utils)

### Overview

* To initialize new curve, you must specify its variables, order (number of points on curve), field prime (over which the modular division would be done)
* All curves expose same generic interface:
    * `getPublicKey()`, `sign()`, `verify()` functions
    * `Point` conforming to `Group` interface with add/multiply/double/negate/add/equals methods
    * `CURVE` object with curve variables like `Gx`, `Gy`, `P` (field), `n` (order)
    * `utils` object with `randomPrivateKey()`, `mod()`, `invert()` methods (`mod CURVE.P`)
* All arithmetics is done with JS bigints over finite fields
* Many features require hashing, which is not provided. `@noble/hashes` can be used for this purpose.
  Any other library must conform to the CHash interface:
    ```ts
    export type CHash = {
      (message: Uint8Array): Uint8Array;
      blockLen: number; outputLen: number; create(): any;
    };
    ```
* w-ary non-adjacent form (wNAF) method with constant-time adjustments is used for point multiplication.
  It is possible to enable precomputes for edwards & weierstrass curves.
  Precomputes are calculated once (takes ~20-40ms), after that most `G` multiplications
  - for example, `getPublicKey()`, `sign()` and similar methods - would be much faster.
  Use `curve.utils.precompute()`
* Special params that tune performance can be optionally provided. For example:
    * `sqrtMod` square root calculation, used for point decompression
    * `endo` endomorphism options for Koblitz curves

### edwards: Twisted Edwards curve

Twisted Edwards curve's formula is: ax² + y² = 1 + dx²y².

* You must specify curve params `a`, `d`, field `P`, order `n`, cofactor `h`, and coordinates `Gx`, `Gy` of generator point.
* For EdDSA signatures, params `hash` is also required. `adjustScalarBytes` which instructs how to change private scalars could be specified.

```typescript
import { twistedEdwards } from '@noble/curves/edwards'; // Twisted Edwards curve
import { sha512 } from '@noble/hashes/sha512';
import * as mod from '@noble/curves/modular';

const ed25519 = twistedEdwards({
  a: -1n,
  d: mod.div(-121665n, 121666n, 2n ** 255n - 19n), // -121665n/121666n
  P: 2n ** 255n - 19n,
  n: 2n ** 252n + 27742317777372353535851937790883648493n,
  h: 8n,
  Gx: 15112221349535400772501151409588531511454012693041857206046113283949847762202n,
  Gy: 46316835694926478169428394003475163141307993866256225615783033603165251855960n,
  hash: sha512,
  randomBytes,
  adjustScalarBytes(bytes) { // optional
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    return bytes;
  },
} as const);
ed25519.getPublicKey(ed25519.utils.randomPrivateKey());
```

`twistedEdwards()` returns `CurveFn` of following type:

```ts
export type CurveFn = {
  CURVE: ReturnType<typeof validateOpts>;
  getPublicKey: (privateKey: PrivKey, isCompressed?: boolean) => Uint8Array;
  sign: (message: Hex, privateKey: Hex) => Uint8Array;
  verify: (sig: SigType, message: Hex, publicKey: PubKey) => boolean;
  Point: PointConstructor;
  ExtendedPoint: ExtendedPointConstructor;
  Signature: SignatureConstructor;
  utils: {
    mod: (a: bigint, b?: bigint) => bigint;
    invert: (number: bigint, modulo?: bigint) => bigint;
    randomPrivateKey: () => Uint8Array;
    getExtendedPublicKey: (key: PrivKey) => {
      head: Uint8Array;
      prefix: Uint8Array;
      scalar: bigint;
      point: PointType;
      pointBytes: Uint8Array;
    };
  };
};
```

### montgomery: Montgomery curve

For now the module only contains methods for x-only ECDH on Curve25519 / Curve448 from RFC7748.

Proper Elliptic Curve Points are not implemented yet.

You must specify curve field, `a24` special variable, `montgomeryBits`, `nByteLength`, and coordinate `u` of generator point.

```typescript
const x25519 = montgomery({
  P: 2n ** 255n - 19n,
  a24: 121665n, // TODO: change to a
  montgomeryBits: 255,
  nByteLength: 32,
  Gu: '0900000000000000000000000000000000000000000000000000000000000000',

  // Optional params
  powPminus2: (x: bigint): bigint => { return mod.pow(x, P-2, P); },
  adjustScalarBytes(bytes) {
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    return bytes;
  },
});
```

### weierstrass: Short Weierstrass curve

Short Weierstrass curve's formula is: y² = x³ + ax + b. Uses deterministic ECDSA from RFC6979. You can also specify `extraEntropy` in `sign()`.

* You must specify curve params: `a`, `b`; field `P`; curve order `n`; coordinates `Gx`, `Gy` of generator point
* For ECDSA, you must specify `hash`, `hmac`. It is also possible to recover keys from signatures
* For ECDH, use `getSharedSecret(privKeyA, pubKeyB)`
* Optional params are `lowS` (default value), `sqrtMod` (square root chain) and `endo` (endomorphism)

```typescript
import { weierstrass } from '@noble/curves/weierstrass'; // Short Weierstrass curve
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { concatBytes, randomBytes } from '@noble/hashes/utils';

const secp256k1 = weierstrass({
  // Required params
  a: 0n,
  b: 7n,
  P: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
  n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
  Gx: 55066263022277343669578718895168534326250603453777594175500187360389116729240n,
  Gy: 32670510020758816978083085130507043184471273380659243275938904335757337482424n,
  hash: sha256,
  hmac: (k: Uint8Array, ...msgs: Uint8Array[]) => hmac(sha256, key, concatBytes(...msgs)),
  randomBytes,

  // Optional params
  // Cofactor
  h: BigInt(1),
  // Allow only low-S signatures by default in sign() and verify()
  lowS: true,
  // More efficient curve-specific implementation of square root
  sqrtMod(y: bigint) { return sqrt(y); },
  // Endomorphism options
  endo: {
    // Beta param
    beta: BigInt('0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee'),
    // Split scalar k into k1, k2
    splitScalar: (k: bigint) => {
      return { k1neg: true, k1: 512n, k2neg: false, k2: 448n };
    },
  },
});

// Usage
const key = secp256k1.utils.randomPrivateKey();
const pub = secp256k1.getPublicKey(key);
const msg = randomBytes(32);
const sig = secp256k1.sign(msg, key);
secp256k1.verify(sig, msg, pub); // true
sig.recoverPublicKey(msg); // == pub
const someonesPubkey = secp256k1.getPublicKey(secp256k1.utils.randomPrivateKey());
const shared = secp256k1.getSharedSecret(key, someonesPubkey);
```

`weierstrass()` returns `CurveFn`:

```ts
export type CurveFn = {
  CURVE: ReturnType<typeof validateOpts>;
  getPublicKey: (privateKey: PrivKey, isCompressed?: boolean) => Uint8Array;
  getSharedSecret: (privateA: PrivKey, publicB: PubKey, isCompressed?: boolean) => Uint8Array;
  sign: (msgHash: Hex, privKey: PrivKey, opts?: SignOpts) => SignatureType;
  verify: (
    signature: Hex | SignatureType, msgHash: Hex, publicKey: PubKey, opts?: {lowS?: boolean;}
  ) => boolean;
  Point: PointConstructor;
  ProjectivePoint: ProjectivePointConstructor;
  Signature: SignatureConstructor;
  utils: {
    mod: (a: bigint, b?: bigint) => bigint;
    invert: (number: bigint, modulo?: bigint) => bigint;
    isValidPrivateKey(privateKey: PrivKey): boolean;
    hashToPrivateKey: (hash: Hex) => Uint8Array;
    randomPrivateKey: () => Uint8Array;
  };
};
```

### modular

Modular arithmetics utilities.

```typescript
import * as mod from '@noble/curves/modular';
mod.mod(21n, 10n); // 21 mod 10 == 1n; fixed version of 21 % 10
mod.invert(17n, 10n); // invert(17) mod 10; modular multiplicative inverse
mod.div(5n, 17n, 10n); // 5/17 mod 10 == 5 * invert(17) mod 10; division
mod.invertBatch([1n, 2n, 4n], 21n); // => [1n, 11n, 16n] in one inversion
mod.sqrt(21n, 73n); // sqrt(21) mod 73; square root
```

### utils

```typescript
import * as utils from '@noble/curves/utils';

utils.bytesToHex(Uint8Array.from([0xde, 0xad, 0xbe, 0xef]));
utils.hexToBytes('deadbeef');
utils.hexToNumber();
utils.bytesToNumberBE(Uint8Array.from([0xde, 0xad, 0xbe, 0xef]));
utils.bytesToNumberLE(Uint8Array.from([0xde, 0xad, 0xbe, 0xef]));
utils.numberToBytesBE(123n);
utils.numberToBytesLE(123n);
utils.numberToHexUnpadded(123n);
utils.concatBytes(Uint8Array.from([0xde, 0xad]), Uint8Array.from([0xbe, 0xef]));
utils.nLength(255n);
utils.hashToPrivateScalar(sha512_of_something, secp256r1.n);
utils.equalBytes(Uint8Array.from([0xde]), Uint8Array.from([0xde]));
```

## Security

The library had no prior security audit.

[Timing attack](https://en.wikipedia.org/wiki/Timing_attack) considerations: _JIT-compiler_ and _Garbage Collector_ make "constant time" extremely hard to achieve in a scripting language. Which means _any other JS library can't have constant-timeness_. Even statically typed Rust, a language without GC, [makes it harder to achieve constant-time](https://www.chosenplaintext.ca/open-source/rust-timing-shield/security) for some cases. If your goal is absolute security, don't use any JS lib — including bindings to native ones. Use low-level libraries & languages. Nonetheless we're targetting algorithmic constant time.

We consider infrastructure attacks like rogue NPM modules very important; that's why it's crucial to minimize the amount of 3rd-party dependencies & native bindings. If your app uses 500 dependencies, any dep could get hacked and you'll be downloading malware with every `npm install`. Our goal is to minimize this attack vector.

## Speed

Benchmark results on Apple M2 with node v18.10:

```
==== secp256k1 ====
  - getPublicKey1 (samples: 10000)
    noble_old x 8,131 ops/sec @ 122μs/op
    secp256k1 x 7,374 ops/sec @ 135μs/op
  - getPublicKey255 (samples: 10000)
    noble_old x 7,894 ops/sec @ 126μs/op
    secp256k1 x 7,327 ops/sec @ 136μs/op
  - sign (samples: 5000)
    noble_old x 5,243 ops/sec @ 190μs/op
    secp256k1 x 4,834 ops/sec @ 206μs/op
  - getSharedSecret (samples: 1000)
    noble_old x 653 ops/sec @ 1ms/op
    secp256k1 x 634 ops/sec @ 1ms/op
  - verify (samples: 1000)
    secp256k1_old x 1,038 ops/sec @ 962μs/op
    secp256k1 x 1,009 ops/sec @ 990μs/op
==== ed25519 ====
  - getPublicKey (samples: 10000)
    old x 8,632 ops/sec @ 115μs/op
    noble x 8,390 ops/sec @ 119μs/op
  - sign (samples: 5000)
    old x 4,376 ops/sec @ 228μs/op
    noble x 4,233 ops/sec @ 236μs/op
  - verify (samples: 1000)
    old x 865 ops/sec @ 1ms/op
    noble x 860 ops/sec @ 1ms/op
==== ed448 ====
  - getPublicKey (samples: 5000)
    noble x 3,224 ops/sec @ 310μs/op
  - sign (samples: 2500)
    noble x 1,561 ops/sec @ 640μs/op
  - verify (samples: 500)
    noble x 313 ops/sec @ 3ms/op
==== nist ====
  - getPublicKey (samples: 2500)
    P256 x 7,993 ops/sec @ 125μs/op
    P384 x 3,819 ops/sec @ 261μs/op
    P521 x 2,074 ops/sec @ 481μs/op
  - sign (samples: 1000)
    P256 x 5,327 ops/sec @ 187μs/op
    P384 x 2,728 ops/sec @ 366μs/op
    P521 x 1,594 ops/sec @ 626μs/op
  - verify (samples: 250)
    P256 x 806 ops/sec @ 1ms/op
    P384 x 353 ops/sec @ 2ms/op
    P521 x 171 ops/sec @ 5ms/op
==== stark ====
  - pedersen (samples: 500)
    old x 85 ops/sec @ 11ms/op
    noble x 1,216 ops/sec @ 822μs/op
  - verify (samples: 500)
    old x 302 ops/sec @ 3ms/op
    noble x 698 ops/sec @ 1ms/op
```

## Contributing & testing

1. Clone the repository
2. `npm install` to install build dependencies like TypeScript
3. `npm run build` to compile TypeScript code
4. `npm run test` will execute all main tests

## License

The MIT License (MIT)

Copyright (c) 2022 Paul Miller [(https://paulmillr.com)](https://paulmillr.com)

See LICENSE file.
