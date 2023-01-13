# noble-curves

Minimal, auditable JS implementation of elliptic curve cryptography.

- Short Weierstrass, Edwards, Montgomery curves
- ECDSA, EdDSA, Schnorr, BLS signature schemes, ECDH key agreement
- [hash to curve](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/)
  for encoding or hashing an arbitrary string to a point on an elliptic curve
- Auditable, [fast](#speed)
- 🔍 Unique tests ensure correctness. Wycheproof vectors included
- 🔻 Tree-shaking-friendly: there is no entry point, which ensures small size of your app

There are two parts of the package:

1. `abstract/` directory specifies zero-dependency EC algorithms
2. root directory utilizes one dependency `@noble/hashes` and provides ready-to-use:
   - NIST curves secp192r1/P192, secp224r1/P224, secp256r1/P256, secp384r1/P384, secp521r1/P521
   - SECG curve secp256k1
   - pairing-friendly curves bls12-381, bn254
   - ed25519/curve25519/x25519/ristretto, edwards448/curve448/x448 RFC7748 / RFC8032 / ZIP215 stuff

Curves incorporate work from previous noble packages
([secp256k1](https://github.com/paulmillr/noble-secp256k1),
[ed25519](https://github.com/paulmillr/noble-ed25519),
[bls12-381](https://github.com/paulmillr/noble-bls12-381)),
which had security audits and were developed from 2019 to 2022.
The goal is to replace them with lean UMD builds based on single-codebase noble-curves.

### This library belongs to _noble_ crypto

> **noble-crypto** — high-security, easily auditable set of contained cryptographic libraries and tools.

- Minimal dependencies, small files
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
// Common.js and ECMAScript Modules (ESM)
import { secp256k1 } from '@noble/curves/secp256k1';

const key = secp256k1.utils.randomPrivateKey();
const pub = secp256k1.getPublicKey(key);
const msg = new Uint8Array(32).fill(1);
const sig = secp256k1.sign(msg, key);
secp256k1.verify(sig, msg, pub) === true;
sig.recoverPublicKey(msg) === pub;
const someonesPub = secp256k1.getPublicKey(secp256k1.utils.randomPrivateKey());
const shared = secp256k1.getSharedSecret(key, someonesPub);
```

All curves:

```ts
import { secp256k1 } from '@noble/curves/secp256k1';
import { ed25519, ed25519ph, ed25519ctx, x25519, RistrettoPoint } from '@noble/curves/ed25519';
import { ed448, ed448ph, ed448ctx, x448 } from '@noble/curves/ed448';
import { p256 } from '@noble/curves/p256';
import { p384 } from '@noble/curves/p384';
import { p521 } from '@noble/curves/p521';
import { pallas, vesta } from '@noble/curves/pasta';
import * as stark from '@noble/curves/stark';
import { bls12_381 } from '@noble/curves/bls12-381';
import { bn254 } from '@noble/curves/bn';
import { jubjub } from '@noble/curves/jubjub';
```

To define a custom curve, check out API below.

## API

- [Overview](#overview)
- [abstract/edwards: Twisted Edwards curve](#abstractedwards-twisted-edwards-curve)
- [abstract/montgomery: Montgomery curve](#abstractmontgomery-montgomery-curve)
- [abstract/weierstrass: Short Weierstrass curve](#abstractweierstrass-short-weierstrass-curve)
- [abstract/hash-to-curve: Hashing strings to curve points](#abstracthash-to-curve-hashing-strings-to-curve-points)
- [abstract/modular](#abstractmodular)
- [abstract/utils](#abstractutils)

### Overview

There are following zero-dependency abstract algorithms:

```ts
import { bls } from '@noble/curves/abstract/bls';
import { twistedEdwards } from '@noble/curves/abstract/edwards';
import { montgomery } from '@noble/curves/abstract/montgomery';
import { weierstrass } from '@noble/curves/abstract/weierstrass';
import * as mod from '@noble/curves/abstract/modular';
import * as utils from '@noble/curves/abstract/utils';
```

They allow to define a new curve in a few lines of code:

```ts
import { Fp } from '@noble/curves/abstract/modular';
import { weierstrass } from '@noble/curves/abstract/weierstrass';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { concatBytes, randomBytes } from '@noble/hashes/utils';

const secp256k1 = weierstrass({
  a: 0n,
  b: 7n,
  Fp: Fp(2n ** 256n - 2n ** 32n - 2n ** 9n - 2n ** 8n - 2n ** 7n - 2n ** 6n - 2n ** 4n - 1n),
  n: 2n ** 256n - 432420386565659656852420866394968145599n,
  Gx: 55066263022277343669578718895168534326250603453777594175500187360389116729240n,
  Gy: 32670510020758816978083085130507043184471273380659243275938904335757337482424n,
  hash: sha256,
  hmac: (key: Uint8Array, ...msgs: Uint8Array[]) => hmac(sha256, key, concatBytes(...msgs)),
  randomBytes,
});
```

- To initialize new curve, you must specify its variables, order (number of points on curve), field prime (over which the modular division would be done)
- All curves expose same generic interface:
  - `getPublicKey()`, `sign()`, `verify()` functions
  - `Point` conforming to `Group` interface with add/multiply/double/negate/add/equals methods
  - `CURVE` object with curve variables like `Gx`, `Gy`, `Fp` (field), `n` (order)
  - `utils` object with `randomPrivateKey()`, `mod()`, `invert()` methods (`mod CURVE.P`)
- All arithmetics is done with JS bigints over finite fields, which is defined from `modular` sub-module
- Many features require hashing, which is not provided. `@noble/hashes` can be used for this purpose.
  Any other library must conform to the CHash interface:
  ```ts
  export type CHash = {
    (message: Uint8Array): Uint8Array;
    blockLen: number;
    outputLen: number;
    create(): any;
  };
  ```
- w-ary non-adjacent form (wNAF) method with constant-time adjustments is used for point multiplication.
  It is possible to enable precomputes for edwards & weierstrass curves.
  Precomputes are calculated once (takes ~20-40ms), after that most `G` base point multiplications:
  for example, `getPublicKey()`, `sign()` and similar methods - would be much faster.
  Use `curve.utils.precompute()` to adjust precomputation window size
- You could use optional special params to tune performance:
  - `Fp({sqrt})` square root calculation, used for point decompression
  - `endo` endomorphism options for Koblitz curves

### abstract/edwards: Twisted Edwards curve

Twisted Edwards curve's formula is: ax² + y² = 1 + dx²y².

- You must specify curve params `a`, `d`, field `Fp`, order `n`, cofactor `h` and coordinates `Gx`, `Gy` of generator point
- For EdDSA signatures, params `hash` is also required. `adjustScalarBytes` which instructs how to change private scalars could be specified

```typescript
import { twistedEdwards } from '@noble/curves/abstract/edwards';
import { div } from '@noble/curves/abstract/modular';
import { sha512 } from '@noble/hashes/sha512';

const ed25519 = twistedEdwards({
  a: -1n,
  d: div(-121665n, 121666n, 2n ** 255n - 19n), // -121665n/121666n
  P: 2n ** 255n - 19n,
  n: 2n ** 252n + 27742317777372353535851937790883648493n,
  h: 8n,
  Gx: 15112221349535400772501151409588531511454012693041857206046113283949847762202n,
  Gy: 46316835694926478169428394003475163141307993866256225615783033603165251855960n,
  hash: sha512,
  randomBytes,
  adjustScalarBytes(bytes) {
    // optional in general, mandatory in ed25519
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    return bytes;
  },
} as const);
const key = ed25519.utils.randomPrivateKey();
const pub = ed25519.getPublicKey(key);
const msg = new TextEncoder().encode('hello world'); // strings not accepted, must be Uint8Array
const sig = ed25519.sign(msg, key);
ed25519.verify(sig, msg, pub) === true;
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

### abstract/montgomery: Montgomery curve

For now the module only contains methods for x-only ECDH on Curve25519 / Curve448 from RFC7748.

Proper Elliptic Curve Points are not implemented yet.

You must specify curve field, `a24` special variable, `montgomeryBits`, `nByteLength`, and coordinate `u` of generator point.

```typescript
import { montgomery } from '@noble/curves/abstract/montgomery';

const x25519 = montgomery({
  P: 2n ** 255n - 19n,
  a24: 121665n, // TODO: change to a
  montgomeryBits: 255,
  nByteLength: 32,
  Gu: '0900000000000000000000000000000000000000000000000000000000000000',

  // Optional params
  powPminus2: (x: bigint): bigint => {
    return mod.pow(x, P - 2, P);
  },
  adjustScalarBytes(bytes) {
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    return bytes;
  },
});
```

### abstract/weierstrass: Short Weierstrass curve

Short Weierstrass curve's formula is: y² = x³ + ax + b. Uses deterministic ECDSA from RFC6979. You can also specify `extraEntropy` in `sign()`.

- You must specify curve params: `a`, `b`, field `Fp`, order `n`, cofactor `h` and coordinates `Gx`, `Gy` of generator point
- For ECDSA, you must specify `hash`, `hmac`. It is also possible to recover keys from signatures
- For ECDH, use `getSharedSecret(privKeyA, pubKeyB)`
- Optional params are `lowS` (default value) and `endo` (endomorphism)

```typescript
import { Fp } from '@noble/curves/abstract/modular';
import { weierstrass } from '@noble/curves/abstract/weierstrass'; // Short Weierstrass curve
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { concatBytes, randomBytes } from '@noble/hashes/utils';

const secp256k1 = weierstrass({
  a: 0n,
  b: 7n,
  Fp: Fp(2n ** 256n - 2n ** 32n - 2n ** 9n - 2n ** 8n - 2n ** 7n - 2n ** 6n - 2n ** 4n - 1n),
  n: 2n ** 256n - 432420386565659656852420866394968145599n,
  Gx: 55066263022277343669578718895168534326250603453777594175500187360389116729240n,
  Gy: 32670510020758816978083085130507043184471273380659243275938904335757337482424n,
  hash: sha256,
  hmac: (k: Uint8Array, ...msgs: Uint8Array[]) => hmac(sha256, key, concatBytes(...msgs)),
  randomBytes,

  // Optional params
  h: 1n, // Cofactor
  lowS: true, // Allow only low-S signatures by default in sign() and verify()
  endo: {
    // Endomorphism options for Koblitz curve
    // Beta param
    beta: 0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501een,
    // Split scalar k into k1, k2
    splitScalar: (k: bigint) => {
      // return { k1neg: true, k1: 512n, k2neg: false, k2: 448n };
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
  signUnhashed: (msg: Uint8Array, privKey: PrivKey, opts?: SignOpts) => SignatureType;
  verify: (
    signature: Hex | SignatureType,
    msgHash: Hex,
    publicKey: PubKey,
    opts?: { lowS?: boolean }
  ) => boolean;
  Point: PointConstructor;
  ProjectivePoint: ProjectivePointConstructor;
  Signature: SignatureConstructor;
  utils: {
    isValidPrivateKey(privateKey: PrivKey): boolean;
    hashToPrivateKey: (hash: Hex) => Uint8Array;
    randomPrivateKey: () => Uint8Array;
  };
};
```

### abstract/hash-to-curve: Hashing strings to curve points

The module allows to hash arbitrary strings to elliptic curve points.

- `expand_message_xmd` [(spec)](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-5.4.1) produces a uniformly random byte string using a cryptographic hash function H that outputs b bits..

    ```ts
    function expand_message_xmd(
      msg: Uint8Array, DST: Uint8Array, lenInBytes: number, H: CHash
    ): Uint8Array;
    function expand_message_xof(
      msg: Uint8Array, DST: Uint8Array, lenInBytes: number, k: number, H: CHash
    ): Uint8Array;
    ```

- `hash_to_field(msg, count, options)` [(spec)](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-5.3)
hashes arbitrary-length byte strings to a list of one or more elements of a finite field F.
    * `msg` a byte string containing the message to hash
    * `count` the number of elements of F to output
    * `options` `{DST: string, p: bigint, m: number, k: number, expand: 'xmd' | 'xof', hash: H}`
    * Returns `[u_0, ..., u_(count - 1)]`, a list of field elements.

    ```ts
    function hash_to_field(msg: Uint8Array, count: number, options: htfOpts): bigint[][];
    type htfOpts = {
      // DST: a domain separation tag
      // defined in section 2.2.5
      DST: string;
      // p: the characteristic of F
      //    where F is a finite field of characteristic p and order q = p^m
      p: bigint;
      // m: the extension degree of F, m >= 1
      //     where F is a finite field of characteristic p and order q = p^m
      m: number;
      // k: the target security level for the suite in bits
      // defined in section 5.1
      k: number;
      // option to use a message that has already been processed by
      // expand_message_xmd
      expand?: 'xmd' | 'xof';
      // Hash functions for: expand_message_xmd is appropriate for use with a
      // wide range of hash functions, including SHA-2, SHA-3, BLAKE2, and others.
      // BBS+ uses blake2: https://github.com/hyperledger/aries-framework-go/issues/2247
      // TODO: verify that hash is shake if expand==='xof' via types
      hash: CHash;
    };
    ```

### abstract/modular

Modular arithmetics utilities.

```typescript
import { Fp, mod, invert, div, invertBatch, sqrt } from '@noble/curves/abstract/modular';
const fp = Fp(2n ** 255n - 19n); // Finite field over 2^255-19
fp.mul(591n, 932n);
fp.pow(481n, 11024858120n);

// Generic non-FP utils are also available
mod(21n, 10n); // 21 mod 10 == 1n; fixed version of 21 % 10
invert(17n, 10n); // invert(17) mod 10; modular multiplicative inverse
div(5n, 17n, 10n); // 5/17 mod 10 == 5 * invert(17) mod 10; division
invertBatch([1n, 2n, 4n], 21n); // => [1n, 11n, 16n] in one inversion
sqrt(21n, 73n); // √21 mod 73; square root
```

### abstract/utils

```typescript
import * as utils from '@noble/curves/abstract/utils';

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
getPublicKey
  secp256k1 x 5,241 ops/sec @ 190μs/op
  P256 x 7,993 ops/sec @ 125μs/op
  P384 x 3,819 ops/sec @ 261μs/op
  P521 x 2,074 ops/sec @ 481μs/op
  ed25519 x 8,390 ops/sec @ 119μs/op
  ed448 x 3,224 ops/sec @ 310μs/op
sign
  secp256k1 x 3,934 ops/sec @ 254μs/op
  P256 x 5,327 ops/sec @ 187μs/op
  P384 x 2,728 ops/sec @ 366μs/op
  P521 x 1,594 ops/sec @ 626μs/op
  ed25519 x 4,233 ops/sec @ 236μs/op
  ed448 x 1,561 ops/sec @ 640μs/op
verify
  secp256k1 x 731 ops/sec @ 1ms/op
  P256 x 806 ops/sec @ 1ms/op
  P384 x 353 ops/sec @ 2ms/op
  P521 x 171 ops/sec @ 5ms/op
  ed25519 x 860 ops/sec @ 1ms/op
  ed448 x 313 ops/sec @ 3ms/op
getSharedSecret
  secp256k1 x 445 ops/sec @ 2ms/op
recoverPublicKey
  secp256k1 x 732 ops/sec @ 1ms/op
==== bls12-381 ====
getPublicKey x 817 ops/sec @ 1ms/op
sign x 50 ops/sec @ 19ms/op
verify x 34 ops/sec @ 28ms/op
pairing x 89 ops/sec @ 11ms/op
==== stark ====
pedersen
  old x 85 ops/sec @ 11ms/op
  noble x 1,216 ops/sec @ 822μs/op
verify
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
