# noble-curves

Audited & minimal JS implementation of elliptic curve cryptography.

- **noble** family, zero dependencies
- Short Weierstrass, Edwards, Montgomery curves
- ECDSA, EdDSA, Schnorr, BLS signature schemes, ECDH key agreement
- #️⃣ [hash to curve](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/)
  for encoding or hashing an arbitrary string to an elliptic curve point
- 🧜‍♂️ [Poseidon](https://www.poseidon-hash.info) ZK-friendly hash
- 🏎 [Ultra-fast](#speed), hand-optimized for caveats of JS engines
- 🔍 Unique tests ensure correctness. Wycheproof vectors included
- 🔻 Tree-shaking-friendly: there is no entry point, which ensures small size of your app

Package consists of two parts:

1. [Abstract](#abstract-api), zero-dependency EC algorithms
2. [Implementations](#implementations), utilizing one dependency `@noble/hashes`, providing ready-to-use:
   - NIST curves secp192r1/P192, secp224r1/P224, secp256r1/P256, secp384r1/P384, secp521r1/P521
   - SECG curve secp256k1
   - ed25519/curve25519/x25519/ristretto255, edwards448/curve448/x448 RFC7748 / RFC8032 / ZIP215 stuff
   - pairing-friendly curves bls12-381, bn254

Check out [Upgrading](#upgrading) if you've previously used single-feature noble packages
([secp256k1](https://github.com/paulmillr/noble-secp256k1), [ed25519](https://github.com/paulmillr/noble-ed25519)).
See [In the wild](#in-the-wild) for real-world software that uses curves.

### This library belongs to _noble_ crypto

> **noble-crypto** — high-security, easily auditable set of contained cryptographic libraries and tools.

- No dependencies, protection against supply chain attacks
- Easily auditable TypeScript/JS code
- Supported in all major browsers and stable node.js versions
- All releases are signed with PGP keys
- Check out [homepage](https://paulmillr.com/noble/) & all libraries:
  [curves](https://github.com/paulmillr/noble-curves)
  ([secp256k1](https://github.com/paulmillr/noble-secp256k1),
  [ed25519](https://github.com/paulmillr/noble-ed25519)),
  [hashes](https://github.com/paulmillr/noble-hashes)

## Usage

Use NPM for browser / node.js:

> npm install @noble/curves

For [Deno](https://deno.land), use it with npm specifier. In browser, you could also include the single file from
[GitHub's releases page](https://github.com/paulmillr/noble-curves/releases).

The library is tree-shaking-friendly and does not expose root entry point as `import * from '@noble/curves'`.
Instead, you need to import specific primitives. This is done to ensure small size of your apps.

### Implementations

Each curve can be used in the following way:

```ts
import { secp256k1 } from '@noble/curves/secp256k1'; // ECMAScript Modules (ESM) and Common.js
// import { secp256k1 } from 'npm:@noble/curves@1.2.0/secp256k1'; // Deno
const priv = secp256k1.utils.randomPrivateKey();
const pub = secp256k1.getPublicKey(priv);
const msg = new Uint8Array(32).fill(1);
const sig = secp256k1.sign(msg, priv);
secp256k1.verify(sig, msg, pub) === true;

const privHex = '46c930bc7bb4db7f55da20798697421b98c4175a52c630294d75a84b9c126236'
const pub2 = secp256k1.getPublicKey(privHex); // keys & other inputs can be Uint8Array-s or hex strings

// Follows hash-to-curve specification to encode arbitrary hashes to EC points
import { hashToCurve, encodeToCurve } from '@noble/curves/secp256k1';
hashToCurve('0102abcd');
```

All curves:

```typescript
import { secp256k1, schnorr } from '@noble/curves/secp256k1';
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

Weierstrass curves feature recovering public keys from signatures and ECDH key agreement:

```ts
// extraEntropy https://moderncrypto.org/mail-archive/curves/2017/000925.html
const sigImprovedSecurity = secp256k1.sign(msg, priv, { extraEntropy: true });
sig.recoverPublicKey(msg) === pub; // public key recovery
const someonesPub = secp256k1.getPublicKey(secp256k1.utils.randomPrivateKey());
const shared = secp256k1.getSharedSecret(priv, someonesPub); // ECDH (elliptic curve diffie-hellman)
```

secp256k1 has schnorr signature implementation which follows
[BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki):

```ts
import { schnorr } from '@noble/curves/secp256k1';
const priv = schnorr.utils.randomPrivateKey();
const pub = schnorr.getPublicKey(priv);
const msg = new TextEncoder().encode('hello');
const sig = schnorr.sign(msg, priv);
const isValid = schnorr.verify(sig, msg, pub);
console.log(isValid);
```

ed25519 module has ed25519ctx / ed25519ph variants,
x25519 ECDH and [ristretto255](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-ristretto255-decaf448).
It follows [ZIP215](https://zips.z.cash/zip-0215) and [can be used in consensus-critical applications](https://hdevalence.ca/blog/2020-10-04-its-25519am):

```ts
import { ed25519 } from '@noble/curves/ed25519';

// Variants from RFC8032: with context, prehashed
import { ed25519ctx, ed25519ph } from '@noble/curves/ed25519';

// ECDH using curve25519 aka x25519
import { x25519 } from '@noble/curves/ed25519';
const priv = 'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4';
const pub = 'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c';
x25519.getSharedSecret(priv, pub) === x25519.scalarMult(priv, pub);
x25519.getPublicKey(priv) === x25519.scalarMultBase(priv);

// hash-to-curve
import { hashToCurve, encodeToCurve } from '@noble/curves/ed25519';

import { RistrettoPoint } from '@noble/curves/ed25519';
const rp = RistrettoPoint.fromHex(
  '6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919'
);
RistrettoPoint.hashToCurve('Ristretto is traditionally a short shot of espresso coffee');
// also has add(), equals(), multiply(), toRawBytes() methods
```

ed448 module is basically the same:

```ts
import { ed448, ed448ph, ed448ctx, x448 } from '@noble/curves/ed448';
import { hashToCurve, encodeToCurve } from '@noble/curves/ed448';
```

BLS12-381 pairing-friendly Barreto-Lynn-Scott elliptic curve construction allows to
construct [zk-SNARKs](https://z.cash/technology/zksnarks/) at the 128-bit security
and use aggregated, batch-verifiable
[threshold signatures](https://medium.com/snigirev.stepan/bls-signatures-better-than-schnorr-5a7fe30ea716),
using Boneh-Lynn-Shacham signature scheme.

```ts
import { bls12_381 as bls } from '@noble/curves/bls12-381';
const privateKey = '67d53f170b908cabb9eb326c3c337762d59289a8fec79f7bc9254b584b73265c';
const message = '64726e3da8';
const publicKey = bls.getPublicKey(privateKey);
const signature = bls.sign(message, privateKey);
const isValid = bls.verify(signature, message, publicKey);
console.log({ publicKey, signature, isValid });

// Sign 1 msg with 3 keys
const privateKeys = [
  '18f020b98eb798752a50ed0563b079c125b0db5dd0b1060d1c1b47d4a193e1e4',
  'ed69a8c50cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9c',
  '16ae669f3be7a2121e17d0c68c05a8f3d6bef21ec0f2315f1d7aec12484e4cf5',
];
const messages = ['d2', '0d98', '05caf3'];
const publicKeys = privateKeys.map(bls.getPublicKey);
const signatures2 = privateKeys.map((p) => bls.sign(message, p));
const aggPubKey2 = bls.aggregatePublicKeys(publicKeys);
const aggSignature2 = bls.aggregateSignatures(signatures2);
const isValid2 = bls.verify(aggSignature2, message, aggPubKey2);
console.log({ signatures2, aggSignature2, isValid2 });

// Sign 3 msgs with 3 keys
const signatures3 = privateKeys.map((p, i) => bls.sign(messages[i], p));
const aggSignature3 = bls.aggregateSignatures(signatures3);
const isValid3 = bls.verifyBatch(aggSignature3, messages, publicKeys);
console.log({ publicKeys, signatures3, aggSignature3, isValid3 });

// Pairings
// bls.pairing(PointG1, PointG2)
```

## Abstract API

Abstract API allows to define custom curves. All arithmetics is done with JS bigints over finite fields,
which is defined from `modular` sub-module. For scalar multiplication, we use [precomputed tables with w-ary non-adjacent form (wNAF)](https://paulmillr.com/posts/noble-secp256k1-fast-ecc/).
Precomputes are enabled for weierstrass and edwards BASE points of a curve. You could precompute any
other point (e.g. for ECDH) using `utils.precompute()` method.

There are following zero-dependency algorithms:

- [abstract/weierstrass: Short Weierstrass curve](#abstractweierstrass-short-weierstrass-curve)
- [abstract/edwards: Twisted Edwards curve](#abstractedwards-twisted-edwards-curve)
- [abstract/montgomery: Montgomery curve](#abstractmontgomery-montgomery-curve)
- [abstract/hash-to-curve: Hashing strings to curve points](#abstracthash-to-curve-hashing-strings-to-curve-points)
- [abstract/poseidon: Poseidon hash](#abstractposeidon-poseidon-hash)
- [abstract/modular: Modular arithmetics utilities](#abstractmodular-modular-arithmetics-utilities)
- [abstract/utils: General utilities](#abstractutils-general-utilities)

### abstract/weierstrass: Short Weierstrass curve

```ts
import { weierstrass } from '@noble/curves/abstract/weierstrass';
```

Short Weierstrass curve's formula is `y² = x³ + ax + b`. `weierstrass` expects arguments `a`, `b`, field `Fp`, curve order `n`, cofactor `h`
and coordinates `Gx`, `Gy` of generator point.

**`k` generation** is done deterministically, following [RFC6979](https://www.rfc-editor.org/rfc/rfc6979).
For this you will need `hmac` & `hash`, which in our implementations is provided by noble-hashes.
If you're using different hashing library, make sure to wrap it in the following interface:

```ts
export type CHash = {
  (message: Uint8Array): Uint8Array;
  blockLen: number;
  outputLen: number;
  create(): any;
};
```

**Weierstrass points:**

1. Exported as `ProjectivePoint`
2. Represented in projective (homogeneous) coordinates: (x, y, z) ∋ (x=x/z, y=y/z)
3. Use complete exception-free formulas for addition and doubling
4. Can be decoded/encoded from/to Uint8Array / hex strings using `ProjectivePoint.fromHex` and `ProjectivePoint#toRawBytes()`
5. Have `assertValidity()` which checks for being on-curve
6. Have `toAffine()` and `x` / `y` getters which convert to 2d xy affine coordinates

```ts
// T is usually bigint, but can be something else like complex numbers in BLS curves
export interface ProjPointType<T> extends Group<ProjPointType<T>> {
  readonly px: T;
  readonly py: T;
  readonly pz: T;
  multiply(scalar: bigint): ProjPointType<T>;
  multiplyUnsafe(scalar: bigint): ProjPointType<T>;
  multiplyAndAddUnsafe(Q: ProjPointType<T>, a: bigint, b: bigint): ProjPointType<T> | undefined;
  toAffine(iz?: T): AffinePoint<T>;
  isTorsionFree(): boolean;
  clearCofactor(): ProjPointType<T>;
  assertValidity(): void;
  hasEvenY(): boolean;
  toRawBytes(isCompressed?: boolean): Uint8Array;
  toHex(isCompressed?: boolean): string;
}
// Static methods for 3d XYZ points
export interface ProjConstructor<T> extends GroupConstructor<ProjPointType<T>> {
  new (x: T, y: T, z: T): ProjPointType<T>;
  fromAffine(p: AffinePoint<T>): ProjPointType<T>;
  fromHex(hex: Hex): ProjPointType<T>;
  fromPrivateKey(privateKey: PrivKey): ProjPointType<T>;
}
```

**ECDSA signatures** are represented by `Signature` instances and can be described by the interface:

```ts
export interface SignatureType {
  readonly r: bigint;
  readonly s: bigint;
  readonly recovery?: number;
  assertValidity(): void;
  addRecoveryBit(recovery: number): SignatureType;
  hasHighS(): boolean;
  normalizeS(): SignatureType;
  recoverPublicKey(msgHash: Hex): ProjPointType<bigint>;
  toCompactRawBytes(): Uint8Array;
  toCompactHex(): string;
  // DER-encoded
  toDERRawBytes(isCompressed?: boolean): Uint8Array;
  toDERHex(isCompressed?: boolean): string;
}
```

Example implementing [secq256k1](https://personaelabs.org/posts/spartan-ecdsa) (NOT secp256k1)
[cycle](https://zcash.github.io/halo2/background/curves.html#cycles-of-curves) of secp256k1 with Fp/N flipped.

```typescript
import { weierstrass } from '@noble/curves/abstract/weierstrass';
import { Field } from '@noble/curves/abstract/modular'; // finite field, mod arithmetics done over it
import { sha256 } from '@noble/hashes/sha256'; // 3rd-party sha256() of type utils.CHash, with blockLen/outputLen
import { hmac } from '@noble/hashes/hmac'; // 3rd-party hmac() that will accept sha256()
import { concatBytes, randomBytes } from '@noble/hashes/utils'; // 3rd-party utilities
const secq256k1 = weierstrass({
  // secq256k1: cycle of secp256k1 with Fp/N flipped.
  a: 0n,
  b: 7n,
  Fp: Field(2n ** 256n - 432420386565659656852420866394968145599n),
  n: 2n ** 256n - 2n ** 32n - 2n ** 9n - 2n ** 8n - 2n ** 7n - 2n ** 6n - 2n ** 4n - 1n,
  Gx: 55066263022277343669578718895168534326250603453777594175500187360389116729240n,
  Gy: 32670510020758816978083085130507043184471273380659243275938904335757337482424n,
  hash: sha256,
  hmac: (key: Uint8Array, ...msgs: Uint8Array[]) => hmac(sha256, key, concatBytes(...msgs)),
  randomBytes,
});

// All curves expose same generic interface.
const priv = secq256k1.utils.randomPrivateKey();
secq256k1.getPublicKey(priv); // Convert private key to public.
const sig = secq256k1.sign(msg, priv); // Sign msg with private key.
secq256k1.verify(sig, msg, priv); // Verify if sig is correct.

const point = secq256k1.Point.BASE; // Elliptic curve Point class and BASE point static var.
point.add(point).equals(point.double()); // add(), equals(), double() methods
point.subtract(point).equals(secq256k1.Point.ZERO); // subtract() method, ZERO static var
point.negate(); // Flips point over x/y coordinate.
point.multiply(31415n); // Multiplication of Point by scalar.

point.assertValidity(); // Checks for being on-curve
point.toAffine();  // Converts to 2d affine xy coordinates

secq256k1.CURVE.n;
secq256k1.CURVE.Fp.mod();
secq256k1.CURVE.hash();
```

`weierstrass()` returns `CurveFn`:

```ts
export type CurveFn = {
  CURVE: ReturnType<typeof validateOpts>;
  getPublicKey: (privateKey: PrivKey, isCompressed?: boolean) => Uint8Array;
  getSharedSecret: (privateA: PrivKey, publicB: Hex, isCompressed?: boolean) => Uint8Array;
  sign: (msgHash: Hex, privKey: PrivKey, opts?: SignOpts) => SignatureType;
  verify: (
    signature: Hex | SignatureType,
    msgHash: Hex,
    publicKey: Hex,
    opts?: { lowS?: boolean; prehash?: boolean }
  ) => boolean;
  ProjectivePoint: ProjectivePointConstructor;
  Signature: SignatureConstructor;
  utils: {
    isValidPrivateKey(privateKey: PrivKey): boolean;
    randomPrivateKey: () => Uint8Array;
  };
};
```

### abstract/edwards: Twisted Edwards curve

Twisted Edwards curve's formula is `ax² + y² = 1 + dx²y²`. You must specify `a`, `d`, field `Fp`, order `n`, cofactor `h`
and coordinates `Gx`, `Gy` of generator point.

For EdDSA signatures, `hash` param required. `adjustScalarBytes` which instructs how to change private scalars could be specified.

**Edwards points:**

1. Exported as `ExtendedPoint`
2. Represented in extended coordinates: (x, y, z, t) ∋ (x=x/z, y=y/z)
3. Use complete exception-free formulas for addition and doubling
4. Can be decoded/encoded from/to Uint8Array / hex strings using `ExtendedPoint.fromHex` and `ExtendedPoint#toRawBytes()`
5. Have `assertValidity()` which checks for being on-curve
6. Have `toAffine()` and `x` / `y` getters which convert to 2d xy affine coordinates
7. Have `isTorsionFree()`, `clearCofactor()` and `isSmallOrder()` utilities to handle torsions

```ts
export interface ExtPointType extends Group<ExtPointType> {
  readonly ex: bigint;
  readonly ey: bigint;
  readonly ez: bigint;
  readonly et: bigint;
  assertValidity(): void;
  multiply(scalar: bigint): ExtPointType;
  multiplyUnsafe(scalar: bigint): ExtPointType;
  isSmallOrder(): boolean;
  isTorsionFree(): boolean;
  clearCofactor(): ExtPointType;
  toAffine(iz?: bigint): AffinePoint<bigint>;
}
// Static methods of Extended Point with coordinates in X, Y, Z, T
export interface ExtPointConstructor extends GroupConstructor<ExtPointType> {
  new (x: bigint, y: bigint, z: bigint, t: bigint): ExtPointType;
  fromAffine(p: AffinePoint<bigint>): ExtPointType;
  fromHex(hex: Hex): ExtPointType;
  fromPrivateKey(privateKey: Hex): ExtPointType;
}
```

Example implementing edwards25519:

```ts
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
    // optional; but mandatory in ed25519
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    return bytes;
  },
} as const);
```

`twistedEdwards()` returns `CurveFn` of following type:

```ts
export type CurveFn = {
  CURVE: ReturnType<typeof validateOpts>;
  getPublicKey: (privateKey: PrivKey, isCompressed?: boolean) => Uint8Array;
  sign: (message: Hex, privateKey: Hex) => Uint8Array;
  verify: (sig: SigType, message: Hex, publicKey: PubKey, context?: Hex) => boolean;
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

The module contains methods for x-only ECDH on Curve25519 / Curve448 from RFC7748. Proper Elliptic Curve Points are not implemented yet.

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

### abstract/hash-to-curve: Hashing strings to curve points

The module allows to hash arbitrary strings to elliptic curve points. Implements [hash-to-curve v11](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11).

`expand_message_xmd` [(spec)](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-5.4.1) produces a uniformly random byte string using a cryptographic hash function H that outputs b bits.

```ts
function expand_message_xmd(msg: Uint8Array, DST: Uint8Array, lenInBytes: number, H: CHash): Uint8Array;
function expand_message_xof(msg: Uint8Array, DST: Uint8Array, lenInBytes: number, k: number, H: CHash): Uint8Array;
```

`hash_to_field(msg, count, options)` [(spec)](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-5.3)
hashes arbitrary-length byte strings to a list of one or more elements of a finite field F.
_ `msg` a byte string containing the message to hash
_ `count` the number of elements of F to output
_ `options` `{DST: string, p: bigint, m: number, k: number, expand: 'xmd' | 'xof', hash: H}`
_ Returns `[u_0, ..., u_(count - 1)]`, a list of field elements.

```ts
function hash_to_field(msg: Uint8Array, count: number, options: htfOpts): bigint[][];
type htfOpts = {
  DST: string; // a domain separation tag defined in section 2.2.5
  // p: the characteristic of F
  //    where F is a finite field of characteristic p and order q = p^m
  p: bigint;
  // m: the extension degree of F, m >= 1
  //     where F is a finite field of characteristic p and order q = p^m
  m: number;
  k: number; // the target security level for the suite in bits defined in section 5.1
  expand?: 'xmd' | 'xof'; // option to use a message that has already been processed by expand_message_xmd
  // Hash functions for: expand_message_xmd is appropriate for use with a
  // wide range of hash functions, including SHA-2, SHA-3, BLAKE2, and others.
  // BBS+ uses blake2: https://github.com/hyperledger/aries-framework-go/issues/2247
  // TODO: verify that hash is shake if expand==='xof' via types
  hash: CHash;
};
```

### abstract/poseidon: Poseidon hash

Implements [Poseidon](https://www.poseidon-hash.info) ZK-friendly hash.

There are many poseidon variants with different constants.
We don't provide them: you should construct them manually.
The only variant provided resides in `stark` module: inspect it for proper usage.

```ts
import { poseidon } from '@noble/curves/abstract/poseidon';

type PoseidonOpts = {
  Fp: Field<bigint>;
  t: number;
  roundsFull: number;
  roundsPartial: number;
  sboxPower?: number;
  reversePartialPowIdx?: boolean; // Hack for stark
  mds: bigint[][];
  roundConstants: bigint[][];
};
const instance = poseidon(opts: PoseidonOpts);
```

### abstract/bls

The module abstracts BLS (Barreto-Lynn-Scott) primitives. In theory you should be able to write BLS12-377, BLS24,
and others with it.

### abstract/modular: Modular arithmetics utilities

The module also contains useful `hashToPrivateScalar` method which allows to create
scalars (e.g. private keys) with the modulo bias being neglible. It follows
FIPS 186 B.4.1. Requires at least 40 bytes of input for 32-byte private key.

```ts
import * as mod from '@noble/curves/abstract/modular';
const fp = mod.Field(2n ** 255n - 19n); // Finite field over 2^255-19
fp.mul(591n, 932n); // multiplication
fp.pow(481n, 11024858120n); // exponentiation
fp.div(5n, 17n); // division: 5/17 mod 2^255-19 == 5 * invert(17)
fp.sqrt(21n); // square root

// Generic non-FP utils are also available
mod.mod(21n, 10n); // 21 mod 10 == 1n; fixed version of 21 % 10
mod.invert(17n, 10n); // invert(17) mod 10; modular multiplicative inverse
mod.invertBatch([1n, 2n, 4n], 21n); // => [1n, 11n, 16n] in one inversion
mod.hashToPrivateScalar(sha512_of_something, secp256r1.n);
```

### abstract/utils: General utilities

```ts
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
utils.equalBytes(Uint8Array.from([0xde]), Uint8Array.from([0xde]));
```

## Security

The library had no prior security audit.

[Timing attack](https://en.wikipedia.org/wiki/Timing_attack) considerations: we are using non-CT bigints. However, _JIT-compiler_ and _Garbage Collector_ make "constant time" extremely hard to achieve in a scripting language. Which means _any other JS library can't have constant-timeness_. Even statically typed Rust, a language without GC, [makes it harder to achieve constant-time](https://www.chosenplaintext.ca/open-source/rust-timing-shield/security) for some cases. If your goal is absolute security, don't use any JS lib — including bindings to native ones. Use low-level libraries & languages. Nonetheless we're targetting algorithmic constant time.

We consider infrastructure attacks like rogue NPM modules very important; that's why it's crucial to minimize the amount of 3rd-party dependencies & native bindings. If your app uses 500 dependencies, any dep could get hacked and you'll be downloading malware with every `npm install`. Our goal is to minimize this attack vector. As for devDependencies used by the library:

- `@scure` base, bip32, bip39 (used in tests), micro-bmark (benchmark), micro-should (testing) are developed by us
  and follow the same practices such as: minimal library size, auditability, signed releases
- prettier (linter), fast-check (property-based testing),
  typescript versions are locked and rarely updated. Every update is checked with `npm-diff`.
  The packages are big, which makes it hard to audit their source code thoroughly and fully.
- They are only used if you clone the git repo and want to add some feature to it. End-users won't use them.

## Speed

Benchmark results on Apple M2 with node v19:

```
secp256k1
init x 58 ops/sec @ 17ms/op
getPublicKey x 5,640 ops/sec @ 177μs/op
sign x 3,909 ops/sec @ 255μs/op
verify x 780 ops/sec @ 1ms/op
getSharedSecret x 465 ops/sec @ 2ms/op
recoverPublicKey x 740 ops/sec @ 1ms/op
schnorr.sign x 597 ops/sec @ 1ms/op
schnorr.verify x 775 ops/sec @ 1ms/op

P256
init x 31 ops/sec @ 31ms/op
getPublicKey x 5,607 ops/sec @ 178μs/op
sign x 3,930 ops/sec @ 254μs/op
verify x 540 ops/sec @ 1ms/op

P384
init x 15 ops/sec @ 63ms/op
getPublicKey x 2,622 ops/sec @ 381μs/op
sign x 1,913 ops/sec @ 522μs/op
verify x 222 ops/sec @ 4ms/op

P521
init x 8 ops/sec @ 119ms/op
getPublicKey x 1,371 ops/sec @ 729μs/op
sign x 1,090 ops/sec @ 917μs/op
verify x 118 ops/sec @ 8ms/op

ed25519
init x 47 ops/sec @ 20ms/op
getPublicKey x 9,414 ops/sec @ 106μs/op
sign x 4,516 ops/sec @ 221μs/op
verify x 912 ops/sec @ 1ms/op

ed448
init x 17 ops/sec @ 56ms/op
getPublicKey x 3,363 ops/sec @ 297μs/op
sign x 1,615 ops/sec @ 619μs/op
verify x 319 ops/sec @ 3ms/op

stark
init x 35 ops/sec @ 28ms/op
pedersen x 884 ops/sec @ 1ms/op
poseidon x 8,598 ops/sec @ 116μs/op
verify x 528 ops/sec @ 1ms/op

bls12-381
init x 32 ops/sec @ 30ms/op
getPublicKey 1-bit x 858 ops/sec @ 1ms/op
getPublicKey x 858 ops/sec @ 1ms/op
sign x 49 ops/sec @ 20ms/op
verify x 34 ops/sec @ 28ms/op
pairing x 94 ops/sec @ 10ms/op
aggregatePublicKeys/8 x 116 ops/sec @ 8ms/op
aggregatePublicKeys/32 x 31 ops/sec @ 31ms/op
aggregatePublicKeys/128 x 7 ops/sec @ 125ms/op
aggregateSignatures/8 x 45 ops/sec @ 22ms/op
aggregateSignatures/32 x 11 ops/sec @ 84ms/op
aggregateSignatures/128 x 3 ops/sec @ 332ms/opp
```

## In the wild

Elliptic curve calculator: [paulmillr.com/ecc](https://paulmillr.com/ecc).

- secp256k1
  - [btc-signer](https://github.com/paulmillr/micro-btc-signer), [eth-signer](https://github.com/paulmillr/micro-eth-signer)
- ed25519
  - [sol-signer](https://github.com/paulmillr/micro-sol-signer)
- BLS12-381
  - Threshold sigs demo [genthresh.com](https://genthresh.com)
  - BBS signatures [github.com/Wind4Greg/BBS-Draft-Checks](https://github.com/Wind4Greg/BBS-Draft-Checks) following [draft-irtf-cfrg-bbs-signatures-latest](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html)

## Upgrading

If you're coming from single-feature noble packages, the following changes need to be kept in mind:

- 2d affine (x, y) points have been removed to reduce complexity and improve speed
- Removed `number` support as a type for private keys, `bigint` is still supported
- `mod`, `invert` are no longer present in `utils`: use `@noble/curves/abstract/modular`

Upgrading from @noble/secp256k1 1.7:

- Compressed (33-byte) public keys are now returned by default, instead of uncompressed
- Methods are now synchronous. Setting `secp.utils.hmacSha256` is no longer required
- `sign()`
  - `der`, `recovered` options were removed
  - `canonical` was renamed to `lowS`
  - Return type is now `{ r: bigint, s: bigint, recovery: number }` instance of `Signature`
- `verify()`
  - `strict` was renamed to `lowS`
- `recoverPublicKey()`: moved to sig instance `Signature#recoverPublicKey(msgHash)`
- `Point` was removed: use `ProjectivePoint` in xyz coordinates
- `utils`: Many methods were removed, others were moved to `schnorr` namespace

Upgrading from @noble/ed25519 1.7:

- Methods are now synchronous. Setting `secp.utils.hmacSha256` is no longer required
- ed25519ph, ed25519ctx
- `Point` was removed: use `ExtendedPoint` in xyzt coordinates
- `Signature` was removed
- `getSharedSecret` was removed: use separate x25519 sub-module
- `bigint` is no longer allowed in `getPublicKey`, `sign`, `verify`. Reason: ed25519 is LE, can lead to bugs

## Contributing & testing

1. Clone the repository
2. `npm install` to install build dependencies like TypeScript
3. `npm run build` to compile TypeScript code
4. `npm run test` will execute all main tests

## License

The MIT License (MIT)

Copyright (c) 2022 Paul Miller [(https://paulmillr.com)](https://paulmillr.com)

See LICENSE file.
