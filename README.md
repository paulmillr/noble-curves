# noble-curves

Audited & minimal JS implementation of elliptic curve cryptography.

- 🔒 [**Audited**](#security) by independent security firms
- 🔻 Tree-shakeable: unused code is excluded from your builds
- 🏎 Fast: hand-optimized for caveats of JS engines
- 🔍 Reliable: cross-library / wycheproof tests and fuzzing ensure correctness
- ➰ Weierstrass, Edwards, Montgomery curves; ECDSA, EdDSA, Schnorr, BLS signatures
- ✍️ ECDH, hash-to-curve, OPRF, Poseidon ZK-friendly hash
- 🔖 Non-repudiation (SUF-CMA, SBS) & consensus-friendliness (ZIP215) in ed25519, ed448
- 🥈 Optional, friendly wrapper over native WebCrypto
- 🪶 29KB (gzipped) including bundled hashes, 11KB for single-curve build

Curves have 5kb sister projects
[secp256k1](https://github.com/paulmillr/noble-secp256k1) & [ed25519](https://github.com/paulmillr/noble-ed25519).
They have smaller attack surface, but less features.

Take a glance at [GitHub Discussions](https://github.com/paulmillr/noble-curves/discussions) for questions and support.

### This library belongs to _noble_ cryptography

> **noble cryptography** — high-security, easily auditable set of contained cryptographic libraries and tools.

- Zero or minimal dependencies
- Highly readable TypeScript / JS code
- PGP-signed releases and transparent NPM builds
- All libraries:
  [ciphers](https://github.com/paulmillr/noble-ciphers),
  [curves](https://github.com/paulmillr/noble-curves),
  [hashes](https://github.com/paulmillr/noble-hashes),
  [post-quantum](https://github.com/paulmillr/noble-post-quantum),
  5kb [secp256k1](https://github.com/paulmillr/noble-secp256k1) /
  [ed25519](https://github.com/paulmillr/noble-ed25519)
- [Check out homepage](https://paulmillr.com/noble/)
  for reading resources, documentation and apps built with noble

## Usage

> `npm install @noble/curves`

> `deno add jsr:@noble/curves`

We support all major platforms and runtimes.
For React Native, you may need a [polyfill for getRandomValues](https://github.com/LinusU/react-native-get-random-values).
A standalone file [noble-curves.js](https://github.com/paulmillr/noble-curves/releases) is also available.

```ts
// import * from '@noble/curves'; // Error: use sub-imports, to ensure small app size
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { ed25519, ed25519ph, ed25519ctx, x25519, ristretto255 } from '@noble/curves/ed25519.js';
import { ed448, ed448ph, x448, decaf448 } from '@noble/curves/ed448.js';
import { p256, p384, p521 } from '@noble/curves/nist.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { bn254 } from '@noble/curves/bn254.js';
import { jubjub, babyjubjub, brainpoolP256r1, brainpoolP384r1, brainpoolP512r1 } from '@noble/curves/misc.js';

// hash-to-curve
import { secp256k1_hasher } from '@noble/curves/secp256k1.js';
import { p256_hasher, p384_hasher, p521_hasher } from '@noble/curves/nist.js';
import { ristretto255_hasher } from '@noble/curves/ed25519.js';
import { decaf448_hasher } from '@noble/curves/ed448.js';

// OPRFs
import { p256_oprf, p384_oprf, p521_oprf } from '@noble/curves/nist.js';
import { ristretto255_oprf } from '@noble/curves/ed25519.js';
import { decaf448_oprf } from '@noble/curves/ed448.js';

// utils
import { bytesToHex, hexToBytes, concatBytes } from '@noble/curves/abstract/utils.js';
import { Field } from '@noble/curves/abstract/modular.js';
import { weierstrass, ecdsa } from '@noble/curves/abstract/weierstrass.js';
import { edwards, eddsa } from '@noble/curves/abstract/edwards.js';
import { poseidon, poseidonSponge } from '@noble/curves/abstract/poseidon.js';
import { FFT, poly } from '@noble/curves/abstract/fft.js';
```

- Examples
  - [ECDSA, EdDSA, Schnorr signatures](#ecdsa-eddsa-schnorr-signatures)
    - [secp256k1, p256, p384, p521, ed25519, ed448, brainpool](#secp256k1-p256-p384-p521-ed25519-ed448-brainpool)
    - [ristretto255, decaf448](#ristretto255-decaf448)
    - [Prehashed signing](#prehashed-signing)
    - [Hedged ECDSA with noise](#hedged-ecdsa-with-noise)
    - [Consensus-friendliness vs e-voting](#consensus-friendliness-vs-e-voting)
  - [ECDH: Diffie-Hellman shared secrets](#ecdh-diffie-hellman-shared-secrets)
  - [webcrypto: Friendly wrapper](#webcrypto-friendly-wrapper)
  - [BLS signatures, bls12-381, bn254 aka alt\_bn128](#bls-signatures-bls12-381-bn254-aka-alt_bn128)
  - [Hashing to curve points](#hash-to-curve-hashing-to-curve-points)
  - [OPRFs](#oprfs)
  - [Poseidon hash](#poseidon-poseidon-hash)
  - [Fast Fourier Transform](#fft-fast-fourier-transform)
  - [utils](#utils-byte-shuffling-conversion)
- [Internals](#internals)
  - [Elliptic curve Point math](#elliptic-curve-point-math)
  - [modular: Modular arithmetics \& finite fields](#modular-modular-arithmetics--finite-fields)
  - [weierstrass: Custom Weierstrass curve](#weierstrass-custom-weierstrass-curve)
  - [edwards: Custom Edwards curve](#edwards-custom-edwards-curve)
  - [Custom ECDSA instance](#custom-ecdsa-instance)
- [Security](#security)
- [Speed](#speed)
- [Contributing & testing](#contributing--testing)
- [Upgrading](#upgrading)

### ECDSA, EdDSA, Schnorr signatures

#### secp256k1, p256, p384, p521, ed25519, ed448, brainpool

```js
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { p256, p384, p521 } from '@noble/curves/nist.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ed448 } from '@noble/curves/ed448.js';
import { brainpoolP256r1, brainpoolP384r1, brainpoolP512r1 } from '@noble/curves/misc.js';
for (const curve of [
  secp256k1, schnorr,
  p256, p384, p521,
  ed25519, ed448,
  brainpoolP256r1, brainpoolP384r1, brainpoolP512r1
]) {
  const { secretKey, publicKey } = curve.keygen();
  const msg = new TextEncoder().encode('hello noble');
  const sig = curve.sign(msg, secretKey);
  const isValid = curve.verify(sig, msg, publicKey);
  console.log(curve, secretKey, publicKey, sig, isValid);
}

// Specific private key
import { hexToBytes } from '@noble/curves/utils.js';
const secret2 = hexToBytes('46c930bc7bb4db7f55da20798697421b98c4175a52c630294d75a84b9c126236');
const pub2 = secp256k1.getPublicKey(secret2);
```

ECDSA signatures use deterministic k, conforming to [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979).
EdDSA conforms to [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032).
Schnorr (secp256k1-only) conforms to [BIP 340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).

#### ristretto255, decaf448

```ts
import { ristretto255, ristretto255_hasher, ristretto255_oprf } from '@noble/curves/ed25519.js';
import { decaf448, decaf448_hasher, decaf448_oprf } from '@noble/curves/ed448.js';

console.log(ristretto255.Point, decaf448.Point);
```

Check out [RFC 9496](https://www.rfc-editor.org/rfc/rfc9496) more info on ristretto255 & decaf448.
Check out separate documentation for [Point](#elliptic-curve-point-math), [hasher](#hash-to-curve-hashing-to-curve-points) and [oprf](#oprfs).

#### Prehashed signing

```js
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak256 } from '@noble/hashes/sha3.js';
const { secretKey } = curve.keygen();
const msg = new TextEncoder().encode('hello noble');
// prehash: true (default) - hash using secp256k1.hash (sha256)
const sig = secp256k1.sign(msg, secretKey);
// prehash: false - hash using custom hash
const sigKeccak = secp256k1.sign(keccak256(msg), secretKey, { prehash: false });
```

ECDSA `sign()` allows providing `prehash: false`, which enables using custom hashes.

A ECDSA signature is not just "math over elliptic curve points".
It's actually math + hashing: p256 is in fact p256 point + sha256 hash.
By default, we hash messages. To use custom hash methods,
make sure to disable prehashing.

> [!NOTE]
> Previously, in noble-curves v1, `prehash: false` was the default.
> Some other libraries (like libsecp256k1) have no prehashing.

#### Hedged ECDSA with noise

```js
import { secp256k1 } from '@noble/curves/secp256k1.js';
const { secretKey } = curve.keygen();
const msg = new TextEncoder().encode('hello noble');
// extraEntropy: false - default, hedging disabled
const sigNoisy = secp256k1.sign(msg, secretKey);
// extraEntropy: true - fetch 32 random bytes from CSPRNG
const sigNoisy = secp256k1.sign(msg, secretKey, { extraEntropy: true });
// extraEntropy: bytes - specific extra entropy
const ent = Uint8Array.from([0xca, 0xfe, 0x01, 0x23]);
const sigNoisy2 = secp256k1.sign(msg, secretKey, { extraEntropy: ent });
```

ECDSA `sign()` allows providing `extraEntropy`, which switches sig generation to hedged mode.

By default, ECDSA signatures are generated deterministically,
following [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979).
However, purely deterministic signatures are vulnerable to fault attacks.
Newer signature schemes, such as BIP340 schnorr, switched to hedged signatures because of this.
Hedging is basically incorporating some randomness into sig generation process.

For more info, check out
[Deterministic signatures are not your friends](https://paulmillr.com/posts/deterministic-signatures/),
[RFC 6979](https://www.rfc-editor.org/rfc/rfc6979) section 3.6,
and [cfrg-det-sigs-with-noise draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-det-sigs-with-noise/).

#### Consensus-friendliness vs e-voting

```js
import { ed25519 } from '@noble/curves/ed25519.js';
const { secretKey, publicKey } = ed25519.keygen();
const msg = new TextEncoder().encode('hello noble');
const sig = ed25519.sign(msg, secretKey);
// zip215: true
const isValid = ed25519.verify(sig, msg, pub);
// SBS / e-voting / RFC8032 / FIPS 186-5
const isValidRfc = ed25519.verify(sig, msg, pub, { zip215: false });
```

In ed25519, there is an ability to choose between consensus-friendliness vs e-voting mode.

- `zip215: true` is default behavior. It has slightly looser verification logic
  to be [consensus-friendly](https://hdevalence.ca/blog/2020-10-04-its-25519am), following [ZIP215](https://zips.z.cash/zip-0215) rules
- `zip215: false` switches verification criteria to strict
  [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) / [FIPS 186-5](https://csrc.nist.gov/publications/detail/fips/186/5/final)
  and additionally provides [non-repudiation with SBS](https://eprint.iacr.org/2020/1244),
  which is useful for:
  - Contract Signing: if A signed an agreement with B using key that allows repudiation, it can later claim that it signed a different contract
  - E-voting: malicious voters may pick keys that allow repudiation in order to deny results
  - Blockchains: transaction of amount X might also be valid for a different amount Y

Both modes have SUF-CMA (strong unforgeability under chosen message attacks).

### ECDH: Diffie-Hellman shared secrets

```js
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { x448 } from '@noble/curves/ed448.js';
import { p256, p384, p521 } from '@noble/curves/nist.js';

for (const curve of [secp256k1, schnorr, x25519, x448, p256, p384, p521]) {
  const alice = curve.keygen();
  const bob = curve.keygen();
  const sharedKey = curve.getSharedSecret(alice.secretKey, bob.publicKey);
  console.log('alice', alice, 'bob', bob, 'shared', sharedKey);
}

// x25519 & x448 specific methods
import { ed25519 } from '@noble/curves/ed25519.js';
const alice = ed25519.keygen();
const bob = ed25519.keygen();
const aliceSecX = ed25519.utils.toMontgomerySecret(alice.secretKey);
const bobPubX = ed25519.utils.toMontgomery(bob.publicKey);
const sharedKey = x25519.getSharedSecret(aliceSecX, bobPubX);
```

We provide ECDH over all Weierstrass curves, and over 2 Montgomery curves
X25519 (Curve25519) & X448 (Curve448), conforming to [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748).

In Weierstrass curves, shared secrets:

- Include y-parity bytes: use `key.slice(1)` to strip it
- Are not hashed: use hashing or KDF on top, like `sha256(shared)` or `hkdf(shared)`

#### webcrypto: Friendly wrapper

> [!NOTE]
> Webcrypto methods are always async.

##### webcrypto signatures

```js
import { ed25519, ed448, p256, p384, p521 } from './src/webcrypto.ts';

(async () => {
  for (let [name, curve] of Object.entries({ p256, p384, p521, ed25519, ed448 })) {
    console.log('curve', name);
    if (!await curve.isSupported()) {
      console.log('is not supported, skipping');
      continue;
    }
    const keys = await curve.keygen();
    const msg = new TextEncoder().encode('hello noble');
    const sig = await curve.sign(msg, keys.secretKey);
    const isValid = await curve.verify(sig, msg, keys.publicKey);
    console.log({
      keys, msg, sig, isValid
    });
  }
})();
```

##### webcrypto ecdh

```js
import { p256, p384, p521, x25519, x448 } from './src/webcrypto.ts';

(async () => {
  for (let [name, curve] of Object.entries({ p256, p384, p521, x25519, x448 })) {
    console.log('curve', name);
    if (!await curve.isSupported()) {
      console.log('is not supported, skipping');
      continue;
    }
    const alice = await curve.keygen();
    const bob = await curve.keygen();
    const shared = await curve.getSharedSecret(alice.secretKey, bob.publicKey);
    const shared2 = await curve.getSharedSecret(bob.secretKey, alice.publicKey);
    console.log({shared});
  }
})();
```

##### Key conversion from noble to webcrypto and back

```js
import { p256 as p256n } from './src/nist.ts';
import { p256 } from './src/webcrypto.ts';
(async () => {
  const nobleKeys = p256n.keygen();
  // convert noble keys to webcrypto
  const webKeys = {
    secretKey: await p256.utils.convertSecretKey(nobleKeys.secretKey, 'raw', 'pkcs8'),
    publicKey: await p256.utils.convertPublicKey(nobleKeys.publicKey, 'raw', 'spki')
  };
  // convert webcrypto keys to noble
  const nobleKeys2 = {
    secretKey: await p256.utils.convertSecretKey(webKeys.secretKey, 'pkcs8', 'raw'),
    publicKey: await p256.utils.convertPublicKey(webKeys.publicKey, 'spki', 'raw')
  };
})();
```

Check out [micro-key-producer](https://github.com/paulmillr/micro-key-producer) for
pure JS key conversion utils.

### BLS signatures, bls12-381, bn254 aka alt_bn128

```ts
import { bls12_381 } from '@noble/curves/bls12-381.js';

// G1 pubkeys, G2 sigs
const blsl = bls12_381.longSignatures;
const { secretKey, publicKey } = blsl.keygen();
// const publicKey = blsl.getPublicKey(secretKey);
const msg = new TextEncoder().encode('hello noble');
// default DST
const msgp = blsl.hash(msg);
// custom DST (Ethereum)
const msgpd = blsl.hash(msg, 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_');
const signature = blsl.sign(msgp, secretKey);
const isValid = blsl.verify(signature, msgp, publicKey);
console.log('long', { publicKey, signature, isValid });

// G1 sigs, G2 pubkeys
const blss = bls12_381.shortSignatures;
const publicKey2 = blss.getPublicKey(secretKey);
const msgp2 = blss.hash(msg, 'BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_');
const signature2 = blss.sign(msgp2, secretKey);
const isValid2 = blss.verify(signature2, msgp2, publicKey);
console.log({ publicKey2, signature2, isValid2 });

// Aggregation
const aggregatedKey = bls12_381.longSignatures.aggregatePublicKeys([
  bls12_381.utils.randomSecretKey(),
  bls12_381.utils.randomSecretKey(),
]);
// const aggregatedSig = bls.aggregateSignatures(sigs)

// Pairings, with and without final exponentiation
// bls.pairing(PointG1, PointG2);
// bls.pairing(PointG1, PointG2, false);
// bls.fields.Fp12.finalExponentiate(bls.fields.Fp12.mul(PointG1, PointG2));

// Others
// bls.G1.Point.BASE, bls.G2.Point.BASE;
// bls.fields.Fp, bls.fields.Fp2, bls.fields.Fp12, bls.fields.Fr;
```

See [abstract/bls](#bls-barreto-lynn-scott-curves).
For example usage, check out [the implementation of BLS EVM precompiles](https://github.com/ethereumjs/ethereumjs-monorepo/blob/361f4edbc239e795a411ac2da7e5567298b9e7e5/packages/evm/src/precompiles/bls12_381/noble.ts).

The BN254 API mirrors [BLS](#bls12-381). The curve was previously called alt_bn128.
The implementation is compatible with [EIP-196](https://eips.ethereum.org/EIPS/eip-196) and
[EIP-197](https://eips.ethereum.org/EIPS/eip-197).

For BN254 usage, check out [the implementation of bn254 EVM precompiles](https://github.com/paulmillr/noble-curves/blob/3ed792f8ad9932765b84d1064afea8663a255457/test/bn254.test.js#L697).
We don't implement Point methods toBytes. To work around this limitation, has to initialize points on their own from BigInts. Reason it's not implemented is because [there is no standard](https://github.com/privacy-scaling-explorations/halo2curves/issues/109).
Points of divergence:

- Endianness: LE vs BE (byte-swapped)
- Flags as first hex bits (similar to BLS) vs no-flags
- Imaginary part last in G2 vs first (c0, c1 vs c1, c0)

### hash-to-curve: hashing to curve points

```ts
import { bls12_381 } from './src/bls12-381.ts';
import { ed25519_hasher, ristretto255_hasher } from './src/ed25519.ts';
import { decaf448_hasher, ed448_hasher } from './src/ed448.ts';
import { p256_hasher, p384_hasher, p521_hasher } from './src/nist.ts';
import { secp256k1_hasher } from './src/secp256k1.ts';

const h = {
  secp256k1_hasher,
  p256_hasher, p384_hasher, p521_hasher,
  ed25519_hasher,
  ed448_hasher,
  ristretto255_hasher,
  decaf448_hasher,
  bls_G1: bls12_381.G1,
  bls_G2: bls12_381.G2
};

const msg = Uint8Array.from([0xca, 0xfe, 0x01, 0x23]);
console.log('msg', msg);
for (let [name, c] of Object.entries(h)) {
  const hashToCurve = c.hashToCurve(msg).toHex();
  const hashToCurve_customDST = c.hashToCurve(msg, { DST: 'hello noble' }).toHex();
  const encodeToCurve = 'encodeToCurve' in c ? c.encodeToCurve(msg).toHex() : undefined;
  // ristretto255, decaf448 only
  const deriveToCurve = 'deriveToCurve' in c ?
    c.deriveToCurve!(new Uint8Array(c.Point.Fp.BYTES * 2)).toHex() : undefined;
  const hashToScalar = c.hashToScalar(msg);
  console.log({
    name, hashToCurve, hashToCurve_customDST, encodeToCurve, deriveToCurve, hashToScalar
  });
}

// abstract methods
import { expand_message_xmd, expand_message_xof, hash_to_field } from '@noble/curves/abstract/hash-to-curve.js';
```

The module allows to hash arbitrary strings to elliptic curve points. Implements [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380).

> [!NOTE]
> Why is `p256_hasher` separate from `p256`?
> The methods reside in separate _hasher namespace for tree-shaking:
> this way users who don't need hash-to-curve, won't have it in their builds.

### OPRFs

```js
import { p256_oprf, p384_oprf, p521_oprf } from '@noble/curves/nist.js';
import { ristretto255_oprf } from '@noble/curves/ed25519.js';
import { decaf448_orpf } from '@noble/curves/ed448.js';
```

We provide OPRFs (oblivious pseudorandom functions),
conforming to [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497).

OPRF allows to interactively create an `Output = PRF(Input, serverSecretKey)`:

- Server cannot calculate Output by itself: it doesn't know Input
- Client cannot calculate Output by itself: it doesn't know server secretKey
- An attacker interception the communication can't restore Input/Output/serverSecretKey and can't
  link Input to some value.

### poseidon: Poseidon hash

Implements [Poseidon](https://www.poseidon-hash.info) ZK-friendly hash:
permutation and sponge.

There are many poseidon variants with different constants.
We don't provide them: you should construct them manually.
Check out [scure-starknet](https://github.com/paulmillr/scure-starknet) package for a proper example.

```ts
import { poseidon, poseidonSponge } from '@noble/curves/abstract/poseidon.js';

const rate = 2;
const capacity = 1;
const { mds, roundConstants } = poseidon.grainGenConstants({
  Fp,
  t: rate + capacity,
  roundsFull: 8,
  roundsPartial: 31,
});
const opts = {
  Fp,
  rate,
  capacity,
  sboxPower: 17,
  mds,
  roundConstants,
  roundsFull: 8,
  roundsPartial: 31,
};
const permutation = poseidon.poseidon(opts);
const sponge = poseidon.poseidonSponge(opts); // use carefully, not specced
```

### fft: Fast Fourier Transform

```ts
import * as fft from '@noble/curves/abstract/fft.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';
const Fr = bls12_381.fields.Fr;
const roots = fft.rootsOfUnity(Fr, 7n);
const fftFr = fft.FFT(roots, Fr);
```

Experimental implementation of NTT / FFT (Fast Fourier Transform) over finite fields.
API may change at any time. The code has not been audited. Feature requests are welcome.

### utils: byte shuffling, conversion

```ts
import { bytesToHex, concatBytes, equalBytes, hexToBytes } from '@noble/curves/abstract/utils.js';

bytesToHex(Uint8Array.from([0xca, 0xfe, 0x01, 0x23]));
hexToBytes('cafe0123');
concatBytes(Uint8Array.from([0xca, 0xfe]), Uint8Array.from([0x01, 0x23]));
equalBytes(Uint8Array.of(0xca), Uint8Array.of(0xca));
```

### Internals

#### Elliptic curve Point math

```js
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { p256, p384, p521 } from '@noble/curves/nist.js';
import { ed25519, ristretto255 } from '@noble/curves/ed25519.js';
import { ed448, decaf448 } from '@noble/curves/ed448.js';
import { bls12_381 } from '@noble/curves/bls12-381.js'
import { bn254 } from '@noble/curves/bn254.js';
import { jubjub, babyjubjub } from '@noble/curves/misc.js';

const curves = [
  secp256k1, schnorr, p256, p384, p521, ed25519, ed448,
  ristretto255, decaf448,
  bls12_381.G1, bls12_381.G2, bn254.G1, bn254.G2,
  jubjub, babyjubjub
];
for (const curve of curves) {
  const { Point } = curve;
  const { BASE, ZERO, Fp, Fn } = Point;
  const p = BASE.multiply(2n);

  // Initialization
  if (info.type === 'weierstrass') {
    // projective (homogeneous) coordinates: (X, Y, Z) ∋ (x=X/Z, y=Y/Z)
    const p_ = new Point(BASE.X, BASE.Y, BASE.Z);
  } else if (info.type === 'edwards') {
    // extended coordinates: (X, Y, Z, T) ∋ (x=X/Z, y=Y/Z)
    const p_ = new Point(BASE.X, BASE.Y, BASE.Z, BASE.T);
  }

  // Math
  const p1 = p.add(p);
  const p2 = p.double();
  const p3 = p.subtract(p);
  const p4 = p.negate();
  const p5 = p.multiply(451n);

  // MSM (multi-scalar multiplication)
  const pa = [BASE, BASE.multiply(2n), BASE.multiply(4n), BASE.multiply(8n)];
  const p6 = Point.msm(pa, [3n, 5n, 7n, 11n]);
  const _true3 = p6.equals(BASE.multiply(129n)); // 129*G

  const pcl = p.clearCofactor();
  console.log(p.isTorsionFree(), p.isSmallOrder());

  const r1 = p.toBytes();
  const r1_ = Point.fromBytes(r1);
  const r2 = p.toAffine();
  const { x, y } = r2;
  const r2_ = Point.fromAffine(r2);
}
```

#### modular: Modular arithmetics & finite fields

```js
import { mod, invert, Field } from '@noble/curves/abstract/modular.js';

// Finite Field utils
const fp = Field(2n ** 255n - 19n); // Finite field over 2^255-19
fp.mul(591n, 932n); // multiplication
fp.pow(481n, 11024858120n); // exponentiation
fp.div(5n, 17n); // division: 5/17 mod 2^255-19 == 5 * invert(17)
fp.inv(5n); // modular inverse
fp.sqrt(21n); // square root

// Non-Field generic utils are also available
mod(21n, 10n); // 21 mod 10 == 1n; fixed version of 21 % 10
invert(17n, 10n); // invert(17) mod 10; modular multiplicative inverse
```

All arithmetics is done with JS bigints over finite fields,
which is defined from `modular` sub-module.

Field operations are not constant-time: see [security](#security).
The fact is mostly irrelevant, but the important method to keep in mind is `pow`,
which may leak exponent bits, when used naïvely.

#### weierstrass: Custom Weierstrass curve

```js
import { weierstrass } from '@noble/curves/abstract/weierstrass.js';
// NIST secp192r1 aka p192. https://www.secg.org/sec2-v2.pdf
const p192_CURVE = {
  p: 0xfffffffffffffffffffffffffffffffeffffffffffffffffn,
  n: 0xffffffffffffffffffffffff99def836146bc9b1b4d22831n,
  h: 1n,
  a: 0xfffffffffffffffffffffffffffffffefffffffffffffffcn,
  b: 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1n,
  Gx: 0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012n,
  Gy: 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811n,
};
const p192_Point = weierstrass(p192_CURVE);
```

Short Weierstrass curve's formula is `y² = x³ + ax + b`. `weierstrass`
expects arguments `a`, `b`, field characteristic `p`, curve order `n`,
cofactor `h` and coordinates `Gx`, `Gy` of generator point.

#### edwards: Custom Edwards curve

```js
import { edwards } from '@noble/curves/abstract/edwards.js';
const ed25519_CURVE = {
  p: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffedn,
  n: 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn,
  h: 8n,
  a: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffecn,
  d: 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3n,
  Gx: 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51an,
  Gy: 0x6666666666666666666666666666666666666666666666666666666666666658n,
};
const ed25519_Point = edwards(ed25519_CURVE);
```

Twisted Edwards curve's formula is `ax² + y² = 1 + dx²y²`.
You must specify `a`, `d`, field characteristic `p`, curve order `n` (sometimes named as `L`),
cofactor `h` and coordinates `Gx`, `Gy` of generator point.

#### Custom ECDSA instance

```js
import { ecdsa } from '@noble/curves/abstract/weierstrass.js';
import { sha256 } from '@noble/hashes/sha2.js';
const p192_sha256 = ecdsa(p192_Point, sha256);
// or
const p192_sha224 = ecdsa(p192.Point, sha224);

const keys = p192_sha256.keygen();
const msg = new TextEncoder().encode('custom curve');
const sig = p192_sha256.sign(msg, keys.secretKey);
const isValid = p192_sha256.verify(sig, msg, keys.publicKey);
```

## Security

The library has been independently audited:

- at version 1.6.0, in Sep 2024, by [Cure53](https://cure53.de)
  - PDFs: [website](https://cure53.de/audit-report_noble-crypto-libs.pdf), [in-repo](./audit/2024-09-cure53-audit-nbl4.pdf)
  - [Changes since audit](https://github.com/paulmillr/noble-curves/compare/1.6.0..main)
  - Scope: ed25519, ed448, their add-ons, bls12-381, bn254,
    hash-to-curve, low-level primitives bls, tower, edwards, montgomery.
  - The audit has been funded by [OpenSats](https://opensats.org)
- at version 1.2.0, in Sep 2023, by [Kudelski Security](https://kudelskisecurity.com)
  - PDFs: [in-repo](./audit/2023-09-kudelski-audit-starknet.pdf)
  - [Changes since audit](https://github.com/paulmillr/noble-curves/compare/1.2.0..main)
  - Scope: [scure-starknet](https://github.com/paulmillr/scure-starknet) and its related
    abstract modules of noble-curves: `curve`, `modular`, `poseidon`, `weierstrass`
  - The audit has been funded by [Starkware](https://starkware.co)
- at version 0.7.3, in Feb 2023, by [Trail of Bits](https://www.trailofbits.com)
  - PDFs: [website](https://github.com/trailofbits/publications/blob/master/reviews/2023-01-ryanshea-noblecurveslibrary-securityreview.pdf),
    [in-repo](./audit/2023-01-trailofbits-audit-curves.pdf)
  - [Changes since audit](https://github.com/paulmillr/noble-curves/compare/0.7.3..main)
  - Scope: abstract modules `curve`, `hash-to-curve`, `modular`, `poseidon`, `utils`, `weierstrass` and
    top-level modules `_shortw_utils` and `secp256k1`
  - The audit has been funded by [Ryan Shea](https://www.shea.io)

It is tested against property-based, cross-library and Wycheproof vectors,
and is being fuzzed in [the separate repo](https://github.com/paulmillr/integration-tests).

If you see anything unusual: investigate and report.

### Constant-timeness

We're targetting algorithmic constant time. _JIT-compiler_ and _Garbage Collector_ make "constant time"
extremely hard to achieve [timing attack](https://en.wikipedia.org/wiki/Timing_attack) resistance
in a scripting language. Which means _any other JS library can't have
constant-timeness_. Even statically typed Rust, a language without GC,
[makes it harder to achieve constant-time](https://www.chosenplaintext.ca/open-source/rust-timing-shield/security)
for some cases. If your goal is absolute security, don't use any JS lib — including bindings to native ones.
Use low-level libraries & languages.

### Memory dumping

Use low-level languages instead of JS / WASM if your goal is absolute security.

The library mostly uses Uint8Arrays and bigints.

- Uint8Arrays have `.fill(0)` which instructs to fill content with zeroes
  but there are no guarantees in JS
- bigints are immutable and don't have a method to zeroize their content:
  a user needs to wait until the next garbage collection cycle
- hex strings are also immutable: there is no way to zeroize them
- `await fn()` will write all internal variables to memory. With
  async functions there are no guarantees when the code
  chunk would be executed. Which means attacker can have
  plenty of time to read data from memory.

This means some secrets could stay in memory longer than anticipated.
However, if an attacker can read application memory, it's doomed anyway:
there is no way to guarantee anything about zeroizing sensitive data without
complex tests-suite which will dump process memory and verify that there is
no sensitive data left. For JS it means testing all browsers (including mobile).
And, of course, it will be useless without using the same
test-suite in the actual application that consumes the library.

### Supply chain security

- **Commits** are signed with PGP keys, to prevent forgery. Make sure to verify commit signatures
- **Releases** are transparent and built on GitHub CI. Make sure to verify [provenance](https://docs.npmjs.com/generating-provenance-statements) logs
  - Use GitHub CLI to verify single-file builds:
    `gh attestation verify --owner paulmillr noble-curves.js`
- **Rare releasing** is followed to ensure less re-audit need for end-users
- **Dependencies** are minimized and locked-down: any dependency could get hacked and users will be downloading malware with every install.
  - We make sure to use as few dependencies as possible
  - Automatic dep updates are prevented by locking-down version ranges; diffs are checked with `npm-diff`
- **Dev Dependencies** are disabled for end-users; they are only used to develop / build the source code

For this package, there is 1 dependency; and a few dev dependencies:

- [noble-hashes](https://github.com/paulmillr/noble-hashes) provides cryptographic hashing functionality
- micro-bmark, micro-should and jsbt are used for benchmarking / testing / build tooling and developed by the same author
- prettier, fast-check and typescript are used for code quality / test generation / ts compilation. It's hard to audit their source code thoroughly and fully because of their size

### Randomness

We're deferring to built-in
[crypto.getRandomValues](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues)
which is considered cryptographically secure (CSPRNG).

In the past, browsers had bugs that made it weak: it may happen again.
Implementing a userspace CSPRNG to get resilient to the weakness
is even worse: there is no reliable userspace source of quality entropy.

### Quantum computers

Cryptographically relevant quantum computer, if built, will allow to
break elliptic curve cryptography (both ECDSA / EdDSA & ECDH) using Shor's algorithm.

Consider switching to newer / hybrid algorithms, such as SPHINCS+. They are available in
[noble-post-quantum](https://github.com/paulmillr/noble-post-quantum).

NIST prohibits classical cryptography (RSA, DSA, ECDSA, ECDH) [after 2035](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf). Australian ASD prohibits it [after 2030](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/ism/cyber-security-guidelines/guidelines-cryptography).

## Speed

```sh
npm run bench
```

noble-curves spends 10+ ms to generate 20MB+ of base point precomputes.
This is done **one-time** per curve.

The generation is deferred until any method (pubkey, sign, verify) is called.
User can force precompute generation by manually calling `Point.BASE.precompute(windowSize, false)`.
Check out the source code.

Benchmark results on Apple M4:

```
# secp256k1
init 10ms
getPublicKey x 9,099 ops/sec @ 109μs/op
sign x 7,182 ops/sec @ 139μs/op
verify x 1,188 ops/sec @ 841μs/op
recoverPublicKey x 1,265 ops/sec @ 790μs/op
getSharedSecret x 735 ops/sec @ 1ms/op
schnorr.sign x 957 ops/sec @ 1ms/op
schnorr.verify x 1,210 ops/sec @ 825μs/op

# ed25519
init 14ms
getPublicKey x 14,216 ops/sec @ 70μs/op
sign x 6,849 ops/sec @ 145μs/op
verify x 1,400 ops/sec @ 713μs/op

# ed448
init 37ms
getPublicKey x 5,273 ops/sec @ 189μs/op
sign x 2,494 ops/sec @ 400μs/op
verify x 476 ops/sec @ 2ms/op

# p256
init 17ms
getPublicKey x 8,977 ops/sec @ 111μs/op
sign x 7,236 ops/sec @ 138μs/op
verify x 877 ops/sec @ 1ms/op

# p384
init 42ms
getPublicKey x 4,084 ops/sec @ 244μs/op
sign x 3,247 ops/sec @ 307μs/op
verify x 331 ops/sec @ 3ms/op

# p521
init 83ms
getPublicKey x 2,049 ops/sec @ 487μs/op
sign x 1,748 ops/sec @ 571μs/op
verify x 170 ops/sec @ 5ms/op

# ristretto255
add x 931,966 ops/sec @ 1μs/op
multiply x 15,444 ops/sec @ 64μs/op
encode x 21,367 ops/sec @ 46μs/op
decode x 21,715 ops/sec @ 46μs/op

# decaf448
add x 478,011 ops/sec @ 2μs/op
multiply x 416 ops/sec @ 2ms/op
encode x 8,562 ops/sec @ 116μs/op
decode x 8,636 ops/sec @ 115μs/op

# ECDH
x25519 x 1,981 ops/sec @ 504μs/op
x448 x 743 ops/sec @ 1ms/op
secp256k1 x 728 ops/sec @ 1ms/op
p256 x 705 ops/sec @ 1ms/op
p384 x 268 ops/sec @ 3ms/op
p521 x 137 ops/sec @ 7ms/op

# hash-to-curve
hashToPrivateScalar x 1,754,385 ops/sec @ 570ns/op
hash_to_field x 135,703 ops/sec @ 7μs/op
hashToCurve secp256k1 x 3,194 ops/sec @ 313μs/op
hashToCurve p256 x 5,962 ops/sec @ 167μs/op
hashToCurve p384 x 2,230 ops/sec @ 448μs/op
hashToCurve p521 x 1,063 ops/sec @ 940μs/op
hashToCurve ed25519 x 4,047 ops/sec @ 247μs/op
hashToCurve ed448 x 1,691 ops/sec @ 591μs/op
hash_to_ristretto255 x 8,733 ops/sec @ 114μs/op
hash_to_decaf448 x 3,882 ops/sec @ 257μs/op

# modular over secp256k1 P field
invert a x 866,551 ops/sec @ 1μs/op
invert b x 693,962 ops/sec @ 1μs/op
sqrt p = 3 mod 4 x 25,738 ops/sec @ 38μs/op
sqrt tonneli-shanks x 847 ops/sec @ 1ms/op

# bls12-381
init 22ms
getPublicKey x 1,325 ops/sec @ 754μs/op
sign x 80 ops/sec @ 12ms/op
verify x 62 ops/sec @ 15ms/op
pairing x 166 ops/sec @ 6ms/op
pairing10 x 54 ops/sec @ 18ms/op ± 23.48% (15ms..36ms)
MSM 4096 scalars x points 3286ms
aggregatePublicKeys/8 x 173 ops/sec @ 5ms/op
aggregatePublicKeys/32 x 46 ops/sec @ 21ms/op
aggregatePublicKeys/128 x 11 ops/sec @ 84ms/op
aggregatePublicKeys/512 x 2 ops/sec @ 335ms/op
aggregatePublicKeys/2048 x 0 ops/sec @ 1346ms/op
aggregateSignatures/8 x 82 ops/sec @ 12ms/op
aggregateSignatures/32 x 21 ops/sec @ 45ms/op
aggregateSignatures/128 x 5 ops/sec @ 178ms/op
aggregateSignatures/512 x 1 ops/sec @ 705ms/op
aggregateSignatures/2048 x 0 ops/sec @ 2823ms/op
```

## Upgrading

Supported node.js versions:

- v2 (2025-08): v20.19+ (ESM-only)
- v1 (2023-04): v14.21+ (ESM & CJS)

### Changelog of curves v1 to curves v2

v2 massively simplifies internals, improves security, reduces bundle size and lays path for the future.
We tried to keep v2 as much backwards-compatible as possible.

To simplify upgrading, upgrade first to curves 1.9.x. It would show deprecations in vscode-like text editor.
Fix them first.

- The package is now ESM-only. ESM can finally be loaded from common.js on node v20.19+
- `.js` extension must be used for all modules
    - Old: `@noble/curves/ed25519`
    - New: `@noble/curves/ed25519.js`
    - This simplifies working in browsers natively without transpilers

New features:

- webcrypto: create friendly noble-like wrapper over built-in WebCrypto
- oprf: implement RFC 9497 OPRFs (oblivious pseudorandom functions)
    - We support p256, p384, p521, ristretto255 and decaf448
- weierstrass, edwards: add `isValidSecretKey`, `isValidPublicKey`
- misc: add Brainpool curves: brainpoolP256r1, brainpoolP384r1, brainpoolP512r1

Changes:

- Most methods now expect Uint8Array, string hex inputs are prohibited
    - The change simplifies reasoning, improves security and reduces malleability
    - `Point.fromHex` now expects string-only hex inputs, use `Point.fromBytes` for Uint8Array
- Breaking changes of ECDSA (secp256k1, p256, p384...):
    - sign, verify: Switch to **prehashed messages**. Instead of
      messageHash, the methods now expect unhashed message.
      To bring back old behavior, use option `{prehash: false}`
    - sign, verify: Switch to **lowS signatures** by default.
      This change doesn't affect secp256k1, which has been using lowS since beginning.
      To bring back old behavior, use option `{lowS: true}`
    - sign, verify: Switch to **Uint8Array signatures** (format: 'compact') by default.
    - verify: **der format must be explicitly specified** in `{format: 'der'}`.
      This reduces malleability
    - verify: **prohibit Signature-instance** signature. User must now always do
      `signature.toBytes()`
- Breaking changes of BLS signatures (bls12-381, bn254):
    - Move getPublicKey, sign, verify, signShortSignature etc into two new namespaces:
      bls.longSignatures (G1 pubkeys, G2 sigs) and bls.shortSignatures (G1 sigs, G2 pubkeys).
    - verifyBatch now expects array of inputs `{message: ..., publicKey: ...}[]`
- Curve changes:
    - Massively simplify curve creation, split it into point creation & sig generator creation
    - New methods are `weierstrass() + ecdsa()` / `edwards() + eddsa()`
    - weierstrass / edwards expect simplified curve params (Fp became p)
    - ecdsa / eddsa expect Point class and hash
    - Remove unnecessary Fn argument in `pippenger`
- modular changes:
    - Field#fromBytes() now validates elements to be in 0..order-1 range
- Massively improve error messages, make them more descriptive

Renamings:

- Module changes
    - `p256`, `p384`, `p521` modules have been moved into `nist`
    - `jubjub` module has been moved into `misc`
- Point changes
    - ExtendedPoint, ProjectivePoint => Point
    - Point coordinates (projective / extended) from px/ex, py/ey, pz/ez, et => X, Y, Z, T
    - Point.normalizeZ, Point.msm => separate methods in `abstract/curve.js` submodule
    - Point.fromPrivateKey() got removed, use `Point.BASE.multiply()` and `Point.Fn.fromBytes(secretKey)`
    - toRawBytes, fromRawBytes => toBytes, fromBytes
    - RistrettoPoint => ristretto255.Point, DecafPoiont => decaf448.Point
- Signature (ECDSA) changes
    - toCompactRawBytes, toDERRawBytes => toBytes('compact'), toBytes('der')
    - toCompactHex, toDERHex => toHex('compact'), toHex('der')
    - fromCompact, fromDER => fromBytes(format), fromHex(format)
- utils changes
    - randomPrivateKey => randomSecretKey
    - utils.precompute, Point#_setWindowSize => Point#precompute
    - edwardsToMontgomery => utils.toMontgomery
    - edwardsToMontgomeryPriv => utils.toMontgomerySecret
- Rename all curve-specific hash-to-curve methods to `*curve*_hasher`.
  Example: `secp256k1.hashToCurve` => `secp256k1_hasher.hashToCurve()`
- Massive type renamings and improvements

Removed features:

- Point#multiplyAndAddUnsafe, Point#hasEvenY
- CURVE property with all kinds of random stuff. Point.CURVE() now replaces it, but only provides
  curve parameters
- Remove `pasta`, `bn254_weierstrass` (NOT pairing-based bn254) curves
- Field.MASK
- utils.normPrivateKeyToScalar

### noble-secp256k1 v1 to curves v1

Previously, the library was split into single-feature packages
[noble-secp256k1](https://github.com/paulmillr/noble-secp256k1),
[noble-ed25519](https://github.com/paulmillr/noble-ed25519) and
[noble-bls12-381](https://github.com/paulmillr/noble-bls12-381).

Curves continue their original work. The single-feature packages changed their
direction towards providing minimal 5kb implementations of cryptography,
which means they have less features.

- `getPublicKey`
  - now produce 33-byte compressed signatures by default
  - to use old behavior, which produced 65-byte uncompressed keys, set
    argument `isCompressed` to `false`: `getPublicKey(priv, false)`
- `sign`
  - is now sync
  - now returns `Signature` instance with `{ r, s, recovery }` properties
  - `canonical` option was renamed to `lowS`
  - `recovered` option has been removed because recovery bit is always returned now
  - `der` option has been removed. There are 2 options:
    1. Use compact encoding: `fromCompact`, `toCompactRawBytes`, `toCompactHex`.
       Compact encoding is simply a concatenation of 32-byte r and 32-byte s.
    2. If you must use DER encoding, switch to noble-curves (see above).
- `verify`
  - is now sync
  - `strict` option was renamed to `lowS`
- `getSharedSecret`
  - now produce 33-byte compressed signatures by default
  - to use old behavior, which produced 65-byte uncompressed keys, set
    argument `isCompressed` to `false`: `getSharedSecret(a, b, false)`
- `recoverPublicKey(msg, sig, rec)` was changed to `sig.recoverPublicKey(msg)`
- `number` type for private keys have been removed: use `bigint` instead
- `Point` (2d xy) has been changed to `ProjectivePoint` (3d xyz)
- `utils` were split into `utils` (same api as in noble-curves) and
  `etc` (`hmacSha256Sync` and others)

### noble-ed25519 v1 to curves v1

Upgrading from [@noble/ed25519](https://github.com/paulmillr/noble-ed25519):

- Methods are now sync by default
- `bigint` is no longer allowed in `getPublicKey`, `sign`, `verify`. Reason: ed25519 is LE, can lead to bugs
- `Point` (2d xy) has been changed to `ExtendedPoint` (xyzt)
- `Signature` was removed: just use raw bytes or hex now
- `utils` were split into `utils` (same api as in noble-curves) and
  `etc` (`sha512Sync` and others)
- `getSharedSecret` was moved to `x25519` module
- `toX25519` has been moved to `edwardsToMontgomeryPub` and `edwardsToMontgomeryPriv` methods

### noble-bls12-381 to curves v1

Upgrading from [@noble/bls12-381](https://github.com/paulmillr/noble-bls12-381):

- Methods and classes were renamed:
  - PointG1 -> G1.Point, PointG2 -> G2.Point
  - PointG2.fromSignature -> Signature.decode, PointG2.toSignature -> Signature.encode
- Fp2 ORDER was corrected

## Contributing & testing

- `npm install && npm run build && npm test` will build the code and run tests.
- `npm run lint` / `npm run format` will run linter / fix linter issues.
- `npm run bench` will run benchmarks
- `npm run build:release` will build single file

See [paulmillr.com/noble](https://paulmillr.com/noble/)
for useful resources, articles, documentation and demos
related to the library.

MuSig2 signature scheme and BIP324 ElligatorSwift mapping for secp256k1
are available [in a separate package](https://github.com/paulmillr/scure-btc-signer).

## License

The MIT License (MIT)

Copyright (c) 2022 Paul Miller [(https://paulmillr.com)](https://paulmillr.com)

See LICENSE file.
