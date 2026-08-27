# noble-curves

Audited & minimal JS implementation of elliptic curve cryptography.

- 🔒 [**Audited**](#security) by independent security firms
- 🪶 Minimal: 15KB (gzipped) secp256k1, unused code is excluded from your builds
- 🏎 Fast: hand-optimized for caveats of JS engines
- 🔍 Reliable: cross-library / wycheproof tests ensure correctness
- ➰ Weierstrass, Edwards curves; ECDSA, EdDSA, Schnorr, BLS signatures
- ✍️ ECDH, hash-to-curve, OPRF, FROST, Poseidon hash, FFT
- 🔖 Non-repudiation (SUF-CMA, SBS) & consensus-friendliness (ZIP215) in ed25519, ed448
- 🥈 Wrapper with identical API over native WebCrypto

Curves have 5kb sister projects
[secp256k1](https://github.com/paulmillr/noble-secp256k1) & [ed25519](https://github.com/paulmillr/noble-ed25519).
They have smaller attack surface, but less features.

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
- WASM version: [awasm-noble](https://github.com/paulmillr/awasm-noble)
- [Check out the homepage](https://paulmillr.com/noble/)
  for reading resources, documentation, and apps built with noble

## Usage

> `npm install @noble/curves`

> `deno add jsr:@noble/curves`

We support all major platforms and runtimes.
For React Native, you may need a [polyfill for getRandomValues](https://github.com/LinusU/react-native-get-random-values).
A standalone file [noble-curves.js](https://github.com/paulmillr/noble-curves/releases) is also available.

```js
// import * from '@noble/curves'; // Error: use sub-imports, to ensure small app size
import { secp256k1 } from '@noble/curves/secp256k1.js';
const { secretKey, publicKey } = secp256k1.keygen();
const msg = new TextEncoder().encode('hello noble');
const sig = secp256k1.sign(msg, secretKey);
const isValid = secp256k1.verify(sig, msg, publicKey);
```

- [ECDSA, EdDSA, Schnorr signatures](#ecdsa-eddsa-schnorr-signatures)
- [ECDH: Diffie-Hellman shared secrets](#ecdh-diffie-hellman-shared-secrets)
- [webcrypto: friendly wrapper](#webcrypto-friendly-wrapper)
- [BLS signatures, bls12-381, bn254 aka alt\_bn128](#bls-signatures-bls12-381-bn254-aka-alt_bn128)
- [hash-to-curve: hashing to curve points](#hash-to-curve-hashing-to-curve-points)
- [OPRFs](#oprfs) | [FROST threshold signatures](#frost-threshold-signatures)
- [poseidon: Poseidon hash](#poseidon-poseidon-hash) | [fft: Fast Fourier Transform](#fft-fast-fourier-transform) | [utils](#utils-byte-shuffling-conversion)
- Internals: [Point math](#elliptic-curve-point-math) | [modular](#modular-modular-arithmetics--finite-fields) | [custom curves](#weierstrass-custom-weierstrass-curve--ecdsa)
- [Specs](#specs)
- [Security](#security) | [Speed](#speed) | [Upgrading](#upgrading) | [Contributing & testing](#contributing--testing) | [License](#license)

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

Messages are always hashed first: see [prehashed signing](#prehashed-signing).
ECDSA uses deterministic k, EdDSA follows RFC 8032, Schnorr (secp256k1-only) follows BIP 340: see [Specs](#specs).

MuSig2 signature scheme and BIP324 ElligatorSwift mapping for secp256k1
are available [in a separate package](https://github.com/paulmillr/scure-btc-signer).

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
import { keccak_256 } from '@noble/hashes/sha3.js';
const { secretKey } = secp256k1.keygen();
const msg = new TextEncoder().encode('hello noble');
// prehash: true (default) - hash using secp256k1.hash (sha256)
const sig = secp256k1.sign(msg, secretKey);
// prehash: false - hash using custom hash
const sigKeccak = secp256k1.sign(keccak_256(msg), secretKey, { prehash: false });
```

By default (`prehash: true`), sign() and verify() apply the curve's built-in hash to the message first:
sha256 for secp256k1, sha512 for p521. `prehash: false` allows using a custom hash
(e.g. secp256k1 + keccak_256). In noble-curves v1, `prehash: false` was the default.

#### Recovering public keys from signatures

```js
import { secp256k1 } from '@noble/curves/secp256k1.js';
const { secretKey, publicKey } = secp256k1.keygen();
const msg = new TextEncoder().encode('hello noble');
const sigRec = secp256k1.sign(msg, secretKey, { format: 'recovered' });
const publicKey_ = secp256k1.recoverPublicKey(sigRec, msg); // == publicKey

// recovered sig is compact sig with an extra byte
const sigNoRec = secp256k1.sign(msg, secretKey, { format: 'compact' });
// sigNoRec == sigRec.slice(1)

// Signature instance
const sigInstance = secp256k1.Signature.fromBytes(sigRec, 'recovered');
```

Public key recovery is only supported with ECDSA. It is a simple math operation:
there are no guarantees the signing was actually done. A forged (r, s, h) recovers into
a random public key, but it's not feasible to find m which would lead to this specific forged h.

#### Hedged ECDSA with noise

```js
import { secp256k1 } from '@noble/curves/secp256k1.js';
const { secretKey } = secp256k1.keygen();
const msg = new TextEncoder().encode('hello noble');
// extraEntropy: false - default, hedging disabled
const sigNoisy = secp256k1.sign(msg, secretKey);
// extraEntropy: true - fetch 32 random bytes from CSPRNG
const sigNoisyA = secp256k1.sign(msg, secretKey, { extraEntropy: true });
// extraEntropy: bytes - specific extra entropy
const ent = Uint8Array.from([0xca, 0xfe, 0x01, 0x23]);
const sigNoisy2 = secp256k1.sign(msg, secretKey, { extraEntropy: ent });
```

By default, ECDSA signatures are deterministic (RFC 6979). Purely deterministic signatures are
vulnerable to fault attacks, so newer schemes, such as BIP340 schnorr, incorporate randomness
into sig generation - a.k.a. hedging. `extraEntropy` enables hedged mode. For more info, check out
[Deterministic signatures are not your friends](https://paulmillr.com/posts/deterministic-signatures/).

#### Consensus-friendliness vs e-voting

```js
import { ed25519 } from '@noble/curves/ed25519.js';
const { secretKey, publicKey } = ed25519.keygen();
const msg = new TextEncoder().encode('hello noble');
const sig = ed25519.sign(msg, secretKey);
// zip215: true
const isValid = ed25519.verify(sig, msg, publicKey);
// SBS / e-voting / RFC8032 / FIPS 186-5
const isValidRfc = ed25519.verify(sig, msg, publicKey, { zip215: false });
```

* `zip215: true` (default) uses the more permissive, [consensus-friendly](https://hdevalence.ca/blog/2020-10-04-its-25519am) verification rules defined in [ZIP215](https://zips.z.cash/zip-0215).
* `zip215: false` enforces strict RFC 8032 / FIPS 186-5 verification and adds SBS-based
  non-repudiation, which is useful for contract signing, e-voting and blockchains.

Both modes have SUF-CMA (strong unforgeability under chosen message attacks);
most other libraries have neither SUF-CMA nor SBS.
See [Taming the many EdDSAs](https://eprint.iacr.org/2020/1244) for more info.

### ECDH: Diffie-Hellman shared secrets

```js
import { x25519 } from '@noble/curves/ed25519.js';
const alice = x25519.keygen();
const bob = x25519.keygen();
const sharedKey = x25519.getSharedSecret(alice.secretKey, bob.publicKey);
// Same API: secp256k1, p256, p384, p521, x448

// converting ed25519 keys to x25519
import { ed25519 } from '@noble/curves/ed25519.js';
const alice2 = ed25519.keygen();
const bob2 = ed25519.keygen();
const aliceSecX = ed25519.utils.toMontgomerySecret(alice2.secretKey);
const bobPubX = ed25519.utils.toMontgomery(bob2.publicKey);
const sharedKey2 = x25519.getSharedSecret(aliceSecX, bobPubX);
```

We provide ECDH over all Weierstrass curves, and over 2 Montgomery curves
X25519 (Curve25519) & X448 (Curve448), conforming to [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748).

In Weierstrass curves, shared secrets:

- Include y-parity bytes: use `key.slice(1)` to strip it
- Are not hashed: use hashing or KDF on top, like `sha256(shared)` or `hkdf(shared)`

### webcrypto: friendly wrapper

```js
import { ed25519, x25519 } from '@noble/curves/webcrypto.js';

// signatures: p256, p384, p521, ed25519, ed448
const keys = await ed25519.keygen();
const msg = new TextEncoder().encode('hello noble');
const sig = await ed25519.sign(msg, keys.secretKey);
const isValid = await ed25519.verify(sig, msg, keys.publicKey);

// ECDH: p256, p384, p521, x25519, x448
const alice = await x25519.keygen();
const bob = await x25519.keygen();
const shared = await x25519.getSharedSecret(alice.secretKey, bob.publicKey);

// key conversion between noble (raw) and webcrypto (pkcs8 / spki) formats
import { p256 as p256n } from '@noble/curves/nist.js';
import { p256 } from '@noble/curves/webcrypto.js';
const nobleKeys = p256n.keygen();
const secretKeyPkcs8 = await p256.utils.convertSecretKey(nobleKeys.secretKey, 'raw', 'pkcs8');
const publicKeySpki = await p256.utils.convertPublicKey(nobleKeys.publicKey, 'raw', 'spki');
```

A thin wrapper over built-in WebCrypto, mirroring the noble API. Methods are always async;
runtime support varies - check with `await curve.isSupported()`.
Check out [micro-key-producer](https://github.com/paulmillr/micro-key-producer) for
pure JS key conversion utils.

### BLS signatures, bls12-381, bn254 aka alt_bn128

```ts
import { bls12_381 } from '@noble/curves/bls12-381.js';

// G1 pubkeys, G2 sigs
const blsl = bls12_381.longSignatures;
const { secretKey, publicKey } = blsl.keygen();
const msg = new TextEncoder().encode('hello noble');
const msgp = blsl.hash(msg); // hash to point, default DST
const msgpd = blsl.hash(msg, 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_'); // custom DST (Ethereum)
const signature = blsl.sign(msgp, secretKey);
const isValid = blsl.verify(signature, msgp, publicKey);

// G1 sigs, G2 pubkeys: identical API
const blss = bls12_381.shortSignatures;

// Aggregation
const aggregatedKey = blsl.aggregatePublicKeys([
  blsl.getPublicKey(bls12_381.utils.randomSecretKey()),
  blsl.getPublicKey(bls12_381.utils.randomSecretKey()),
]);
// const aggregatedSig = blsl.aggregateSignatures(sigs)

// Pairings: bls12_381.pairing(PointG1, PointG2)
// Fields: bls12_381.fields.Fp, Fp2, Fp12, Fr
```

For example usage, check out [the implementation of BLS EVM precompiles](https://github.com/ethereumjs/ethereumjs-monorepo/blob/361f4edbc239e795a411ac2da7e5567298b9e7e5/packages/evm/src/precompiles/bls12_381/noble.ts).

The BN254 API mirrors bls12-381. The curve was previously called alt_bn128.
The implementation is compatible with [EIP-196](https://eips.ethereum.org/EIPS/eip-196) and
[EIP-197](https://eips.ethereum.org/EIPS/eip-197):
check out [the implementation of bn254 EVM precompiles](https://github.com/paulmillr/noble-curves/blob/3ed792f8ad9932765b84d1064afea8663a255457/test/bn254.test.js#L697).
bn254 points don't implement toBytes, [because there is no serialization standard](https://github.com/privacy-scaling-explorations/halo2curves/issues/109):
implementations diverge on endianness, flags and G2 imaginary-part order.
Initialize points from bigints instead.

### hash-to-curve: hashing to curve points

```ts
import { secp256k1_hasher } from '@noble/curves/secp256k1.js';

const msg = Uint8Array.from([0xca, 0xfe, 0x01, 0x23]);
const point = secp256k1_hasher.hashToCurve(msg);
const pointDst = secp256k1_hasher.hashToCurve(msg, { DST: 'hello noble' });
const pointNu = secp256k1_hasher.encodeToCurve(msg);
const scalar = secp256k1_hasher.hashToScalar(msg);

// Same API: p256_hasher, p384_hasher, p521_hasher (nist.js),
// ed25519_hasher, ristretto255_hasher (ed25519.js), ed448_hasher, decaf448_hasher (ed448.js),
// bls12_381.G1, bls12_381.G2.
// ristretto255 & decaf448 also provide deriveToCurve.

// abstract methods
import { expand_message_xmd, expand_message_xof, hash_to_field } from '@noble/curves/abstract/hash-to-curve.js';
```

The module allows to hash arbitrary strings to elliptic curve points. Implements [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380).
`_hasher` namespaces are separate from curves for tree-shaking:
users who don't need hash-to-curve won't have it in their builds.

### OPRFs

```js
import { p256_oprf, p384_oprf, p521_oprf } from '@noble/curves/nist.js';
import { ristretto255_oprf } from '@noble/curves/ed25519.js';
import { decaf448_oprf } from '@noble/curves/ed448.js';
```

We provide OPRFs (oblivious pseudorandom functions),
conforming to [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497).

OPRF allows to interactively create an `Output = PRF(Input, serverSecretKey)`:

- Server cannot calculate Output by itself: it doesn't know Input
- Client cannot calculate Output by itself: it doesn't know server secretKey
- An attacker interception the communication can't restore Input/Output/serverSecretKey and can't
  link Input to some value.

### FROST threshold signatures

FROST implements [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591) threshold Schnorr signing.
It is similar to multisig from the application point of view: any `min` of `max` participants
can jointly produce one Schnorr signature under a shared public key.
Supported ciphersuites are `p256_FROST`, `ed25519_FROST`, `ed448_FROST`, `ristretto255_FROST`,
`secp256k1_FROST`, and `schnorr_FROST` (Taproot-compatible secp256k1).
Signing has two rounds: selected signers commit first, then produce signature shares.

```js
import { p256_FROST } from '@noble/curves/nist.js';

const signers = { min: 2, max: 3 };
const alice = p256_FROST.Identifier.derive('alice@example.com');
const bob = p256_FROST.Identifier.derive('bob@example.com');
const carol = p256_FROST.Identifier.derive('carol@example.com');
// trusted dealer
const deal = p256_FROST.trustedDealer(signers, [alice, bob, carol]);
for (const id of [alice, bob, carol]) p256_FROST.validateSecret(deal.secretShares[id], deal.public);

const msg = new TextEncoder().encode('hello threshold');
// round 1: selected signers commit
const aliceRound1 = p256_FROST.commit(deal.secretShares[alice]);
const bobRound1 = p256_FROST.commit(deal.secretShares[bob]);
const commitmentList = [aliceRound1.commitments, bobRound1.commitments];
// round 2: signers produce signature shares
const sigShares = {
  [alice]: p256_FROST.signShare(
    deal.secretShares[alice],
    deal.public,
    aliceRound1.nonces,
    commitmentList,
    msg
  ),
  [bob]: p256_FROST.signShare(
    deal.secretShares[bob],
    deal.public,
    bobRound1.nonces,
    commitmentList,
    msg
  ),
};
const sig = p256_FROST.aggregate(deal.public, commitmentList, msg, sigShares);
const isValid = p256_FROST.verify(sig, msg, deal.public.commitments[0]);
```

Key generation can be done with a trusted dealer (above) or with DKG (distributed key generation).
DKG has three rounds: participants commit to key generation, exchange private shares,
then derive final participant keys - see `DKG.round1` / `round2` / `round3` usage in
[the tests](./test/rfc9591-frost.test.ts).
The library implements the cryptographic steps, not the surrounding application protocol:
callers still need authenticated communication, coordination, retries, session handling, and policy.

### poseidon: Poseidon hash

Implements [Poseidon](https://www.poseidon-hash.info) ZK-friendly hash:
permutation and sponge.

There are many poseidon variants with different constants.
We don't provide them: you should construct them manually.
Check out [scure-starknet](https://github.com/paulmillr/scure-starknet) package for a proper example.

```ts
import { bn254 } from '@noble/curves/bn254.js';
import { grainGenConstants, poseidon, poseidonSponge } from '@noble/curves/abstract/poseidon.js';

const rate = 2;
const capacity = 1;
const Fp = bn254.fields.Fr;
const { mds, roundConstants } = grainGenConstants({
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
const permutation = poseidon({ ...opts, t: rate + capacity });
const sponge = poseidonSponge(opts); // use carefully, not specced
```

### fft: Fast Fourier Transform

```ts
import * as fft from '@noble/curves/abstract/fft.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';
const Fr = bls12_381.fields.Fr;
const roots = fft.rootsOfUnity(Fr, 7n);
const fftFr = fft.FFT(roots, Fr);
```

NTT / FFT (Fast Fourier Transform) over finite fields.

### utils: byte shuffling, conversion

```ts
import { bytesToHex, concatBytes, equalBytes, hexToBytes } from '@noble/curves/utils.js';

bytesToHex(Uint8Array.from([0xca, 0xfe, 0x01, 0x23]));
hexToBytes('cafe0123');
concatBytes(Uint8Array.from([0xca, 0xfe]), Uint8Array.from([0x01, 0x23]));
equalBytes(Uint8Array.of(0xca), Uint8Array.of(0xca));
```

### Internals

#### Elliptic curve Point math

```js
import { secp256k1 } from '@noble/curves/secp256k1.js';
const { Point } = secp256k1;
const { BASE, ZERO, Fp, Fn } = Point;
const p = BASE.multiply(2n);

// Math
const p1 = p.add(p);
const p2 = p.double();
const p3 = p.subtract(p);
const p4 = p.negate();
const p5 = p.multiply(451n);

// MSM (multi-scalar multiplication)
import { pippenger } from '@noble/curves/abstract/curve.js';
const pa = [BASE, BASE.multiply(2n), BASE.multiply(4n), BASE.multiply(8n)];
const p6 = pippenger(Point, pa, [3n, 5n, 7n, 11n]); // == BASE.multiply(129n)

// Cofactor
const pcl = p.clearCofactor();
const isTorsionFree = p.isTorsionFree();

// Conversions
const bytes = p.toBytes();
const p_ = Point.fromBytes(bytes);
const { x, y } = p.toAffine();
const p__ = Point.fromAffine({ x, y });
```

Every curve exposes its Point class: secp256k1, schnorr, p256, p384, p521, ed25519, ed448,
ristretto255, decaf448, bls12_381.G1 / G2, bn254.G1, jubjub, babyjubjub.
Weierstrass points use projective (homogeneous) coordinates `new Point(X, Y, Z)`,
edwards points use extended coordinates `new Point(X, Y, Z, T)`; both with x=X/Z, y=Y/Z.

#### modular: Modular arithmetics & finite fields

```js
import { mod, invert, Field } from '@noble/curves/abstract/modular.js';

// Finite Field utils
const fp = Field(2n ** 255n - 19n); // Finite field over 2^255-19
fp.mul(591n, 932n); // multiplication
fp.pow(481n, 11024858120n); // exponentiation
fp.div(5n, 17n); // division: 5/17 mod 2^255-19 == 5 * invert(17)
fp.inv(5n); // modular inverse
fp.sqrt(4n); // square root

// Non-Field generic utils are also available
mod(21n, 10n); // 21 mod 10 == 1n; fixed version of 21 % 10
invert(17n, 10n); // invert(17) mod 10; modular multiplicative inverse
```

All arithmetics is done with JS bigints over finite fields,
which is defined from `modular` sub-module.

Field operations are not constant-time: see [security](#security).
The fact is mostly irrelevant, but the important method to keep in mind is `pow`,
which may leak exponent bits, when used naïvely.

#### weierstrass: custom Weierstrass curve & ECDSA

```js
import { weierstrass, ecdsa } from '@noble/curves/abstract/weierstrass.js';
import { sha256 } from '@noble/hashes/sha2.js';
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
const p192 = ecdsa(p192_Point, sha256);

const keys = p192.keygen();
const msg = new TextEncoder().encode('custom curve');
const sig = p192.sign(msg, keys.secretKey);
const isValid = p192.verify(sig, msg, keys.publicKey);
```

Short Weierstrass curve's formula is `y² = x³ + ax + b`. `weierstrass`
expects arguments `a`, `b`, field characteristic `p`, curve order `n`,
cofactor `h` and coordinates `Gx`, `Gy` of generator point, and returns a Point class.
`ecdsa` combines a Point class with a hash function into a signature scheme.

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

### Specs

- ECDSA: deterministic k from [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979),
  hedged signatures from [cfrg-det-sigs-with-noise draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-det-sigs-with-noise/)
- EdDSA: [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032),
  [FIPS 186-5](https://csrc.nist.gov/publications/detail/fips/186/5/final);
  consensus-friendly verification: [ZIP215](https://zips.z.cash/zip-0215)
- Schnorr signatures: [BIP 340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- X25519, X448 ECDH: [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)
- ristretto255, decaf448: [RFC 9496](https://www.rfc-editor.org/rfc/rfc9496)
- hash-to-curve: [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380)
- OPRFs: [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497)
- FROST: [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591)
- bn254: [EIP-196](https://eips.ethereum.org/EIPS/eip-196), [EIP-197](https://eips.ethereum.org/EIPS/eip-197)
- Poseidon: [site](https://www.poseidon-hash.info)

## Security

The library has been audited:

- at version 2.3.0, in Aug 2026, by [Trail of Bits](https://www.trailofbits.com), in collaboration with OpenAI
  - It was done during "Patch the Planet" initiative
  - Scope: everything
- at version 1.6.0, in Sep 2024, independently, by [Cure53](https://cure53.de)
  - PDFs: [website](https://cure53.de/audit-report_noble-crypto-libs.pdf), [in-repo](./audit/2024-09-cure53-audit-nbl4.pdf)
  - Scope: ed25519, ed448, their add-ons, bls12-381, bn254,
    hash-to-curve, low-level primitives bls, tower, edwards, montgomery.
  - The audit has been funded by [OpenSats](https://opensats.org)
- at version 1.2.0, in Sep 2023, independently, by [Kudelski Security](https://kudelskisecurity.com)
  - PDFs: [in-repo](./audit/2023-09-kudelski-audit-starknet.pdf)
  - Scope: [scure-starknet](https://github.com/paulmillr/scure-starknet) and its related
    abstract modules of noble-curves: `curve`, `modular`, `poseidon`, `weierstrass`
  - The audit has been funded by [Starkware](https://starkware.co)
- at version 0.7.3, in Feb 2023, independently, by [Trail of Bits](https://www.trailofbits.com)
  - PDFs: [website](https://github.com/trailofbits/publications/blob/master/reviews/2023-01-ryanshea-noblecurveslibrary-securityreview.pdf),
    [in-repo](./audit/2023-01-trailofbits-audit-curves.pdf)
  - Scope: abstract modules `curve`, `hash-to-curve`, `modular`, `poseidon`, `utils`, `weierstrass` and
    top-level modules `_shortw_utils` and `secp256k1`
  - The audit has been funded by [Ryan Shea](https://www.shea.io)

We've started regular AI-assisted self-audits in Apr 2026.

It is tested against property-based, cross-library and Wycheproof vectors,
and is being fuzzed in github ci.

If you see anything unusual: investigate and report.

### Constant-timeness

We're targetting algorithmic constant time. _JIT-compiler_ and _Garbage Collector_ make "constant time"
extremely hard to achieve [timing attack](https://en.wikipedia.org/wiki/Timing_attack) resistance
in a scripting language. Which means _any other JS library can't have
constant-timeness_. Even statically typed Rust, a language without GC,
[makes it harder to achieve constant-time](https://www.chosenplaintext.ca/open-source/rust-timing-shield/security)
for some cases. If your goal is absolute security, don't use any JS lib — including bindings to native ones.
Use low-level libraries & languages.

Within those limits, secret-scalar multiplication provides specific, measurable properties:

- **Fixed operation sequence:** `multiply()` uses signed fixed-window tables with
  data-oblivious table scans — the number and order of point operations
  is independent of the scalar value.
- **Scalar blinding:** secret scalars are additionally masked as `s + r·n` with a random
  128-bit `r` before multiplication. This applies to all multiplications on cofactor-1
  curves (p256, p384, p521, secp256k1), and to base-point multiplications everywhere.
- **Statistical validation:** a dudect-style Welch t-test harness (`benchmark/ct.ts`)
  compares timing across adversarial scalar classes (sparse vs dense, low vs high bits,
  near-order, bit patterns). Base-point multiplication shows no distinguishable timing on any
  curve, and random-point multiplication shows none on the Weierstrass curves
  (max |t| ≤ 2.8 at 1000 samples; threshold 4.5).

Known limitation: on cofactored Edwards curves (ed25519, ed448), multiplying a **non-base**
point by a secret scalar is not blinded. The same harness detects this reliably. EdDSA signing is
unaffected (it only multiplies the blinded base point), and X25519/X448 use a separate
Montgomery-ladder implementation (also unaffected). It matters for protocols that multiply arbitrary
Edwards/Ristretto points by long-lived secret scalars; prefer scalars that are
full-width by construction there. Note that detectability in an isolated harness does not
imply practical exploitability: we attempted scalar extraction in a realistic
cross-tenant / in-browser setting and were unable to recover Edwards scalars
even with 100,000 timing samples.

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

- **Commits** are signed with PGP keys to prevent forgery. Be sure to verify the commit signatures
- **Releases** are made transparently through token-less GitHub CI and Trusted Publishing. Be sure to verify the [provenance logs](https://docs.npmjs.com/generating-provenance-statements) for authenticity.
- **Rare releasing** is practiced to minimize the need for re-audits by end-users.
- **Dependencies** are minimized and strictly pinned to reduce supply-chain risk.
  - We use as few dependencies as possible.
  - Version ranges are locked, and changes are checked with npm-diff.
- **Dev dependencies** are excluded from end-user installs; they’re only used for development and build steps.

For this package, there is 1 dependency; and a few dev dependencies:

- [noble-hashes](https://github.com/paulmillr/noble-hashes) provides cryptographic hashing functionality
- jsbt is used for benchmarking / testing / build tooling and developed by the same author
- prettier, fast-check and typescript are used for code quality / test generation / ts compilation

### Randomness

We rely on the built-in
[`crypto.getRandomValues`](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues),
which is considered a cryptographically secure PRNG.

Browsers have had weaknesses in the past - and could again - but implementing a userspace CSPRNG is even worse, as there’s no reliable userspace source of high-quality entropy.

### Quantum computers

Cryptographically relevant quantum computer, if built, will allow to
break elliptic curve cryptography (both ECDSA / EdDSA & ECDH) using Shor's algorithm.

Consider switching to newer / hybrid algorithms, such as SPHINCS+. They are available in
[noble-post-quantum](https://github.com/paulmillr/noble-post-quantum).

NIST prohibits classical cryptography (RSA, DSA, ECDSA, ECDH) [after 2035](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf). Australian ASD prohibits it [after 2030](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/ism/cyber-security-guidelines/guidelines-cryptography).

## Speed

```sh
npm run benchmark
```

noble-curves spends 10+ ms to generate 20MB+ of base point precomputes.
This is done **one-time** per curve.

The generation is deferred until any method (pubkey, sign, verify) is called.
User can force precompute generation by manually calling `Point.BASE.precompute(windowSize, false)`.
Check out the source code.

Benchmark results on Apple M4:

```
# algorithm=getPublicKey
ed25519                    7,299 ops/sec · 137 μs/op
secp256k1                  4,872 ops/sec · 205 μs/op · -1.5x
p256                       4,724 ops/sec · 212 μs/op · -1.5x
bls12_381 (long, G2 sig)   3,466 ops/sec · 288 μs/op · -2.1x
ed448                      3,224 ops/sec · 310 μs/op · -2.3x
p384                       2,185 ops/sec · 458 μs/op · -3.3x
p521                       1,221 ops/sec · 819 μs/op · -6x
bls12_381 (short, G1 sig)  1,070 ops/sec · 934 μs/op · -6.8x

# algorithm=sign
secp256k1                  4,217 ops/sec · 237 μs/op
p256                       4,116 ops/sec · 243 μs/op · ≈
ed25519                    3,536 ops/sec · 283 μs/op · -1.2x
p384                       1,992 ops/sec · 502 μs/op · -2.1x
ed448                      1,577 ops/sec · 634 μs/op · -2.7x
p521                       1,131 ops/sec · 884 μs/op · -3.7x
bls12_381 (short, G1 sig)  417 ops/sec · 2.39 ms/op · -10x
bls12_381 (long, G2 sig)   112 ops/sec · 8.88 ms/op · -37x

# algorithm=verify
ed25519                    1,504 ops/sec · 665 μs/op
secp256k1                  1,352 ops/sec · 739 μs/op · -1.1x
p256                       917 ops/sec · 1.09 ms/op · -1.6x
ed448                      546 ops/sec · 1.83 ms/op · -2.8x
p384                       381 ops/sec · 2.62 ms/op · -3.9x
p521                       187 ops/sec · 5.34 ms/op · -8x
bls12_381 (short, G1 sig)  100 ops/sec · 9.98 ms/op · -15x
bls12_381 (long, G2 sig)   77 ops/sec · 12.9 ms/op · -19x

# algorithm=getSharedSecret
ed25519                    1,695 ops/sec · 590 μs/op
secp256k1                  763 ops/sec · 1.31 ms/op · -2.2x
p256                       737 ops/sec · 1.36 ms/op · -2.3x
ed448                      599 ops/sec · 1.67 ms/op · -2.8x
p384                       326 ops/sec · 3.06 ms/op · -5.2x
p521                       176 ops/sec · 5.68 ms/op · -9.6x
```

## Upgrading

Supported node.js versions:

- v2 (2025-08): v20.19+ (ESM-only)
- v1 (2023-04): v14.21+ (ESM & CJS)

### v1 to v2

v2 massively simplifies internals, improves security, reduces bundle size and lays path for the future.
We tried to keep v2 as much backwards-compatible as possible.

**Upgrade path:** upgrade to curves v1.9.x first. Fix the deprecation warnings, then switch to v2.

Modules:

- The package is now ESM-only. ESM can finally be loaded from common.js on node v20.19+
- `.js` extension is now required: `@noble/curves/ed25519` => `@noble/curves/ed25519.js`.
  This enables native browser usage, without transpilers
- `p256`, `p384`, `p521` were moved into `nist`; `jubjub` was moved into `misc`
- `pasta` and `bn254_weierstrass` (NOT pairing-based bn254) curves were removed

New features:

- webcrypto: friendly noble-like wrapper over built-in WebCrypto
- oprf: RFC 9497 OPRFs (oblivious pseudorandom functions)
  for p256, p384, p521, ristretto255 and decaf448
- weierstrass, edwards: new `isValidSecretKey`, `isValidPublicKey` methods
- misc: Brainpool curves brainpoolP256r1, brainpoolP384r1, brainpoolP512r1
- Massively improved, more descriptive error messages

Breaking changes:

- Most methods now only accept Uint8Array; string hex inputs are prohibited.
  This simplifies reasoning, improves security and reduces malleability.
  `Point.fromHex` is now string-only: use `Point.fromBytes` for Uint8Array
- ECDSA (secp256k1, p256, p384...) sign & verify:
    - **Prehashed messages**: methods now expect the unhashed message
      instead of messageHash. Old behavior: `{prehash: false}`
    - **lowS signatures** by default. secp256k1 is unaffected: it has used
      lowS since the beginning. Old behavior: `{lowS: false}`
    - **Uint8Array signatures** (format: 'compact') by default
    - verify: **der format must be explicitly specified** in `{format: 'der'}`.
      This reduces malleability
    - verify: **Signature instances are prohibited**: call `signature.toBytes()` first
- BLS signatures (bls12-381, bn254):
    - getPublicKey, sign, verify, signShortSignature etc were moved into two new namespaces:
      `longSignatures` (G1 pubkeys, G2 sigs) and `shortSignatures` (G1 sigs, G2 pubkeys)
    - verifyBatch now expects array of inputs `{message: ..., publicKey: ...}[]`
- Custom curves:
    - Curve creation was massively simplified and split into point creation &
      sig generator creation: `weierstrass() + ecdsa()` / `edwards() + eddsa()`.
      weierstrass / edwards expect simplified curve params (Fp became p);
      ecdsa / eddsa expect Point class and hash
    - pippenger: removed unnecessary Fn argument
    - Field#fromBytes() now validates elements to be in 0..order-1 range

Renamings (curves v1.9 highlights old names as deprecated):

- Points
    - ExtendedPoint, ProjectivePoint => Point
    - Point coordinates px/ex, py/ey, pz/ez, et => X, Y, Z, T
    - toRawBytes, fromRawBytes => toBytes, fromBytes
    - Point.normalizeZ, Point.msm => separate methods in `abstract/curve.js` submodule
    - Point.fromPrivateKey(key) => `Point.BASE.multiply(Point.Fn.fromBytes(key))`
    - `CURVE` property with all kinds of random stuff => Point.CURVE(),
      which only provides curve parameters
    - RistrettoPoint => ristretto255.Point, DecafPoint => decaf448.Point
- ECDSA Signatures
    - toCompactRawBytes, toDERRawBytes => toBytes('compact'), toBytes('der')
    - toCompactHex, toDERHex => toHex('compact'), toHex('der')
    - fromCompact, fromDER => fromBytes(bytes, format), fromHex(hex, format)
- utils
    - randomPrivateKey => randomSecretKey
    - normPrivateKeyToScalar => Point.Fn.fromBytes
    - utils.precompute, Point#_setWindowSize => Point#precompute
    - edwardsToMontgomery, edwardsToMontgomeryPriv => utils.toMontgomery, utils.toMontgomerySecret
- Curve-specific hash-to-curve methods => `*curve*_hasher`.
  Example: `secp256k1.hashToCurve` => `secp256k1_hasher.hashToCurve()`
- Massive type renamings and improvements

Removed features: Point#multiplyAndAddUnsafe, Point#hasEvenY, Field.MASK

## Contributing & testing

`npm install && npm run build && npm test` will build the code and run tests.

There are **additional** suites: slow large-scalar / large-curve tests `npm run test:slow`,
and the constant-timeness harness `npm run benchmark:ct`.

See [paulmillr.com/noble](https://paulmillr.com/noble/) for useful resources, articles,
documentation and demos related to the library.

## License

The MIT License (MIT)

Copyright (c) 2022 Paul Miller [(https://paulmillr.com)](https://paulmillr.com)

See LICENSE file.
