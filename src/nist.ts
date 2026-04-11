/**
 * Internal module for NIST P256, P384, P521 curves.
 * Do not use for now.
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import { createFROST, type FROST } from './abstract/frost.ts';
import { createHasher, type H2CHasher } from './abstract/hash-to-curve.ts';
import { createOPRF, type OPRF } from './abstract/oprf.ts';
import {
  ecdsa,
  mapToCurveSimpleSWU,
  weierstrass,
  type ECDSA,
  type WeierstrassOpts,
  type WeierstrassPointCons,
} from './abstract/weierstrass.ts';
import { type TRet } from './utils.ts';

// p = 2n**224n * (2n**32n-1n) + 2n**192n + 2n**96n - 1n
// a = Fp256.create(BigInt('-3'));
const p256_CURVE: WeierstrassOpts<bigint> = /* @__PURE__ */ (() => ({
  p: BigInt('0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff'),
  n: BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'),
  h: BigInt(1),
  a: BigInt('0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc'),
  b: BigInt('0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b'),
  Gx: BigInt('0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'),
  Gy: BigInt('0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'),
}))();

// p = 2n**384n - 2n**128n - 2n**96n + 2n**32n - 1n
const p384_CURVE: WeierstrassOpts<bigint> = /* @__PURE__ */ (() => ({
  p: BigInt(
    '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff'
  ),
  n: BigInt(
    '0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973'
  ),
  h: BigInt(1),
  a: BigInt(
    '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc'
  ),
  b: BigInt(
    '0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef'
  ),
  Gx: BigInt(
    '0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7'
  ),
  Gy: BigInt(
    '0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f'
  ),
}))();

// p = 2n**521n - 1n
const p521_CURVE: WeierstrassOpts<bigint> = /* @__PURE__ */ (() => ({
  p: BigInt(
    '0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
  ),
  n: BigInt(
    '0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409'
  ),
  h: BigInt(1),
  a: BigInt(
    '0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc'
  ),
  b: BigInt(
    '0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00'
  ),
  Gx: BigInt(
    '0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66'
  ),
  Gy: BigInt(
    '0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650'
  ),
}))();

type SwuOpts = {
  A: bigint;
  B: bigint;
  Z: bigint;
};

function createSWU(Point: WeierstrassPointCons<bigint>, opts: SwuOpts) {
  let map: ((u: bigint) => { x: bigint; y: bigint }) | undefined;
  // RFC 9380's NIST suites here all use m = 1, so createHasher passes one field element per map.
  // Building the SWU sqrt-ratio helper eagerly adds noticeable `nist.js` import cost, so defer it
  // to first use; after that the cached mapper is reused directly.
  return (scalars: bigint[]) => (map || (map = mapToCurveSimpleSWU(Point.Fp, opts)))(scalars[0]);
}

// NIST P256
const p256_Point = /* @__PURE__ */ weierstrass(p256_CURVE);
/**
 * NIST P256 (aka secp256r1, prime256v1) curve, ECDSA and ECDH methods.
 * Hashes inputs with sha256 by default.
 *
 * @example
 * Generate one P-256 keypair, sign a message, and verify it.
 *
 * ```js
 * import { p256 } from '@noble/curves/nist.js';
 * const { secretKey, publicKey } = p256.keygen();
 * // const publicKey = p256.getPublicKey(secretKey);
 * const msg = new TextEncoder().encode('hello noble');
 * const sig = p256.sign(msg, secretKey);
 * const isValid = p256.verify(sig, msg, publicKey);
 * // const sigKeccak = p256.sign(keccak256(msg), secretKey, { prehash: false });
 * ```
 */
export const p256: ECDSA = /* @__PURE__ */ ecdsa(p256_Point, sha256);
/**
 * Hashing / encoding to p256 points / field. RFC 9380 methods.
 * @example
 * Hash one message onto the P-256 curve.
 *
 * ```ts
 * const point = p256_hasher.hashToCurve(new TextEncoder().encode('hello noble'));
 * ```
 */
export const p256_hasher: H2CHasher<WeierstrassPointCons<bigint>> = /* @__PURE__ */ (() => {
  return createHasher(
    p256_Point,
    createSWU(p256_Point, {
      A: p256_CURVE.a,
      B: p256_CURVE.b,
      Z: p256_Point.Fp.create(BigInt('-10')),
    }),
    {
      DST: 'P256_XMD:SHA-256_SSWU_RO_',
      encodeDST: 'P256_XMD:SHA-256_SSWU_NU_',
      p: p256_CURVE.p,
      m: 1,
      k: 128,
      expand: 'xmd',
      hash: sha256,
    }
  );
})();
/**
 * p256 OPRF, defined in RFC 9497.
 * @example
 * Run one blind/evaluate/finalize OPRF round over P-256.
 *
 * ```ts
 * const input = new TextEncoder().encode('hello noble');
 * const keys = p256_oprf.oprf.generateKeyPair();
 * const blind = p256_oprf.oprf.blind(input);
 * const evaluated = p256_oprf.oprf.blindEvaluate(keys.secretKey, blind.blinded);
 * const output = p256_oprf.oprf.finalize(input, blind.blind, evaluated);
 * ```
 */
export const p256_oprf: TRet<OPRF> = /* @__PURE__ */ (() =>
  createOPRF({
    name: 'P256-SHA256',
    Point: p256_Point,
    hash: sha256,
    hashToGroup: p256_hasher.hashToCurve,
    hashToScalar: p256_hasher.hashToScalar,
  }))();
/**
 * FROST threshold signatures over p256. RFC 9591.
 * @example
 * Create one trusted-dealer package for 2-of-3 p256 signing.
 *
 * ```ts
 * const alice = p256_FROST.Identifier.derive('alice@example.com');
 * const bob = p256_FROST.Identifier.derive('bob@example.com');
 * const carol = p256_FROST.Identifier.derive('carol@example.com');
 * const deal = p256_FROST.trustedDealer({ min: 2, max: 3 }, [alice, bob, carol]);
 * ```
 */
export const p256_FROST: TRet<FROST> = /* @__PURE__ */ (() =>
  createFROST({
    name: 'FROST-P256-SHA256-v1',
    Point: p256_Point,
    hashToScalar: p256_hasher.hashToScalar,
    hash: sha256,
  }))();

// NIST P384
const p384_Point = /* @__PURE__ */ weierstrass(p384_CURVE);
/**
 * NIST P384 (aka secp384r1) curve, ECDSA and ECDH methods. Hashes inputs with sha384 by default.
 * @example
 * Generate one P-384 keypair, sign a message, and verify it.
 *
 * ```ts
 * const { secretKey, publicKey } = p384.keygen();
 * const msg = new TextEncoder().encode('hello noble');
 * const sig = p384.sign(msg, secretKey);
 * const isValid = p384.verify(sig, msg, publicKey);
 * ```
 */
export const p384: ECDSA = /* @__PURE__ */ ecdsa(p384_Point, sha384);
/**
 * Hashing / encoding to p384 points / field. RFC 9380 methods.
 * @example
 * Hash one message onto the P-384 curve.
 *
 * ```ts
 * const point = p384_hasher.hashToCurve(new TextEncoder().encode('hello noble'));
 * ```
 */
export const p384_hasher: H2CHasher<WeierstrassPointCons<bigint>> = /* @__PURE__ */ (() => {
  return createHasher(
    p384_Point,
    createSWU(p384_Point, {
      A: p384_CURVE.a,
      B: p384_CURVE.b,
      Z: p384_Point.Fp.create(BigInt('-12')),
    }),
    {
      DST: 'P384_XMD:SHA-384_SSWU_RO_',
      encodeDST: 'P384_XMD:SHA-384_SSWU_NU_',
      p: p384_CURVE.p,
      m: 1,
      k: 192,
      expand: 'xmd',
      hash: sha384,
    }
  );
})();
/**
 * p384 OPRF, defined in RFC 9497.
 * @example
 * Run one blind/evaluate/finalize OPRF round over P-384.
 *
 * ```ts
 * const input = new TextEncoder().encode('hello noble');
 * const keys = p384_oprf.oprf.generateKeyPair();
 * const blind = p384_oprf.oprf.blind(input);
 * const evaluated = p384_oprf.oprf.blindEvaluate(keys.secretKey, blind.blinded);
 * const output = p384_oprf.oprf.finalize(input, blind.blind, evaluated);
 * ```
 */
export const p384_oprf: TRet<OPRF> = /* @__PURE__ */ (() =>
  createOPRF({
    name: 'P384-SHA384',
    Point: p384_Point,
    hash: sha384,
    hashToGroup: p384_hasher.hashToCurve,
    hashToScalar: p384_hasher.hashToScalar,
  }))();

// NIST P521
// RFC 7518 fixes the canonical JWK/JOSE width at 66 bytes:
// - Section 3.4 says ECDSA octet strings must not omit leading zero octets
// - Sections 6.2.1.2/6.2.1.3 say P-521 coordinates "x"/"y" must be 66 octets
// - Section 6.2.2.1 says private scalar "d" must be ceil(log2(n)/8) octets, i.e. 66 for P-521
// NIST FIPS 186-5 Appendix A.3.3 also routes deterministic ECDSA private keys through Appendix
// B.2.3, whose Integer-to-Octet-String output has explicit fixed length L; for P-521 that is the
// same 66-byte order width.
// RFC 6979 matches that width too: private key x is an integer, while `int2octets(x)` uses
// rlen = 8 * ceil(qlen/8); for P-521, qlen = 521 so the canonical octet width is 66 bytes.
// Wycheproof ECDH stores private values as integers, not fixed-width scalar bytes, so it does not
// require a dedicated 65-byte parser path; the repo tests now normalize those integer fixtures to
// the canonical 66-byte width before use. There is no good standards or oracle reason to accept
// exactly 65 bytes here: the coherent choices are canonical 66 only, or a broader integer-style
// parser across many widths. Since this field parser is fixed-width, keep it canonical and use the
// default exact-66-byte scalar field path.
const p521_Point = /* @__PURE__ */ weierstrass(p521_CURVE);
/**
 * NIST P521 (aka secp521r1) curve, ECDSA and ECDH methods. Hashes inputs with sha512 by default.
 * Deterministic `keygen(seed)` expects 99 seed bytes here because the generic scalar-derivation
 * helper uses `getMinHashLength(n)`, not the 66-byte canonical secret-key width.
 * @example
 * Generate one P-521 keypair, sign a message, and verify it.
 *
 * ```ts
 * const { secretKey, publicKey } = p521.keygen();
 * const msg = new TextEncoder().encode('hello noble');
 * const sig = p521.sign(msg, secretKey);
 * const isValid = p521.verify(sig, msg, publicKey);
 * ```
 */
export const p521: ECDSA = /* @__PURE__ */ ecdsa(p521_Point, sha512);
/**
 * Hashing / encoding to p521 points / field. RFC 9380 methods.
 * @example
 * Hash one message onto the P-521 curve.
 *
 * ```ts
 * const point = p521_hasher.hashToCurve(new TextEncoder().encode('hello noble'));
 * ```
 */
export const p521_hasher: H2CHasher<WeierstrassPointCons<bigint>> = /* @__PURE__ */ (() => {
  return createHasher(
    p521_Point,
    createSWU(p521_Point, {
      A: p521_CURVE.a,
      B: p521_CURVE.b,
      Z: p521_Point.Fp.create(BigInt('-4')),
    }),
    {
      DST: 'P521_XMD:SHA-512_SSWU_RO_',
      encodeDST: 'P521_XMD:SHA-512_SSWU_NU_',
      p: p521_CURVE.p,
      m: 1,
      k: 256,
      expand: 'xmd',
      hash: sha512,
    }
  );
})();
/**
 * p521 OPRF, defined in RFC 9497.
 * @example
 * Run one blind/evaluate/finalize OPRF round over P-521.
 *
 * ```ts
 * const input = new TextEncoder().encode('hello noble');
 * const keys = p521_oprf.oprf.generateKeyPair();
 * const blind = p521_oprf.oprf.blind(input);
 * const evaluated = p521_oprf.oprf.blindEvaluate(keys.secretKey, blind.blinded);
 * const output = p521_oprf.oprf.finalize(input, blind.blind, evaluated);
 * ```
 */
export const p521_oprf: TRet<OPRF> = /* @__PURE__ */ (() =>
  createOPRF({
    name: 'P521-SHA512',
    Point: p521_Point,
    hash: sha512,
    hashToGroup: p521_hasher.hashToCurve,
    hashToScalar: p521_hasher.hashToScalar, // produces L=98 just like in RFC
  }))();
