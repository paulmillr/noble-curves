/**
 * Edwards448 (also called Goldilocks) curve with following addons:
 * - X448 ECDH
 * - Decaf cofactor elimination
 * - Elligator hash-to-group / point indistinguishability
 * Conforms to RFC 8032 https://www.rfc-editor.org/rfc/rfc8032.html#section-5.2
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { shake256 } from '@noble/hashes/sha3.js';
import { concatBytes, hexToBytes, createHasher as wrapConstructor } from '@noble/hashes/utils.js';
import type { AffinePoint } from './abstract/curve.ts';
import {
  eddsa,
  edwards,
  PrimeEdwardsPoint,
  type EdDSA,
  type EdDSAOpts,
  type EdwardsOpts,
  type EdwardsPoint,
  type EdwardsPointCons,
} from './abstract/edwards.ts';
import { createFROST, type FROST } from './abstract/frost.ts';
import {
  _DST_scalar,
  createHasher,
  expand_message_xof,
  type H2CDSTOpts,
  type H2CHasher,
  type H2CHasherBase,
} from './abstract/hash-to-curve.ts';
import { Field, FpInvertBatch, isNegativeLE, mod, pow2, type IField } from './abstract/modular.ts';
import { montgomery, type MontgomeryECDH } from './abstract/montgomery.ts';
import { createOPRF, type OPRF } from './abstract/oprf.ts';
import {
  abytes,
  asciiToBytes,
  bytesToNumberLE,
  equalBytes,
  type TArg,
  type TRet,
} from './utils.ts';

// edwards448 curve
// a = 1n
// d = Fp.neg(39081n)
// Finite field 2n**448n - 2n**224n - 1n
// Subgroup order
// 2n**446n - 13818066809895115352007386748515426880336692474882178609894547503885n
const ed448_CURVE_p = /* @__PURE__ */ BigInt(
  '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
);
const ed448_CURVE: EdwardsOpts = /* @__PURE__ */ (() => ({
  p: ed448_CURVE_p,
  n: BigInt(
    '0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3'
  ),
  h: BigInt(4),
  a: BigInt(1),
  d: BigInt(
    '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffff6756'
  ),
  Gx: BigInt(
    '0x4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e'
  ),
  Gy: BigInt(
    '0x693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14'
  ),
}))();

// This is not RFC 8032 edwards448 / Goldilocks (`ed448` below, d = -39081).
// It is NIST SP 800-186 §3.2.3.3 E448, the Curve448-isomorphic Edwards model
// also described in draft-ietf-lwig-curve-representations-23 Appendix M, with
// d = 39082/39081 and Gy = 3/2.
// RFC 7748's literal Edwards point / birational map are wrong here: the literal
// point is the wrong-sign (Gx, -Gy) order-2*n variant. Keep the corrected
// prime-order (Gx, Gy) base so Point.BASE stays a subgroup generator, which is
// what noble's generic Edwards API expects.
const E448_CURVE: EdwardsOpts = /* @__PURE__ */ (() =>
  Object.assign({}, ed448_CURVE, {
    d: BigInt(
      '0xd78b4bdc7f0daf19f24f38c29373a2ccad46157242a50f37809b1da3412a12e79ccc9c81264cfe9ad080997058fb61c4243cc32dbaa156b9'
    ),
    Gx: BigInt(
      '0x79a70b2b70400553ae7c9df416c792c61128751ac92969240c25a07d728bdc93e21f7787ed6972249de732f38496cd11698713093e9c04fc'
    ),
    Gy: BigInt(
      '0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffff80000000000000000000000000000000000000000000000000000001'
    ),
  }))();

const shake256_114 = /* @__PURE__ */ wrapConstructor(() => shake256.create({ dkLen: 114 }));
const shake256_64 = /* @__PURE__ */ wrapConstructor(() => shake256.create({ dkLen: 64 }));

// prettier-ignore
const _1n = /* @__PURE__ */ BigInt(1), _2n = /* @__PURE__ */ BigInt(2), _3n = /* @__PURE__ */ BigInt(3), _4n = /* @__PURE__ */ BigInt(4), _11n = /* @__PURE__ */ BigInt(11);
// prettier-ignore
const _22n = /* @__PURE__ */ BigInt(22), _44n = /* @__PURE__ */ BigInt(44), _88n = /* @__PURE__ */ BigInt(88), _223n = /* @__PURE__ */ BigInt(223);

// powPminus3div4 calculates z = x^k mod p, where k = (p-3)/4.
// Used for efficient square root calculation.
// ((P-3)/4).toString(2) would produce bits [223x 1, 0, 222x 1]
function ed448_pow_Pminus3div4(x: bigint): bigint {
  const P = ed448_CURVE_p;
  const b2 = (x * x * x) % P;
  const b3 = (b2 * b2 * x) % P;
  const b6 = (pow2(b3, _3n, P) * b3) % P;
  const b9 = (pow2(b6, _3n, P) * b3) % P;
  const b11 = (pow2(b9, _2n, P) * b2) % P;
  const b22 = (pow2(b11, _11n, P) * b11) % P;
  const b44 = (pow2(b22, _22n, P) * b22) % P;
  const b88 = (pow2(b44, _44n, P) * b44) % P;
  const b176 = (pow2(b88, _88n, P) * b88) % P;
  const b220 = (pow2(b176, _44n, P) * b44) % P;
  const b222 = (pow2(b220, _2n, P) * b2) % P;
  const b223 = (pow2(b222, _1n, P) * x) % P;
  return (pow2(b223, _223n, P) * b222) % P;
}

// Mutates and returns the provided buffer in place. The final `bytes[56] = 0`
// write is the Ed448 path; for 56-byte X448 inputs it is an out-of-bounds no-op.
function adjustScalarBytes(bytes: TArg<Uint8Array>): TRet<Uint8Array> {
  // Section 5: Likewise, for X448, set the two least significant bits of the first byte to 0,
  bytes[0] &= 252; // 0b11111100
  // and the most significant bit of the last byte to 1.
  bytes[55] |= 128; // 0b10000000
  // NOTE: is NOOP for 56 bytes scalars (X25519/X448)
  bytes[56] = 0; // Byte outside of group (456 buts vs 448 bits)
  return bytes as TRet<Uint8Array>;
}

// Constant-time Ed448 decode helper for RFC 8032 §5.2.3 steps 2-3. Unlike
// `SQRT_RATIO_M1`, the returned `value` only has the documented meaning when
// `isValid` is true.
function uvRatio(u: bigint, v: bigint): { isValid: boolean; value: bigint } {
  const P = ed448_CURVE_p;
  // https://www.rfc-editor.org/rfc/rfc8032#section-5.2.3
  // To compute the square root of (u/v), the first step is to compute the
  //   candidate root x = (u/v)^((p+1)/4).  This can be done using the
  // following trick, to use a single modular powering for both the
  // inversion of v and the square root:
  // x = (u/v)^((p+1)/4)   = u³v(u⁵v³)^((p-3)/4)   (mod p)
  const u2v = mod(u * u * v, P); // u²v
  const u3v = mod(u2v * u, P); // u³v
  const u5v3 = mod(u3v * u2v * v, P); // u⁵v³
  const root = ed448_pow_Pminus3div4(u5v3);
  const x = mod(u3v * root, P);
  // Verify that root is exists
  const x2 = mod(x * x, P); // x²
  // If vx² = u, the recovered x-coordinate is x.  Otherwise, no
  // square root exists, and the decoding fails.
  return { isValid: mod(x2 * v, P) === u, value: x };
}

// Finite field 2n**448n - 2n**224n - 1n
// RFC 8032 encodes Ed448 field/scalar elements in 57 bytes even though field
// values fit in 448 bits and scalars in 446 bits. Noble models that with a
// 456-bit storage width so the final-octet x-sign bit (bit 455) still fits in
// the shared little-endian container.
const Fp = /* @__PURE__ */ (() => Field(ed448_CURVE_p, { BITS: 456, isLE: true }))();
// Same 57-byte container shape as `Fp`; canonical scalar encodings still have
// the top ten bits clear per RFC 8032.
const Fn = /* @__PURE__ */ (() => Field(ed448_CURVE.n, { BITS: 456, isLE: true }))();
// Generic 56-byte field shape used by decaf448 and raw X448 u-coordinates.
// Plain `Field` decoding stays canonical here, so callers that want RFC 7748's
// modulo-p acceptance must reduce externally.
const Fp448 = /* @__PURE__ */ (() => Field(ed448_CURVE_p, { BITS: 448, isLE: true }))();
// Strict 56-byte scalar parser matching RFC 9496's recommended canonical form.
const Fn448 = /* @__PURE__ */ (() => Field(ed448_CURVE.n, { BITS: 448, isLE: true }))();

// SHAKE256(dom4(phflag,context)||x, 114)
// RFC 8032 `dom4` prefix. Empty contexts are valid; the accepted length range
// is 0..255 octets inclusive.
function dom4(data: TArg<Uint8Array>, ctx: TArg<Uint8Array>, phflag: boolean): TRet<Uint8Array> {
  if (ctx.length > 255) throw new Error('context must be smaller than 255, got: ' + ctx.length);
  return concatBytes(
    asciiToBytes('SigEd448'),
    new Uint8Array([phflag ? 1 : 0, ctx.length]),
    ctx,
    data
  ) as TRet<Uint8Array>;
}
const ed448_Point = /* @__PURE__ */ edwards(ed448_CURVE, { Fp, Fn, uvRatio });

// Shared internal factory for both `ed448` and `ed448ph`; callers are only
// expected to override narrow family options such as prehashing.
function ed4(opts: TArg<EdDSAOpts>) {
  return eddsa(
    ed448_Point,
    shake256_114,
    Object.assign({ adjustScalarBytes, domain: dom4 }, opts as EdDSAOpts)
  );
}

/**
 * ed448 EdDSA curve and methods.
 * @example
 * Generate one Ed448 keypair, sign a message, and verify it.
 *
 * ```js
 * import { ed448 } from '@noble/curves/ed448.js';
 * const { secretKey, publicKey } = ed448.keygen();
 * // const publicKey = ed448.getPublicKey(secretKey);
 * const msg = new TextEncoder().encode('hello noble');
 * const sig = ed448.sign(msg, secretKey);
 * const isValid = ed448.verify(sig, msg, publicKey);
 * ```
 */
export const ed448: EdDSA = /* @__PURE__ */ ed4({});

// There is no ed448ctx, since ed448 supports ctx by default
/**
 * Prehashed version of ed448. See {@link ed448}
 * @example
 * Use the prehashed Ed448 variant for one message.
 *
 * ```ts
 * const { secretKey, publicKey } = ed448ph.keygen();
 * const msg = new TextEncoder().encode('hello noble');
 * const sig = ed448ph.sign(msg, secretKey);
 * const isValid = ed448ph.verify(sig, msg, publicKey);
 * ```
 */
export const ed448ph: EdDSA = /* @__PURE__ */ ed4({ prehash: shake256_64 });
/**
 * E448 here is NIST SP 800-186 §3.2.3.3 E448, the Edwards representation of
 * Curve448, not RFC 8032 edwards448 / Goldilocks.
 * Goldilocks is the separate 4-isogenous curve exposed as `ed448`.
 * We keep the corrected prime-order base here; RFC 7748's literal Edwards
 * point / map are wrong for this curve model, and the literal point is the
 * wrong-sign order-2*n variant.
 * @param X - Projective X coordinate.
 * @param Y - Projective Y coordinate.
 * @param Z - Projective Z coordinate.
 * @param T - Projective T coordinate.
 * @example
 * Multiply the E448 base point.
 *
 * ```ts
 * const point = E448.BASE.multiply(2n);
 * ```
 */
export const E448: EdwardsPointCons = /* @__PURE__ */ edwards(E448_CURVE);

/**
 * ECDH using curve448 aka x448.
 * The wrapper aborts on all-zero shared secrets by default, and seeded
 * `keygen(seed)` reuses the provided 56-byte seed buffer instead of copying it.
 *
 * @example
 * Derive one shared secret between two X448 peers.
 *
 * ```js
 * import { x448 } from '@noble/curves/ed448.js';
 * const alice = x448.keygen();
 * const bob = x448.keygen();
 * const shared = x448.getSharedSecret(alice.secretKey, bob.publicKey);
 * ```
 */
export const x448: TRet<MontgomeryECDH> = /* @__PURE__ */ (() => {
  const P = ed448_CURVE_p;
  return montgomery({
    P,
    type: 'x448',
    powPminus2: (x: bigint): bigint => {
      const Pminus3div4 = ed448_pow_Pminus3div4(x);
      const Pminus3 = pow2(Pminus3div4, _2n, P);
      return mod(Pminus3 * x, P); // Pminus3 * x = Pminus2
    },
    adjustScalarBytes,
  });
})();

// Hash To Curve Elligator2 Map
// 1. c1 = (q - 3) / 4 # Integer arithmetic
const ELL2_C1 = /* @__PURE__ */ (() => (ed448_CURVE_p - BigInt(3)) / BigInt(4))();
const ELL2_J = /* @__PURE__ */ BigInt(156326);

// Returns RFC 9380 Appendix G.2.3 rational Montgomery numerators/denominators
// `{ xn, xd, yn, yd }`, not an affine point.
function map_to_curve_elligator2_curve448(u: bigint) {
  let tv1 = Fp.sqr(u); // 1.  tv1 = u^2
  let e1 = Fp.eql(tv1, Fp.ONE); // 2.   e1 = tv1 == 1
  tv1 = Fp.cmov(tv1, Fp.ZERO, e1); // 3.  tv1 = CMOV(tv1, 0, e1)  # If Z * u^2 == -1, set tv1 = 0
  let xd = Fp.sub(Fp.ONE, tv1); // 4.   xd = 1 - tv1
  let x1n = Fp.neg(ELL2_J); // 5.  x1n = -J
  let tv2 = Fp.sqr(xd); // 6.  tv2 = xd^2
  let gxd = Fp.mul(tv2, xd); // 7.  gxd = tv2 * xd          # gxd = xd^3
  let gx1 = Fp.mul(tv1, Fp.neg(ELL2_J)); // 8.  gx1 = -J * tv1          # x1n + J * xd
  gx1 = Fp.mul(gx1, x1n); // 9.  gx1 = gx1 * x1n         # x1n^2 + J * x1n * xd
  gx1 = Fp.add(gx1, tv2); // 10. gx1 = gx1 + tv2         # x1n^2 + J * x1n * xd + xd^2
  gx1 = Fp.mul(gx1, x1n); // 11. gx1 = gx1 * x1n         # x1n^3 + J * x1n^2 * xd + x1n * xd^2
  let tv3 = Fp.sqr(gxd); // 12. tv3 = gxd^2
  tv2 = Fp.mul(gx1, gxd); // 13. tv2 = gx1 * gxd         # gx1 * gxd
  tv3 = Fp.mul(tv3, tv2); // 14. tv3 = tv3 * tv2         # gx1 * gxd^3
  let y1 = Fp.pow(tv3, ELL2_C1); // 15.  y1 = tv3^c1            # (gx1 * gxd^3)^((p - 3) / 4)
  y1 = Fp.mul(y1, tv2); // 16.  y1 = y1 * tv2          # gx1 * gxd * (gx1 * gxd^3)^((p - 3) / 4)
  // 17. x2n = -tv1 * x1n # x2 = x2n / xd = -1 * u^2 * x1n / xd
  let x2n = Fp.mul(x1n, Fp.neg(tv1));
  let y2 = Fp.mul(y1, u); // 18.  y2 = y1 * u
  y2 = Fp.cmov(y2, Fp.ZERO, e1); // 19.  y2 = CMOV(y2, 0, e1)
  tv2 = Fp.sqr(y1); // 20. tv2 = y1^2
  tv2 = Fp.mul(tv2, gxd); // 21. tv2 = tv2 * gxd
  let e2 = Fp.eql(tv2, gx1); // 22.  e2 = tv2 == gx1
  let xn = Fp.cmov(x2n, x1n, e2); // 23.  xn = CMOV(x2n, x1n, e2)  # If e2, x = x1, else x = x2
  let y = Fp.cmov(y2, y1, e2); // 24.   y = CMOV(y2, y1, e2)    # If e2, y = y1, else y = y2
  let e3 = Fp.isOdd(y); // 25.  e3 = sgn0(y) == 1        # Fix sign of y
  y = Fp.cmov(y, Fp.neg(y), e2 !== e3); // 26.   y = CMOV(y, -y, e2 XOR e3)
  return { xn, xd, yn: y, yd: Fp.ONE }; // 27. return (xn, xd, y, 1)
}

// Returns affine `{ x, y }` after inverting the Appendix G.2.4 denominators.
function map_to_curve_elligator2_edwards448(u: bigint) {
  // 1. (xn, xd, yn, yd) = map_to_curve_elligator2_curve448(u)
  let { xn, xd, yn, yd } = map_to_curve_elligator2_curve448(u);
  let xn2 = Fp.sqr(xn); // 2.  xn2 = xn^2
  let xd2 = Fp.sqr(xd); // 3.  xd2 = xd^2
  let xd4 = Fp.sqr(xd2); // 4.  xd4 = xd2^2
  let yn2 = Fp.sqr(yn); // 5.  yn2 = yn^2
  let yd2 = Fp.sqr(yd); // 6.  yd2 = yd^2
  let xEn = Fp.sub(xn2, xd2); // 7.  xEn = xn2 - xd2
  let tv2 = Fp.sub(xEn, xd2); // 8.  tv2 = xEn - xd2
  xEn = Fp.mul(xEn, xd2); // 9.  xEn = xEn * xd2
  xEn = Fp.mul(xEn, yd); // 10. xEn = xEn * yd
  xEn = Fp.mul(xEn, yn); // 11. xEn = xEn * yn
  xEn = Fp.mul(xEn, _4n); // 12. xEn = xEn * 4
  tv2 = Fp.mul(tv2, xn2); // 13. tv2 = tv2 * xn2
  tv2 = Fp.mul(tv2, yd2); // 14. tv2 = tv2 * yd2
  let tv3 = Fp.mul(yn2, _4n); // 15. tv3 = 4 * yn2
  let tv1 = Fp.add(tv3, yd2); // 16. tv1 = tv3 + yd2
  tv1 = Fp.mul(tv1, xd4); // 17. tv1 = tv1 * xd4
  let xEd = Fp.add(tv1, tv2); // 18. xEd = tv1 + tv2
  tv2 = Fp.mul(tv2, xn); // 19. tv2 = tv2 * xn
  let tv4 = Fp.mul(xn, xd4); // 20. tv4 = xn * xd4
  let yEn = Fp.sub(tv3, yd2); // 21. yEn = tv3 - yd2
  yEn = Fp.mul(yEn, tv4); // 22. yEn = yEn * tv4
  yEn = Fp.sub(yEn, tv2); // 23. yEn = yEn - tv2
  tv1 = Fp.add(xn2, xd2); // 24. tv1 = xn2 + xd2
  tv1 = Fp.mul(tv1, xd2); // 25. tv1 = tv1 * xd2
  tv1 = Fp.mul(tv1, xd); // 26. tv1 = tv1 * xd
  tv1 = Fp.mul(tv1, yn2); // 27. tv1 = tv1 * yn2
  tv1 = Fp.mul(tv1, BigInt(-2)); // 28. tv1 = -2 * tv1
  let yEd = Fp.add(tv2, tv1); // 29. yEd = tv2 + tv1
  tv4 = Fp.mul(tv4, yd2); // 30. tv4 = tv4 * yd2
  yEd = Fp.add(yEd, tv4); // 31. yEd = yEd + tv4
  tv1 = Fp.mul(xEd, yEd); // 32. tv1 = xEd * yEd
  let e = Fp.eql(tv1, Fp.ZERO); // 33.   e = tv1 == 0
  xEn = Fp.cmov(xEn, Fp.ZERO, e); // 34. xEn = CMOV(xEn, 0, e)
  xEd = Fp.cmov(xEd, Fp.ONE, e); // 35. xEd = CMOV(xEd, 1, e)
  yEn = Fp.cmov(yEn, Fp.ONE, e); // 36. yEn = CMOV(yEn, 1, e)
  yEd = Fp.cmov(yEd, Fp.ONE, e); // 37. yEd = CMOV(yEd, 1, e)

  const inv = FpInvertBatch(Fp, [xEd, yEd], true); // batch division
  return { x: Fp.mul(xEn, inv[0]), y: Fp.mul(yEn, inv[1]) }; // 38. return (xEn, xEd, yEn, yEd)
}

/**
 * Hashing / encoding to ed448 points / field. RFC 9380 methods.
 * Public `mapToCurve()` consumes one field element bigint for `m = 1`, and RFC
 * Appendix J vectors use the special `QUUX-V01-*` test DST overrides rather
 * than the default suite IDs below.
 * @example
 * Hash one message onto the ed448 curve.
 *
 * ```ts
 * const point = ed448_hasher.hashToCurve(new TextEncoder().encode('hello noble'));
 * ```
 */
export const ed448_hasher: H2CHasher<EdwardsPointCons> = /* @__PURE__ */ (() =>
  createHasher(ed448_Point, (scalars: bigint[]) => map_to_curve_elligator2_edwards448(scalars[0]), {
    DST: 'edwards448_XOF:SHAKE256_ELL2_RO_',
    encodeDST: 'edwards448_XOF:SHAKE256_ELL2_NU_',
    p: ed448_CURVE_p,
    m: 1,
    k: 224,
    expand: 'xof',
    hash: shake256,
  }))();
/**
 * FROST threshold signatures over ed448. RFC 9591.
 * @example
 * Create one trusted-dealer package for 2-of-3 ed448 signing.
 *
 * ```ts
 * const alice = ed448_FROST.Identifier.derive('alice@example.com');
 * const bob = ed448_FROST.Identifier.derive('bob@example.com');
 * const carol = ed448_FROST.Identifier.derive('carol@example.com');
 * const deal = ed448_FROST.trustedDealer({ min: 2, max: 3 }, [alice, bob, carol]);
 * ```
 */
export const ed448_FROST: TRet<FROST> = /* @__PURE__ */ (() =>
  createFROST({
    name: 'FROST-ED448-SHAKE256-v1',
    Point: ed448_Point,
    validatePoint: (p) => {
      p.assertValidity();
      if (!p.isTorsionFree()) throw new Error('bad point: not torsion-free');
    },
    // Group:  edwards448 [RFC8032], where Ne = 57 and Ns = 57.
    // Fn is 57 bytes, Fp is 57 bytes too
    Fn,
    hash: shake256_114,
    H2: 'SigEd448\0\0',
  }))();

// 1-d
const ONE_MINUS_D = /* @__PURE__ */ BigInt('39082');
// 1-2d
const ONE_MINUS_TWO_D = /* @__PURE__ */ BigInt('78163');
// √(-d)
const SQRT_MINUS_D = /* @__PURE__ */ BigInt(
  '98944233647732219769177004876929019128417576295529901074099889598043702116001257856802131563896515373927712232092845883226922417596214'
);
// 1 / √(-d)
const INVSQRT_MINUS_D = /* @__PURE__ */ BigInt(
  '315019913931389607337177038330951043522456072897266928557328499619017160722351061360252776265186336876723201881398623946864393857820716'
);
// RFC 9496 `SQRT_RATIO_M1` must return `CT_ABS(s)`, i.e. the nonnegative root.
// Keep this Decaf-local: RFC 9496 decode/encode/map formulas depend on that
// canonical representative, while ordinary Ed448 decoding still uses `uvRatio()`
// plus the public sign bit from RFC 8032.
const sqrtRatioM1 = (u: bigint, v: bigint) => {
  const P = ed448_CURVE_p;
  const { isValid, value } = uvRatio(u, v);
  return { isValid, value: isNegativeLE(value, P) ? Fp448.create(-value) : value };
};
const invertSqrt = (number: bigint) => sqrtRatioM1(_1n, number);

/**
 * Elligator map for hash-to-curve of decaf448.
 * Primary formula source is RFC 9496 §5.3.4. Step 1 intentionally reduces the
 * input modulo `p`, and the return value is the internal Edwards
 * representation, not a public decaf encoding.
 */
function calcElligatorDecafMap(r0: bigint): EdwardsPoint {
  const { d, p: P } = ed448_CURVE;
  const mod = (n: bigint) => Fp448.create(n);

  const r = mod(-(r0 * r0)); // 1
  const u0 = mod(d * (r - _1n)); // 2
  const u1 = mod((u0 + _1n) * (u0 - r)); // 3

  const { isValid: was_square, value: v } = sqrtRatioM1(ONE_MINUS_TWO_D, mod((r + _1n) * u1)); // 4

  let v_prime = v; // 5
  if (!was_square) v_prime = mod(r0 * v);

  let sgn = _1n; // 6
  if (!was_square) sgn = mod(-_1n);

  const s = mod(v_prime * (r + _1n)); // 7
  let s_abs = s;
  if (isNegativeLE(s, P)) s_abs = mod(-s);

  const s2 = s * s;
  const W0 = mod(s_abs * _2n); // 8
  const W1 = mod(s2 + _1n); // 9
  const W2 = mod(s2 - _1n); // 10
  const W3 = mod(v_prime * s * (r - _1n) * ONE_MINUS_TWO_D + sgn); // 11
  return new ed448_Point(mod(W0 * W3), mod(W2 * W1), mod(W1 * W3), mod(W0 * W2));
}

// Keep the Decaf448 base representative literal here: deriving it with
// `new _DecafPoint(ed448_Point.BASE).multiplyUnsafe(2)` forces eager WNAF precomputes and
// adds about 100ms to `ed448.js` import time.
const DECAF_BASE_X = /* @__PURE__ */ BigInt(
  '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa955555555555555555555555555555555555555555555555555555555'
);
const DECAF_BASE_Y = /* @__PURE__ */ BigInt(
  '0xae05e9634ad7048db359d6205086c2b0036ed7a035884dd7b7e36d728ad8c4b80d6565833a2a3098bbbcb2bed1cda06bdaeafbcdea9386ed'
);
const DECAF_BASE_T = /* @__PURE__ */ BigInt(
  '0x696d84643374bace9d70983a12aa9d461da74d2d5c35e8d97ba72c3aba4450a5d29274229bd22c1d5e3a6474ee4ffb0e7a9e200a28eee402'
);

/**
 * Each ed448/EdwardsPoint has 4 different equivalent points. This can be
 * a source of bugs for protocols like ring signatures. Decaf was created to solve this.
 * Decaf point operates in X:Y:Z:T extended coordinates like EdwardsPoint,
 * but it should work in its own namespace: do not combine those two.
 * See [RFC9496](https://www.rfc-editor.org/rfc/rfc9496).
 */
class _DecafPoint extends PrimeEdwardsPoint<_DecafPoint> {
  // The following gymnastics is done because typescript strips comments otherwise
  // prettier-ignore
  static BASE: _DecafPoint =
    /* @__PURE__ */ (() => new _DecafPoint(new ed448_Point(DECAF_BASE_X, DECAF_BASE_Y, _1n, DECAF_BASE_T)))();
  // prettier-ignore
  static ZERO: _DecafPoint =
    /* @__PURE__ */ (() => new _DecafPoint(ed448_Point.ZERO))();
  // prettier-ignore
  static Fp: IField<bigint> =
    /* @__PURE__ */ (() => Fp448)();
  // prettier-ignore
  static Fn: IField<bigint> =
    /* @__PURE__ */ (() => Fn448)();

  constructor(ep: EdwardsPoint) {
    super(ep);
  }

  /**
   * Create one Decaf448 point from affine Edwards coordinates.
   * This wraps the internal Edwards representative directly and is not a
   * canonical decaf448 decoding path.
   * Use `toBytes()` / `fromBytes()` if canonical decaf448 bytes matter.
   */
  static fromAffine(ap: AffinePoint<bigint>): _DecafPoint {
    return new _DecafPoint(ed448_Point.fromAffine(ap));
  }

  protected assertSame(other: _DecafPoint): void {
    if (!(other instanceof _DecafPoint)) throw new Error('DecafPoint expected');
  }

  protected init(ep: EdwardsPoint): _DecafPoint {
    return new _DecafPoint(ep);
  }

  static fromBytes(bytes: TArg<Uint8Array>): _DecafPoint {
    abytes(bytes, 56);
    const { d, p: P } = ed448_CURVE;
    const mod = (n: bigint) => Fp448.create(n);
    const s = Fp448.fromBytes(bytes);

    // 1. Check that s_bytes is the canonical encoding of a field element, or else abort.
    // 2. Check that s is non-negative, or else abort
    if (!equalBytes(Fn448.toBytes(s), bytes) || isNegativeLE(s, P))
      throw new Error('invalid decaf448 encoding 1');

    const s2 = mod(s * s); // 1
    const u1 = mod(_1n + s2); // 2
    const u1sq = mod(u1 * u1);
    const u2 = mod(u1sq - _4n * d * s2); // 3

    const { isValid, value: invsqrt } = invertSqrt(mod(u2 * u1sq)); // 4

    let u3 = mod((s + s) * invsqrt * u1 * SQRT_MINUS_D); // 5
    if (isNegativeLE(u3, P)) u3 = mod(-u3);

    const x = mod(u3 * invsqrt * u2 * INVSQRT_MINUS_D); // 6
    const y = mod((_1n - s2) * invsqrt * u1); // 7
    const t = mod(x * y); // 8

    if (!isValid) throw new Error('invalid decaf448 encoding 2');
    return new _DecafPoint(new ed448_Point(x, y, _1n, t));
  }

  /**
   * Converts decaf-encoded string to decaf point.
   * Described in [RFC9496](https://www.rfc-editor.org/rfc/rfc9496#name-decode-2).
   * @param hex - Decaf-encoded 56 bytes. Not every 56-byte string is valid decaf encoding
   */
  static fromHex(hex: string): _DecafPoint {
    return _DecafPoint.fromBytes(hexToBytes(hex));
  }

  /**
   * Encodes decaf point to Uint8Array.
   * Described in [RFC9496](https://www.rfc-editor.org/rfc/rfc9496#name-encode-2).
   */
  toBytes(): TRet<Uint8Array> {
    const { X, Z, T } = this.ep;
    const P = ed448_CURVE.p;
    const mod = (n: bigint) => Fp448.create(n);
    const u1 = mod(mod(X + T) * mod(X - T)); // 1
    const x2 = mod(X * X);
    const { value: invsqrt } = invertSqrt(mod(u1 * ONE_MINUS_D * x2)); // 2
    let ratio = mod(invsqrt * u1 * SQRT_MINUS_D); // 3
    if (isNegativeLE(ratio, P)) ratio = mod(-ratio);
    const u2 = mod(INVSQRT_MINUS_D * ratio * Z - T); // 4
    let s = mod(ONE_MINUS_D * invsqrt * X * u2); // 5
    if (isNegativeLE(s, P)) s = mod(-s);
    return Fn448.toBytes(s) as TRet<Uint8Array>;
  }

  /**
   * Compare one point to another.
   * Described in [RFC9496](https://www.rfc-editor.org/rfc/rfc9496#name-equals-2).
   */
  equals(other: _DecafPoint): boolean {
    this.assertSame(other);
    const { X: X1, Y: Y1 } = this.ep;
    const { X: X2, Y: Y2 } = other.ep;
    // (x1 * y2 == y1 * x2)
    return Fp448.create(X1 * Y2) === Fp448.create(Y1 * X2);
  }

  is0(): boolean {
    return this.equals(_DecafPoint.ZERO);
  }
}
Object.freeze(_DecafPoint.BASE);
Object.freeze(_DecafPoint.ZERO);
Object.freeze(_DecafPoint.prototype);
Object.freeze(_DecafPoint);

/** Prime-order Decaf448 group bundle. */
export const decaf448: {
  Point: typeof _DecafPoint;
} = /* @__PURE__ */ Object.freeze({ Point: _DecafPoint });

/**
 * Hashing to decaf448 points / field. RFC 9380 methods.
 * `hashToCurve()` is RFC 9380 `hash_to_decaf448`, `deriveToCurve()` is RFC
 * 9496 element derivation, and `hashToScalar()` is a library helper layered on
 * top of RFC 9496 scalar reduction.
 * @example
 * Hash one message onto decaf448.
 *
 * ```ts
 * const point = decaf448_hasher.hashToCurve(new TextEncoder().encode('hello noble'));
 * ```
 */
export const decaf448_hasher: H2CHasherBase<typeof _DecafPoint> = Object.freeze({
  Point: _DecafPoint,
  hashToCurve(msg: TArg<Uint8Array>, options?: TArg<H2CDSTOpts>): _DecafPoint {
    // Preserve explicit empty/invalid DST overrides so expand_message_xof() can reject them.
    const DST = options?.DST === undefined ? 'decaf448_XOF:SHAKE256_D448MAP_RO_' : options.DST;
    return decaf448_hasher.deriveToCurve!(expand_message_xof(msg, DST, 112, 224, shake256));
  },
  /**
   * Warning: has big modulo bias of 2^-64.
   * RFC is invalid. RFC says "use 64-byte xof", while for 2^-112 bias
   * it must use 84-byte xof (56+56/2), not 64.
   */
  hashToScalar(msg: TArg<Uint8Array>, options: TArg<H2CDSTOpts> = { DST: _DST_scalar }): bigint {
    // Can't use `Fn448.fromBytes()`. 64-byte input => 56-byte field element
    const xof = expand_message_xof(msg, options.DST, 64, 256, shake256);
    return Fn448.create(bytesToNumberLE(xof));
  },
  /**
   * HashToCurve-like construction based on RFC 9496 (Element Derivation).
   * Converts 112 uniform random bytes into a curve point.
   *
   * WARNING: This represents an older hash-to-curve construction from before
   * RFC 9380 was finalized.
   * It was later reused as a component in the newer
   * `hash_to_decaf448` function defined in RFC 9380.
   */
  deriveToCurve(bytes: TArg<Uint8Array>): _DecafPoint {
    abytes(bytes, 112);
    const skipValidation = true;
    // Note: Similar to the field element decoding described in
    // [RFC7748], and unlike the field element decoding described in
    // Section 5.3.1, non-canonical values are accepted.
    const r1 = Fp448.create(Fp448.fromBytes(bytes.subarray(0, 56), skipValidation));
    const R1 = calcElligatorDecafMap(r1);
    const r2 = Fp448.create(Fp448.fromBytes(bytes.subarray(56, 112), skipValidation));
    const R2 = calcElligatorDecafMap(r2);
    return new _DecafPoint(R1.add(R2));
  },
});

/**
 * decaf448 OPRF, defined in RFC 9497.
 * @example
 * Run one blind/evaluate/finalize OPRF round over decaf448.
 *
 * ```ts
 * const input = new TextEncoder().encode('hello noble');
 * const keys = decaf448_oprf.oprf.generateKeyPair();
 * const blind = decaf448_oprf.oprf.blind(input);
 * const evaluated = decaf448_oprf.oprf.blindEvaluate(keys.secretKey, blind.blinded);
 * const output = decaf448_oprf.oprf.finalize(input, blind.blind, evaluated);
 * ```
 */
export const decaf448_oprf: TRet<OPRF> = /* @__PURE__ */ (() =>
  createOPRF({
    name: 'decaf448-SHAKE256',
    Point: _DecafPoint,
    hash: (msg: TArg<Uint8Array>) => shake256(msg, { dkLen: 64 }),
    hashToGroup: decaf448_hasher.hashToCurve,
    hashToScalar: decaf448_hasher.hashToScalar,
  }))();

/**
 * Weird / bogus points, useful for debugging.
 * Unlike ed25519, there is no ed448 generator point which can produce full T subgroup.
 * Instead, the torsion subgroup here is cyclic of order 4, generated by
 * `(1, 0)`, and the array below lists that subgroup set (Klein four-group).
 * @example
 * Decode one known torsion point for debugging.
 *
 * ```ts
 * import { ED448_TORSION_SUBGROUP, ed448 } from '@noble/curves/ed448.js';
 * const point = ed448.Point.fromHex(ED448_TORSION_SUBGROUP[1]);
 * ```
 */
export const ED448_TORSION_SUBGROUP: readonly string[] = /* @__PURE__ */ Object.freeze([
  '010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
  'fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff00',
  '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
  '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080',
]);
