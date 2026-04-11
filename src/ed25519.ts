/**
 * ed25519 Twisted Edwards curve with following addons:
 * - X25519 ECDH
 * - Ristretto cofactor elimination
 * - Elligator hash-to-group / point indistinguishability
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { sha512 } from '@noble/hashes/sha2.js';
import { abytes, concatBytes, hexToBytes } from '@noble/hashes/utils.js';
import { type AffinePoint } from './abstract/curve.ts';
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
  expand_message_xmd,
  type H2CDSTOpts,
  type H2CHasher,
  type H2CHasherBase,
} from './abstract/hash-to-curve.ts';
import {
  FpInvertBatch,
  FpSqrtEven,
  isNegativeLE,
  mod,
  pow2,
  type IField,
} from './abstract/modular.ts';
import { montgomery, type MontgomeryECDH } from './abstract/montgomery.ts';
import { createOPRF, type OPRF } from './abstract/oprf.ts';
import { asciiToBytes, bytesToNumberLE, equalBytes, type TArg, type TRet } from './utils.ts';

// prettier-ignore
const _0n = /* @__PURE__ */ BigInt(0), _1n = /* @__PURE__ */ BigInt(1), _2n = /* @__PURE__ */ BigInt(2), _3n = /* @__PURE__ */ BigInt(3);
// prettier-ignore
const _5n = /* @__PURE__ */ BigInt(5), _8n = /* @__PURE__ */ BigInt(8);

// P = 2n**255n - 19n
const ed25519_CURVE_p = /* @__PURE__ */ BigInt(
  '0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed'
);
// N = 2n**252n + 27742317777372353535851937790883648493n
// a = Fp.create(BigInt(-1))
// d = -121665/121666 a.k.a. Fp.neg(121665 * Fp.inv(121666))
const ed25519_CURVE: EdwardsOpts = /* @__PURE__ */ (() => ({
  p: ed25519_CURVE_p,
  n: BigInt('0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed'),
  h: _8n,
  a: BigInt('0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec'),
  d: BigInt('0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3'),
  Gx: BigInt('0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a'),
  Gy: BigInt('0x6666666666666666666666666666666666666666666666666666666666666658'),
}))();

function ed25519_pow_2_252_3(x: bigint) {
  // prettier-ignore
  const _10n = BigInt(10), _20n = BigInt(20), _40n = BigInt(40), _80n = BigInt(80);
  const P = ed25519_CURVE_p;
  const x2 = (x * x) % P;
  const b2 = (x2 * x) % P; // x^3, 11
  const b4 = (pow2(b2, _2n, P) * b2) % P; // x^15, 1111
  const b5 = (pow2(b4, _1n, P) * x) % P; // x^31
  const b10 = (pow2(b5, _5n, P) * b5) % P;
  const b20 = (pow2(b10, _10n, P) * b10) % P;
  const b40 = (pow2(b20, _20n, P) * b20) % P;
  const b80 = (pow2(b40, _40n, P) * b40) % P;
  const b160 = (pow2(b80, _80n, P) * b80) % P;
  const b240 = (pow2(b160, _80n, P) * b80) % P;
  const b250 = (pow2(b240, _10n, P) * b10) % P;
  const pow_p_5_8 = (pow2(b250, _2n, P) * x) % P;
  // ^ This is x^((p-5)/8); multiply by x once more to get x^((p+3)/8).
  return { pow_p_5_8, b2 };
}

// Mutates and returns the provided 32-byte buffer in place.
function adjustScalarBytes(bytes: TArg<Uint8Array>): TRet<Uint8Array> {
  // Section 5: For X25519, in order to decode 32 random bytes as an integer scalar,
  // set the three least significant bits of the first byte
  bytes[0] &= 248; // 0b1111_1000
  // and the most significant bit of the last to zero,
  bytes[31] &= 127; // 0b0111_1111
  // set the second most significant bit of the last byte to 1
  bytes[31] |= 64; // 0b0100_0000
  return bytes as TRet<Uint8Array>;
}

// √(-1) aka √(a) aka 2^((p-1)/4)
// Fp.sqrt(Fp.neg(1))
const ED25519_SQRT_M1 = /* @__PURE__ */ BigInt(
  '19681161376707505956807079304988542015446066515923890162744021073123829784752'
);
// sqrt(u/v). Returns `{ isValid, value }`; on non-squares `value` is still a
// dummy root-shaped field element so callers can stay constant-time.
function uvRatio(u: bigint, v: bigint): { isValid: boolean; value: bigint } {
  const P = ed25519_CURVE_p;
  const v3 = mod(v * v * v, P); // v³
  const v7 = mod(v3 * v3 * v, P); // v⁷
  // (p+3)/8 and (p-5)/8
  const pow = ed25519_pow_2_252_3(u * v7).pow_p_5_8;
  let x = mod(u * v3 * pow, P); // (uv³)(uv⁷)^(p-5)/8
  const vx2 = mod(v * x * x, P); // vx²
  const root1 = x; // First root candidate
  const root2 = mod(x * ED25519_SQRT_M1, P); // Second root candidate
  const useRoot1 = vx2 === u; // If vx² = u (mod p), x is a square root
  const useRoot2 = vx2 === mod(-u, P); // If vx² = -u, set x <-- x * 2^((p-1)/4)
  const noRoot = vx2 === mod(-u * ED25519_SQRT_M1, P); // There is no valid root, vx² = -u√(-1)
  if (useRoot1) x = root1;
  if (useRoot2 || noRoot) x = root2; // We return root2 anyway, for const-time
  if (isNegativeLE(x, P)) x = mod(-x, P);
  return { isValid: useRoot1 || useRoot2, value: x };
}

const ed25519_Point = /* @__PURE__ */ edwards(ed25519_CURVE, { uvRatio });
// Public field alias stays stricter than the RFC 8032 Appendix A sample code:
// `Fp.inv(0)` throws instead of returning `0`.
const Fp = /* @__PURE__ */ (() => ed25519_Point.Fp)();
const Fn = /* @__PURE__ */ (() => ed25519_Point.Fn)();

// RFC 8032 `dom2` helper for ctx/ph variants only. Plain Ed25519 keeps the
// empty-domain path in `ed()` and would be wrong if routed through this helper.
function ed25519_domain(
  data: TArg<Uint8Array>,
  ctx: TArg<Uint8Array>,
  phflag: boolean
): TRet<Uint8Array> {
  if (ctx.length > 255) throw new Error('Context is too big');
  return concatBytes(
    asciiToBytes('SigEd25519 no Ed25519 collisions'),
    new Uint8Array([phflag ? 1 : 0, ctx.length]),
    ctx,
    data
  ) as TRet<Uint8Array>;
}

function ed(opts: TArg<EdDSAOpts>) {
  // Ed25519 keeps ZIP-215 default verification semantics for consensus compatibility.
  return eddsa(
    ed25519_Point,
    sha512,
    Object.assign({ adjustScalarBytes, zip215: true }, opts as EdDSAOpts)
  );
}

/**
 * ed25519 curve with EdDSA signatures.
 * Seeded `keygen(seed)` / `utils.randomSecretKey(seed)` reuse the provided
 * 32-byte seed buffer instead of copying it.
 * @example
 * Generate one Ed25519 keypair, sign a message, and verify it.
 *
 * ```js
 * import { ed25519 } from '@noble/curves/ed25519.js';
 * const { secretKey, publicKey } = ed25519.keygen();
 * // const publicKey = ed25519.getPublicKey(secretKey);
 * const msg = new TextEncoder().encode('hello noble');
 * const sig = ed25519.sign(msg, secretKey);
 * const isValid = ed25519.verify(sig, msg, publicKey); // ZIP215
 * // RFC8032 / FIPS 186-5
 * const isValid2 = ed25519.verify(sig, msg, publicKey, { zip215: false });
 * ```
 */
export const ed25519: EdDSA = /* @__PURE__ */ ed({});
/**
 * Context version of ed25519 (ctx for domain separation). See {@link ed25519}
 * Seeded `keygen(seed)` / `utils.randomSecretKey(seed)` reuse the provided
 * 32-byte seed buffer instead of copying it.
 * @example
 * Sign and verify with Ed25519ctx under one explicit context.
 *
 * ```ts
 * const context = new TextEncoder().encode('docs');
 * const { secretKey, publicKey } = ed25519ctx.keygen();
 * const msg = new TextEncoder().encode('hello noble');
 * const sig = ed25519ctx.sign(msg, secretKey, { context });
 * const isValid = ed25519ctx.verify(sig, msg, publicKey, { context });
 * ```
 */
export const ed25519ctx: EdDSA = /* @__PURE__ */ ed({ domain: ed25519_domain });
/**
 * Prehashed version of ed25519. See {@link ed25519}
 * Seeded `keygen(seed)` / `utils.randomSecretKey(seed)` reuse the provided
 * 32-byte seed buffer instead of copying it.
 * @example
 * Use the prehashed Ed25519 variant for one message.
 *
 * ```ts
 * const { secretKey, publicKey } = ed25519ph.keygen();
 * const msg = new TextEncoder().encode('hello noble');
 * const sig = ed25519ph.sign(msg, secretKey);
 * const isValid = ed25519ph.verify(sig, msg, publicKey);
 * ```
 */
export const ed25519ph: EdDSA = /* @__PURE__ */ ed({ domain: ed25519_domain, prehash: sha512 });
/**
 * FROST threshold signatures over ed25519. RFC 9591.
 * @example
 * Create one trusted-dealer package for 2-of-3 ed25519 signing.
 *
 * ```ts
 * const alice = ed25519_FROST.Identifier.derive('alice@example.com');
 * const bob = ed25519_FROST.Identifier.derive('bob@example.com');
 * const carol = ed25519_FROST.Identifier.derive('carol@example.com');
 * const deal = ed25519_FROST.trustedDealer({ min: 2, max: 3 }, [alice, bob, carol]);
 * ```
 */
export const ed25519_FROST: TRet<FROST> = /* @__PURE__ */ (() =>
  createFROST({
    name: 'FROST-ED25519-SHA512-v1',
    Point: ed25519_Point,
    validatePoint: (p) => {
      p.assertValidity();
      if (!p.isTorsionFree()) throw new Error('bad point: not torsion-free');
    },
    hash: sha512,
    // RFC 9591 keeps H2 undecorated here for RFC 8032 compatibility. In createFROST(),
    // `H2: ''` becomes an empty DST prefix; the built-in hashToScalar fallback treats
    // that the same as omitted DST, even though custom hooks can still observe the empty bag.
    H2: '',
  }))();

/**
 * ECDH using curve25519 aka x25519.
 * `getSharedSecret()` rejects low-order peer inputs by default, and seeded
 * `keygen(seed)` reuses the provided 32-byte seed buffer instead of copying it.
 * @example
 * Derive one shared secret between two X25519 peers.
 *
 * ```js
 * import { x25519 } from '@noble/curves/ed25519.js';
 * const alice = x25519.keygen();
 * const bob = x25519.keygen();
 * const shared = x25519.getSharedSecret(alice.secretKey, bob.publicKey);
 * ```
 */
export const x25519: TRet<MontgomeryECDH> = /* @__PURE__ */ (() => {
  const P = ed25519_CURVE_p;
  return montgomery({
    P,
    type: 'x25519',
    powPminus2: (x: bigint): bigint => {
      // x^(p-2) aka x^(2^255-21)
      const { pow_p_5_8, b2 } = ed25519_pow_2_252_3(x);
      return mod(pow2(pow_p_5_8, _3n, P) * b2, P);
    },
    adjustScalarBytes,
  });
})();

// Hash To Curve Elligator2 Map (NOTE: different from ristretto255 elligator)
// RFC 9380 Appendix G.2.2 / Err4730 requires `sgn0(c1) = 0` for the Edwards
// map constant below, so use the even root explicitly.
// 1. c1 = (q + 3) / 8 # Integer arithmetic
const ELL2_C1 = /* @__PURE__ */ (() => (ed25519_CURVE_p + _3n) / _8n)();
const ELL2_C2 = /* @__PURE__ */ (() => Fp.pow(_2n, ELL2_C1))(); // 2. c2 = 2^c1
const ELL2_C3 = /* @__PURE__ */ (() => Fp.sqrt(Fp.neg(Fp.ONE)))(); // 3. c3 = sqrt(-1)

/**
 * RFC 9380 method `map_to_curve_elligator2_curve25519`. Experimental name: may be renamed later.
 * @private
 */
// prettier-ignore
export function _map_to_curve_elligator2_curve25519(u: bigint): {
  xMn: bigint, xMd: bigint, yMn: bigint, yMd: bigint
} {
  const ELL2_C4 = (ed25519_CURVE_p - _5n) / _8n; // 4. c4 = (q - 5) / 8       # Integer arithmetic
  const ELL2_J = BigInt(486662);

  let tv1 = Fp.sqr(u);          //  1.  tv1 = u^2
  tv1 = Fp.mul(tv1, _2n);       //  2.  tv1 = 2 * tv1
  // 3. xd = tv1 + 1 # Nonzero: -1 is square (mod p), tv1 is not
  let xd = Fp.add(tv1, Fp.ONE);
  let x1n = Fp.neg(ELL2_J);     //  4.  x1n = -J              # x1 = x1n / xd = -J / (1 + 2 * u^2)
  let tv2 = Fp.sqr(xd);         //  5.  tv2 = xd^2
  let gxd = Fp.mul(tv2, xd);    //  6.  gxd = tv2 * xd        # gxd = xd^3
  let gx1 = Fp.mul(tv1, ELL2_J);//  7.  gx1 = J * tv1         # x1n + J * xd
  gx1 = Fp.mul(gx1, x1n);       //  8.  gx1 = gx1 * x1n       # x1n^2 + J * x1n * xd
  gx1 = Fp.add(gx1, tv2);       //  9.  gx1 = gx1 + tv2       # x1n^2 + J * x1n * xd + xd^2
  gx1 = Fp.mul(gx1, x1n);       //  10. gx1 = gx1 * x1n       # x1n^3 + J * x1n^2 * xd + x1n * xd^2
  let tv3 = Fp.sqr(gxd);        //  11. tv3 = gxd^2
  tv2 = Fp.sqr(tv3);            //  12. tv2 = tv3^2           # gxd^4
  tv3 = Fp.mul(tv3, gxd);       //  13. tv3 = tv3 * gxd       # gxd^3
  tv3 = Fp.mul(tv3, gx1);       //  14. tv3 = tv3 * gx1       # gx1 * gxd^3
  tv2 = Fp.mul(tv2, tv3);       //  15. tv2 = tv2 * tv3       # gx1 * gxd^7
  let y11 = Fp.pow(tv2, ELL2_C4); //  16. y11 = tv2^c4        # (gx1 * gxd^7)^((p - 5) / 8)
  y11 = Fp.mul(y11, tv3);       //  17. y11 = y11 * tv3       # gx1*gxd^3*(gx1*gxd^7)^((p-5)/8)
  let y12 = Fp.mul(y11, ELL2_C3); //  18. y12 = y11 * c3
  tv2 = Fp.sqr(y11);            //  19. tv2 = y11^2
  tv2 = Fp.mul(tv2, gxd);       //  20. tv2 = tv2 * gxd
  let e1 = Fp.eql(tv2, gx1);    //  21.  e1 = tv2 == gx1
  // 22. y1 = CMOV(y12, y11, e1) # If g(x1) is square, this is its sqrt
  let y1 = Fp.cmov(y12, y11, e1);
  let x2n = Fp.mul(x1n, tv1);   //  23. x2n = x1n * tv1       # x2 = x2n / xd = 2 * u^2 * x1n / xd
  let y21 = Fp.mul(y11, u);     //  24. y21 = y11 * u
  y21 = Fp.mul(y21, ELL2_C2);   //  25. y21 = y21 * c2
  let y22 = Fp.mul(y21, ELL2_C3); //  26. y22 = y21 * c3
  let gx2 = Fp.mul(gx1, tv1);   //  27. gx2 = gx1 * tv1       # g(x2) = gx2 / gxd = 2 * u^2 * g(x1)
  tv2 = Fp.sqr(y21);            //  28. tv2 = y21^2
  tv2 = Fp.mul(tv2, gxd);       //  29. tv2 = tv2 * gxd
  let e2 = Fp.eql(tv2, gx2);    //  30.  e2 = tv2 == gx2
  // 31. y2 = CMOV(y22, y21, e2) # If g(x2) is square, this is its sqrt
  let y2 = Fp.cmov(y22, y21, e2);
  tv2 = Fp.sqr(y1);             //  32. tv2 = y1^2
  tv2 = Fp.mul(tv2, gxd);       //  33. tv2 = tv2 * gxd
  let e3 = Fp.eql(tv2, gx1);    //  34.  e3 = tv2 == gx1
  let xn = Fp.cmov(x2n, x1n, e3); //  35.  xn = CMOV(x2n, x1n, e3)  # If e3, x = x1, else x = x2
  let y = Fp.cmov(y2, y1, e3);  //  36.   y = CMOV(y2, y1, e3)    # If e3, y = y1, else y = y2
  let e4 = Fp.isOdd!(y);         //  37.  e4 = sgn0(y) == 1        # Fix sign of y
  y = Fp.cmov(y, Fp.neg(y), e3 !== e4); //  38.   y = CMOV(y, -y, e3 XOR e4)
  return { xMn: xn, xMd: xd, yMn: y, yMd: _1n }; //  39. return (xn, xd, y, 1)
}

// sgn0(c1) MUST equal 0
const ELL2_C1_EDWARDS = /* @__PURE__ */ (() => FpSqrtEven(Fp, Fp.neg(BigInt(486664))))();
function map_to_curve_elligator2_edwards25519(u: bigint) {
  // 1. (xMn, xMd, yMn, yMd) = map_to_curve_elligator2_curve25519(u)
  const { xMn, xMd, yMn, yMd } = _map_to_curve_elligator2_curve25519(u);
  // map_to_curve_elligator2_curve25519(u)
  let xn = Fp.mul(xMn, yMd); //  2.  xn = xMn * yMd
  xn = Fp.mul(xn, ELL2_C1_EDWARDS); //  3.  xn = xn * c1
  let xd = Fp.mul(xMd, yMn); //  4.  xd = xMd * yMn    # xn / xd = c1 * xM / yM
  let yn = Fp.sub(xMn, xMd); //  5.  yn = xMn - xMd
  // 6. yd = xMn + xMd # (n / d - 1) / (n / d + 1) = (n - d) / (n + d)
  let yd = Fp.add(xMn, xMd);
  let tv1 = Fp.mul(xd, yd); //  7. tv1 = xd * yd
  let e = Fp.eql(tv1, Fp.ZERO); //  8.   e = tv1 == 0
  xn = Fp.cmov(xn, Fp.ZERO, e); //  9.  xn = CMOV(xn, 0, e)
  xd = Fp.cmov(xd, Fp.ONE, e); //  10. xd = CMOV(xd, 1, e)
  yn = Fp.cmov(yn, Fp.ONE, e); //  11. yn = CMOV(yn, 1, e)
  yd = Fp.cmov(yd, Fp.ONE, e); //  12. yd = CMOV(yd, 1, e)
  const [xd_inv, yd_inv] = FpInvertBatch(Fp, [xd, yd], true); // batch division
  // Noble normalizes the RFC rational representation to affine `{ x, y }`
  // before returning from the internal helper.
  return { x: Fp.mul(xn, xd_inv), y: Fp.mul(yn, yd_inv) }; //  13. return (xn, xd, yn, yd)
}

/**
 * Hashing to ed25519 points / field. RFC 9380 methods.
 * Public `mapToCurve()` returns the cofactor-cleared subgroup point; the
 * internal map callback below consumes one field element bigint, not `[bigint]`.
 * @example
 * Hash one message onto the ed25519 curve.
 *
 * ```ts
 * const point = ed25519_hasher.hashToCurve(new TextEncoder().encode('hello noble'));
 * ```
 */
export const ed25519_hasher: H2CHasher<EdwardsPointCons> = /* @__PURE__ */ (() =>
  createHasher(
    ed25519_Point,
    (scalars: bigint[]) => map_to_curve_elligator2_edwards25519(scalars[0]),
    {
      DST: 'edwards25519_XMD:SHA-512_ELL2_RO_',
      encodeDST: 'edwards25519_XMD:SHA-512_ELL2_NU_',
      p: ed25519_CURVE_p,
      m: 1,
      k: 128,
      expand: 'xmd',
      hash: sha512,
    }
  ))();

// √(-1) aka √(a) aka 2^((p-1)/4)
const SQRT_M1 = ED25519_SQRT_M1;
// √(ad - 1)
const SQRT_AD_MINUS_ONE = /* @__PURE__ */ BigInt(
  '25063068953384623474111414158702152701244531502492656460079210482610430750235'
);
// 1 / √(a-d)
const INVSQRT_A_MINUS_D = /* @__PURE__ */ BigInt(
  '54469307008909316920995813868745141605393597292927456921205312896311721017578'
);
// 1-d²
const ONE_MINUS_D_SQ = /* @__PURE__ */ BigInt(
  '1159843021668779879193775521855586647937357759715417654439879720876111806838'
);
// (d-1)²
const D_MINUS_ONE_SQ = /* @__PURE__ */ BigInt(
  '40440834346308536858101042469323190826248399146238708352240133220865137265952'
);
// `SQRT_RATIO_M1(1, number)` specialization. Returns `{ isValid, value }`,
// where non-squares get the nonnegative `sqrt(SQRT_M1 / number)` branch.
const invertSqrt = (number: bigint) => uvRatio(_1n, number);

const MAX_255B = /* @__PURE__ */ BigInt(
  '0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
);
// RFC 9496 §4.3.4 MAP parser: masks bit 255 and reduces modulo p for element
// derivation. The decode path has the opposite contract and rejects that bit.
const bytes255ToNumberLE = (bytes: TArg<Uint8Array>) =>
  Fp.create(bytesToNumberLE(bytes) & MAX_255B);

/**
 * Computes Elligator map for Ristretto255.
 * Primary formula source is RFC 9496 §4.3.4 MAP; RFC 9380 Appendix B builds
 * `hash_to_ristretto255` on top of this helper.
 * Returns an internal Edwards representative, not a public `_RistrettoPoint`.
 */
function calcElligatorRistrettoMap(r0: bigint): EdwardsPoint {
  const { d } = ed25519_CURVE;
  const P = ed25519_CURVE_p;
  const mod = (n: bigint) => Fp.create(n);
  const r = mod(SQRT_M1 * r0 * r0); // 1
  const Ns = mod((r + _1n) * ONE_MINUS_D_SQ); // 2
  let c = BigInt(-1); // 3
  const D = mod((c - d * r) * mod(r + d)); // 4
  let { isValid: Ns_D_is_sq, value: s } = uvRatio(Ns, D); // 5
  let s_ = mod(s * r0); // 6
  if (!isNegativeLE(s_, P)) s_ = mod(-s_);
  if (!Ns_D_is_sq) s = s_; // 7
  if (!Ns_D_is_sq) c = r; // 8
  const Nt = mod(c * (r - _1n) * D_MINUS_ONE_SQ - D); // 9
  const s2 = s * s;
  const W0 = mod((s + s) * D); // 10
  const W1 = mod(Nt * SQRT_AD_MINUS_ONE); // 11
  const W2 = mod(_1n - s2); // 12
  const W3 = mod(_1n + s2); // 13
  return new ed25519_Point(mod(W0 * W3), mod(W2 * W1), mod(W1 * W3), mod(W0 * W2));
}

/**
 * Wrapper over Edwards Point for ristretto255.
 *
 * Each ed25519/EdwardsPoint has 8 different equivalent points. This can be
 * a source of bugs for protocols like ring signatures. Ristretto was created to solve this.
 * Ristretto point operates in X:Y:Z:T extended coordinates like EdwardsPoint,
 * but it should work in its own namespace: do not combine those two.
 * See [RFC9496](https://www.rfc-editor.org/rfc/rfc9496).
 */
class _RistrettoPoint extends PrimeEdwardsPoint<_RistrettoPoint> {
  // Do NOT change syntax: the following gymnastics is done,
  // because typescript strips comments, which makes bundlers disable tree-shaking.
  // prettier-ignore
  static BASE: _RistrettoPoint =
    /* @__PURE__ */ (() => new _RistrettoPoint(ed25519_Point.BASE))();
  // prettier-ignore
  static ZERO: _RistrettoPoint =
    /* @__PURE__ */ (() => new _RistrettoPoint(ed25519_Point.ZERO))();
  // prettier-ignore
  static Fp: IField<bigint> =
    /* @__PURE__ */ (() => Fp)();
  // prettier-ignore
  static Fn: IField<bigint> =
    /* @__PURE__ */ (() => Fn)();

  constructor(ep: EdwardsPoint) {
    super(ep);
  }

  /**
   * Create one Ristretto255 point from affine Edwards coordinates.
   * This wraps the internal Edwards representative directly and is not a
   * canonical ristretto255 decoding path.
   * Use `toBytes()` / `fromBytes()` if canonical ristretto255 bytes matter.
   */
  static fromAffine(ap: AffinePoint<bigint>): _RistrettoPoint {
    return new _RistrettoPoint(ed25519_Point.fromAffine(ap));
  }

  protected assertSame(other: _RistrettoPoint): void {
    if (!(other instanceof _RistrettoPoint)) throw new Error('RistrettoPoint expected');
  }

  protected init(ep: EdwardsPoint): _RistrettoPoint {
    return new _RistrettoPoint(ep);
  }

  static fromBytes(bytes: TArg<Uint8Array>): _RistrettoPoint {
    abytes(bytes, 32);
    const { a, d } = ed25519_CURVE;
    const P = ed25519_CURVE_p;
    const mod = (n: bigint) => Fp.create(n);
    const s = bytes255ToNumberLE(bytes);
    // 1. Check that s_bytes is the canonical encoding of a field element, or else abort.
    // 3. Check that s is non-negative, or else abort
    if (!equalBytes(Fp.toBytes(s), bytes) || isNegativeLE(s, P))
      throw new Error('invalid ristretto255 encoding 1');
    const s2 = mod(s * s);
    const u1 = mod(_1n + a * s2); // 4 (a is -1)
    const u2 = mod(_1n - a * s2); // 5
    const u1_2 = mod(u1 * u1);
    const u2_2 = mod(u2 * u2);
    const v = mod(a * d * u1_2 - u2_2); // 6
    const { isValid, value: I } = invertSqrt(mod(v * u2_2)); // 7
    const Dx = mod(I * u2); // 8
    const Dy = mod(I * Dx * v); // 9
    let x = mod((s + s) * Dx); // 10
    if (isNegativeLE(x, P)) x = mod(-x); // 10
    const y = mod(u1 * Dy); // 11
    const t = mod(x * y); // 12
    if (!isValid || isNegativeLE(t, P) || y === _0n)
      throw new Error('invalid ristretto255 encoding 2');
    return new _RistrettoPoint(new ed25519_Point(x, y, _1n, t));
  }

  /**
   * Converts ristretto-encoded string to ristretto point.
   * Described in [RFC9496](https://www.rfc-editor.org/rfc/rfc9496#name-decode).
   * @param hex - Ristretto-encoded 32 bytes. Not every 32-byte string is valid ristretto encoding
   */
  static fromHex(hex: string): _RistrettoPoint {
    return _RistrettoPoint.fromBytes(hexToBytes(hex));
  }

  /**
   * Encodes ristretto point to Uint8Array.
   * Described in [RFC9496](https://www.rfc-editor.org/rfc/rfc9496#name-encode).
   */
  toBytes(): TRet<Uint8Array> {
    let { X, Y, Z, T } = this.ep;
    const P = ed25519_CURVE_p;
    const mod = (n: bigint) => Fp.create(n);
    const u1 = mod(mod(Z + Y) * mod(Z - Y)); // 1
    const u2 = mod(X * Y); // 2
    // Square root always exists
    const u2sq = mod(u2 * u2);
    const { value: invsqrt } = invertSqrt(mod(u1 * u2sq)); // 3
    const D1 = mod(invsqrt * u1); // 4
    const D2 = mod(invsqrt * u2); // 5
    const zInv = mod(D1 * D2 * T); // 6
    let D: bigint; // 7
    if (isNegativeLE(T * zInv, P)) {
      let _x = mod(Y * SQRT_M1);
      let _y = mod(X * SQRT_M1);
      X = _x;
      Y = _y;
      D = mod(D1 * INVSQRT_A_MINUS_D);
    } else {
      D = D2; // 8
    }
    if (isNegativeLE(X * zInv, P)) Y = mod(-Y); // 9
    let s = mod((Z - Y) * D); // 10 (check footer's note, no sqrt(-a))
    if (isNegativeLE(s, P)) s = mod(-s);
    return Fp.toBytes(s) as TRet<Uint8Array>; // 11
  }

  /**
   * Compares two Ristretto points.
   * Described in [RFC9496](https://www.rfc-editor.org/rfc/rfc9496#name-equals).
   */
  equals(other: _RistrettoPoint): boolean {
    this.assertSame(other);
    const { X: X1, Y: Y1 } = this.ep;
    const { X: X2, Y: Y2 } = other.ep;
    const mod = (n: bigint) => Fp.create(n);
    // (x1 * y2 == y1 * x2) | (y1 * y2 == x1 * x2)
    const one = mod(X1 * Y2) === mod(Y1 * X2);
    const two = mod(Y1 * Y2) === mod(X1 * X2);
    return one || two;
  }

  is0(): boolean {
    return this.equals(_RistrettoPoint.ZERO);
  }
}
Object.freeze(_RistrettoPoint.BASE);
Object.freeze(_RistrettoPoint.ZERO);
Object.freeze(_RistrettoPoint.prototype);
Object.freeze(_RistrettoPoint);

/** Prime-order Ristretto255 group bundle. */
export const ristretto255: {
  Point: typeof _RistrettoPoint;
} = /* @__PURE__ */ Object.freeze({ Point: _RistrettoPoint });

/**
 * Hashing to ristretto255 points / field. RFC 9380 methods.
 * `hashToCurve()` is RFC 9380 Appendix B, `deriveToCurve()` is the RFC 9496
 * §4.3.4 element-derivation building block, and `hashToScalar()` is a
 * library-specific helper for OPRF-style use.
 * @example
 * Hash one message onto ristretto255.
 *
 * ```ts
 * const point = ristretto255_hasher.hashToCurve(new TextEncoder().encode('hello noble'));
 * ```
 */
export const ristretto255_hasher: H2CHasherBase<typeof _RistrettoPoint> = Object.freeze({
  Point: _RistrettoPoint,
  /**
  * Spec: https://www.rfc-editor.org/rfc/rfc9380.html#name-hashing-to-ristretto255. Caveats:
  * * There are no test vectors
  * * encodeToCurve / mapToCurve is undefined
  * * mapToCurve would be `calcElligatorRistrettoMap(scalars[0])`, not ristretto255_map!
  * * hashToScalar is undefined too, so we just use OPRF implementation
  * * We cannot re-use 'createHasher', because ristretto255_map is different algorithm/RFC
    (os2ip -> bytes255ToNumberLE)
  * * mapToCurve == calcElligatorRistrettoMap, hashToCurve == ristretto255_map
  * * hashToScalar is undefined in RFC9380 for ristretto, so we use the OPRF
    version here. Using `bytes255ToNumblerLE` will create a different result
    if we use `bytes255ToNumberLE` as os2ip
  * * current version is closest to spec.
  */
  hashToCurve(msg: TArg<Uint8Array>, options?: TArg<H2CDSTOpts>): _RistrettoPoint {
    // == 'hash_to_ristretto255'
    // Preserve explicit empty/invalid DST overrides so expand_message_xmd() can reject them.
    const DST = options?.DST === undefined ? 'ristretto255_XMD:SHA-512_R255MAP_RO_' : options.DST;
    const xmd = expand_message_xmd(msg, DST, 64, sha512);
    // NOTE: RFC 9380 incorrectly calls this function `ristretto255_map`.
    // In RFC 9496, `map` was the per-point function inside the construction.
    // That also led to confusion that `ristretto255_map` is `mapToCurve`.
    // It is not: it is the older hash-to-curve construction.
    return ristretto255_hasher.deriveToCurve!(xmd);
  },
  hashToScalar(msg: TArg<Uint8Array>, options: TArg<H2CDSTOpts> = { DST: _DST_scalar }) {
    const xmd = expand_message_xmd(msg, options.DST, 64, sha512);
    return Fn.create(bytesToNumberLE(xmd));
  },
  /**
   * HashToCurve-like construction based on RFC 9496 (Element Derivation).
   * Converts 64 uniform random bytes into a curve point.
   *
   * WARNING: This represents an older hash-to-curve construction from before
   * RFC 9380 was finalized.
   * It was later reused as a component in the newer
   * `hash_to_ristretto255` function defined in RFC 9380.
   */
  deriveToCurve(bytes: TArg<Uint8Array>): _RistrettoPoint {
    // https://www.rfc-editor.org/rfc/rfc9496.html#name-element-derivation
    abytes(bytes, 64);
    const r1 = bytes255ToNumberLE(bytes.subarray(0, 32));
    const R1 = calcElligatorRistrettoMap(r1);
    const r2 = bytes255ToNumberLE(bytes.subarray(32, 64));
    const R2 = calcElligatorRistrettoMap(r2);
    return new _RistrettoPoint(R1.add(R2));
  },
});

/**
 * ristretto255 OPRF/VOPRF/POPRF bundle, defined in RFC 9497.
 * @example
 * Run one blind/evaluate/finalize OPRF round over ristretto255.
 *
 * ```ts
 * const input = new TextEncoder().encode('hello noble');
 * const keys = ristretto255_oprf.oprf.generateKeyPair();
 * const blind = ristretto255_oprf.oprf.blind(input);
 * const evaluated = ristretto255_oprf.oprf.blindEvaluate(keys.secretKey, blind.blinded);
 * const output = ristretto255_oprf.oprf.finalize(input, blind.blind, evaluated);
 * ```
 */
export const ristretto255_oprf: TRet<OPRF> = /* @__PURE__ */ (() =>
  createOPRF({
    name: 'ristretto255-SHA512',
    Point: _RistrettoPoint,
    hash: sha512,
    hashToGroup: ristretto255_hasher.hashToCurve,
    hashToScalar: ristretto255_hasher.hashToScalar,
  }))();
/**
 * FROST threshold signatures over ristretto255. RFC 9591.
 * @example
 * Create one trusted-dealer package for 2-of-3 ristretto255 signing.
 *
 * ```ts
 * const alice = ristretto255_FROST.Identifier.derive('alice@example.com');
 * const bob = ristretto255_FROST.Identifier.derive('bob@example.com');
 * const carol = ristretto255_FROST.Identifier.derive('carol@example.com');
 * const deal = ristretto255_FROST.trustedDealer({ min: 2, max: 3 }, [alice, bob, carol]);
 * ```
 */
export const ristretto255_FROST: TRet<FROST> = /* @__PURE__ */ (() =>
  createFROST({
    name: 'FROST-RISTRETTO255-SHA512-v1',
    Point: _RistrettoPoint,
    validatePoint: (p) => {
      // Prime-order wrappers are torsion-free at the abstract-group level.
      p.assertValidity();
    },
    hash: sha512,
  }))();

/**
 * Weird / bogus points, useful for debugging.
 * All 8 ed25519 points of 8-torsion subgroup can be generated from the point
 * T = `26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05`.
 * The subgroup generated by `T` is `{ O, T, 2T, 3T, 4T, 5T, 6T, 7T }`; the
 * array below is that set, not the powers in that exact index order.
 * @example
 * Decode one known torsion point for debugging.
 *
 * ```ts
 * import { ED25519_TORSION_SUBGROUP, ed25519 } from '@noble/curves/ed25519.js';
 * const point = ed25519.Point.fromHex(ED25519_TORSION_SUBGROUP[1]);
 * ```
 */
export const ED25519_TORSION_SUBGROUP: readonly string[] = /* @__PURE__ */ Object.freeze([
  '0100000000000000000000000000000000000000000000000000000000000000',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  '0000000000000000000000000000000000000000000000000000000000000080',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
  '0000000000000000000000000000000000000000000000000000000000000000',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
]);
