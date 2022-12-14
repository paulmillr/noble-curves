/*! @noble/curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { sha512 } from '@noble/hashes/sha512';
import { concatBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils';
import { twistedEdwards, ExtendedPointType } from '@noble/curves/edwards';
import { montgomery } from '@noble/curves/montgomery';
import { mod, pow2, isNegativeLE } from '@noble/curves/modular';
import {
  ensureBytes,
  equalBytes,
  bytesToHex,
  bytesToNumberLE,
  numberToBytesLE,
  Hex,
} from '@noble/curves/utils';

/**
 * ed25519 Twisted Edwards curve with following addons:
 * - X25519 ECDH
 * - Ristretto cofactor elimination
 * - Elligator hash-to-group / point indistinguishability
 */

const ED25519_P = BigInt(
  '57896044618658097711785492504343953926634992332820282019728792003956564819949'
);
// √(-1) aka √(a) aka 2^((p-1)/4)
const ED25519_SQRT_M1 = BigInt(
  '19681161376707505956807079304988542015446066515923890162744021073123829784752'
);

// prettier-ignore
const _0n = BigInt(0), _1n = BigInt(1), _2n = BigInt(2), _5n = BigInt(5);
// prettier-ignore
const _10n = BigInt(10), _20n = BigInt(20), _40n = BigInt(40), _80n = BigInt(80);
function ed25519_pow_2_252_3(x: bigint) {
  const P = ED25519_P;
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
  // ^ To pow to (p+3)/8, multiply it by x.
  return { pow_p_5_8, b2 };
}
function adjustScalarBytes(bytes: Uint8Array): Uint8Array {
  // Section 5: For X25519, in order to decode 32 random bytes as an integer scalar,
  // set the three least significant bits of the first byte
  bytes[0] &= 248; // 0b1111_1000
  // and the most significant bit of the last to zero,
  bytes[31] &= 127; // 0b0111_1111
  // set the second most significant bit of the last byte to 1
  bytes[31] |= 64; // 0b0100_0000
  return bytes;
}
// sqrt(u/v)
function uvRatio(u: bigint, v: bigint): { isValid: boolean; value: bigint } {
  const P = ED25519_P;
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

// Just in case
export const ED25519_TORSION_SUBGROUP = [
  '0100000000000000000000000000000000000000000000000000000000000000',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  '0000000000000000000000000000000000000000000000000000000000000080',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
  '0000000000000000000000000000000000000000000000000000000000000000',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
];

const ED25519_DEF = {
  // Param: a
  a: BigInt(-1),
  // Equal to -121665/121666 over finite field.
  // Negative number is P - number, and division is invert(number, P)
  d: BigInt('37095705934669439343138083508754565189542113879843219016388785533085940283555'),
  // Finite field 𝔽p over which we'll do calculations; 2n ** 255n - 19n
  P: ED25519_P,
  // Subgroup order: how many points ed25519 has
  // 2n ** 252n + 27742317777372353535851937790883648493n;
  n: BigInt('7237005577332262213973186563042994240857116359379907606001950938285454250989'),
  // Cofactor
  h: BigInt(8),
  // Base point (x, y) aka generator point
  Gx: BigInt('15112221349535400772501151409588531511454012693041857206046113283949847762202'),
  Gy: BigInt('46316835694926478169428394003475163141307993866256225615783033603165251855960'),
  hash: sha512,
  randomBytes,
  adjustScalarBytes,
  // dom2
  // Ratio of u to v. Allows us to combine inversion and square root. Uses algo from RFC8032 5.1.3.
  // Constant-time, u/√v
  uvRatio,
} as const;

export const ed25519 = twistedEdwards(ED25519_DEF);
function ed25519_domain(data: Uint8Array, ctx: Uint8Array, phflag: boolean) {
  if (ctx.length > 255) throw new Error('Context is too big');
  return concatBytes(
    utf8ToBytes('SigEd25519 no Ed25519 collisions'),
    new Uint8Array([phflag ? 1 : 0, ctx.length]),
    ctx,
    data
  );
}
export const ed25519ctx = twistedEdwards({ ...ED25519_DEF, domain: ed25519_domain });
export const ed25519ph = twistedEdwards({
  ...ED25519_DEF,
  domain: ed25519_domain,
  preHash: sha512,
});

export const x25519 = montgomery({
  P: ED25519_P,
  a24: BigInt('121665'),
  montgomeryBits: 255, // n is 253 bits
  nByteLength: 32,
  Gu: '0900000000000000000000000000000000000000000000000000000000000000',
  powPminus2: (x: bigint): bigint => {
    const P = ED25519_P;
    // x^(p-2) aka x^(2^255-21)
    const { pow_p_5_8, b2 } = ed25519_pow_2_252_3(x);
    return mod(pow2(pow_p_5_8, BigInt(3), P) * b2, P);
  },
  adjustScalarBytes,
});

function assertRstPoint(other: unknown) {
  if (!(other instanceof RistrettoPoint)) throw new TypeError('RistrettoPoint expected');
}
// √(-1) aka √(a) aka 2^((p-1)/4)
const SQRT_M1 = BigInt(
  '19681161376707505956807079304988542015446066515923890162744021073123829784752'
);
// √(ad - 1)
const SQRT_AD_MINUS_ONE = BigInt(
  '25063068953384623474111414158702152701244531502492656460079210482610430750235'
);
// 1 / √(a-d)
const INVSQRT_A_MINUS_D = BigInt(
  '54469307008909316920995813868745141605393597292927456921205312896311721017578'
);
// 1-d²
const ONE_MINUS_D_SQ = BigInt(
  '1159843021668779879193775521855586647937357759715417654439879720876111806838'
);
// (d-1)²
const D_MINUS_ONE_SQ = BigInt(
  '40440834346308536858101042469323190826248399146238708352240133220865137265952'
);
// Calculates 1/√(number)
const invertSqrt = (number: bigint) => uvRatio(_1n, number);

const MAX_255B = BigInt('0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
const bytes255ToNumberLE = (bytes: Uint8Array) =>
  ed25519.utils.mod(bytesToNumberLE(bytes) & MAX_255B);

type ExtendedPoint = ExtendedPointType;

/**
 * Each ed25519/ExtendedPoint has 8 different equivalent points. This can be
 * a source of bugs for protocols like ring signatures. Ristretto was created to solve this.
 * Ristretto point operates in X:Y:Z:T extended coordinates like ExtendedPoint,
 * but it should work in its own namespace: do not combine those two.
 * https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-ristretto255-decaf448
 */
export class RistrettoPoint {
  static BASE = new RistrettoPoint(ed25519.ExtendedPoint.BASE);
  static ZERO = new RistrettoPoint(ed25519.ExtendedPoint.ZERO);

  // Private property to discourage combining ExtendedPoint + RistrettoPoint
  // Always use Ristretto encoding/decoding instead.
  constructor(private readonly ep: ExtendedPoint) {}

  // Computes Elligator map for Ristretto
  // https://ristretto.group/formulas/elligator.html
  private static calcElligatorRistrettoMap(r0: bigint): ExtendedPoint {
    const { d, P } = ed25519.CURVE;
    const { mod } = ed25519.utils;
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
    return new ed25519.ExtendedPoint(mod(W0 * W3), mod(W2 * W1), mod(W1 * W3), mod(W0 * W2));
  }

  /**
   * Takes uniform output of 64-bit hash function like sha512 and converts it to `RistrettoPoint`.
   * The hash-to-group operation applies Elligator twice and adds the results.
   * **Note:** this is one-way map, there is no conversion from point to hash.
   * https://ristretto.group/formulas/elligator.html
   * @param hex 64-bit output of a hash function
   */
  static hashToCurve(hex: Hex): RistrettoPoint {
    hex = ensureBytes(hex, 64);
    const r1 = bytes255ToNumberLE(hex.slice(0, 32));
    const R1 = this.calcElligatorRistrettoMap(r1);
    const r2 = bytes255ToNumberLE(hex.slice(32, 64));
    const R2 = this.calcElligatorRistrettoMap(r2);
    return new RistrettoPoint(R1.add(R2));
  }

  /**
   * Converts ristretto-encoded string to ristretto point.
   * https://ristretto.group/formulas/decoding.html
   * @param hex Ristretto-encoded 32 bytes. Not every 32-byte string is valid ristretto encoding
   */
  static fromHex(hex: Hex): RistrettoPoint {
    hex = ensureBytes(hex, 32);
    const { a, d, P } = ed25519.CURVE;
    const { mod } = ed25519.utils;
    const emsg = 'RistrettoPoint.fromHex: the hex is not valid encoding of RistrettoPoint';
    const s = bytes255ToNumberLE(hex);
    // 1. Check that s_bytes is the canonical encoding of a field element, or else abort.
    // 3. Check that s is non-negative, or else abort
    if (!equalBytes(numberToBytesLE(s, 32), hex) || isNegativeLE(s, P)) throw new Error(emsg);
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
    if (!isValid || isNegativeLE(t, P) || y === _0n) throw new Error(emsg);
    return new RistrettoPoint(new ed25519.ExtendedPoint(x, y, _1n, t));
  }

  /**
   * Encodes ristretto point to Uint8Array.
   * https://ristretto.group/formulas/encoding.html
   */
  toRawBytes(): Uint8Array {
    let { x, y, z, t } = this.ep;
    const { P } = ed25519.CURVE;
    const { mod } = ed25519.utils;
    const u1 = mod(mod(z + y) * mod(z - y)); // 1
    const u2 = mod(x * y); // 2
    // Square root always exists
    const u2sq = mod(u2 * u2);
    const { value: invsqrt } = invertSqrt(mod(u1 * u2sq)); // 3
    const D1 = mod(invsqrt * u1); // 4
    const D2 = mod(invsqrt * u2); // 5
    const zInv = mod(D1 * D2 * t); // 6
    let D: bigint; // 7
    if (isNegativeLE(t * zInv, P)) {
      let _x = mod(y * SQRT_M1);
      let _y = mod(x * SQRT_M1);
      x = _x;
      y = _y;
      D = mod(D1 * INVSQRT_A_MINUS_D);
    } else {
      D = D2; // 8
    }
    if (isNegativeLE(x * zInv, P)) y = mod(-y); // 9
    let s = mod((z - y) * D); // 10 (check footer's note, no sqrt(-a))
    if (isNegativeLE(s, P)) s = mod(-s);
    return numberToBytesLE(s, 32); // 11
  }

  toHex(): string {
    return bytesToHex(this.toRawBytes());
  }

  toString(): string {
    return this.toHex();
  }

  // Compare one point to another.
  equals(other: RistrettoPoint): boolean {
    assertRstPoint(other);
    const a = this.ep;
    const b = other.ep;
    const { mod } = ed25519.utils;
    // (x1 * y2 == y1 * x2) | (y1 * y2 == x1 * x2)
    const one = mod(a.x * b.y) === mod(a.y * b.x);
    const two = mod(a.y * b.y) === mod(a.x * b.x);
    return one || two;
  }

  add(other: RistrettoPoint): RistrettoPoint {
    assertRstPoint(other);
    return new RistrettoPoint(this.ep.add(other.ep));
  }

  subtract(other: RistrettoPoint): RistrettoPoint {
    assertRstPoint(other);
    return new RistrettoPoint(this.ep.subtract(other.ep));
  }

  multiply(scalar: number | bigint): RistrettoPoint {
    return new RistrettoPoint(this.ep.multiply(scalar));
  }

  multiplyUnsafe(scalar: number | bigint): RistrettoPoint {
    return new RistrettoPoint(this.ep.multiplyUnsafe(scalar));
  }
}
