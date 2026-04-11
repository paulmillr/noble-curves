/**
 * Towered extension fields.
 * Rather than implementing a massive 12th-degree extension directly, it is more efficient
 * to build it up from smaller extensions: a tower of extensions.
 *
 * For BLS12-381, the Fp12 field is implemented as a quadratic (degree two) extension,
 * on top of a cubic (degree three) extension, on top of a quadratic extension of Fp.
 *
 * For more info: "Pairings for beginners" by Costello, section 7.3.
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import {
  abytes,
  aInRange,
  asafenumber,
  bitGet,
  bitLen,
  concatBytes,
  notImplemented,
  validateObject,
  type TArg,
  type TRet,
} from '../utils.ts';
import * as mod from './modular.ts';
import type { WeierstrassPoint, WeierstrassPointCons } from './weierstrass.ts';

// Be friendly to bad ECMAScript parsers by not using bigint literals
// prettier-ignore
const _0n = /* @__PURE__ */ BigInt(0), _1n = /* @__PURE__ */ BigInt(1), _2n = /* @__PURE__ */ BigInt(2), _3n = /* @__PURE__ */ BigInt(3), _6n = /* @__PURE__ */ BigInt(6), _12n = /* @__PURE__ */ BigInt(12);

// Fp₂ over complex plane
/** Pair of bigints used for quadratic-extension tuples. */
export type BigintTuple = [bigint, bigint];
/** Prime-field element. */
export type Fp = bigint;
// Finite extension field over irreducible polynominal.
// Fp(u) / (u² - β) where β = -1
/** Quadratic-extension field element `c0 + c1 * u`. */
export type Fp2 = {
  /** Real component. */
  c0: bigint;
  /** Imaginary component. */
  c1: bigint;
};
/** Six bigints used for sextic-extension tuples. */
export type BigintSix = [bigint, bigint, bigint, bigint, bigint, bigint];
/** Sextic-extension field element `c0 + c1 * v + c2 * v^2`. */
export type Fp6 = {
  /** Constant coefficient. */
  c0: Fp2;
  /** Linear coefficient. */
  c1: Fp2;
  /** Quadratic coefficient. */
  c2: Fp2;
};
/**
 * Degree-12 extension field element `c0 + c1 * w`.
 * Fp₁₂ = Fp₆² over Fp₂³, with Fp₆(w) / (w² - γ) where γ = v.
 */
export type Fp12 = {
  /** Constant coefficient. */
  c0: Fp6;
  /** Linear coefficient. */
  c1: Fp6;
};
// prettier-ignore
/** Twelve bigints used for degree-12 extension tuples. */
export type BigintTwelve = [
  bigint, bigint, bigint, bigint, bigint, bigint,
  bigint, bigint, bigint, bigint, bigint, bigint
];

const isObj = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === 'object';

/** BLS-friendly helpers on top of the quadratic extension field. */
export type Fp2Bls = mod.IField<Fp2> & {
  /** Underlying prime field. */
  Fp: mod.IField<Fp>;
  /** Apply one Frobenius map. */
  frobeniusMap(num: Fp2, power: number): Fp2;
  /** Build one field element from a raw bigint tuple. */
  fromBigTuple(num: BigintTuple): Fp2;
  /** Multiply by the curve `b` constant. */
  mulByB: (num: Fp2) => Fp2;
  /** Multiply by the quadratic non-residue. */
  mulByNonresidue: (num: Fp2) => Fp2;
  /** Split one quadratic element into real and imaginary components. */
  reim: (num: Fp2) => { re: Fp; im: Fp };
  /** Specialized helper used by sextic squaring formulas. */
  Fp4Square: (a: Fp2, b: Fp2) => { first: Fp2; second: Fp2 };
  /** Quadratic non-residue used by the extension. */
  NONRESIDUE: Fp2;
};

/** BLS-friendly helpers on top of the sextic extension field. */
export type Fp6Bls = mod.IField<Fp6> & {
  /** Underlying quadratic extension field. */
  Fp2: Fp2Bls;
  /** Apply one Frobenius map. */
  frobeniusMap(num: Fp6, power: number): Fp6;
  /** Build one field element from a raw six-bigint tuple. */
  fromBigSix: (tuple: BigintSix) => Fp6;
  /** Multiply by a sparse `(0, b1, 0)` sextic element. */
  mul1(num: Fp6, b1: Fp2): Fp6;
  /** Multiply by a sparse `(b0, b1, 0)` sextic element. */
  mul01(num: Fp6, b0: Fp2, b1: Fp2): Fp6;
  /** Multiply by one quadratic-extension element. */
  mulByFp2(lhs: Fp6, rhs: Fp2): Fp6;
  /** Multiply by the sextic non-residue. */
  mulByNonresidue: (num: Fp6) => Fp6;
};

/** BLS-friendly helpers on top of the degree-12 extension field. */
export type Fp12Bls = mod.IField<Fp12> & {
  /** Underlying sextic extension field. */
  Fp6: Fp6Bls;
  /** Apply one Frobenius map. */
  frobeniusMap(num: Fp12, power: number): Fp12;
  /** Build one field element from a raw twelve-bigint tuple. */
  fromBigTwelve: (t: BigintTwelve) => Fp12;
  /** Multiply by a sparse `(o0, o1, 0, 0, o4, 0)` element. */
  mul014(num: Fp12, o0: Fp2, o1: Fp2, o4: Fp2): Fp12;
  /** Multiply by a sparse `(o0, 0, 0, o3, o4, 0)` element. */
  mul034(num: Fp12, o0: Fp2, o3: Fp2, o4: Fp2): Fp12;
  /** Multiply by one quadratic-extension element. */
  mulByFp2(lhs: Fp12, rhs: Fp2): Fp12;
  /** Conjugate one degree-12 element. */
  conjugate(num: Fp12): Fp12;
  /** Apply the final exponentiation from pairing arithmetic. */
  finalExponentiate(num: Fp12): Fp12;
  /** Apply one cyclotomic square. */
  _cyclotomicSquare(num: Fp12): Fp12;
  /** Apply one cyclotomic exponentiation. */
  _cyclotomicExp(num: Fp12, n: bigint): Fp12;
};

function calcFrobeniusCoefficients<T>(
  Fp: TArg<mod.IField<T>>,
  nonResidue: T,
  modulus: bigint,
  degree: number,
  num: number = 1,
  divisor?: number
): T[][] {
  asafenumber(num, 'num');
  const F = Fp as mod.IField<T>;
  // Generic callers can hit empty / fractional row counts through `__TEST`; fail closed instead of
  // silently returning `[]` or deriving extra Frobenius rows from a truncated loop bound.
  if (num <= 0)
    throw new Error('calcFrobeniusCoefficients: expected positive row count, got ' + num);
  const _divisor = BigInt(divisor === undefined ? degree : divisor);
  const towerModulus: any = modulus ** BigInt(degree);
  const res: T[][] = [];
  // Derive tower-basis multipliers for the `p^k` Frobenius action. The
  // divisions below are expected to be exact for the chosen tower parameters.
  for (let i = 0; i < num; i++) {
    const a = BigInt(i + 1);
    const powers: T[] = [];
    for (let j = 0, qPower = _1n; j < degree; j++) {
      const numer = a * qPower - a;
      // Shipped towers divide cleanly here, but generic callers can pick bad
      // params. Bigint division would floor and derive the wrong Frobenius table.
      if (numer % _divisor) throw new Error('calcFrobeniusCoefficients: inexact tower exponent');
      const power = (numer / _divisor) % towerModulus;
      powers.push(F.pow(nonResidue, power));
      qPower *= modulus;
    }
    res.push(powers);
  }
  return res;
}

export const __TEST: { calcFrobeniusCoefficients: typeof calcFrobeniusCoefficients } =
  /* @__PURE__ */ Object.freeze({
    calcFrobeniusCoefficients,
  });

// This works same at least for bls12-381, bn254 and bls12-377
/**
 * @param Fp - Base field implementation.
 * @param Fp2 - Quadratic extension field.
 * @param base - Twist-specific Frobenius base whose powers yield the `c1` / `c2` constants.
 * BLS12-381 uses `1 / NONRESIDUE`; BN254 uses `NONRESIDUE`.
 * @returns Frobenius endomorphism helpers.
 * @throws If the derived Frobenius constants are inconsistent for the tower. {@link Error}
 * @example
 * Build Frobenius endomorphism helpers for a BLS extension tower.
 *
 * ```ts
 * import { psiFrobenius } from '@noble/curves/abstract/tower.js';
 * import { bls12_381 } from '@noble/curves/bls12-381.js';
 * const Fp = bls12_381.fields.Fp;
 * const Fp2 = bls12_381.fields.Fp2;
 * const frob = psiFrobenius(Fp, Fp2, Fp2.div(Fp2.ONE, Fp2.NONRESIDUE));
 * const point = frob.G2psi(bls12_381.G2.Point, bls12_381.G2.Point.BASE);
 * ```
 */
export function psiFrobenius(
  Fp: TArg<mod.IField<Fp>>,
  Fp2: TArg<Fp2Bls>,
  base: TArg<Fp2>
): {
  psi: (x: Fp2, y: Fp2) => [Fp2, Fp2];
  psi2: (x: Fp2, y: Fp2) => [Fp2, Fp2];
  G2psi: (c: WeierstrassPointCons<Fp2>, P: WeierstrassPoint<Fp2>) => WeierstrassPoint<Fp2>;
  G2psi2: (c: WeierstrassPointCons<Fp2>, P: WeierstrassPoint<Fp2>) => WeierstrassPoint<Fp2>;
  PSI_X: Fp2;
  PSI_Y: Fp2;
  PSI2_X: Fp2;
  PSI2_Y: Fp2;
} {
  // GLV endomorphism Ψ(P)
  const PSI_X = Fp2.pow(base, (Fp.ORDER - _1n) / _3n); // u^((p-1)/3)
  const PSI_Y = Fp2.pow(base, (Fp.ORDER - _1n) / _2n); // u^((p-1)/2)
  function psi(x: Fp2, y: Fp2): [Fp2, Fp2] {
    // This x10 faster than previous version in bls12-381
    const x2 = Fp2.mul(Fp2.frobeniusMap(x, 1), PSI_X);
    const y2 = Fp2.mul(Fp2.frobeniusMap(y, 1), PSI_Y);
    return [x2, y2];
  }
  // Ψ²(P) endomorphism (psi2(x) = psi(psi(x)))
  const PSI2_X = Fp2.pow(base, (Fp.ORDER ** _2n - _1n) / _3n); // u^((p^2 - 1)/3)
  // Current towers rely on this landing on `-1`, which lets psi2 map `y` with
  // one negation instead of carrying a separate Frobenius multiplier.
  const PSI2_Y = Fp2.pow(base, (Fp.ORDER ** _2n - _1n) / _2n); // u^((p^2 - 1)/2)
  if (!Fp2.eql(PSI2_Y, Fp2.neg(Fp2.ONE))) throw new Error('psiFrobenius: PSI2_Y!==-1');
  function psi2(x: Fp2, y: Fp2): [Fp2, Fp2] {
    return [Fp2.mul(x, PSI2_X), Fp2.neg(y)];
  }
  // Map points
  const mapAffine =
    <T>(fn: (x: T, y: T) => [T, T]) =>
    (c: WeierstrassPointCons<T>, P: WeierstrassPoint<T>) => {
      const affine = P.toAffine();
      const p = fn(affine.x, affine.y);
      return c.fromAffine({ x: p[0], y: p[1] });
    };
  const G2psi = mapAffine(psi);
  const G2psi2 = mapAffine(psi2);
  return { psi, psi2, G2psi, G2psi2, PSI_X, PSI_Y, PSI2_X, PSI2_Y };
}

/** Construction options for the BLS-style degree-12 tower. */
export type Tower12Opts = {
  /** Prime-field order. */
  ORDER: bigint;
  /** Bit length of the BLS parameter `x`. */
  X_LEN: number;
  /** Prime-field non-residue used by the quadratic extension. */
  NONRESIDUE?: Fp;
  /** Quadratic-extension non-residue used by the sextic tower. */
  FP2_NONRESIDUE: BigintTuple;
  /**
   * Optional custom quadratic square-root helper.
   * Receives one quadratic-extension element and returns one square root.
   */
  Fp2sqrt?: (num: Fp2) => Fp2;
  /**
   * Multiply one quadratic element by the curve `b` constant.
   * @param num - Quadratic-extension element to scale.
   * @returns Product by the curve `b` constant.
   */
  Fp2mulByB: (num: Fp2) => Fp2;
  /**
   * Final exponentiation used by pairing arithmetic.
   * @param num - Degree-12 field element to exponentiate.
   * @returns Pairing result after final exponentiation.
   */
  Fp12finalExponentiate: (num: Fp12) => Fp12;
};

class _Field2 implements mod.IField<Fp2> {
  readonly ORDER: bigint;
  readonly BITS: number;
  readonly BYTES: number;
  readonly isLE: boolean;

  readonly ZERO: Fp2;
  readonly ONE: Fp2;
  readonly Fp: mod.IField<bigint>;

  readonly NONRESIDUE: Fp2;
  readonly mulByB: Tower12Opts['Fp2mulByB'];
  readonly Fp_NONRESIDUE: bigint;
  readonly Fp_div2: bigint;
  readonly FROBENIUS_COEFFICIENTS: readonly Fp[];

  constructor(
    Fp: mod.IField<bigint>,
    opts: Partial<{
      NONRESIDUE: bigint;
      FP2_NONRESIDUE: BigintTuple;
      Fp2mulByB: Tower12Opts['Fp2mulByB'];
    }> = {}
  ) {
    const { NONRESIDUE = BigInt(-1), FP2_NONRESIDUE, Fp2mulByB } = opts;
    const ORDER = Fp.ORDER;
    const FP2_ORDER = ORDER * ORDER;
    this.Fp = Fp;
    this.ORDER = FP2_ORDER;
    this.BITS = bitLen(FP2_ORDER);
    this.BYTES = Math.ceil(bitLen(FP2_ORDER) / 8);
    this.isLE = Fp.isLE;
    this.ZERO = this.create({ c0: Fp.ZERO, c1: Fp.ZERO });
    this.ONE = this.create({ c0: Fp.ONE, c1: Fp.ZERO });

    // These knobs only swap constants for the shipped quadratic tower shape:
    // arithmetic below assumes `u^2 = -1`, and bytes are handled as two adjacent
    // `Fp` limbs (`fromBytes` / `toBytes` expect the shipped `2 * Fp.BYTES` layout).
    this.Fp_NONRESIDUE = Fp.create(NONRESIDUE);
    this.Fp_div2 = Fp.div(Fp.ONE, _2n); // 1/2
    this.NONRESIDUE = this.create({ c0: FP2_NONRESIDUE![0], c1: FP2_NONRESIDUE![1] });
    // const Fp2Nonresidue = this.create({ c0: FP2_NONRESIDUE![0], c1: FP2_NONRESIDUE![1] });
    this.FROBENIUS_COEFFICIENTS = Object.freeze(
      calcFrobeniusCoefficients(Fp, this.Fp_NONRESIDUE, Fp.ORDER, 2)[0]
    );
    this.mulByB = (num) => {
      // This config hook is trusted to return a canonical Fp2 value already.
      // Copy+freeze it to keep the tower immutability invariant without mutating caller objects.
      const { c0, c1 } = Fp2mulByB!(num);
      return Object.freeze({ c0, c1 });
    };
    Object.freeze(this);
  }
  fromBigTuple(tuple: BigintTuple) {
    if (!Array.isArray(tuple) || tuple.length !== 2) throw new Error('invalid Fp2.fromBigTuple');
    const [c0, c1] = tuple;
    if (typeof c0 !== 'bigint' || typeof c1 !== 'bigint')
      throw new Error('invalid Fp2.fromBigTuple');
    return this.create({ c0, c1 });
  }
  create(num: Fp2) {
    const { Fp } = this;
    const c0 = Fp.create(num.c0);
    const c1 = Fp.create(num.c1);
    // Bigint field elements are immutable values, and higher-level code relies on
    // that invariant. Copy+freeze tower values too without mutating caller-owned objects.
    return Object.freeze({ c0, c1 });
  }
  isValid(num: Fp2) {
    if (!isObj(num))
      throw new TypeError('invalid field element: expected object, got ' + typeof num);
    const { c0, c1 } = num;
    const { Fp } = this;
    // Match base-field `isValid(...)`: malformed coordinate types are errors, not a `false`
    // predicate result.
    return Fp.isValid(c0) && Fp.isValid(c1);
  }
  is0(num: Fp2) {
    if (!isObj(num)) return false;
    const { c0, c1 } = num;
    const { Fp } = this;
    return Fp.is0(c0) && Fp.is0(c1);
  }
  isValidNot0(num: Fp2) {
    return !this.is0(num) && this.isValid(num);
  }
  eql({ c0, c1 }: Fp2, { c0: r0, c1: r1 }: Fp2) {
    const { Fp } = this;
    return Fp.eql(c0, r0) && Fp.eql(c1, r1);
  }
  neg({ c0, c1 }: Fp2) {
    const { Fp } = this;
    return Object.freeze({ c0: Fp.neg(c0), c1: Fp.neg(c1) });
  }
  pow(num: Fp2, power: bigint): Fp2 {
    return mod.FpPow(this, num, power);
  }
  invertBatch(nums: Fp2[]): Fp2[] {
    return mod.FpInvertBatch(this, nums);
  }
  // Normalized
  add(f1: Fp2, f2: Fp2): Fp2 {
    const { Fp } = this;
    const { c0, c1 } = f1;
    const { c0: r0, c1: r1 } = f2;
    return Object.freeze({
      c0: Fp.add(c0, r0),
      c1: Fp.add(c1, r1),
    });
  }
  sub({ c0, c1 }: Fp2, { c0: r0, c1: r1 }: Fp2) {
    const { Fp } = this;
    return Object.freeze({
      c0: Fp.sub(c0, r0),
      c1: Fp.sub(c1, r1),
    });
  }
  mul({ c0, c1 }: Fp2, rhs: Fp2) {
    const { Fp } = this;
    if (typeof rhs === 'bigint') return Object.freeze({ c0: Fp.mul(c0, rhs), c1: Fp.mul(c1, rhs) });
    // (a+bi)(c+di) = (ac−bd) + (ad+bc)i
    const { c0: r0, c1: r1 } = rhs;
    let t1 = Fp.mul(c0, r0); // c0 * o0
    let t2 = Fp.mul(c1, r1); // c1 * o1
    // (T1 - T2) + ((c0 + c1) * (r0 + r1) - (T1 + T2))*i
    const o0 = Fp.sub(t1, t2);
    const o1 = Fp.sub(Fp.mul(Fp.add(c0, c1), Fp.add(r0, r1)), Fp.add(t1, t2));
    return Object.freeze({ c0: o0, c1: o1 });
  }
  sqr({ c0, c1 }: Fp2) {
    const { Fp } = this;
    const a = Fp.add(c0, c1);
    const b = Fp.sub(c0, c1);
    const c = Fp.add(c0, c0);
    return Object.freeze({ c0: Fp.mul(a, b), c1: Fp.mul(c, c1) });
  }
  // NonNormalized stuff
  addN(a: Fp2, b: Fp2): Fp2 {
    return this.add(a, b);
  }
  subN(a: Fp2, b: Fp2): Fp2 {
    return this.sub(a, b);
  }
  mulN(a: Fp2, b: Fp2): Fp2 {
    return this.mul(a, b);
  }
  sqrN(a: Fp2): Fp2 {
    return this.sqr(a);
  }
  // Why inversion for bigint inside Fp instead of Fp2? it is even used in that context?
  div(lhs: Fp2, rhs: Fp2): Fp2 {
    const { Fp } = this;
    // @ts-ignore
    return this.mul(lhs, typeof rhs === 'bigint' ? Fp.inv(Fp.create(rhs)) : this.inv(rhs));
  }
  inv({ c0: a, c1: b }: Fp2): Fp2 {
    // We wish to find the multiplicative inverse of a nonzero
    // element a + bu in Fp2. We leverage an identity
    //
    // (a + bu)(a - bu) = a² + b²
    //
    // which holds because u² = -1. This can be rewritten as
    //
    // (a + bu)(a - bu)/(a² + b²) = 1
    //
    // because a² + b² = 0 has no nonzero solutions for (a, b).
    // This gives that (a - bu)/(a² + b²) is the inverse
    // of (a + bu). Importantly, this can be computing using
    // only a single inversion in Fp.
    const { Fp } = this;
    const factor = Fp.inv(Fp.create(a * a + b * b));
    return Object.freeze({ c0: Fp.mul(factor, Fp.create(a)), c1: Fp.mul(factor, Fp.create(-b)) });
  }
  sqrt(num: Fp2) {
    // This is generic for all quadratic extensions (Fp2)
    const { Fp } = this;
    const Fp2 = this;
    const { c0, c1 } = num;
    if (Fp.is0(c1)) {
      // if c0 is quadratic residue
      if (mod.FpLegendre(Fp, c0) === 1) return Fp2.create({ c0: Fp.sqrt(c0), c1: Fp.ZERO });
      else return Fp2.create({ c0: Fp.ZERO, c1: Fp.sqrt(Fp.div(c0, this.Fp_NONRESIDUE)) });
    }
    const a = Fp.sqrt(Fp.sub(Fp.sqr(c0), Fp.mul(Fp.sqr(c1), this.Fp_NONRESIDUE)));
    let d = Fp.mul(Fp.add(a, c0), this.Fp_div2);
    const legendre = mod.FpLegendre(Fp, d);
    // -1, Quadratic non residue
    if (legendre === -1) d = Fp.sub(d, a);
    const a0 = Fp.sqrt(d);
    const candidateSqrt = Fp2.create({ c0: a0, c1: Fp.div(Fp.mul(c1, this.Fp_div2), a0) });
    if (!Fp2.eql(Fp2.sqr(candidateSqrt), num)) throw new Error('Cannot find square root');
    // Normalize root: at this point candidateSqrt ** 2 = num, but also -candidateSqrt ** 2 = num
    const x1 = candidateSqrt;
    const x2 = Fp2.neg(x1);
    const { re: re1, im: im1 } = Fp2.reim(x1);
    const { re: re2, im: im2 } = Fp2.reim(x2);
    if (im1 > im2 || (im1 === im2 && re1 > re2)) return x1;
    return x2;
  }
  // Same as sgn0_m_eq_2 in RFC 9380
  isOdd(x: Fp2) {
    const { re: x0, im: x1 } = this.reim(x);
    const sign_0 = x0 % _2n;
    const zero_0 = x0 === _0n;
    const sign_1 = x1 % _2n;
    return BigInt(sign_0 || (zero_0 && sign_1)) == _1n;
  }
  // Bytes util
  fromBytes(b: Uint8Array): Fp2 {
    const { Fp } = this;
    abytes(b);
    if (b.length !== this.BYTES) throw new Error('fromBytes invalid length=' + b.length);
    return this.create({
      c0: Fp.fromBytes(b.subarray(0, Fp.BYTES)),
      c1: Fp.fromBytes(b.subarray(Fp.BYTES)),
    });
  }
  toBytes({ c0, c1 }: Fp2): Uint8Array {
    return concatBytes(this.Fp.toBytes(c0), this.Fp.toBytes(c1));
  }
  cmov({ c0, c1 }: Fp2, { c0: r0, c1: r1 }: Fp2, c: boolean) {
    const { Fp } = this;
    return this.create({
      c0: Fp.cmov(c0, r0, c),
      c1: Fp.cmov(c1, r1, c),
    });
  }
  reim({ c0, c1 }: Fp2) {
    return { re: c0, im: c1 };
  }
  Fp4Square(a: Fp2, b: Fp2): { first: Fp2; second: Fp2 } {
    const Fp2 = this;
    const a2 = Fp2.sqr(a);
    const b2 = Fp2.sqr(b);
    return {
      first: Fp2.add(Fp2.mulByNonresidue(b2), a2), // b² * Nonresidue + a²
      second: Fp2.sub(Fp2.sub(Fp2.sqr(Fp2.add(a, b)), a2), b2), // (a + b)² - a² - b²
    };
  }
  // multiply by u + 1
  mulByNonresidue({ c0, c1 }: Fp2) {
    return this.mul({ c0, c1 }, this.NONRESIDUE);
  }
  frobeniusMap({ c0, c1 }: Fp2, power: number): Fp2 {
    return Object.freeze({
      c0,
      c1: this.Fp.mul(c1, this.FROBENIUS_COEFFICIENTS[power % 2]),
    });
  }
}

class _Field6 implements Fp6Bls {
  readonly ORDER: bigint;
  readonly BITS: number;
  readonly BYTES: number;
  readonly isLE: boolean;

  readonly ZERO: Fp6;
  readonly ONE: Fp6;
  readonly Fp2: Fp2Bls;

  constructor(Fp2: Fp2Bls) {
    this.Fp2 = Fp2;
    // `IField.ORDER` is the field cardinality `q`; for sextic extensions that is `p^6`.
    // Generic helpers like Frobenius-style `x^q = x` checks rely on the literal field size here.
    this.ORDER = Fp2.Fp.ORDER ** _6n;
    this.BITS = 3 * Fp2.BITS;
    this.BYTES = 3 * Fp2.BYTES;
    this.isLE = Fp2.isLE;
    this.ZERO = this.create({ c0: Fp2.ZERO, c1: Fp2.ZERO, c2: Fp2.ZERO });
    this.ONE = this.create({ c0: Fp2.ONE, c1: Fp2.ZERO, c2: Fp2.ZERO });
    Object.freeze(this);
  }
  // Most callers never touch Frobenius maps, so keep the sextic tables lazy:
  // eagerly deriving them dominates `bls12-381.js` / `bn254.js` import time.
  get FROBENIUS_COEFFICIENTS_1(): readonly Fp2[] {
    const frob = _FROBENIUS_COEFFICIENTS_6.get(this);
    if (frob) return frob[0];
    const { Fp2 } = this;
    const { Fp } = Fp2;
    const rows = calcFrobeniusCoefficients(Fp2, Fp2.NONRESIDUE, Fp.ORDER, 6, 2, 3);
    const cache = [Object.freeze(rows[0]), Object.freeze(rows[1])] as const;
    _FROBENIUS_COEFFICIENTS_6.set(this, cache);
    return cache[0];
  }
  get FROBENIUS_COEFFICIENTS_2(): readonly Fp2[] {
    const frob = _FROBENIUS_COEFFICIENTS_6.get(this);
    if (frob) return frob[1];
    void this.FROBENIUS_COEFFICIENTS_1;
    return _FROBENIUS_COEFFICIENTS_6.get(this)![1];
  }
  add({ c0, c1, c2 }: Fp6, { c0: r0, c1: r1, c2: r2 }: Fp6) {
    const { Fp2 } = this;
    return Object.freeze({
      c0: Fp2.add(c0, r0),
      c1: Fp2.add(c1, r1),
      c2: Fp2.add(c2, r2),
    });
  }
  sub({ c0, c1, c2 }: Fp6, { c0: r0, c1: r1, c2: r2 }: Fp6) {
    const { Fp2 } = this;
    return Object.freeze({
      c0: Fp2.sub(c0, r0),
      c1: Fp2.sub(c1, r1),
      c2: Fp2.sub(c2, r2),
    });
  }
  mul({ c0, c1, c2 }: Fp6, rhs: Fp6 | bigint) {
    const { Fp2 } = this;
    if (typeof rhs === 'bigint') {
      return Object.freeze({
        c0: Fp2.mul(c0, rhs),
        c1: Fp2.mul(c1, rhs),
        c2: Fp2.mul(c2, rhs),
      });
    }
    const { c0: r0, c1: r1, c2: r2 } = rhs;
    const t0 = Fp2.mul(c0, r0); // c0 * o0
    const t1 = Fp2.mul(c1, r1); // c1 * o1
    const t2 = Fp2.mul(c2, r2); // c2 * o2
    return Object.freeze({
      // t0 + (c1 + c2) * (r1 * r2) - (T1 + T2) * (u + 1)
      c0: Fp2.add(
        t0,
        Fp2.mulByNonresidue(Fp2.sub(Fp2.mul(Fp2.add(c1, c2), Fp2.add(r1, r2)), Fp2.add(t1, t2)))
      ),
      // (c0 + c1) * (r0 + r1) - (T0 + T1) + T2 * (u + 1)
      c1: Fp2.add(
        Fp2.sub(Fp2.mul(Fp2.add(c0, c1), Fp2.add(r0, r1)), Fp2.add(t0, t1)),
        Fp2.mulByNonresidue(t2)
      ),
      // T1 + (c0 + c2) * (r0 + r2) - T0 + T2
      c2: Fp2.sub(Fp2.add(t1, Fp2.mul(Fp2.add(c0, c2), Fp2.add(r0, r2))), Fp2.add(t0, t2)),
    });
  }
  sqr({ c0, c1, c2 }: Fp6) {
    const { Fp2 } = this;
    let t0 = Fp2.sqr(c0); // c0²
    let t1 = Fp2.mul(Fp2.mul(c0, c1), _2n); // 2 * c0 * c1
    let t3 = Fp2.mul(Fp2.mul(c1, c2), _2n); // 2 * c1 * c2
    let t4 = Fp2.sqr(c2); // c2²
    return Object.freeze({
      c0: Fp2.add(Fp2.mulByNonresidue(t3), t0), // T3 * (u + 1) + T0
      c1: Fp2.add(Fp2.mulByNonresidue(t4), t1), // T4 * (u + 1) + T1
      // T1 + (c0 - c1 + c2)² + T3 - T0 - T4
      c2: Fp2.sub(Fp2.sub(Fp2.add(Fp2.add(t1, Fp2.sqr(Fp2.add(Fp2.sub(c0, c1), c2))), t3), t0), t4),
    });
  }
  addN(a: Fp6, b: Fp6): Fp6 {
    return this.add(a, b);
  }
  subN(a: Fp6, b: Fp6): Fp6 {
    return this.sub(a, b);
  }
  mulN(a: Fp6, b: Fp6): Fp6 {
    return this.mul(a, b);
  }
  sqrN(a: Fp6): Fp6 {
    return this.sqr(a);
  }

  create(num: Fp6) {
    const { Fp2 } = this;
    const c0 = Fp2.create(num.c0);
    const c1 = Fp2.create(num.c1);
    const c2 = Fp2.create(num.c2);
    return Object.freeze({ c0, c1, c2 });
  }

  isValid(num: Fp6) {
    if (!isObj(num))
      throw new TypeError('invalid field element: expected object, got ' + typeof num);
    const { c0, c1, c2 } = num;
    const { Fp2 } = this;
    return Fp2.isValid(c0) && Fp2.isValid(c1) && Fp2.isValid(c2);
  }
  is0(num: Fp6) {
    if (!isObj(num)) return false;
    const { c0, c1, c2 } = num;
    const { Fp2 } = this;
    return Fp2.is0(c0) && Fp2.is0(c1) && Fp2.is0(c2);
  }
  isValidNot0(num: Fp6) {
    return !this.is0(num) && this.isValid(num);
  }
  neg({ c0, c1, c2 }: Fp6) {
    const { Fp2 } = this;
    return Object.freeze({ c0: Fp2.neg(c0), c1: Fp2.neg(c1), c2: Fp2.neg(c2) });
  }
  eql({ c0, c1, c2 }: Fp6, { c0: r0, c1: r1, c2: r2 }: Fp6) {
    const { Fp2 } = this;
    return Fp2.eql(c0, r0) && Fp2.eql(c1, r1) && Fp2.eql(c2, r2);
  }
  sqrt(_: Fp6) {
    // Sextic extensions can use generic odd-field Tonelli-Shanks, but the helper must work
    // over `IField<T>` with a quadratic non-residue from Fp6 itself. The current
    // `mod.tonelliShanks(P)` precomputation only searches integer residues in the base field.
    return notImplemented();
  }
  // Do we need division by bigint at all? Should be done via order:
  div(lhs: Fp6, rhs: Fp6) {
    const { Fp2 } = this;
    const { Fp } = Fp2;
    return this.mul(lhs, typeof rhs === 'bigint' ? Fp.inv(Fp.create(rhs)) : this.inv(rhs));
  }
  pow(num: Fp6, power: Fp): Fp6 {
    return mod.FpPow(this, num, power);
  }
  invertBatch(nums: Fp6[]): Fp6[] {
    return mod.FpInvertBatch(this, nums);
  }

  inv({ c0, c1, c2 }: Fp6) {
    const { Fp2 } = this;
    let t0 = Fp2.sub(Fp2.sqr(c0), Fp2.mulByNonresidue(Fp2.mul(c2, c1))); // c0² - c2 * c1 * (u + 1)
    let t1 = Fp2.sub(Fp2.mulByNonresidue(Fp2.sqr(c2)), Fp2.mul(c0, c1)); // c2² * (u + 1) - c0 * c1
    let t2 = Fp2.sub(Fp2.sqr(c1), Fp2.mul(c0, c2)); // c1² - c0 * c2
    // 1/(((c2 * T1 + c1 * T2) * v) + c0 * T0)
    let t4 = Fp2.inv(
      Fp2.add(Fp2.mulByNonresidue(Fp2.add(Fp2.mul(c2, t1), Fp2.mul(c1, t2))), Fp2.mul(c0, t0))
    );
    return Object.freeze({ c0: Fp2.mul(t4, t0), c1: Fp2.mul(t4, t1), c2: Fp2.mul(t4, t2) });
  }
  // Bytes utils
  fromBytes(b: Uint8Array): Fp6 {
    const { Fp2 } = this;
    abytes(b);
    if (b.length !== this.BYTES) throw new Error('fromBytes invalid length=' + b.length);
    const B2 = Fp2.BYTES;
    return this.create({
      c0: Fp2.fromBytes(b.subarray(0, B2)),
      c1: Fp2.fromBytes(b.subarray(B2, B2 * 2)),
      c2: Fp2.fromBytes(b.subarray(2 * B2)),
    });
  }
  toBytes({ c0, c1, c2 }: Fp6): Uint8Array {
    const { Fp2 } = this;
    return concatBytes(Fp2.toBytes(c0), Fp2.toBytes(c1), Fp2.toBytes(c2));
  }
  cmov({ c0, c1, c2 }: Fp6, { c0: r0, c1: r1, c2: r2 }: Fp6, c: boolean) {
    const { Fp2 } = this;
    return this.create({
      c0: Fp2.cmov(c0, r0, c),
      c1: Fp2.cmov(c1, r1, c),
      c2: Fp2.cmov(c2, r2, c),
    });
  }
  fromBigSix(tuple: BigintSix): Fp6 {
    const { Fp2 } = this;
    if (!Array.isArray(tuple) || tuple.length !== 6) throw new Error('invalid Fp6.fromBigSix');
    for (let i = 0; i < 6; i++)
      if (typeof tuple[i] !== 'bigint') throw new Error('invalid Fp6.fromBigSix');
    const t = tuple;
    return this.create({
      c0: Fp2.fromBigTuple(t.slice(0, 2) as BigintTuple),
      c1: Fp2.fromBigTuple(t.slice(2, 4) as BigintTuple),
      c2: Fp2.fromBigTuple(t.slice(4, 6) as BigintTuple),
    });
  }
  frobeniusMap({ c0, c1, c2 }: Fp6, power: number) {
    const { Fp2 } = this;
    return Object.freeze({
      c0: Fp2.frobeniusMap(c0, power),
      c1: Fp2.mul(Fp2.frobeniusMap(c1, power), this.FROBENIUS_COEFFICIENTS_1[power % 6]),
      c2: Fp2.mul(Fp2.frobeniusMap(c2, power), this.FROBENIUS_COEFFICIENTS_2[power % 6]),
    });
  }
  mulByFp2({ c0, c1, c2 }: Fp6, rhs: Fp2): Fp6 {
    const { Fp2 } = this;
    return Object.freeze({
      c0: Fp2.mul(c0, rhs),
      c1: Fp2.mul(c1, rhs),
      c2: Fp2.mul(c2, rhs),
    });
  }
  mulByNonresidue({ c0, c1, c2 }: Fp6) {
    const { Fp2 } = this;
    return Object.freeze({ c0: Fp2.mulByNonresidue(c2), c1: c0, c2: c1 });
  }
  // Sparse multiplication
  mul1({ c0, c1, c2 }: Fp6, b1: Fp2): Fp6 {
    const { Fp2 } = this;
    return Object.freeze({
      c0: Fp2.mulByNonresidue(Fp2.mul(c2, b1)),
      c1: Fp2.mul(c0, b1),
      c2: Fp2.mul(c1, b1),
    });
  }
  // Sparse multiplication
  mul01({ c0, c1, c2 }: Fp6, b0: Fp2, b1: Fp2): Fp6 {
    const { Fp2 } = this;
    let t0 = Fp2.mul(c0, b0); // c0 * b0
    let t1 = Fp2.mul(c1, b1); // c1 * b1
    return Object.freeze({
      // ((c1 + c2) * b1 - T1) * (u + 1) + T0
      c0: Fp2.add(Fp2.mulByNonresidue(Fp2.sub(Fp2.mul(Fp2.add(c1, c2), b1), t1)), t0),
      // (b0 + b1) * (c0 + c1) - T0 - T1
      c1: Fp2.sub(Fp2.sub(Fp2.mul(Fp2.add(b0, b1), Fp2.add(c0, c1)), t0), t1),
      // (c0 + c2) * b0 - T0 + T1
      c2: Fp2.add(Fp2.sub(Fp2.mul(Fp2.add(c0, c2), b0), t0), t1),
    });
  }
}

// Keep lazy tower caches off-object: field instances stay frozen, and debugger output
// stays readable without JS private slots while second/subsequent lookups still hit cache.
const _FROBENIUS_COEFFICIENTS_6 = new WeakMap<_Field6, readonly [readonly Fp2[], readonly Fp2[]]>();

class _Field12 implements Fp12Bls {
  readonly ORDER: bigint;
  readonly BITS: number;
  readonly BYTES: number;
  readonly isLE: boolean;

  readonly ZERO: Fp12;
  readonly ONE: Fp12;

  readonly Fp6: Fp6Bls;
  readonly X_LEN: number;
  readonly finalExponentiate: Tower12Opts['Fp12finalExponentiate'];

  constructor(Fp6: Fp6Bls, opts: Tower12Opts) {
    const { X_LEN, Fp12finalExponentiate } = opts;
    const { Fp2 } = Fp6;
    const { Fp } = Fp2;
    this.Fp6 = Fp6;

    // `IField.ORDER` is the field cardinality `q`; for degree-12 extensions that is `p^12`.
    // Keeping `p^2` here breaks generic field identities like `x^q = x` on Fp12.
    this.ORDER = Fp.ORDER ** _12n;
    this.BITS = 2 * Fp6.BITS;
    this.BYTES = 2 * Fp6.BYTES;
    this.isLE = Fp6.isLE;
    // Returned tower values are frozen, so larger constants can safely reuse
    // already-frozen child coefficients instead of cloning them.
    this.ZERO = this.create({ c0: Fp6.ZERO, c1: Fp6.ZERO });
    this.ONE = this.create({ c0: Fp6.ONE, c1: Fp6.ZERO });
    this.X_LEN = X_LEN;
    this.finalExponentiate = (num) => {
      const copy2 = ({ c0, c1 }: Fp2): Fp2 => Object.freeze({ c0, c1 });
      const copy6 = ({ c0, c1, c2 }: Fp6): Fp6 =>
        Object.freeze({ c0: copy2(c0), c1: copy2(c1), c2: copy2(c2) });
      // This config hook is trusted to return a canonical Fp12 value already.
      // Copy+freeze it to keep the tower immutability invariant without mutating caller objects.
      const res = Fp12finalExponentiate(num);
      return Object.freeze({ c0: copy6(res.c0), c1: copy6(res.c1) });
    };
    Object.freeze(this);
  }
  // Keep the degree-12 Frobenius row lazy too; after the first lookup the cached
  // array is reused exactly like the old eager table.
  get FROBENIUS_COEFFICIENTS(): readonly Fp2[] {
    const frob = _FROBENIUS_COEFFICIENTS_12.get(this);
    if (frob) return frob;
    const { Fp2 } = this.Fp6;
    const { Fp } = Fp2;
    const cache = Object.freeze(
      calcFrobeniusCoefficients(Fp2, Fp2.NONRESIDUE, Fp.ORDER, 12, 1, 6)[0]
    );
    _FROBENIUS_COEFFICIENTS_12.set(this, cache);
    return cache;
  }
  create(num: Fp12) {
    const { Fp6 } = this;
    const c0 = Fp6.create(num.c0);
    const c1 = Fp6.create(num.c1);
    return Object.freeze({ c0, c1 });
  }
  isValid(num: Fp12) {
    if (!isObj(num))
      throw new TypeError('invalid field element: expected object, got ' + typeof num);
    const { c0, c1 } = num;
    const { Fp6 } = this;
    return Fp6.isValid(c0) && Fp6.isValid(c1);
  }
  is0(num: Fp12) {
    if (!isObj(num)) return false;
    const { c0, c1 } = num;
    const { Fp6 } = this;
    return Fp6.is0(c0) && Fp6.is0(c1);
  }
  isValidNot0(num: Fp12) {
    return !this.is0(num) && this.isValid(num);
  }
  neg({ c0, c1 }: Fp12) {
    const { Fp6 } = this;
    return Object.freeze({ c0: Fp6.neg(c0), c1: Fp6.neg(c1) });
  }
  eql({ c0, c1 }: Fp12, { c0: r0, c1: r1 }: Fp12) {
    const { Fp6 } = this;
    return Fp6.eql(c0, r0) && Fp6.eql(c1, r1);
  }
  sqrt(_: Fp12): Fp12 {
    // Fp12 is quadratic over Fp6, so a dedicated quadratic-extension sqrt is possible here
    // once Fp6.sqrt() exists. Without that lower-level sqrt, only a field-generic
    // Tonelli-Shanks path over Fp12 itself would work.
    return notImplemented();
  }
  inv({ c0, c1 }: Fp12) {
    const { Fp6 } = this;
    let t = Fp6.inv(Fp6.sub(Fp6.sqr(c0), Fp6.mulByNonresidue(Fp6.sqr(c1)))); // 1 / (c0² - c1² * v)
    // ((C0 * T) * T) + (-C1 * T) * w
    return Object.freeze({ c0: Fp6.mul(c0, t), c1: Fp6.neg(Fp6.mul(c1, t)) });
  }
  div(lhs: Fp12, rhs: Fp12) {
    const { Fp6 } = this;
    const { Fp2 } = Fp6;
    const { Fp } = Fp2;
    return this.mul(lhs, typeof rhs === 'bigint' ? Fp.inv(Fp.create(rhs)) : this.inv(rhs));
  }
  pow(num: Fp12, power: bigint): Fp12 {
    return mod.FpPow(this, num, power);
  }
  invertBatch(nums: Fp12[]): Fp12[] {
    return mod.FpInvertBatch(this, nums);
  }

  // Normalized
  add({ c0, c1 }: Fp12, { c0: r0, c1: r1 }: Fp12) {
    const { Fp6 } = this;
    return Object.freeze({
      c0: Fp6.add(c0, r0),
      c1: Fp6.add(c1, r1),
    });
  }
  sub({ c0, c1 }: Fp12, { c0: r0, c1: r1 }: Fp12) {
    const { Fp6 } = this;
    return Object.freeze({
      c0: Fp6.sub(c0, r0),
      c1: Fp6.sub(c1, r1),
    });
  }
  mul({ c0, c1 }: Fp12, rhs: Fp12 | bigint) {
    const { Fp6 } = this;
    if (typeof rhs === 'bigint')
      return Object.freeze({ c0: Fp6.mul(c0, rhs), c1: Fp6.mul(c1, rhs) });
    let { c0: r0, c1: r1 } = rhs;
    let t1 = Fp6.mul(c0, r0); // c0 * r0
    let t2 = Fp6.mul(c1, r1); // c1 * r1
    return Object.freeze({
      c0: Fp6.add(t1, Fp6.mulByNonresidue(t2)), // T1 + T2 * v
      // (c0 + c1) * (r0 + r1) - (T1 + T2)
      c1: Fp6.sub(Fp6.mul(Fp6.add(c0, c1), Fp6.add(r0, r1)), Fp6.add(t1, t2)),
    });
  }
  sqr({ c0, c1 }: Fp12) {
    const { Fp6 } = this;
    let ab = Fp6.mul(c0, c1); // c0 * c1
    return Object.freeze({
      // (c1 * v + c0) * (c0 + c1) - AB - AB * v
      c0: Fp6.sub(
        Fp6.sub(Fp6.mul(Fp6.add(Fp6.mulByNonresidue(c1), c0), Fp6.add(c0, c1)), ab),
        Fp6.mulByNonresidue(ab)
      ),
      c1: Fp6.add(ab, ab),
    }); // AB + AB
  }
  // NonNormalized stuff
  addN(a: Fp12, b: Fp12): Fp12 {
    return this.add(a, b);
  }
  subN(a: Fp12, b: Fp12): Fp12 {
    return this.sub(a, b);
  }
  mulN(a: Fp12, b: Fp12): Fp12 {
    return this.mul(a, b);
  }
  sqrN(a: Fp12): Fp12 {
    return this.sqr(a);
  }

  // Bytes utils
  fromBytes(b: Uint8Array): Fp12 {
    const { Fp6 } = this;
    abytes(b);
    if (b.length !== this.BYTES) throw new Error('fromBytes invalid length=' + b.length);
    return this.create({
      c0: Fp6.fromBytes(b.subarray(0, Fp6.BYTES)),
      c1: Fp6.fromBytes(b.subarray(Fp6.BYTES)),
    });
  }
  toBytes({ c0, c1 }: Fp12): Uint8Array {
    const { Fp6 } = this;
    return concatBytes(Fp6.toBytes(c0), Fp6.toBytes(c1));
  }
  cmov({ c0, c1 }: Fp12, { c0: r0, c1: r1 }: Fp12, c: boolean) {
    const { Fp6 } = this;
    return this.create({
      c0: Fp6.cmov(c0, r0, c),
      c1: Fp6.cmov(c1, r1, c),
    });
  }
  // Utils
  // toString() {
  //   return '' + 'Fp12(' + this.c0 + this.c1 + '* w');
  // },
  // fromTuple(c: [Fp6, Fp6]) {
  //   return new Fp12(...c);
  // }
  fromBigTwelve(tuple: BigintTwelve): Fp12 {
    const { Fp6 } = this;
    if (!Array.isArray(tuple) || tuple.length !== 12) throw new Error('invalid Fp12.fromBigTwelve');
    for (let i = 0; i < 12; i++)
      if (typeof tuple[i] !== 'bigint') throw new Error('invalid Fp12.fromBigTwelve');
    const t = tuple;
    return this.create({
      c0: Fp6.fromBigSix(t.slice(0, 6) as BigintSix),
      c1: Fp6.fromBigSix(t.slice(6, 12) as BigintSix),
    });
  }
  // Raises to q**i -th power
  frobeniusMap(lhs: Fp12, power: number) {
    const { Fp6 } = this;
    const { Fp2 } = Fp6;
    const { c0, c1, c2 } = Fp6.frobeniusMap(lhs.c1, power);
    const coeff = this.FROBENIUS_COEFFICIENTS[power % 12];
    return Object.freeze({
      c0: Fp6.frobeniusMap(lhs.c0, power),
      c1: Object.freeze({
        c0: Fp2.mul(c0, coeff),
        c1: Fp2.mul(c1, coeff),
        c2: Fp2.mul(c2, coeff),
      }),
    });
  }
  mulByFp2({ c0, c1 }: Fp12, rhs: Fp2): Fp12 {
    const { Fp6 } = this;
    return Object.freeze({
      c0: Fp6.mulByFp2(c0, rhs),
      c1: Fp6.mulByFp2(c1, rhs),
    });
  }
  conjugate({ c0, c1 }: Fp12): Fp12 {
    // Reuse `c0` by reference and only negate the `w` coefficient.
    return Object.freeze({ c0, c1: this.Fp6.neg(c1) });
  }
  // Sparse multiplication
  mul014({ c0, c1 }: Fp12, o0: Fp2, o1: Fp2, o4: Fp2) {
    const { Fp6 } = this;
    const { Fp2 } = Fp6;
    let t0 = Fp6.mul01(c0, o0, o1);
    let t1 = Fp6.mul1(c1, o4);
    return Object.freeze({
      c0: Fp6.add(Fp6.mulByNonresidue(t1), t0), // T1 * v + T0
      // (c1 + c0) * [o0, o1+o4] - T0 - T1
      c1: Fp6.sub(Fp6.sub(Fp6.mul01(Fp6.add(c1, c0), o0, Fp2.add(o1, o4)), t0), t1),
    });
  }
  mul034({ c0, c1 }: Fp12, o0: Fp2, o3: Fp2, o4: Fp2) {
    const { Fp6 } = this;
    const { Fp2 } = Fp6;
    const a = Object.freeze({
      c0: Fp2.mul(c0.c0, o0),
      c1: Fp2.mul(c0.c1, o0),
      c2: Fp2.mul(c0.c2, o0),
    });
    const b = Fp6.mul01(c1, o3, o4);
    const e = Fp6.mul01(Fp6.add(c0, c1), Fp2.add(o0, o3), o4);
    return Object.freeze({
      c0: Fp6.add(Fp6.mulByNonresidue(b), a),
      c1: Fp6.sub(e, Fp6.add(a, b)),
    });
  }

  // A cyclotomic group is a subgroup of Fp^n defined by
  //   GΦₙ(p) = {α ∈ Fpⁿ : α^Φₙ(p) = 1}
  // The result of any pairing is in a cyclotomic subgroup
  // https://eprint.iacr.org/2009/565.pdf
  // https://eprint.iacr.org/2010/354.pdf
  _cyclotomicSquare({ c0, c1 }: Fp12): Fp12 {
    const { Fp6 } = this;
    const { Fp2 } = Fp6;
    const { c0: c0c0, c1: c0c1, c2: c0c2 } = c0;
    const { c0: c1c0, c1: c1c1, c2: c1c2 } = c1;
    const { first: t3, second: t4 } = Fp2.Fp4Square(c0c0, c1c1);
    const { first: t5, second: t6 } = Fp2.Fp4Square(c1c0, c0c2);
    const { first: t7, second: t8 } = Fp2.Fp4Square(c0c1, c1c2);
    const t9 = Fp2.mulByNonresidue(t8); // T8 * (u + 1)
    return Object.freeze({
      c0: Object.freeze({
        c0: Fp2.add(Fp2.mul(Fp2.sub(t3, c0c0), _2n), t3), // 2 * (T3 - c0c0)  + T3
        c1: Fp2.add(Fp2.mul(Fp2.sub(t5, c0c1), _2n), t5), // 2 * (T5 - c0c1)  + T5
        c2: Fp2.add(Fp2.mul(Fp2.sub(t7, c0c2), _2n), t7),
      }), // 2 * (T7 - c0c2)  + T7
      c1: Object.freeze({
        c0: Fp2.add(Fp2.mul(Fp2.add(t9, c1c0), _2n), t9), // 2 * (T9 + c1c0) + T9
        c1: Fp2.add(Fp2.mul(Fp2.add(t4, c1c1), _2n), t4), // 2 * (T4 + c1c1) + T4
        c2: Fp2.add(Fp2.mul(Fp2.add(t6, c1c2), _2n), t6),
      }),
    }); // 2 * (T6 + c1c2) + T6
  }
  // https://eprint.iacr.org/2009/565.pdf
  _cyclotomicExp(num: Fp12, n: bigint): Fp12 {
    // The loop only consumes `X_LEN` bits, so out-of-range exponents would otherwise get silently
    // truncated (or sign-extended for negatives) instead of matching the caller's requested power.
    aInRange('cyclotomic exponent', n, _0n, _1n << BigInt(this.X_LEN));
    let z = this.ONE;
    for (let i = this.X_LEN - 1; i >= 0; i--) {
      z = this._cyclotomicSquare(z);
      if (bitGet(n, i)) z = this.mul(z, num);
    }
    return z;
  }
}

const _FROBENIUS_COEFFICIENTS_12 = new WeakMap<_Field12, readonly Fp2[]>();

/**
 * @param opts - Tower construction options. See {@link Tower12Opts}.
 * @returns BLS tower fields.
 * @throws If the tower options or derived Frobenius helpers are invalid. {@link Error}
 * @example
 * Construct the Fp2/Fp6/Fp12 tower used by a pairing-friendly curve.
 *
 * ```ts
 * const fields = tower12({
 *   ORDER: 17n,
 *   X_LEN: 4,
 *   FP2_NONRESIDUE: [1n, 1n],
 *   Fp2mulByB: (num) => num,
 *   Fp12finalExponentiate: (num) => num,
 * });
 * const fp12 = fields.Fp12.ONE;
 * ```
 */
export function tower12(opts: TArg<Tower12Opts>): TRet<{
  Fp: Readonly<mod.IField<bigint> & Required<Pick<mod.IField<bigint>, 'isOdd'>>>;
  Fp2: Fp2Bls;
  Fp6: Fp6Bls;
  Fp12: Fp12Bls;
}> {
  validateObject(
    opts,
    {
      ORDER: 'bigint',
      X_LEN: 'number',
      FP2_NONRESIDUE: 'object',
      Fp2mulByB: 'function',
      Fp12finalExponentiate: 'function',
    },
    { NONRESIDUE: 'bigint' }
  );
  asafenumber(opts.X_LEN, 'X_LEN');
  if (opts.X_LEN < 1) throw new Error('invalid X_LEN');
  const nonresidue = opts.FP2_NONRESIDUE as bigint[];
  if (!Array.isArray(nonresidue) || nonresidue.length !== 2)
    throw new Error('invalid FP2_NONRESIDUE');
  if (typeof nonresidue[0] !== 'bigint' || typeof nonresidue[1] !== 'bigint')
    throw new Error('invalid FP2_NONRESIDUE');
  const Fp = mod.Field(opts.ORDER);
  const Fp2 = new _Field2(Fp, opts);
  const Fp6 = new _Field6(Fp2);
  const Fp12 = new _Field12(Fp6, opts);
  return { Fp, Fp2, Fp6, Fp12 } as TRet<{
    Fp: Readonly<mod.IField<bigint> & Required<Pick<mod.IField<bigint>, 'isOdd'>>>;
    Fp2: Fp2Bls;
    Fp6: Fp6Bls;
    Fp12: Fp12Bls;
  }>;
}
