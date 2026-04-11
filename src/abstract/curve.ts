/**
 * Methods for elliptic curve multiplication by scalars.
 * Contains wNAF, pippenger.
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { bitLen, bitMask, validateObject, type Signer, type TArg, type TRet } from '../utils.ts';
import { Field, FpInvertBatch, validateField, type IField } from './modular.ts';

const _0n = /* @__PURE__ */ BigInt(0);
const _1n = /* @__PURE__ */ BigInt(1);

/** Affine point coordinates without projective fields. */
export type AffinePoint<T> = {
  /** Affine x coordinate. */
  x: T;
  /** Affine y coordinate. */
  y: T;
} & { Z?: never };

// We can't "abstract out" coordinates (X, Y, Z; and T in Edwards): argument names of constructor
// are not accessible. See Typescript gh-56093, gh-41594.
//
// We have to use recursive types, so it will return actual point, not constained `CurvePoint`.
// If, at any point, P is `any`, it will erase all types and replace it
// with `any`, because of recursion, `any implements CurvePoint`,
// but we lose all constrains on methods.

/** Base interface for all elliptic-curve point instances. */
export interface CurvePoint<F, P extends CurvePoint<F, P>> {
  /** Affine x coordinate. Different from projective / extended X coordinate. */
  x: F;
  /** Affine y coordinate. Different from projective / extended Y coordinate. */
  y: F;
  /** Projective Z coordinate when the point keeps projective state. */
  Z?: F;
  /**
   * Double the point.
   * @returns Doubled point.
   */
  double(): P;
  /**
   * Negate the point.
   * @returns Negated point.
   */
  negate(): P;
  /**
   * Add another point from the same curve.
   * @param other - Point to add.
   * @returns Sum point.
   */
  add(other: P): P;
  /**
   * Subtract another point from the same curve.
   * @param other - Point to subtract.
   * @returns Difference point.
   */
  subtract(other: P): P;
  /**
   * Compare two points for equality.
   * @param other - Point to compare.
   * @returns Whether the points are equal.
   */
  equals(other: P): boolean;
  /**
   * Multiply the point by a scalar in constant time.
   * Implementations keep the subgroup-scalar contract strict and may reject
   * `0` instead of returning the identity point.
   * @param scalar - Scalar multiplier.
   * @returns Product point.
   */
  multiply(scalar: bigint): P;
  /** Assert that the point satisfies the curve equation and subgroup checks. */
  assertValidity(): void;
  /**
   * Map the point into the prime-order subgroup when the curve requires it.
   * @returns Prime-order point.
   */
  clearCofactor(): P;
  /**
   * Check whether the point is the point at infinity.
   * @returns Whether the point is zero.
   */
  is0(): boolean;
  /**
   * Check whether the point belongs to the prime-order subgroup.
   * @returns Whether the point is torsion-free.
   */
  isTorsionFree(): boolean;
  /**
   * Check whether the point lies in a small torsion subgroup.
   * @returns Whether the point has small order.
   */
  isSmallOrder(): boolean;
  /**
   * Multiply the point by a scalar without constant-time guarantees.
   * Public-scalar callers that need `0` should use this method instead of
   * relying on `multiply(...)` to return the identity point.
   * @param scalar - Scalar multiplier.
   * @returns Product point.
   */
  multiplyUnsafe(scalar: bigint): P;
  /**
   * Massively speeds up `p.multiply(n)` by using precompute tables (caching). See {@link wNAF}.
   * Cache state lives in internal WeakMaps keyed by point identity, not on the point object.
   * Repeating `precompute(...)` for the same point identity replaces the remembered window size
   * and forces table regeneration for that point.
   * @param windowSize - Precompute window size.
   * @param isLazy - calculate cache now. Default (true) ensures it's deferred to first `multiply()`
   * @returns Same point instance with precompute tables attached.
   */
  precompute(windowSize?: number, isLazy?: boolean): P;
  /**
   * Converts point to 2D xy affine coordinates.
   * @param invertedZ - Optional inverted Z coordinate for batch normalization.
   * @returns Affine x/y coordinates.
   */
  toAffine(invertedZ?: F): AffinePoint<F>;
  /**
   * Encode the point into the curve's canonical byte form.
   * @returns Encoded point bytes.
   */
  toBytes(): Uint8Array;
  /**
   * Encode the point into the curve's canonical hex form.
   * @returns Encoded point hex.
   */
  toHex(): string;
}

/** Base interface for elliptic-curve point constructors. */
export interface CurvePointCons<P extends CurvePoint<any, P>> {
  /**
   * Runtime brand check for points created by this constructor.
   * @param item - Value to test.
   * @returns Whether the value is a point from this constructor.
   */
  [Symbol.hasInstance]: (item: unknown) => boolean;
  /** Canonical subgroup generator. */
  BASE: P;
  /** Point at infinity. */
  ZERO: P;
  /** Field for basic curve math */
  Fp: IField<P_F<P>>;
  /** Scalar field, for scalars in multiply and others */
  Fn: IField<bigint>;
  /**
   * Create one point from affine coordinates.
   * Does NOT validate curve, subgroup, or wrapper invariants.
   * Use `.assertValidity()` on adversarial inputs.
   * @param p - Affine point coordinates.
   * @returns Point instance.
   */
  fromAffine(p: AffinePoint<P_F<P>>): P;
  /**
   * Decode a point from the canonical byte encoding.
   * @param bytes - Encoded point bytes.
   * Implementations MUST treat `bytes` as read-only.
   * @returns Point instance.
   */
  fromBytes(bytes: Uint8Array): P;
  /**
   * Decode a point from the canonical hex encoding.
   * @param hex - Encoded point hex.
   * @returns Point instance.
   */
  fromHex(hex: string): P;
}

// Type inference helpers: PC - PointConstructor, P - Point, Fp - Field element
// Short names, because we use them a lot in result types:
// * we can't do 'P = GetCurvePoint<PC>': this is default value and doesn't constrain anything
// * we can't do 'type X = GetCurvePoint<PC>': it won't be accesible for arguments/return types
// * `CurvePointCons<P extends CurvePoint<any, P>>` constraints from interface definition
//   won't propagate, if `PC extends CurvePointCons<any>`: the P would be 'any', which is incorrect
// * PC could be super specific with super specific P, which implements CurvePoint<any, P>.
//   this means we need to do stuff like
//   `function test<P extends CurvePoint<any, P>, PC extends CurvePointCons<P>>(`
//   if we want type safety around P, otherwise PC_P<PC> will be any

/** Returns the affine field type for a point instance (`P_F<P> == P.F`). */
export type P_F<P extends CurvePoint<any, P>> = P extends CurvePoint<infer F, P> ? F : never;
/** Returns the affine field type for a point constructor (`PC_F<PC> == PC.P.F`). */
export type PC_F<PC extends CurvePointCons<CurvePoint<any, any>>> = PC['Fp']['ZERO'];
/** Returns the point instance type for a point constructor (`PC_P<PC> == PC.P`). */
export type PC_P<PC extends CurvePointCons<CurvePoint<any, any>>> = PC['ZERO'];

// Ugly hack to get proper type inference, because in typescript fails to infer resursively.
// The hack allows to do up to 10 chained operations without applying type erasure.
//
// Types which won't work:
// * `CurvePointCons<CurvePoint<any, any>>`, will return `any` after 1 operation
// * `CurvePointCons<any>: WeierstrassPointCons<bigint> extends CurvePointCons<any> = false`
// * `P extends CurvePoint, PC extends CurvePointCons<P>`
//     * It can't infer P from PC alone
//     * Too many relations between F, P & PC
//     * It will infer P/F if `arg: CurvePointCons<F, P>`, but will fail if PC is generic
//     * It will work correctly if there is an additional argument of type P
//     * But generally, we don't want to parametrize `CurvePointCons` over `F`: it will complicate
//       types, making them un-inferable
// prettier-ignore
/** Wide point-constructor type used when the concrete curve is not important. */
export type PC_ANY = CurvePointCons<
  CurvePoint<any,
  CurvePoint<any,
  CurvePoint<any,
  CurvePoint<any,
  CurvePoint<any,
  CurvePoint<any,
  CurvePoint<any,
  CurvePoint<any,
  CurvePoint<any,
  CurvePoint<any, any>
  >>>>>>>>>
>;

/**
 * Validates the static surface of a point constructor.
 * This is only a cheap sanity check for the constructor hooks and fields consumed by generic
 * factories; it does not certify `BASE`/`ZERO` semantics or prove the curve implementation itself.
 * @param Point - Runtime point constructor.
 * @throws On missing constructor hooks or malformed field metadata. {@link TypeError}
 * @example
 * Check that one point constructor exposes the static hooks generic helpers need.
 *
 * ```ts
 * import { ed25519 } from '@noble/curves/ed25519.js';
 * import { validatePointCons } from '@noble/curves/abstract/curve.js';
 * validatePointCons(ed25519.Point);
 * ```
 */
export function validatePointCons<P extends CurvePoint<any, P>>(Point: CurvePointCons<P>): void {
  const pc = Point as unknown as CurvePointCons<any>;
  if (typeof (pc as unknown) !== 'function') throw new TypeError('Point must be a constructor');
  // validateObject only accepts plain objects, so copy the constructor statics into one bag first.
  validateObject(
    {
      Fp: pc.Fp,
      Fn: pc.Fn,
      fromAffine: pc.fromAffine,
      fromBytes: pc.fromBytes,
      fromHex: pc.fromHex,
    },
    {
      Fp: 'object',
      Fn: 'object',
      fromAffine: 'function',
      fromBytes: 'function',
      fromHex: 'function',
    }
  );
  validateField(pc.Fp);
  validateField(pc.Fn);
}

/** Byte lengths used by one curve implementation. */
export interface CurveLengths {
  /** Secret-key length in bytes. */
  secretKey?: number;
  /** Compressed public-key length in bytes. */
  publicKey?: number;
  /** Uncompressed public-key length in bytes. */
  publicKeyUncompressed?: number;
  /** Whether public-key encodings include a format prefix byte. */
  publicKeyHasPrefix?: boolean;
  /** Signature length in bytes. */
  signature?: number;
  /** Seed length in bytes when the curve exposes deterministic keygen from seed. */
  seed?: number;
}

/** Reorders or otherwise remaps a batch while preserving its element type. */
export type Mapper<T> = (i: T[]) => T[];

/**
 * Computes both candidates first, but the final selection still branches on `condition`, so this
 * is not a strict constant-time CMOV primitive.
 * @param condition - Whether to negate the point.
 * @param item - Point-like value.
 * @returns Original or negated value.
 * @example
 * Keep the point or return its negation based on one boolean branch.
 *
 * ```ts
 * import { negateCt } from '@noble/curves/abstract/curve.js';
 * import { p256 } from '@noble/curves/nist.js';
 * const maybeNegated = negateCt(true, p256.Point.BASE);
 * ```
 */
export function negateCt<T extends { negate: () => T }>(condition: boolean, item: T): T {
  const neg = item.negate();
  return condition ? neg : item;
}

/**
 * Takes a bunch of Projective Points but executes only one
 * inversion on all of them. Inversion is very slow operation,
 * so this improves performance massively.
 * Optimization: converts a list of projective points to a list of identical points with Z=1.
 * Input points are left unchanged; the normalized points are returned as fresh instances.
 * @param c - Point constructor.
 * @param points - Projective points.
 * @returns Fresh projective points reconstructed from normalized affine coordinates.
 * @example
 * Batch-normalize projective points with a single shared inversion.
 *
 * ```ts
 * import { normalizeZ } from '@noble/curves/abstract/curve.js';
 * import { p256 } from '@noble/curves/nist.js';
 * const points = normalizeZ(p256.Point, [p256.Point.BASE, p256.Point.BASE.double()]);
 * ```
 */
export function normalizeZ<P extends CurvePoint<any, P>, PC extends CurvePointCons<P>>(
  c: PC,
  points: P[]
): P[] {
  const invertedZs = FpInvertBatch(
    c.Fp,
    points.map((p) => p.Z!)
  );
  return points.map((p, i) => c.fromAffine(p.toAffine(invertedZs[i])));
}

function validateW(W: number, bits: number) {
  if (!Number.isSafeInteger(W) || W <= 0 || W > bits)
    throw new Error('invalid window size, expected [1..' + bits + '], got W=' + W);
}

/** Internal wNAF opts for specific W and scalarBits.
 * Zero digits are skipped, so tables store only the positive half-window and callers reserve one
 * extra carry window.
 */
type WOpts = {
  windows: number;
  windowSize: number;
  mask: bigint;
  maxNumber: number;
  shiftBy: bigint;
};

function calcWOpts(W: number, scalarBits: number): WOpts {
  validateW(W, scalarBits);
  const windows = Math.ceil(scalarBits / W) + 1; // W=8 33. Not 32, because we skip zero
  const windowSize = 2 ** (W - 1); // W=8 128. Not 256, because we skip zero
  const maxNumber = 2 ** W; // W=8 256
  const mask = bitMask(W); // W=8 255 == mask 0b11111111
  const shiftBy = BigInt(W); // W=8 8
  return { windows, windowSize, mask, maxNumber, shiftBy };
}

function calcOffsets(n: bigint, window: number, wOpts: WOpts) {
  const { windowSize, mask, maxNumber, shiftBy } = wOpts;
  let wbits = Number(n & mask); // extract W bits.
  let nextN = n >> shiftBy; // shift number by W bits.

  // What actually happens here:
  // const highestBit = Number(mask ^ (mask >> 1n));
  // let wbits2 = wbits - 1; // skip zero
  // if (wbits2 & highestBit) { wbits2 ^= Number(mask); // (~);

  // split if bits > max: +224 => 256-32
  if (wbits > windowSize) {
    // we skip zero, which means instead of `>= size-1`, we do `> size`
    wbits -= maxNumber; // -32, can be maxNumber - wbits, but then we need to set isNeg here.
    nextN += _1n; // +256 (carry)
  }
  const offsetStart = window * windowSize;
  const offset = offsetStart + Math.abs(wbits) - 1; // -1 because we skip zero; ignore when isZero
  const isZero = wbits === 0; // is current window slice a 0?
  const isNeg = wbits < 0; // is current window slice negative?
  const isNegF = window % 2 !== 0; // fake branch noise only
  const offsetF = offsetStart; // fake branch noise only
  return { nextN, offset, isZero, isNeg, isNegF, offsetF };
}

function validateMSMPoints(points: any[], c: any) {
  if (!Array.isArray(points)) throw new Error('array expected');
  points.forEach((p, i) => {
    if (!(p instanceof c)) throw new Error('invalid point at index ' + i);
  });
}
function validateMSMScalars(scalars: any[], field: any) {
  if (!Array.isArray(scalars)) throw new Error('array of scalars expected');
  scalars.forEach((s, i) => {
    if (!field.isValid(s)) throw new Error('invalid scalar at index ' + i);
  });
}

// Since points in different groups cannot be equal (different object constructor),
// we can have single place to store precomputes.
// Allows to make points frozen / immutable.
const pointPrecomputes = new WeakMap<any, any[]>();
const pointWindowSizes = new WeakMap<any, number>();

function getW(P: any): number {
  // To disable precomputes:
  // return 1;
  // `1` is also the uncached sentinel: use the ladder / non-precomputed path.
  return pointWindowSizes.get(P) || 1;
}

function assert0(n: bigint): void {
  // Internal invariant: a non-zero remainder here means the wNAF window decomposition or loop
  // count is inconsistent, not that the original caller provided a bad scalar.
  if (n !== _0n) throw new Error('invalid wNAF');
}

/**
 * Elliptic curve multiplication of Point by scalar. Fragile.
 * Table generation takes **30MB of ram and 10ms on high-end CPU**,
 * but may take much longer on slow devices. Actual generation will happen on
 * first call of `multiply()`. By default, `BASE` point is precomputed.
 *
 * Scalars should always be less than curve order: this should be checked inside of a curve itself.
 * Creates precomputation tables for fast multiplication:
 * - private scalar is split by fixed size windows of W bits
 * - every window point is collected from window's table & added to accumulator
 * - since windows are different, same point inside tables won't be accessed more than once per calc
 * - each multiplication is 'Math.ceil(CURVE_ORDER / 𝑊) + 1' point additions (fixed for any scalar)
 * - +1 window is neccessary for wNAF
 * - wNAF reduces table size: 2x less memory + 2x faster generation, but 10% slower multiplication
 *
 * TODO: research returning a 2d JS array of windows instead of a single window.
 * This would allow windows to be in different memory locations.
 * @param Point - Point constructor.
 * @param bits - Scalar bit length.
 * @example
 * Elliptic curve multiplication of Point by scalar.
 *
 * ```ts
 * import { wNAF } from '@noble/curves/abstract/curve.js';
 * import { p256 } from '@noble/curves/nist.js';
 * const ladder = new wNAF(p256.Point, p256.Point.Fn.BITS);
 * ```
 */
export class wNAF<PC extends PC_ANY> {
  private readonly BASE: PC_P<PC>;
  private readonly ZERO: PC_P<PC>;
  private readonly Fn: PC['Fn'];
  readonly bits: number;

  // Parametrized with a given Point class (not individual point)
  constructor(Point: PC, bits: number) {
    this.BASE = Point.BASE;
    this.ZERO = Point.ZERO;
    this.Fn = Point.Fn;
    this.bits = bits;
  }

  // non-const time multiplication ladder
  _unsafeLadder(elm: PC_P<PC>, n: bigint, p: PC_P<PC> = this.ZERO): PC_P<PC> {
    let d: PC_P<PC> = elm;
    while (n > _0n) {
      if (n & _1n) p = p.add(d);
      d = d.double();
      n >>= _1n;
    }
    return p;
  }

  /**
   * Creates a wNAF precomputation window. Used for caching.
   * Default window size is set by `utils.precompute()` and is equal to 8.
   * Number of precomputed points depends on the curve size:
   * 2^(𝑊−1) * (Math.ceil(𝑛 / 𝑊) + 1), where:
   * - 𝑊 is the window size
   * - 𝑛 is the bitlength of the curve order.
   * For a 256-bit curve and window size 8, the number of precomputed points is 128 * 33 = 4224.
   * @param point - Point instance
   * @param W - window size
   * @returns precomputed point tables flattened to a single array
   */
  private precomputeWindow(point: PC_P<PC>, W: number): PC_P<PC>[] {
    const { windows, windowSize } = calcWOpts(W, this.bits);
    const points: PC_P<PC>[] = [];
    let p: PC_P<PC> = point;
    let base = p;
    for (let window = 0; window < windows; window++) {
      base = p;
      points.push(base);
      // i=1, bc we skip 0
      for (let i = 1; i < windowSize; i++) {
        base = base.add(p);
        points.push(base);
      }
      p = base.double();
    }
    return points;
  }

  /**
   * Implements ec multiplication using precomputed tables and w-ary non-adjacent form.
   * More compact implementation:
   * https://github.com/paulmillr/noble-secp256k1/blob/47cb1669b6e506ad66b35fe7d76132ae97465da2/index.ts#L502-L541
   * @returns real and fake (for const-time) points
   */
  private wNAF(W: number, precomputes: PC_P<PC>[], n: bigint): { p: PC_P<PC>; f: PC_P<PC> } {
    // Scalar should be smaller than field order
    if (!this.Fn.isValid(n)) throw new Error('invalid scalar');
    // Accumulators
    let p = this.ZERO;
    let f = this.BASE;
    // This code was first written with assumption that 'f' and 'p' will never be infinity point:
    // since each addition is multiplied by 2 ** W, it cannot cancel each other. However,
    // there is negate now: it is possible that negated element from low value
    // would be the same as high element, which will create carry into next window.
    // It's not obvious how this can fail, but still worth investigating later.
    const wo = calcWOpts(W, this.bits);
    for (let window = 0; window < wo.windows; window++) {
      // (n === _0n) is handled and not early-exited. isEven and offsetF are used for noise
      const { nextN, offset, isZero, isNeg, isNegF, offsetF } = calcOffsets(n, window, wo);
      n = nextN;
      if (isZero) {
        // bits are 0: add garbage to fake point
        // Important part for const-time getPublicKey: add random "noise" point to f.
        f = f.add(negateCt(isNegF, precomputes[offsetF]));
      } else {
        // bits are 1: add to result point
        p = p.add(negateCt(isNeg, precomputes[offset]));
      }
    }
    assert0(n);
    // Return both real and fake points so JIT keeps the noise path alive.
    // Known caveat: negate/carry interactions can still drive `f` to infinity even when `p` is not,
    // which weakens the noise path and leaves this only "less const-time" by about one bigint mul.
    return { p, f };
  }

  /**
   * Implements unsafe EC multiplication using precomputed tables
   * and w-ary non-adjacent form.
   * @param acc - accumulator point to add result of multiplication
   * @returns point
   */
  private wNAFUnsafe(
    W: number,
    precomputes: PC_P<PC>[],
    n: bigint,
    acc: PC_P<PC> = this.ZERO
  ): PC_P<PC> {
    const wo = calcWOpts(W, this.bits);
    for (let window = 0; window < wo.windows; window++) {
      if (n === _0n) break; // Early-exit, skip 0 value
      const { nextN, offset, isZero, isNeg } = calcOffsets(n, window, wo);
      n = nextN;
      if (isZero) {
        // Window bits are 0: skip processing.
        // Move to next window.
        continue;
      } else {
        const item = precomputes[offset];
        acc = acc.add(isNeg ? item.negate() : item); // Re-using acc allows to save adds in MSM
      }
    }
    assert0(n);
    return acc;
  }

  private getPrecomputes(W: number, point: PC_P<PC>, transform?: Mapper<PC_P<PC>>): PC_P<PC>[] {
    // Cache key is only point identity plus the remembered window size; callers must not reuse the
    // same point with incompatible `transform(...)` layouts and expect a separate cache entry.
    let comp = pointPrecomputes.get(point);
    if (!comp) {
      comp = this.precomputeWindow(point, W) as PC_P<PC>[];
      if (W !== 1) {
        // Doing transform outside of if brings 15% perf hit
        if (typeof transform === 'function') comp = transform(comp);
        pointPrecomputes.set(point, comp);
      }
    }
    return comp;
  }

  cached(
    point: PC_P<PC>,
    scalar: bigint,
    transform?: Mapper<PC_P<PC>>
  ): { p: PC_P<PC>; f: PC_P<PC> } {
    const W = getW(point);
    return this.wNAF(W, this.getPrecomputes(W, point, transform), scalar);
  }

  unsafe(point: PC_P<PC>, scalar: bigint, transform?: Mapper<PC_P<PC>>, prev?: PC_P<PC>): PC_P<PC> {
    const W = getW(point);
    if (W === 1) return this._unsafeLadder(point, scalar, prev); // For W=1 ladder is ~x2 faster
    return this.wNAFUnsafe(W, this.getPrecomputes(W, point, transform), scalar, prev);
  }

  // We calculate precomputes for elliptic curve point multiplication
  // using windowed method. This specifies window size and
  // stores precomputed values. Usually only base point would be precomputed.
  createCache(P: PC_P<PC>, W: number): void {
    validateW(W, this.bits);
    pointWindowSizes.set(P, W);
    pointPrecomputes.delete(P);
  }

  hasCache(elm: PC_P<PC>): boolean {
    return getW(elm) !== 1;
  }
}

/**
 * Endomorphism-specific multiplication for Koblitz curves.
 * Cost: 128 dbl, 0-256 adds.
 * @param Point - Point constructor.
 * @param point - Input point.
 * @param k1 - First non-negative absolute scalar chunk.
 * @param k2 - Second non-negative absolute scalar chunk.
 * @returns Partial multiplication results.
 * @example
 * Endomorphism-specific multiplication for Koblitz curves.
 *
 * ```ts
 * import { mulEndoUnsafe } from '@noble/curves/abstract/curve.js';
 * import { secp256k1 } from '@noble/curves/secp256k1.js';
 * const parts = mulEndoUnsafe(secp256k1.Point, secp256k1.Point.BASE, 3n, 5n);
 * ```
 */
export function mulEndoUnsafe<P extends CurvePoint<any, P>, PC extends CurvePointCons<P>>(
  Point: PC,
  point: P,
  k1: bigint,
  k2: bigint
): { p1: P; p2: P } {
  let acc = point;
  let p1 = Point.ZERO;
  let p2 = Point.ZERO;
  while (k1 > _0n || k2 > _0n) {
    if (k1 & _1n) p1 = p1.add(acc);
    if (k2 & _1n) p2 = p2.add(acc);
    acc = acc.double();
    k1 >>= _1n;
    k2 >>= _1n;
  }
  return { p1, p2 };
}

/**
 * Pippenger algorithm for multi-scalar multiplication (MSM, Pa + Qb + Rc + ...).
 * 30x faster vs naive addition on L=4096, 10x faster than precomputes.
 * For N=254bit, L=1, it does: 1024 ADD + 254 DBL. For L=5: 1536 ADD + 254 DBL.
 * Algorithmically constant-time (for same L), even when 1 point + scalar, or when scalar = 0.
 * @param c - Curve Point constructor
 * @param points - array of L curve points
 * @param scalars - array of L scalars (aka secret keys / bigints)
 * @returns MSM result point. Empty input is accepted and returns the identity.
 * @throws If the point set, scalar set, or MSM sizing is invalid. {@link Error}
 * @example
 * Pippenger algorithm for multi-scalar multiplication (MSM, Pa + Qb + Rc + ...).
 *
 * ```ts
 * import { pippenger } from '@noble/curves/abstract/curve.js';
 * import { p256 } from '@noble/curves/nist.js';
 * const point = pippenger(p256.Point, [p256.Point.BASE, p256.Point.BASE.double()], [2n, 3n]);
 * ```
 */
export function pippenger<P extends CurvePoint<any, P>, PC extends CurvePointCons<P>>(
  c: PC,
  points: P[],
  scalars: bigint[]
): P {
  // If we split scalars by some window (let's say 8 bits), every chunk will only
  // take 256 buckets even if there are 4096 scalars, also re-uses double.
  // TODO:
  // - https://eprint.iacr.org/2024/750.pdf
  // - https://tches.iacr.org/index.php/TCHES/article/view/10287
  // 0 is accepted in scalars
  const fieldN = c.Fn;
  validateMSMPoints(points, c);
  validateMSMScalars(scalars, fieldN);
  const plength = points.length;
  const slength = scalars.length;
  if (plength !== slength) throw new Error('arrays of points and scalars must have equal length');
  // if (plength === 0) throw new Error('array must be of length >= 2');
  const zero = c.ZERO;
  const wbits = bitLen(BigInt(plength));
  let windowSize = 1; // bits
  if (wbits > 12) windowSize = wbits - 3;
  else if (wbits > 4) windowSize = wbits - 2;
  else if (wbits > 0) windowSize = 2;
  const MASK = bitMask(windowSize);
  const buckets = new Array(Number(MASK) + 1).fill(zero); // +1 for zero array
  const lastBits = Math.floor((fieldN.BITS - 1) / windowSize) * windowSize;
  let sum = zero;
  for (let i = lastBits; i >= 0; i -= windowSize) {
    buckets.fill(zero);
    for (let j = 0; j < slength; j++) {
      const scalar = scalars[j];
      const wbits = Number((scalar >> BigInt(i)) & MASK);
      buckets[wbits] = buckets[wbits].add(points[j]);
    }
    let resI = zero; // not using this will do small speed-up, but will lose ct
    // Skip first bucket, because it is zero
    for (let j = buckets.length - 1, sumI = zero; j > 0; j--) {
      sumI = sumI.add(buckets[j]);
      resI = resI.add(sumI);
    }
    sum = sum.add(resI);
    if (i !== 0) for (let j = 0; j < windowSize; j++) sum = sum.double();
  }
  return sum as P;
}
/**
 * Precomputed multi-scalar multiplication (MSM, Pa + Qb + Rc + ...).
 * @param c - Curve Point constructor
 * @param points - array of L curve points
 * @param windowSize - Precompute window size.
 * @returns Function which multiplies points with scalars. The closure accepts
 *   `scalars.length <= points.length`, and omitted trailing scalars are treated as zero.
 * @throws If the point set or precompute window is invalid. {@link Error}
 * @example
 * Precomputed multi-scalar multiplication (MSM, Pa + Qb + Rc + ...).
 *
 * ```ts
 * import { precomputeMSMUnsafe } from '@noble/curves/abstract/curve.js';
 * import { p256 } from '@noble/curves/nist.js';
 * const msm = precomputeMSMUnsafe(p256.Point, [p256.Point.BASE], 4);
 * const point = msm([3n]);
 * ```
 */
export function precomputeMSMUnsafe<P extends CurvePoint<any, P>, PC extends CurvePointCons<P>>(
  c: PC,
  points: P[],
  windowSize: number
): (scalars: bigint[]) => P {
  /**
   * Performance Analysis of Window-based Precomputation
   *
   * Base Case (256-bit scalar, 8-bit window):
   * - Standard precomputation requires:
   *   - 31 additions per scalar × 256 scalars = 7,936 ops
   *   - Plus 255 summary additions = 8,191 total ops
   *   Note: Summary additions can be optimized via accumulator
   *
   * Chunked Precomputation Analysis:
   * - Using 32 chunks requires:
   *   - 255 additions per chunk
   *   - 256 doublings
   *   - Total: (255 × 32) + 256 = 8,416 ops
   *
   * Memory Usage Comparison:
   * Window Size | Standard Points | Chunked Points
   * ------------|-----------------|---------------
   *     4-bit   |     520         |      15
   *     8-bit   |    4,224        |     255
   *    10-bit   |   13,824        |   1,023
   *    16-bit   |  557,056        |  65,535
   *
   * Key Advantages:
   * 1. Enables larger window sizes due to reduced memory overhead
   * 2. More efficient for smaller scalar counts:
   *    - 16 chunks: (16 × 255) + 256 = 4,336 ops
   *    - ~2x faster than standard 8,191 ops
   *
   * Limitations:
   * - Not suitable for plain precomputes (requires 256 constant doublings)
   * - Performance degrades with larger scalar counts:
   *   - Optimal for ~256 scalars
   *   - Less efficient for 4096+ scalars (Pippenger preferred)
   */
  const fieldN = c.Fn;
  validateW(windowSize, fieldN.BITS);
  validateMSMPoints(points, c);
  const zero = c.ZERO;
  const tableSize = 2 ** windowSize - 1; // table size (without zero)
  const chunks = Math.ceil(fieldN.BITS / windowSize); // chunks of item
  const MASK = bitMask(windowSize);
  const tables = points.map((p: P) => {
    const res = [];
    for (let i = 0, acc = p; i < tableSize; i++) {
      res.push(acc);
      acc = acc.add(p);
    }
    return res;
  });
  return (scalars: bigint[]): P => {
    validateMSMScalars(scalars, fieldN);
    if (scalars.length > points.length)
      throw new Error('array of scalars must be smaller than array of points');
    let res = zero;
    for (let i = 0; i < chunks; i++) {
      // No need to double if accumulator is still zero.
      if (res !== zero) for (let j = 0; j < windowSize; j++) res = res.double();
      const shiftBy = BigInt(chunks * windowSize - (i + 1) * windowSize);
      for (let j = 0; j < scalars.length; j++) {
        const n = scalars[j];
        const curr = Number((n >> shiftBy) & MASK);
        if (!curr) continue; // skip zero scalars chunks
        res = res.add(tables[j][curr - 1]);
      }
    }
    return res;
  };
}

/** Minimal curve parameters needed to construct a Weierstrass or Edwards curve. */
export type ValidCurveParams<T> = {
  /** Base-field modulus. */
  p: bigint;
  /** Prime subgroup order. */
  n: bigint;
  /** Cofactor. */
  h: bigint;
  /** Curve parameter `a`. */
  a: T;
  /** Weierstrass curve parameter `b`. */
  b?: T;
  /** Edwards curve parameter `d`. */
  d?: T;
  /** Generator x coordinate. */
  Gx: T;
  /** Generator y coordinate. */
  Gy: T;
};

function createField<T>(order: bigint, field?: TArg<IField<T>>, isLE?: boolean): TRet<IField<T>> {
  if (field) {
    // Reuse supplied field overrides as-is; `isLE` only affects freshly constructed fallback
    // fields, and validateField() below only checks the arithmetic subset, not full byte/cmov
    // behavior.
    if (field.ORDER !== order) throw new Error('Field.ORDER must match order: Fp == p, Fn == n');
    validateField(field);
    return field as TRet<IField<T>>;
  } else {
    return Field(order, { isLE }) as unknown as TRet<IField<T>>;
  }
}
/** Pair of fields used by curve constructors. */
export type FpFn<T> = {
  /** Base field used for curve coordinates. */
  Fp: IField<T>;
  /** Scalar field used for secret scalars and subgroup arithmetic. */
  Fn: IField<bigint>;
};

/**
 * Validates basic CURVE shape and field membership, then creates fields.
 * This does not prove that the generator is on-curve, that subgroup/order data are consistent, or
 * that the curve equation itself is otherwise sane.
 * @param type - Curve family.
 * @param CURVE - Curve parameters.
 * @param curveOpts - Optional field overrides:
 *   - `Fp` (optional): Optional base-field override.
 *   - `Fn` (optional): Optional scalar-field override.
 * @param FpFnLE - Whether field encoding is little-endian.
 * @returns Frozen curve parameters and fields.
 * @throws If the curve parameters or field overrides are invalid. {@link Error}
 * @example
 * Build curve fields from raw constants before constructing a curve instance.
 *
 * ```ts
 * const curve = createCurveFields('weierstrass', {
 *   p: 17n,
 *   n: 19n,
 *   h: 1n,
 *   a: 2n,
 *   b: 2n,
 *   Gx: 5n,
 *   Gy: 1n,
 * });
 * ```
 */
export function createCurveFields<T>(
  type: 'weierstrass' | 'edwards',
  CURVE: ValidCurveParams<T>,
  curveOpts: TArg<Partial<FpFn<T>>> = {},
  FpFnLE?: boolean
): TRet<FpFn<T> & { CURVE: ValidCurveParams<T> }> {
  if (FpFnLE === undefined) FpFnLE = type === 'edwards';
  if (!CURVE || typeof CURVE !== 'object') throw new Error(`expected valid ${type} CURVE object`);
  for (const p of ['p', 'n', 'h'] as const) {
    const val = CURVE[p];
    if (!(typeof val === 'bigint' && val > _0n))
      throw new Error(`CURVE.${p} must be positive bigint`);
  }
  const Fp = createField(CURVE.p, curveOpts.Fp, FpFnLE);
  const Fn = createField(CURVE.n, curveOpts.Fn, FpFnLE);
  const _b: 'b' | 'd' = type === 'weierstrass' ? 'b' : 'd';
  const params = ['Gx', 'Gy', 'a', _b] as const;
  for (const p of params) {
    // @ts-ignore
    if (!Fp.isValid(CURVE[p]))
      throw new Error(`CURVE.${p} must be valid field element of CURVE.Fp`);
  }
  CURVE = Object.freeze(Object.assign({}, CURVE));
  return { CURVE, Fp, Fn } as TRet<FpFn<T> & { CURVE: ValidCurveParams<T> }>;
}

type KeygenFn = (
  seed?: Uint8Array,
  isCompressed?: boolean
) => { secretKey: Uint8Array; publicKey: Uint8Array };
/**
 * @param randomSecretKey - Secret-key generator.
 * @param getPublicKey - Public-key derivation helper.
 * @returns Keypair generator.
 * @example
 * Build a `keygen()` helper from existing secret-key and public-key primitives.
 *
 * ```ts
 * import { createKeygen } from '@noble/curves/abstract/curve.js';
 * import { p256 } from '@noble/curves/nist.js';
 * const keygen = createKeygen(p256.utils.randomSecretKey, p256.getPublicKey);
 * const pair = keygen();
 * ```
 */
export function createKeygen(
  randomSecretKey: Function,
  getPublicKey: TArg<Signer['getPublicKey']>
): TRet<KeygenFn> {
  return function keygen(seed?: TArg<Uint8Array>) {
    const secretKey = randomSecretKey(seed) as TRet<Uint8Array>;
    return { secretKey, publicKey: getPublicKey(secretKey) as TRet<Uint8Array> };
  };
}
