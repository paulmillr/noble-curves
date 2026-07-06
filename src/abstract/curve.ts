/**
 * Methods for elliptic curve multiplication by scalars.
 * Contains wNAF-based ScalarMultiplier, pippenger.
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import {
  aarray,
  abool,
  afunction,
  aobject,
  bitLen,
  bitMask,
  bytesToNumberBE,
  inRange,
  isPosBig,
  validateObject,
  type Signer,
  type TArg,
  type TRet,
} from '../utils.ts';
import { Field, FpInvertBatch, validateField, type IField } from './modular.ts';

const _0n = /* @__PURE__ */ BigInt(0);
const _1n = /* @__PURE__ */ BigInt(1);
const _4n = /* @__PURE__ */ BigInt(4);
const BLIND_BYTES = 16;
const BLIND_BITS = 8 * BLIND_BYTES;
// Fixed-window width for the constant-time multiply of un-precomputed points (W===1).
// A flat 2^FW_WINDOW table has a small, scalar-independent build cost that amortizes over a single
// multiply, unlike the larger per-point wNAF tables that only pay off when cached.
const FW_WINDOW = 5;
// Precompute tables are capped at ~2 GiB of estimated heap. Rejecting larger windows up front
// turns a typo'd window size into an immediate error instead of a multi-GB allocation (or an
// effective hang) when the lazy table is built on first multiply.
const TABLE_BYTES_MAX = 2 ** 31;

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
   * Massively speeds up `p.multiply(n)` by using precompute tables (caching). See {@link ScalarMultiplier}.
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
  if (typeof (pc as unknown) !== 'function')
    throw new TypeError('"Point" expected constructor, got type=' + typeof Point);
  afunction(pc.fromAffine, 'Point.fromAffine');
  afunction(pc.fromBytes, 'Point.fromBytes');
  afunction(pc.fromHex, 'Point.fromHex');
  // Generic helpers (ScalarMultiplier, normalizeZ, MSM) dereference BASE / ZERO:
  // fail here with a typed error instead of an `undefined` access later.
  aobject(pc.BASE, 'Point.BASE');
  aobject(pc.ZERO, 'Point.ZERO');
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
 * Takes a bunch of Projective Points but executes only one
 * inversion on all of them. Inversion is very slow operation,
 * so this improves performance massively.
 * Optimization: converts a list of projective points to a list of identical points with Z=1.
 * Input points are left unchanged; the normalized points are returned as fresh instances.
 * @param c - Point constructor.
 * @param points - Projective points.
 * @returns Fresh projective points reconstructed from normalized affine coordinates.
 * @throws If a documented runtime validation or state check fails. {@link Error}
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
  // Match MSM helpers: reject malformed public inputs before reading projective internals.
  validatePointCons(c);
  validateMSMPoints(points, c);
  // Identity points (Z=0) rely on an implicit contract: FpInvertBatch without `passZero`
  // yields `undefined` for zero inputs, and `toAffine(undefined)` falls back to its internal
  // is0 handling instead of using the batch inverse.
  const invertedZs = FpInvertBatch(
    c.Fp,
    points.map((p) => p.Z!)
  );
  return points.map((p, i) => c.fromAffine(p.toAffine(invertedZs[i])));
}

function validateW(W: number, bits: number, min: number = 1) {
  if (!Number.isSafeInteger(W) || W < min || W > bits)
    throw new Error('invalid window size, expected [' + min + '..' + bits + '], got W=' + W);
}

// Rough per-point heap estimate for the {@link TABLE_BYTES_MAX} cap: up to 4 projective/extended
// coordinates of Fp.BYTES each, plus bigint/object overhead. Callers pass the point count of the
// largest table the checked parameters can produce.
function validateTableBytes(numPoints: number, fpBytes: number): void {
  const bytes = numPoints * (4 * fpBytes + 128);
  if (bytes > TABLE_BYTES_MAX)
    throw new Error(
      'invalid window size: table would need ~' +
        Math.ceil(bytes / 2 ** 20) +
        ' MiB, max ' +
        TABLE_BYTES_MAX / 2 ** 20 +
        ' MiB'
    );
}

/** RNG interface used for scalar / nonce blinding. */
export type RandomBytes = (bytesLength?: number) => TRet<Uint8Array>;

/**
 * Probes an RNG once, at construction time: returns `undefined` when it is unavailable —
 * throws or returns malformed bytes — so callers can downgrade to their unblinded /
 * deterministic constant-time fallback. Blinding is defense-in-depth (DPA/template
 * hardening), not a correctness or key-secrecy requirement, so availability-based
 * downgrade is acceptable.
 *
 * The downgrade decision is deliberately static. After a successful probe the RNG becomes
 * part of the trusted contract: later misbehavior must fail closed in per-call validation
 * (throw), never downgrade — a dynamic fallback would let a tampered RNG silently strip
 * blinding on demand. A probe can only ever classify broken environments, not adversarial
 * RNGs: a stateful RNG can always behave while probed and misbehave later.
 */
export function probeRandomBytes(
  randomBytes: RandomBytes | undefined,
  length: number
): RandomBytes | undefined {
  if (randomBytes === undefined) return undefined;
  afunction(randomBytes, 'randomBytes');
  try {
    const probe = randomBytes(length);
    if (!(probe instanceof Uint8Array) || probe.length !== length) return undefined;
  } catch {
    return undefined;
  }
  return randomBytes;
}

function validateMSMPoints(points: any[], c: any) {
  aarray(points, 'points');
  points.forEach((p, i) => {
    if (!(p instanceof c)) throw new Error('invalid point at index ' + i);
  });
}
// Default bound is field membership (0 <= s < field.ORDER); a `maxScalar` override widens it
// to 0 <= s < maxScalar for callers that accept oversized scalars.
function validateMSMScalars(scalars: any[], field: any, maxScalar?: bigint) {
  if (!Array.isArray(scalars)) throw new Error('array of scalars expected');
  scalars.forEach((s, i) => {
    const ok = maxScalar === undefined ? field.isValid(s) : isPosBig(s) && s < maxScalar;
    if (!ok) throw new Error('invalid scalar at index ' + i);
  });
}

// Since points in different groups cannot be equal (different object constructor),
// we can have single place to store window sizes.
// Allows to make points frozen / immutable.
type WnafPrecomputeEntry<T> = { W: number; bits: number; windows: number; comp: T[] };
/** Result of a constant-time multiply: real point `p`, fake accumulator `f` (discarded). */
type MulResult<P> = { p: P; f: P };
const pointWindowSizes = new WeakMap<any, number>();

function getWindowSize(P: any): number {
  // `1` is the uncached sentinel: use the non-precomputed (wNAF / fixed-window) path.
  return pointWindowSizes.get(P) || 1;
}

/** Table of odd multiples [1P, 3P, ..., (2⋅size−1)P]; width-W wNAF uses size = 2^(W−2). */
function oddMultiples<P extends { double(): P; add(other: P): P }>(p: P, size: number): P[] {
  const dbl = p.double();
  const t = [p];
  for (let j = 1; j < size; j++) t.push(t[j - 1].add(dbl));
  return t;
}

/**
 * Width-W wNAF signed-digit recoding (W >= 2), LSB-first: digits are 0 or odd with
 * |digit| < 2^(W−1); nonzero density ~1/(W+1) (a nonzero digit is followed by W−1 zeros).
 */
function wnafDigits(n: bigint, W: number): number[] {
  const size = 2 ** W;
  const half = size / 2;
  const mask = BigInt(size - 1);
  const d: number[] = [];
  while (n > _0n) {
    let w = 0;
    if (n & _1n) {
      w = Number(n & mask); // n mod 2^W, odd
      if (w >= half) w -= size; // signed residue
      n -= BigInt(w); // n - w ≡ 0 mod 2^W: next W−1 digits are zero
    }
    d.push(w);
    n >>= _1n;
  }
  return d;
}

/**
 * Fixed-position signed-window recoding for precomputed wNAF: `n = Σ digits[w]⋅2^(w⋅W)` with
 * digits in `[−2^(W−1)+1, 2^(W−1)]`. Digit count is fixed by `windows` (callers reserve one
 * extra window for the final carry), so recoding length does not depend on the scalar.
 */
function signedWindowDigits(n: bigint, W: number, windows: number): number[] {
  const size = 2 ** W;
  const half = size / 2;
  const mask = BigInt(size - 1);
  const shiftBy = BigInt(W);
  const d: number[] = [];
  for (let w = 0; w < windows; w++) {
    let v = Number(n & mask);
    n >>= shiftBy;
    if (v > half) {
      v -= size; // negative digit, carry into the next window
      n += _1n;
    }
    d.push(v);
  }
  // Internal invariant: leftover bits mean the window count did not cover the scalar.
  if (n !== _0n) throw new Error('invalid wnaf');
  return d;
}

/**
 * Shared vartime walk over per-scalar wNAF digit streams: one doubling of a single shared
 * accumulator per bit position of the longest recoding, one signed table addition per
 * nonzero digit. `tables[i]` must hold the odd multiples of the i-th point.
 */
function wnafWalk<P extends { double(): P; add(other: P): P; negate(): P }>(
  zero: P,
  tables: P[][],
  digits: number[][]
): P {
  let max = 0;
  for (const d of digits) max = Math.max(max, d.length);
  let acc = zero;
  for (let bit = max - 1; bit >= 0; bit--) {
    if (bit !== max - 1) acc = acc.double();
    for (let i = 0; i < digits.length; i++) {
      const w = digits[i][bit]; // reads past shorter recodings yield undefined, skipped below
      if (w) {
        const item = tables[i][(Math.abs(w) - 1) >> 1];
        acc = acc.add(w < 0 ? item.negate() : item);
      }
    }
  }
  return acc;
}

/**
 * Elliptic curve multiplication of Point by scalar.
 * Routes between cached-table, fixed-window, and one-shot wNAF paths; entry points validate
 * their own scalars (`mulCT`/`mulCTBlinded`: `1 <= s < Fn.ORDER`; `mulUnsafe`: up to the
 * `Fn.ORDER^4` DoS cap via {@link mulAddUnsafe}).
 * Table generation is expensive and happens on first call of `multiply()`
 * (or eagerly via `precompute(W, false)`). By default, `BASE` point is precomputed.
 *
 * Cached algorithm is signed fixed-window wNAF:
 * - table stores, for every window w, the multiples `[1..2^(W−1)]⋅2^(w⋅W)⋅P` — all doublings
 *   are baked in, so a multiplication is exactly one table addition per window
 * - window count is fixed (`ceil(bits/W) + 1`), so the point-operation count is scalar-independent
 *   (basis of the constant-time path)
 * - for a 256-bit curve and W=6: 44⋅32 = 1408 table points, 44 additions per multiply
 * - secret scalars are additionally blinded (see {@link ScalarMultiplier.mulCTBlinded}), which
 *   widens tables by 128 bits
 * @param Point - Point constructor.
 * @param randomBytes - RNG used for scalar blinding; required by the blinded secret path.
 * @example
 * Elliptic curve multiplication of Point by scalar.
 *
 * ```ts
 * import { ScalarMultiplier } from '@noble/curves/abstract/curve.js';
 * import { p256 } from '@noble/curves/nist.js';
 * const mul = new ScalarMultiplier(p256.Point);
 * ```
 */
export class ScalarMultiplier<PC extends PC_ANY> {
  private readonly Point: PC;
  private readonly BASE: PC_P<PC>;
  private readonly ZERO: PC_P<PC>;
  private readonly randomBytes?: RandomBytes;
  private readonly wnafPrecomputes = new WeakMap<PC_P<PC>, WnafPrecomputeEntry<PC_P<PC>>[]>();
  private baseCanBeBlinded: boolean | undefined;
  readonly bits: number;

  // Parametrized with a given Point class (not individual point)
  constructor(Point: PC, randomBytes?: RandomBytes) {
    validatePointCons(Point);
    // Probe the RNG once (see {@link probeRandomBytes}): in environments without working
    // randomness (e.g. no WebCrypto), shouldBlind() then routes secret multiplication to the
    // unblinded constant-time path instead of throwing on every multiply(). The shape of
    // returned bytes is still validated on every blinded call, where breakage fails closed.
    this.randomBytes = probeRandomBytes(randomBytes, BLIND_BYTES);
    this.Point = Point;
    this.BASE = Point.BASE;
    this.ZERO = Point.ZERO;
    this.bits = Point.Fn.BITS;
  }

  /**
   * Creates a signed fixed-window wNAF precomputation table: for every window w, the
   * multiples `[1..2^(W−1)]⋅2^(w⋅W)⋅P`, flattened. All doublings are baked into the table,
   * so cached multiplication is additions-only. `windows = ceil(bits/W) + 1`: the extra
   * window absorbs the final carry of signed-digit recoding.
   * For a 256-bit curve and W=6, the table is 44⋅32 = 1408 points.
   * @param point - Point instance
   * @param W - window size
   * @param bits - scalar bitlength the table must cover
   */
  private buildWnafTable(point: PC_P<PC>, W: number, bits: number): WnafPrecomputeEntry<PC_P<PC>> {
    // W needs no re-validation: its only source is setWindowSize(), which enforces
    // 1 <= W <= Fn.BITS <= bits (the blinded path only ever widens bits) and caps the
    // resulting table at ~2 GiB (sized against the wider blinded layout).
    const windows = Math.ceil(bits / W) + 1;
    const half = 2 ** (W - 1);
    const comp: PC_P<PC>[] = [];
    let base = point;
    for (let w = 0; w < windows; w++) {
      let acc = base;
      for (let i = 0; i < half; i++) {
        comp.push(acc);
        acc = acc.add(base);
      }
      base = comp[comp.length - 1].double(); // 2⋅(2^(W−1)⋅base) = next window's base
    }
    return { W, bits, windows, comp };
  }

  /**
   * Implements ec multiplication using precomputed signed fixed-window wNAF tables.
   * Constant-time: fixed window count with one table addition per window — zero digits feed
   * the fake accumulator — and no doublings; the lookup scans the whole window slice.
   * Scalar bounds are validated by the public entry points ({@link ScalarMultiplier.mulCT},
   * {@link ScalarMultiplier.mulCTBlinded}, {@link ScalarMultiplier.mulUnsafe});
   * signedWindowDigits throws if `n` exceeds the table.
   * @returns real and fake (for const-time) points
   */
  private wnafCachedCT(precomputes: WnafPrecomputeEntry<PC_P<PC>>, n: bigint): MulResult<PC_P<PC>> {
    const { W, windows, comp } = precomputes;
    const half = 2 ** (W - 1);
    const digits = signedWindowDigits(n, W, windows);
    let p = this.ZERO;
    let f = this.BASE;
    for (let w = 0; w < windows; w++) {
      const digit = digits[w];
      const start = w * half;
      // Data-oblivious select: touch every entry of the window before the digit branch.
      const idx = Math.abs(digit) - 1; // -1 for zero digits: matches nothing, `sel` unused
      let sel = comp[start];
      for (let i = 1; i < half; i++) sel = i === idx ? comp[start + i] : sel;
      const neg = sel.negate(); // compute both signs; the digit only picks one
      if (digit === 0) f = f.add(comp[start]);
      else p = p.add(digit < 0 ? neg : sel);
    }
    return { p, f };
  }

  // Cache key is point identity plus (W, bits); at most two entries exist per point (public-width
  // `Fn.BITS` and blinded `Fn.BITS + BLIND_BITS`). Callers must not reuse the same point with
  // incompatible `transform(...)` layouts and expect a separate cache entry.
  private getWnafPrecomputes(
    W: number,
    point: PC_P<PC>,
    bits: number,
    transform?: Mapper<PC_P<PC>>
  ): WnafPrecomputeEntry<PC_P<PC>> {
    let entries = this.wnafPrecomputes.get(point);
    let comp = entries?.find((entry) => entry.W === W && entry.bits === bits);
    if (!comp) {
      comp = this.buildWnafTable(point, W, bits);
      if (typeof transform === 'function') comp = { ...comp, comp: transform(comp.comp) };
      if (!entries) {
        entries = [];
        this.wnafPrecomputes.set(point, entries);
      }
      entries.push(comp);
    }
    return comp;
  }

  private assertPoint(point: PC_P<PC>): void {
    if (!(point instanceof this.Point))
      throw new TypeError('"point" expected Point instance, got type=' + typeof point);
  }

  // Shared prologue of the constant-time entry points. Rejects scalar 0: in key/signature-style
  // callers a zero scalar means broken upstream plumbing, and concrete Points already reject it.
  // Uses inRange instead of Fn.isValidNot0: validateField() only certifies the arithmetic subset.
  private validateMulInput(point: PC_P<PC>, scalar: bigint): void {
    this.assertPoint(point);
    if (!inRange(scalar, _1n, this.Point.Fn.ORDER)) throw new Error('invalid scalar');
  }

  // Constant-time dispatch shared by mulCT / mulCTBlinded. Un-precomputed points (W===1, e.g.
  // ECDH peer keys) skip building a throwaway cached table in favor of a small fixed-window
  // multiply. `n` must be < 2^bits.
  private runCT(
    point: PC_P<PC>,
    n: bigint,
    bits: number,
    transform?: Mapper<PC_P<PC>>
  ): MulResult<PC_P<PC>> {
    const W = getWindowSize(point);
    if (W === 1) return this.fixedWindowCT(point, n, bits);
    return this.wnafCachedCT(this.getWnafPrecomputes(W, point, bits, transform), n);
  }

  mulCT(point: PC_P<PC>, scalar: bigint, transform?: Mapper<PC_P<PC>>): MulResult<PC_P<PC>> {
    this.validateMulInput(point, scalar);
    return this.runCT(point, scalar, this.bits, transform);
  }

  mulCTBlinded(point: PC_P<PC>, scalar: bigint, transform?: Mapper<PC_P<PC>>): MulResult<PC_P<PC>> {
    this.validateMulInput(point, scalar);
    // Blinding computes n = scalar + blind*Fn.ORDER, then n*P via a constant-time multiply. This
    // equals scalar*P only when Fn.ORDER*P == O; callers guarantee that via shouldBlind() (always
    // for cofactor-1 curves; for cofactored curves only BASE, and only after checking BASE*n == O).
    // Fail before building the (large) precompute table if randomness is unavailable.
    if (this.randomBytes === undefined)
      throw new Error('randomBytes is required for scalar blinding');
    const bits = this.Point.Fn.BITS + BLIND_BITS;
    const blind = this.randomBytes(BLIND_BYTES);
    if (!(blind instanceof Uint8Array) || blind.length !== BLIND_BYTES)
      throw new Error('randomBytes returned invalid byte array');
    // Force the top two bits of the 128-bit blind to 10xxxxxx, so blind is in [2^127, 1.5*2^127):
    // * `| 0x80` (bit 127 = 1) is the load-bearing part: it guarantees blind >= 2^127, so the blind
    //   is always a full-width, nonzero factor and the scalar is masked even under a degenerate RNG.
    // * `& 0x3f` (bit 126 = 0) is a safety margin: it caps blind < 1.5*2^127, keeping
    //   blind*Fn.ORDER + scalar < 0.75*2^(nBits+128), i.e. ~half a window below the 2^(nBits+128)
    //   ceiling. Not strictly required for the bound (see below), but it reserves headroom so the
    //   guarantee does not rest on the tight `Fn.ORDER < 2^Fn.BITS` fact and the final carry window
    //   only ever holds a small carry, never a full digit.
    blind[0] = (blind[0] & 0x3f) | 0x80;
    // Even at the extreme (blind < 2^128, scalar < Fn.ORDER < 2^nBits): n <= 2^128*Fn.ORDER - 1 <
    // 2^(nBits+128), so n stays below 2^bits and within the blinded table's
    // window count. Both cached CT kernels run a fixed number of windows/rows with one point-add
    // each, so the add count is independent of scalar (constant-time).
    const n = scalar + bytesToNumberBE(blind) * this.Point.Fn.ORDER;
    return this.runCT(point, n, bits, transform);
  }

  /**
   * Constant-time multiplication `n*point` for an un-precomputed point, via a small fixed window.
   * A cached wNAF table only pays off when reused; a flat 2^FW_WINDOW table (`size-1` adds) is far cheaper
   * to build for a single use. The point-operation sequence is independent of `n`: build the table,
   * then per window exactly FW_WINDOW doublings, a data-oblivious scan over every table entry, and
   * one addition (adds the identity when the window digit is 0 — never skipped).
   *
   * `n` must be `< 2^bits`. Assumes complete addition (adding the identity costs the same
   * as any add), which holds for the Weierstrass/Edwards point types used here. The table is left in
   * projective form (no normalizeZ): normalizing this small a table costs more than the mixed-add
   * savings it would buy for a single multiply.
   * @returns real point `p`; `f` duplicates it only to match {@link wnafCachedCT}'s return shape (this
   * path needs no fake accumulator — its op-count is already scalar-independent).
   */
  private fixedWindowCT(point: PC_P<PC>, n: bigint, bits: number): MulResult<PC_P<PC>> {
    const W = FW_WINDOW;
    const size = 1 << W;
    const mask = bitMask(W);
    // Flat table [O, point, 2*point, ..., (size-1)*point].
    const table: PC_P<PC>[] = new Array(size);
    table[0] = this.ZERO;
    for (let i = 1; i < size; i++) table[i] = table[i - 1].add(point);
    // Horner MSB->LSB. windows*W >= bits and n < 2^bits, so every bit of n is consumed.
    const windows = Math.ceil(bits / W);
    let acc = this.ZERO;
    for (let window = windows - 1; window >= 0; window--) {
      // W doublings per window; skipped for the first (topmost) window, where acc is still the
      // identity. The skip is scalar-independent: it depends only on the loop index.
      if (window !== windows - 1) for (let d = 0; d < W; d++) acc = acc.double();
      const digit = Number((n >> BigInt(window * W)) & mask);
      // Data-oblivious select: touch every entry, same as wnafCachedCT.
      let sel = table[0];
      for (let i = 1; i < size; i++) sel = i === digit ? table[i] : sel;
      acc = acc.add(sel); // one add per window, even for digit 0
    }
    return { p: acc, f: acc };
  }

  private shouldBlind(point: PC_P<PC>, cofactor: bigint): boolean {
    // No usable RNG (probed in the constructor): blinding is impossible, use the plain CT path.
    if (this.randomBytes === undefined) return false;
    if (cofactor === _1n) return true;
    if (point !== this.BASE) return false;
    if (this.baseCanBeBlinded === undefined)
      this.baseCanBeBlinded = this.mulUnsafe(this.BASE, this.Point.Fn.ORDER).is0();
    return this.baseCanBeBlinded;
  }

  mulSecret(
    point: PC_P<PC>,
    scalar: bigint,
    cofactor: bigint,
    transform?: Mapper<PC_P<PC>>
  ): MulResult<PC_P<PC>> {
    return this.shouldBlind(point, cofactor)
      ? this.mulCTBlinded(point, scalar, transform)
      : this.mulCT(point, scalar, transform);
  }

  mulUnsafe(point: PC_P<PC>, scalar: bigint, transform?: Mapper<PC_P<PC>>): PC_P<PC> {
    this.assertPoint(point);
    if (!isPosBig(scalar)) throw new Error('invalid scalar');
    const W = getWindowSize(point);
    // W === 1 (un-precomputed): one-shot width-4 wNAF via {@link mulAddUnsafe} with L=1 —
    // a cached table would be thrown away after one use. `allowOversized` swaps the
    // `s < Fn.ORDER` check for mulAddUnsafe's `Fn.ORDER^4` DoS cap.
    //
    // Oversized scalar could happen when:
    // a) user passes large scalar on their own (rare)
    // b) `assertValidity()` calls `isTorsionFree()`, which multiplies point by `Fn.ORDER`
    if (W === 1 || scalar >= this.Point.Fn.ORDER)
      return mulAddUnsafe(this.Point, [point], [scalar], true);
    // Precomputed points reuse the CT kernel (fake accumulator discarded): with W=6 only
    // ~1/64 of window-adds are skippable, so a dedicated vartime kernel saved just ~6% on
    // this path while doubling the cached-table code surface.
    const precomputes = this.getWnafPrecomputes(W, point, this.bits, transform);
    return this.wnafCachedCT(precomputes, scalar).p;
  }

  // Remembers the window size used for precomputed wNAF multiplication of the given point
  // and drops any previously built tables. Usually only the base point is precomputed.
  // W=1 resets the point to the un-precomputed (table-less) paths.
  // W is additionally capped so tables stay under ~2 GiB ({@link TABLE_BYTES_MAX}).
  setWindowSize(point: PC_P<PC>, W: number): void {
    this.assertPoint(point);
    validateW(W, this.bits);
    // Size against the widest table this W can produce: the blinded path adds BLIND_BITS.
    const windows = Math.ceil((this.bits + BLIND_BITS) / W) + 1;
    validateTableBytes(windows * 2 ** (W - 1), this.Point.Fp.BYTES);
    pointWindowSizes.set(point, W);
    this.wnafPrecomputes.delete(point);
  }

  // True when a window size is set: tables themselves are built lazily on first multiply.
  hasWindowSize(point: PC_P<PC>): boolean {
    return getWindowSize(point) !== 1;
  }
}

/**
 * Combined multi-scalar multiplication `Σ scalars[i]⋅points[i]` via interleaved width-4 wNAF
 * (Strauss–Shamir). Every input gets its own table of odd multiples `[1P, 3P, 5P, 7P]` and
 * signed-digit recoding, but all walks share one doubling chain, so total cost is
 * `~bits` doublings + `L⋅bits/5` additions instead of `L⋅bits` doublings for separate
 * multiplications. Intended for the 2-4 point shapes of signature verification
 * (`R = u1⋅G + u2⋅P`); use {@link pippenger} for larger batches.
 *
 * Not constant-time: only for public inputs. Scalars must satisfy `0 <= s < Fn.ORDER`;
 * fold negative signs into the points before calling.
 * @param c - Point constructor.
 * @param points - Array of curve points.
 * @param scalars - Array of non-negative scalars, same length as points.
 * @param allowOversized - Replace the `s < Fn.ORDER` scalar check with a `Fn.ORDER^4` DoS cap.
 *   Off by default. For scalars that must NOT be reduced mod ORDER: torsion checks
 *   (`Fn.ORDER⋅P ≟ O`) and cofactor-clearing multiples. Walk length grows with `bitLen(s)`.
 * @returns Combined multiplication result; identity for empty input.
 * @throws If the point set or scalar set is invalid. {@link Error}
 * @example
 * Combined multi-scalar multiplication via Strauss–Shamir.
 *
 * ```ts
 * import { mulAddUnsafe } from '@noble/curves/abstract/curve.js';
 * import { p256 } from '@noble/curves/nist.js';
 * const G = p256.Point.BASE;
 * const R = mulAddUnsafe(p256.Point, [G, G.double()], [2n, 3n]); // 2⋅G + 3⋅(2⋅G)
 * ```
 */
export function mulAddUnsafe<P extends CurvePoint<any, P>, PC extends CurvePointCons<P>>(
  c: PC,
  points: P[],
  scalars: bigint[],
  allowOversized: boolean = false
): P {
  validatePointCons(c);
  validateMSMPoints(points, c);
  abool(allowOversized, 'allowOversized');
  // Oversized cap is ORDER^4: hard bound to mitigate DoS, walk length grows with bitLen(s).
  validateMSMScalars(scalars, c.Fn, allowOversized ? c.Fn.ORDER ** _4n : undefined);
  if (points.length !== scalars.length)
    throw new Error('arrays of points and scalars must have equal length');
  const tables = points.map((p) => oddMultiples(p, 4));
  const digits = scalars.map((n) => wnafDigits(n, 4));
  return wnafWalk(c.ZERO, tables, digits);
}

/**
 * Pippenger algorithm for multi-scalar multiplication (MSM, Pa + Qb + Rc + ...).
 * 30x faster vs naive addition on L=4096, 10x faster than precomputes.
 * For N=254bit, L=1, it does: 1024 ADD + 254 DBL. For L=5: 1536 ADD + 254 DBL.
 * Point-operation count is scalar-independent (for same L), even when 1 point + scalar, or when
 * scalar = 0 — but bucket indices are scalar windows, so the memory-access pattern is
 * scalar-dependent: do not rely on this for secret scalars.
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
  validatePointCons(c);
  const fieldN = c.Fn;
  validateMSMPoints(points, c);
  validateMSMScalars(scalars, fieldN);
  const plength = points.length;
  const slength = scalars.length;
  if (plength !== slength) throw new Error('arrays of points and scalars must have equal length');
  const zero = c.ZERO;
  // Without this, the window loop below would still run ~Fn.BITS doublings of ZERO.
  if (plength === 0) return zero as P;
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
 * Interleaved wNAF multi-scalar multiplication (MSM, Pa + Qb + Rc + ...) over a FIXED set
 * of points: each point gets a one-time table of odd multiples
 * `[1P, 3P, ..., (2^(W−1)−1)P]`, and the returned closure evaluates MSMs against those
 * tables. All scalars share one doubling chain (Straus 1964) — one doubling per scalar bit
 * plus one signed table addition per nonzero width-W wNAF digit (density ~1/(W+1)) — the
 * "interleaving" method of Möller, "Algorithms for multi-exponentiation" (SAC 2001).
 *
 * Table memory is `L⋅2^(W−2)` points, capped at ~2 GiB. Prefer this over {@link pippenger}
 * when the same points are reused across many MSMs (fixed-base commitments etc.) and up to a
 * few hundred points; prefer pippenger for one-shot MSMs or thousands of points, where
 * bucketing beats per-point tables.
 *
 * Not constant-time (zero digits are skipped): public inputs only.
 * @param c - Curve Point constructor
 * @param points - array of L curve points, captured by the returned closure
 * @param windowSize - window width W in bits, 2 <= W <= Fn.BITS; also capped so the
 *   per-closure tables stay under ~2 GiB
 * @returns Function which multiplies points with scalars. The closure accepts
 *   `scalars.length <= points.length`, and omitted trailing scalars are treated as zero.
 * @throws If the point set or precompute window is invalid. {@link Error}
 * @example
 * Interleaved wNAF multi-scalar multiplication (MSM, Pa + Qb + Rc + ...).
 *
 * ```ts
 * import { interleavedMSMUnsafe } from '@noble/curves/abstract/curve.js';
 * import { p256 } from '@noble/curves/nist.js';
 * const msm = interleavedMSMUnsafe(p256.Point, [p256.Point.BASE], 4);
 * const point = msm([3n]);
 * ```
 */
export function interleavedMSMUnsafe<P extends CurvePoint<any, P>, PC extends CurvePointCons<P>>(
  c: PC,
  points: P[],
  windowSize: number
): (scalars: bigint[]) => P {
  validatePointCons(c);
  const fieldN = c.Fn;
  // Signed odd digits need at least width 2 (W=2 is plain NAF with a single-entry table).
  validateW(windowSize, fieldN.BITS, 2);
  validateMSMPoints(points, c);
  validateTableBytes(points.length * 2 ** (windowSize - 2), c.Fp.BYTES);
  const tables = points.map((p) => oddMultiples(p, 2 ** (windowSize - 2)));
  return (scalars: bigint[]): P => {
    validateMSMScalars(scalars, fieldN);
    if (scalars.length > points.length)
      throw new Error('array of scalars must not be larger than array of points');
    return wnafWalk(
      c.ZERO,
      tables,
      scalars.map((n) => wnafDigits(n, windowSize))
    );
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
 * @param curveOpts - Optional field overrides. See {@link FpFn}:
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
  if (type !== 'weierstrass' && type !== 'edwards')
    throw new Error('expected curve type "weierstrass" or "edwards"');
  if (FpFnLE === undefined) FpFnLE = type === 'edwards';
  if (!CURVE || typeof CURVE !== 'object') throw new Error(`expected valid ${type} CURVE object`);
  // Validate before reading Fp/Fn so explicit null fails with an options-object error.
  validateObject(curveOpts);
  for (const p of ['p', 'n', 'h'] as const) {
    const val = CURVE[p];
    if (!(isPosBig(val) && val !== _0n)) throw new Error(`CURVE.${p} must be positive bigint`);
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

type KeygenFn = (seed?: Uint8Array) => { secretKey: Uint8Array; publicKey: Uint8Array };
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
