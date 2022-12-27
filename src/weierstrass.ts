/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// Short Weierstrass curve. The formula is: y² = x³ + ax + b

// TODO: sync vs async naming
// TODO: default randomBytes
// Differences from @noble/secp256k1 1.7:
// 1. Different double() formula (but same addition)
// 2. Different sqrt() function
// 3. truncateHash() truncateOnly mode
// 4. DRBG supports outputLen bigger than outputLen of hmac

import * as mod from './modular.js';
import {
  bytesToHex,
  bytesToNumberBE,
  concatBytes,
  ensureBytes,
  hexToBytes,
  hexToNumber,
  numberToHexUnpadded,
  hashToPrivateScalar,
  Hex,
  PrivKey,
} from './utils.js';
import * as utils from './utils.js';
import { hash_to_field, htfOpts, validateHTFOpts } from './hashToCurve.js';
import { Group, GroupConstructor, wNAF } from './group.js';

type HmacFnSync = (key: Uint8Array, ...messages: Uint8Array[]) => Uint8Array;
type EndomorphismOpts = {
  beta: bigint;
  splitScalar: (k: bigint) => { k1neg: boolean; k1: bigint; k2neg: boolean; k2: bigint };
};
export type BasicCurve<T> = utils.BasicCurve<T> & {
  // Params: a, b
  a: T;
  b: T;
  // TODO: move into options?

  normalizePrivateKey?: (key: PrivKey) => PrivKey;
  // Endomorphism options for Koblitz curves
  endo?: EndomorphismOpts;
  // Torsions, can be optimized via endomorphisms
  isTorsionFree?: (c: ProjectiveConstructor<T>, point: ProjectivePointType<T>) => boolean;
  clearCofactor?: (
    c: ProjectiveConstructor<T>,
    point: ProjectivePointType<T>
  ) => ProjectivePointType<T>;
  // Hash to field opts
  htfDefaults?: htfOpts;
  mapToCurve?: (scalar: bigint[]) => { x: T; y: T };
};
// DER encoding utilities
class DERError extends Error {
  constructor(message: string) {
    super(message);
  }
}

function sliceDER(s: string): string {
  // Proof: any([(i>=0x80) == (int(hex(i).replace('0x', '').zfill(2)[0], 16)>=8)  for i in range(0, 256)])
  // Padding done by numberToHex
  return Number.parseInt(s[0], 16) >= 8 ? '00' + s : s;
}

function parseDERInt(data: Uint8Array) {
  if (data.length < 2 || data[0] !== 0x02) {
    throw new DERError(`Invalid signature integer tag: ${bytesToHex(data)}`);
  }
  const len = data[1];
  const res = data.subarray(2, len + 2);
  if (!len || res.length !== len) {
    throw new DERError(`Invalid signature integer: wrong length`);
  }
  // Strange condition, its not about length, but about first bytes of number.
  if (res[0] === 0x00 && res[1] <= 0x7f) {
    throw new DERError('Invalid signature integer: trailing length');
  }
  return { data: bytesToNumberBE(res), left: data.subarray(len + 2) };
}

function parseDERSignature(data: Uint8Array) {
  if (data.length < 2 || data[0] != 0x30) {
    throw new DERError(`Invalid signature tag: ${bytesToHex(data)}`);
  }
  if (data[1] !== data.length - 2) {
    throw new DERError('Invalid signature: incorrect length');
  }
  const { data: r, left: sBytes } = parseDERInt(data.subarray(2));
  const { data: s, left: rBytesLeft } = parseDERInt(sBytes);
  if (rBytesLeft.length) {
    throw new DERError(`Invalid signature: left bytes after parsing: ${bytesToHex(rBytesLeft)}`);
  }
  return { r, s };
}

// Be friendly to bad ECMAScript parsers by not using bigint literals like 123n
const _0n = BigInt(0);
const _1n = BigInt(1);
const _3n = BigInt(3);

type Entropy = Hex | true;
type SignOpts = { lowS?: boolean; extraEntropy?: Entropy };

/**
 * ### Design rationale for types
 *
 * * Interaction between classes from different curves should fail:
 *   `k256.Point.BASE.add(p256.Point.BASE)`
 * * For this purpose we want to use `instanceof` operator, which is fast and works during runtime
 * * Different calls of `curve()` would return different classes -
 *   `curve(params) !== curve(params)`: if somebody decided to monkey-patch their curve,
 *   it won't affect others
 *
 * TypeScript can't infer types for classes created inside a function. Classes is one instance of nominative types in TypeScript and interfaces only check for shape, so it's hard to create unique type for every function call.
 *
 * We can use generic types via some param, like curve opts, but that would:
 *     1. Enable interaction between `curve(params)` and `curve(params)` (curves of same params)
 *     which is hard to debug.
 *     2. Params can be generic and we can't enforce them to be constant value:
 *     if somebody creates curve from non-constant params,
 *     it would be allowed to interact with other curves with non-constant params
 *
 * TODO: https://www.typescriptlang.org/docs/handbook/release-notes/typescript-2-7.html#unique-symbol
 */

// Instance
export interface ProjectivePointType<T> extends Group<ProjectivePointType<T>> {
  readonly x: T;
  readonly y: T;
  readonly z: T;
  multiply(scalar: number | bigint, affinePoint?: PointType<T>): ProjectivePointType<T>;
  multiplyUnsafe(scalar: bigint): ProjectivePointType<T>;
  toAffine(invZ?: T): PointType<T>;
}
// Static methods
export interface ProjectiveConstructor<T> extends GroupConstructor<ProjectivePointType<T>> {
  new (x: T, y: T, z: T): ProjectivePointType<T>;
  fromAffine(p: PointType<T>): ProjectivePointType<T>;
  toAffineBatch(points: ProjectivePointType<T>[]): PointType<T>[];
  normalizeZ(points: ProjectivePointType<T>[]): ProjectivePointType<T>[];
}
// Instance
export interface PointType<T> extends Group<PointType<T>> {
  readonly x: T;
  readonly y: T;
  _setWindowSize(windowSize: number): void;
  hasEvenY(): boolean;
  toRawBytes(isCompressed?: boolean): Uint8Array;
  toHex(isCompressed?: boolean): string;
  assertValidity(): void;
  multiplyAndAddUnsafe(Q: PointType<T>, a: bigint, b: bigint): PointType<T> | undefined;
}
// Static methods
export interface PointConstructor<T> extends GroupConstructor<PointType<T>> {
  new (x: T, y: T): PointType<T>;
  fromHex(hex: Hex): PointType<T>;
  fromPrivateKey(privateKey: PrivKey): PointType<T>;
  hashToCurve(msg: Hex, options?: Partial<htfOpts>): PointType<T>;
  encodeToCurve(msg: Hex, options?: Partial<htfOpts>): PointType<T>;
}

export type CurvePointsType<T> = BasicCurve<T> & {
  // Bytes
  fromBytes: (bytes: Uint8Array) => { x: T; y: T };
  toBytes: (c: PointConstructor<T>, point: PointType<T>, compressed: boolean) => Uint8Array;
};

function validatePointOpts<T>(curve: CurvePointsType<T>) {
  const opts = utils.validateOpts(curve);
  const Fp = opts.Fp;
  for (const i of ['a', 'b'] as const) {
    if (!Fp.isValid(curve[i]))
      throw new Error(`Invalid curve param ${i}=${opts[i]} (${typeof opts[i]})`);
  }
  for (const i of ['isTorsionFree', 'clearCofactor', 'mapToCurve'] as const) {
    if (curve[i] === undefined) continue; // Optional
    if (typeof curve[i] !== 'function') throw new Error(`Invalid ${i} function`);
  }
  const endo = opts.endo;
  if (endo) {
    if (!Fp.equals(opts.a, Fp.ZERO)) {
      throw new Error('Endomorphism can only be defined for Koblitz curves that have a=0');
    }
    if (
      typeof endo !== 'object' ||
      typeof endo.beta !== 'bigint' ||
      typeof endo.splitScalar !== 'function'
    ) {
      throw new Error('Expected endomorphism with beta: bigint and splitScalar: function');
    }
  }
  if (typeof opts.fromBytes !== 'function') throw new Error('Invalid fromBytes function');
  if (typeof opts.toBytes !== 'function') throw new Error('Invalid fromBytes function');
  // Requires including hashToCurve file
  if (opts.htfDefaults !== undefined) validateHTFOpts(opts.htfDefaults);
  // Set defaults
  return Object.freeze({ ...opts } as const);
}

export type CurvePointsRes<T> = {
  Point: PointConstructor<T>;
  ProjectivePoint: ProjectiveConstructor<T>;
  normalizePrivateKey: (key: PrivKey) => bigint;
  weierstrassEquation: (x: T) => T;
  isWithinCurveOrder: (num: bigint) => boolean;
};

export function weierstrassPoints<T>(opts: CurvePointsType<T>) {
  const CURVE = validatePointOpts(opts);
  const Fp = CURVE.Fp;
  // Lengths
  // All curves has same field / group length as for now, but it can be different for other curves
  const { nByteLength, nBitLength } = CURVE;
  const groupLen = nByteLength;

  // Not using ** operator with bigints for old engines.
  // 2n ** (8n * 32n) == 2n << (8n * 32n - 1n)
  //const FIELD_MASK = _2n << (_8n * BigInt(fieldLen) - _1n);
  // function numToFieldStr(num: bigint): string {
  //   if (typeof num !== 'bigint') throw new Error('Expected bigint');
  //   if (!(_0n <= num && num < FIELD_MASK)) throw new Error(`Expected number < 2^${fieldLen * 8}`);
  //   return num.toString(16).padStart(2 * fieldLen, '0');
  // }

  /**
   * y² = x³ + ax + b: Short weierstrass curve formula
   * @returns y²
   */
  function weierstrassEquation(x: T): T {
    const { a, b } = CURVE;
    const x2 = Fp.square(x); // x * x
    const x3 = Fp.multiply(x2, x); // x2 * x
    return Fp.add(Fp.add(x3, Fp.multiply(x, a)), b); // x3 + a * x + b
  }

  function isWithinCurveOrder(num: bigint): boolean {
    return _0n < num && num < CURVE.n;
  }

  function normalizePrivateKey(key: PrivKey): bigint {
    if (typeof CURVE.normalizePrivateKey === 'function') {
      key = CURVE.normalizePrivateKey(key);
    }
    let num: bigint;
    if (typeof key === 'bigint') {
      num = key;
    } else if (typeof key === 'number' && Number.isSafeInteger(key) && key > 0) {
      num = BigInt(key);
    } else if (typeof key === 'string') {
      if (key.length !== 2 * groupLen) throw new Error(`Expected ${groupLen} bytes of private key`);
      num = hexToNumber(key);
    } else if (key instanceof Uint8Array) {
      if (key.length !== groupLen) throw new Error(`Expected ${groupLen} bytes of private key`);
      num = bytesToNumberBE(key);
    } else {
      throw new TypeError('Expected valid private key');
    }
    if (CURVE.wrapPrivateKey) num = mod.mod(num, CURVE.n);
    if (!isWithinCurveOrder(num)) throw new Error('Expected private key: 0 < key < n');
    return num;
  }

  function normalizeScalar(num: number | bigint): bigint {
    if (typeof num === 'number' && Number.isSafeInteger(num) && num > 0) return BigInt(num);
    if (typeof num === 'bigint' && isWithinCurveOrder(num)) return num;
    throw new TypeError('Expected valid private scalar: 0 < scalar < curve.n');
  }

  /**
   * Projective Point works in 3d / projective (homogeneous) coordinates: (x, y, z) ∋ (x=x/z, y=y/z)
   * Default Point works in 2d / affine coordinates: (x, y)
   * We're doing calculations in projective, because its operations don't require costly inversion.
   */
  class ProjectivePoint implements ProjectivePointType<T> {
    constructor(readonly x: T, readonly y: T, readonly z: T) {}

    static readonly BASE = new ProjectivePoint(CURVE.Gx, CURVE.Gy, Fp.ONE);
    static readonly ZERO = new ProjectivePoint(Fp.ZERO, Fp.ONE, Fp.ZERO);

    static fromAffine(p: Point): ProjectivePoint {
      if (!(p instanceof Point)) {
        throw new TypeError('ProjectivePoint#fromAffine: expected Point');
      }
      // fromAffine(x:0, y:0) would produce (x:0, y:0, z:1), but we need (x:0, y:1, z:0)
      if (p.equals(Point.ZERO)) return ProjectivePoint.ZERO;
      return new ProjectivePoint(p.x, p.y, Fp.ONE);
    }

    /**
     * Takes a bunch of Projective Points but executes only one
     * invert on all of them. invert is very slow operation,
     * so this improves performance massively.
     */
    static toAffineBatch(points: ProjectivePoint[]): Point[] {
      const toInv = Fp.invertBatch(points.map((p) => p.z));
      return points.map((p, i) => p.toAffine(toInv[i]));
    }

    static normalizeZ(points: ProjectivePoint[]): ProjectivePoint[] {
      return ProjectivePoint.toAffineBatch(points).map(ProjectivePoint.fromAffine);
    }

    /**
     * Compare one point to another.
     */
    equals(other: ProjectivePoint): boolean {
      if (!(other instanceof ProjectivePoint)) throw new TypeError('ProjectivePoint expected');
      const { x: X1, y: Y1, z: Z1 } = this;
      const { x: X2, y: Y2, z: Z2 } = other;
      const U1 = Fp.equals(Fp.multiply(X1, Z2), Fp.multiply(X2, Z1));
      const U2 = Fp.equals(Fp.multiply(Y1, Z2), Fp.multiply(Y2, Z1));
      return U1 && U2;
    }

    /**
     * Flips point to one corresponding to (x, -y) in Affine coordinates.
     */
    negate(): ProjectivePoint {
      return new ProjectivePoint(this.x, Fp.negate(this.y), this.z);
    }

    doubleAdd(): ProjectivePoint {
      return this.add(this);
    }

    // Renes-Costello-Batina exception-free doubling formula.
    // There is 30% faster Jacobian formula, but it is not complete.
    // https://eprint.iacr.org/2015/1060, algorithm 3
    // Cost: 8M + 3S + 3*a + 2*b3 + 15add.
    double() {
      const { a, b } = CURVE;
      const b3 = Fp.multiply(b, 3n);
      const { x: X1, y: Y1, z: Z1 } = this;
      let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO; // prettier-ignore
      let t0 = Fp.multiply(X1, X1); // step 1
      let t1 = Fp.multiply(Y1, Y1);
      let t2 = Fp.multiply(Z1, Z1);
      let t3 = Fp.multiply(X1, Y1);
      t3 = Fp.add(t3, t3); // step 5
      Z3 = Fp.multiply(X1, Z1);
      Z3 = Fp.add(Z3, Z3);
      X3 = Fp.multiply(a, Z3);
      Y3 = Fp.multiply(b3, t2);
      Y3 = Fp.add(X3, Y3); // step 10
      X3 = Fp.subtract(t1, Y3);
      Y3 = Fp.add(t1, Y3);
      Y3 = Fp.multiply(X3, Y3);
      X3 = Fp.multiply(t3, X3);
      Z3 = Fp.multiply(b3, Z3); // step 15
      t2 = Fp.multiply(a, t2);
      t3 = Fp.subtract(t0, t2);
      t3 = Fp.multiply(a, t3);
      t3 = Fp.add(t3, Z3);
      Z3 = Fp.add(t0, t0); // step 20
      t0 = Fp.add(Z3, t0);
      t0 = Fp.add(t0, t2);
      t0 = Fp.multiply(t0, t3);
      Y3 = Fp.add(Y3, t0);
      t2 = Fp.multiply(Y1, Z1); // step 25
      t2 = Fp.add(t2, t2);
      t0 = Fp.multiply(t2, t3);
      X3 = Fp.subtract(X3, t0);
      Z3 = Fp.multiply(t2, t1);
      Z3 = Fp.add(Z3, Z3); // step 30
      Z3 = Fp.add(Z3, Z3);
      return new ProjectivePoint(X3, Y3, Z3);
    }

    // Renes-Costello-Batina exception-free addition formula.
    // There is 30% faster Jacobian formula, but it is not complete.
    // https://eprint.iacr.org/2015/1060, algorithm 1
    // Cost: 12M + 0S + 3*a + 3*b3 + 23add.
    add(other: ProjectivePoint): ProjectivePoint {
      if (!(other instanceof ProjectivePoint)) throw new TypeError('ProjectivePoint expected');
      const { x: X1, y: Y1, z: Z1 } = this;
      const { x: X2, y: Y2, z: Z2 } = other;
      let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO; // prettier-ignore
      const a = CURVE.a;
      const b3 = Fp.multiply(CURVE.b, 3n);
      let t0 = Fp.multiply(X1, X2); // step 1
      let t1 = Fp.multiply(Y1, Y2);
      let t2 = Fp.multiply(Z1, Z2);
      let t3 = Fp.add(X1, Y1);
      let t4 = Fp.add(X2, Y2); // step 5
      t3 = Fp.multiply(t3, t4);
      t4 = Fp.add(t0, t1);
      t3 = Fp.subtract(t3, t4);
      t4 = Fp.add(X1, Z1);
      let t5 = Fp.add(X2, Z2); // step 10
      t4 = Fp.multiply(t4, t5);
      t5 = Fp.add(t0, t2);
      t4 = Fp.subtract(t4, t5);
      t5 = Fp.add(Y1, Z1);
      X3 = Fp.add(Y2, Z2); // step 15
      t5 = Fp.multiply(t5, X3);
      X3 = Fp.add(t1, t2);
      t5 = Fp.subtract(t5, X3);
      Z3 = Fp.multiply(a, t4);
      X3 = Fp.multiply(b3, t2); // step 20
      Z3 = Fp.add(X3, Z3);
      X3 = Fp.subtract(t1, Z3);
      Z3 = Fp.add(t1, Z3);
      Y3 = Fp.multiply(X3, Z3);
      t1 = Fp.add(t0, t0); // step 25
      t1 = Fp.add(t1, t0);
      t2 = Fp.multiply(a, t2);
      t4 = Fp.multiply(b3, t4);
      t1 = Fp.add(t1, t2);
      t2 = Fp.subtract(t0, t2); // step 30
      t2 = Fp.multiply(a, t2);
      t4 = Fp.add(t4, t2);
      t0 = Fp.multiply(t1, t4);
      Y3 = Fp.add(Y3, t0);
      t0 = Fp.multiply(t5, t4); // step 35
      X3 = Fp.multiply(t3, X3);
      X3 = Fp.subtract(X3, t0);
      t0 = Fp.multiply(t3, t1);
      Z3 = Fp.multiply(t5, Z3);
      Z3 = Fp.add(Z3, t0); // step 40
      return new ProjectivePoint(X3, Y3, Z3);
    }

    subtract(other: ProjectivePoint) {
      return this.add(other.negate());
    }

    /**
     * Non-constant-time multiplication. Uses double-and-add algorithm.
     * It's faster, but should only be used when you don't care about
     * an exposed private key e.g. sig verification, which works over *public* keys.
     */
    multiplyUnsafe(scalar: bigint): ProjectivePoint {
      const P0 = ProjectivePoint.ZERO;
      if (typeof scalar === 'bigint' && scalar === _0n) return P0;
      // Will throw on 0
      let n = normalizeScalar(scalar);
      if (n === _1n) return this;

      if (!CURVE.endo) return wnaf.unsafeLadder(this, n);

      // Apply endomorphism
      let { k1neg, k1, k2neg, k2 } = CURVE.endo.splitScalar(n);
      let k1p = P0;
      let k2p = P0;
      let d: ProjectivePoint = this;
      while (k1 > _0n || k2 > _0n) {
        if (k1 & _1n) k1p = k1p.add(d);
        if (k2 & _1n) k2p = k2p.add(d);
        d = d.double();
        k1 >>= _1n;
        k2 >>= _1n;
      }
      if (k1neg) k1p = k1p.negate();
      if (k2neg) k2p = k2p.negate();
      k2p = new ProjectivePoint(Fp.multiply(k2p.x, CURVE.endo.beta), k2p.y, k2p.z);
      return k1p.add(k2p);
    }

    /**
     * Implements w-ary non-adjacent form for calculating ec multiplication.
     */
    private wNAF(n: bigint, affinePoint?: Point): { p: ProjectivePoint; f: ProjectivePoint } {
      if (!affinePoint && this.equals(ProjectivePoint.BASE)) affinePoint = Point.BASE;
      const W = (affinePoint && affinePoint._WINDOW_SIZE) || 1;
      // Calculate precomputes on a first run, reuse them after
      let precomputes = affinePoint && pointPrecomputes.get(affinePoint);
      if (!precomputes) {
        precomputes = wnaf.precomputeWindow(this, W) as ProjectivePoint[];
        if (affinePoint && W !== 1) {
          precomputes = ProjectivePoint.normalizeZ(precomputes);
          pointPrecomputes.set(affinePoint, precomputes);
        }
      }
      return wnaf.wNAF(W, precomputes, n);
    }

    /**
     * Constant time multiplication.
     * Uses wNAF method. Windowed method may be 10% faster,
     * but takes 2x longer to generate and consumes 2x memory.
     * @param scalar by which the point would be multiplied
     * @param affinePoint optional point ot save cached precompute windows on it
     * @returns New point
     */
    multiply(scalar: number | bigint, affinePoint?: Point): ProjectivePoint {
      let n = normalizeScalar(scalar);

      // Real point.
      let point: ProjectivePoint;
      // Fake point, we use it to achieve constant-time multiplication.
      let fake: ProjectivePoint;
      if (CURVE.endo) {
        const { k1neg, k1, k2neg, k2 } = CURVE.endo.splitScalar(n);
        let { p: k1p, f: f1p } = this.wNAF(k1, affinePoint);
        let { p: k2p, f: f2p } = this.wNAF(k2, affinePoint);
        k1p = wnaf.constTimeNegate(k1neg, k1p);
        k2p = wnaf.constTimeNegate(k2neg, k2p);
        k2p = new ProjectivePoint(Fp.multiply(k2p.x, CURVE.endo.beta), k2p.y, k2p.z);
        point = k1p.add(k2p);
        fake = f1p.add(f2p);
      } else {
        const { p, f } = this.wNAF(n, affinePoint);
        point = p;
        fake = f;
      }
      // Normalize `z` for both points, but return only real one
      return ProjectivePoint.normalizeZ([point, fake])[0];
    }

    // Converts Projective point to affine (x, y) coordinates.
    // Can accept precomputed Z^-1 - for example, from invertBatch.
    // (x, y, z) ∋ (x=x/z, y=y/z)
    toAffine(invZ?: T): Point {
      const { x, y, z } = this;
      const is0 = this.equals(ProjectivePoint.ZERO);
      // If invZ was 0, we return zero point. However we still want to execute
      // all operations, so we replace invZ with a random number, 1.
      if (invZ == null) invZ = is0 ? Fp.ONE : Fp.invert(z);
      const ax = Fp.multiply(x, invZ);
      const ay = Fp.multiply(y, invZ);
      const zz = Fp.multiply(z, invZ);
      if (is0) return Point.ZERO;
      if (!Fp.equals(zz, Fp.ONE)) throw new Error('invZ was invalid');
      return new Point(ax, ay);
    }
    isTorsionFree(): boolean {
      if (CURVE.h === _1n) return true; // No subgroups, always torsion fee
      if (CURVE.isTorsionFree) return CURVE.isTorsionFree(ProjectivePoint, this);
      // is multiplyUnsafe(CURVE.n) is always ok, same as for edwards?
      throw new Error('Unsupported!');
    }
    // Clear cofactor of G1
    // https://eprint.iacr.org/2019/403
    clearCofactor(): ProjectivePoint {
      if (CURVE.h === _1n) return this; // Fast-path
      if (CURVE.clearCofactor) return CURVE.clearCofactor(ProjectivePoint, this) as ProjectivePoint;
      return this.multiplyUnsafe(CURVE.h);
    }
  }
  const wnaf = wNAF(ProjectivePoint, CURVE.endo ? nBitLength / 2 : nBitLength);
  // Stores precomputed values for points.
  const pointPrecomputes = new WeakMap<Point, ProjectivePoint[]>();

  /**
   * Default Point works in default aka affine coordinates: (x, y)
   */
  class Point implements PointType<T> {
    /**
     * Base point aka generator. public_key = Point.BASE * private_key
     */
    static BASE: Point = new Point(CURVE.Gx, CURVE.Gy);
    /**
     * Identity point aka point at infinity. point = point + zero_point
     */
    static ZERO: Point = new Point(Fp.ZERO, Fp.ZERO);

    // We calculate precomputes for elliptic curve point multiplication
    // using windowed method. This specifies window size and
    // stores precomputed values. Usually only base point would be precomputed.
    _WINDOW_SIZE?: number;

    constructor(readonly x: T, readonly y: T) {}

    // "Private method", don't use it directly
    _setWindowSize(windowSize: number) {
      this._WINDOW_SIZE = windowSize;
      pointPrecomputes.delete(this);
    }

    // Checks for y % 2 == 0
    hasEvenY(): boolean {
      if (Fp.isOdd) return !Fp.isOdd(this.y);
      throw new Error("Field doesn't support isOdd");
    }

    /**
     * Converts hash string or Uint8Array to Point.
     * @param hex short/long ECDSA hex
     */
    static fromHex(hex: Hex): Point {
      const { x, y } = CURVE.fromBytes(ensureBytes(hex));
      const point = new Point(x, y);
      point.assertValidity();
      return point;
    }

    // Multiplies generator point by privateKey.
    static fromPrivateKey(privateKey: PrivKey) {
      return Point.BASE.multiply(normalizePrivateKey(privateKey));
    }

    toRawBytes(isCompressed = false): Uint8Array {
      this.assertValidity();
      return CURVE.toBytes(Point, this, isCompressed);
    }

    toHex(isCompressed = false): string {
      return bytesToHex(this.toRawBytes(isCompressed));
    }
    // A point on curve is valid if it conforms to equation.
    assertValidity(): void {
      // Zero is valid point too!
      if (this.equals(Point.ZERO)) {
        if (CURVE.allowInfinityPoint) return;
        throw new Error('Point is infinity');
      }
      // Some 3rd-party test vectors require different wording between here & `fromCompressedHex`
      const msg = 'Point is not on elliptic curve';
      const { x, y } = this;
      if (!Fp.isValid(x) || !Fp.isValid(y)) throw new Error(msg);
      const left = Fp.square(y);
      const right = weierstrassEquation(x);
      if (!Fp.equals(left, right)) throw new Error(msg);
      // TODO: flag to disable this?
      if (!this.isTorsionFree()) throw new Error('Point must be of prime-order subgroup');
    }

    equals(other: Point): boolean {
      if (!(other instanceof Point)) throw new TypeError('Point#equals: expected Point');
      return Fp.equals(this.x, other.x) && Fp.equals(this.y, other.y);
    }

    // Returns the same point with inverted `y`
    negate() {
      return new Point(this.x, Fp.negate(this.y));
    }

    // Adds point to itself
    double() {
      return ProjectivePoint.fromAffine(this).double().toAffine();
    }

    // Adds point to other point
    add(other: Point) {
      return ProjectivePoint.fromAffine(this).add(ProjectivePoint.fromAffine(other)).toAffine();
    }

    // Subtracts other point from the point
    subtract(other: Point) {
      return this.add(other.negate());
    }

    multiply(scalar: number | bigint) {
      return ProjectivePoint.fromAffine(this).multiply(scalar, this).toAffine();
    }

    multiplyUnsafe(scalar: bigint) {
      return ProjectivePoint.fromAffine(this).multiplyUnsafe(scalar).toAffine();
    }
    clearCofactor() {
      return ProjectivePoint.fromAffine(this).clearCofactor().toAffine();
    }

    isTorsionFree(): boolean {
      return ProjectivePoint.fromAffine(this).isTorsionFree();
    }

    /**
     * Efficiently calculate `aP + bQ`.
     * Unsafe, can expose private key, if used incorrectly.
     * TODO: Utilize Shamir's trick
     * @returns non-zero affine point
     */
    multiplyAndAddUnsafe(Q: Point, a: bigint, b: bigint): Point | undefined {
      const P = ProjectivePoint.fromAffine(this);
      const aP =
        a === _0n || a === _1n || this !== Point.BASE ? P.multiplyUnsafe(a) : P.multiply(a);
      const bQ = ProjectivePoint.fromAffine(Q).multiplyUnsafe(b);
      const sum = aP.add(bQ);
      return sum.equals(ProjectivePoint.ZERO) ? undefined : sum.toAffine();
    }

    // Encodes byte string to elliptic curve
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-3
    static hashToCurve(msg: Hex, options?: Partial<htfOpts>) {
      if (!CURVE.mapToCurve) throw new Error('No mapToCurve defined for curve');
      msg = ensureBytes(msg);
      const u = hash_to_field(msg, 2, { ...CURVE.htfDefaults, ...options } as htfOpts);
      const { x: x0, y: y0 } = CURVE.mapToCurve(u[0]);
      const { x: x1, y: y1 } = CURVE.mapToCurve(u[1]);
      const p = new Point(x0, y0).add(new Point(x1, y1)).clearCofactor();
      return p;
    }
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#section-3
    static encodeToCurve(msg: Hex, options?: Partial<htfOpts>) {
      if (!CURVE.mapToCurve) throw new Error('No mapToCurve defined for curve');
      msg = ensureBytes(msg);
      const u = hash_to_field(msg, 1, { ...CURVE.htfDefaults, ...options } as htfOpts);
      const { x, y } = CURVE.mapToCurve(u[0]);
      return new Point(x, y).clearCofactor();
    }
  }
  return {
    Point: Point as PointConstructor<T>,
    ProjectivePoint: ProjectivePoint as ProjectiveConstructor<T>,
    normalizePrivateKey,
    weierstrassEquation,
    isWithinCurveOrder,
  };
}

// Instance
export interface SignatureType {
  readonly r: bigint;
  readonly s: bigint;
  readonly recovery?: number;
  assertValidity(): void;
  copyWithRecoveryBit(recovery: number): SignatureType;
  hasHighS(): boolean;
  normalizeS(): SignatureType;
  recoverPublicKey(msgHash: Hex): PointType<bigint>;
  // DER-encoded
  toDERRawBytes(isCompressed?: boolean): Uint8Array;
  toDERHex(isCompressed?: boolean): string;
  toCompactRawBytes(): Uint8Array;
  toCompactHex(): string;
}
// Static methods
export type SignatureConstructor = {
  new (r: bigint, s: bigint): SignatureType;
  fromCompact(hex: Hex): SignatureType;
  fromDER(hex: Hex): SignatureType;
};

export type PubKey = Hex | PointType<bigint>;

export type CurveType = BasicCurve<bigint> & {
  // Default options
  lowS?: boolean;
  // Hashes
  hash: utils.CHash; // Because we need outputLen for DRBG
  hmac: HmacFnSync;
  randomBytes: (bytesLength?: number) => Uint8Array;
  truncateHash?: (hash: Uint8Array, truncateOnly?: boolean) => bigint;
};

function validateOpts(curve: CurveType) {
  const opts = utils.validateOpts(curve);
  if (typeof opts.hash !== 'function' || !Number.isSafeInteger(opts.hash.outputLen))
    throw new Error('Invalid hash function');
  if (typeof opts.hmac !== 'function') throw new Error('Invalid hmac function');
  if (typeof opts.randomBytes !== 'function') throw new Error('Invalid randomBytes function');
  // Set defaults
  return Object.freeze({ lowS: true, ...opts } as const);
}

export type CurveFn = {
  CURVE: ReturnType<typeof validateOpts>;
  getPublicKey: (privateKey: PrivKey, isCompressed?: boolean) => Uint8Array;
  getSharedSecret: (privateA: PrivKey, publicB: PubKey, isCompressed?: boolean) => Uint8Array;
  sign: (msgHash: Hex, privKey: PrivKey, opts?: SignOpts) => SignatureType;
  verify: (
    signature: Hex | SignatureType,
    msgHash: Hex,
    publicKey: PubKey,
    opts?: {
      lowS?: boolean;
    }
  ) => boolean;
  Point: PointConstructor<bigint>;
  ProjectivePoint: ProjectiveConstructor<bigint>;
  Signature: SignatureConstructor;
  utils: {
    mod: (a: bigint, b?: bigint) => bigint;
    invert: (number: bigint, modulo?: bigint) => bigint;
    _bigintToBytes: (num: bigint) => Uint8Array;
    _bigintToString: (num: bigint) => string;
    _normalizePrivateKey: (key: PrivKey) => bigint;
    _normalizePublicKey: (publicKey: PubKey) => PointType<bigint>;
    _isWithinCurveOrder: (num: bigint) => boolean;
    _isValidFieldElement: (num: bigint) => boolean;
    _weierstrassEquation: (x: bigint) => bigint;
    isValidPrivateKey(privateKey: PrivKey): boolean;
    hashToPrivateKey: (hash: Hex) => Uint8Array;
    randomPrivateKey: () => Uint8Array;
  };
};

/**
 * Minimal HMAC-DRBG (NIST 800-90) for signatures.
 * Used only for RFC6979, does not fully implement DRBG spec.
 */
class HmacDrbg {
  k: Uint8Array;
  v: Uint8Array;
  counter: number;
  constructor(public hashLen: number, public qByteLen: number, public hmacFn: HmacFnSync) {
    if (typeof hashLen !== 'number' || hashLen < 2) throw new Error('hashLen must be a number');
    if (typeof qByteLen !== 'number' || qByteLen < 2) throw new Error('qByteLen must be a number');
    if (typeof hmacFn !== 'function') throw new Error('hmacFn must be a function');
    // Step B, Step C: set hashLen to 8*ceil(hlen/8)
    this.v = new Uint8Array(hashLen).fill(1);
    this.k = new Uint8Array(hashLen).fill(0);
    this.counter = 0;
  }
  private hmacSync(...values: Uint8Array[]) {
    return this.hmacFn(this.k, ...values);
  }
  incr() {
    if (this.counter >= 1000) throw new Error('Tried 1,000 k values for sign(), all were invalid');
    this.counter += 1;
  }
  reseedSync(seed = new Uint8Array()) {
    this.k = this.hmacSync(this.v, Uint8Array.from([0x00]), seed);
    this.v = this.hmacSync(this.v);
    if (seed.length === 0) return;
    this.k = this.hmacSync(this.v, Uint8Array.from([0x01]), seed);
    this.v = this.hmacSync(this.v);
  }
  // TODO: review
  generateSync(): Uint8Array {
    this.incr();

    let len = 0;
    const out: Uint8Array[] = [];
    while (len < this.qByteLen) {
      this.v = this.hmacSync(this.v);
      const sl = this.v.slice();
      out.push(sl);
      len += this.v.length;
    }
    return concatBytes(...out);
  }
  // There is no need in clean() method
  // It's useless, there are no guarantees with JS GC
  // whether bigints are removed even if you clean Uint8Arrays.
}

export function weierstrass(curveDef: CurveType): CurveFn {
  const CURVE = validateOpts(curveDef) as ReturnType<typeof validateOpts>;
  const CURVE_ORDER = CURVE.n;
  const Fp = CURVE.Fp;
  const compressedLen = Fp.BYTES + 1; // 33
  const uncompressedLen = 2 * Fp.BYTES + 1; // 65

  function isValidFieldElement(num: bigint): boolean {
    // 0 is disallowed by arbitrary reasons. Probably because infinity point?
    return _0n < num && num < Fp.ORDER;
  }

  const { Point, ProjectivePoint, normalizePrivateKey, weierstrassEquation, isWithinCurveOrder } =
    weierstrassPoints({
      ...CURVE,
      toBytes(c, point, isCompressed: boolean): Uint8Array {
        if (isCompressed) {
          return concatBytes(new Uint8Array([point.hasEvenY() ? 0x02 : 0x03]), Fp.toBytes(point.x));
        } else {
          return concatBytes(new Uint8Array([0x04]), Fp.toBytes(point.x), Fp.toBytes(point.y));
        }
      },
      fromBytes(bytes: Uint8Array) {
        const len = bytes.length;
        const header = bytes[0];
        // this.assertValidity() is done inside of fromHex
        if (len === compressedLen && (header === 0x02 || header === 0x03)) {
          const x = bytesToNumberBE(bytes.subarray(1));
          if (!isValidFieldElement(x)) throw new Error('Point is not on curve');
          const y2 = weierstrassEquation(x); // y² = x³ + ax + b
          let y = Fp.sqrt(y2); // y = y² ^ (p+1)/4
          const isYOdd = (y & _1n) === _1n;
          // ECDSA
          const isFirstByteOdd = (bytes[0] & 1) === 1;
          if (isFirstByteOdd !== isYOdd) y = Fp.negate(y);
          return { x, y };
        } else if (len === uncompressedLen && header === 0x04) {
          const x = Fp.fromBytes(bytes.subarray(1, Fp.BYTES + 1));
          const y = Fp.fromBytes(bytes.subarray(Fp.BYTES + 1, 2 * Fp.BYTES + 1));
          return { x, y };
        } else {
          throw new Error(
            `Point.fromHex: received invalid point. Expected ${compressedLen} compressed bytes or ${uncompressedLen} uncompressed bytes, not ${len}`
          );
        }
      },
    });
  type Point = typeof Point.BASE;

  // Do we need these functions at all?
  function numToField(num: bigint): Uint8Array {
    if (typeof num !== 'bigint') throw new Error('Expected bigint');
    if (!(_0n <= num && num < Fp.MASK)) throw new Error(`Expected number < 2^${Fp.BYTES * 8}`);
    return Fp.toBytes(num);
  }
  const numToFieldStr = (num: bigint): string => bytesToHex(numToField(num));

  /**
   * Normalizes hex, bytes, Point to Point. Checks for curve equation.
   */
  function normalizePublicKey(publicKey: PubKey): PointType<bigint> {
    if (publicKey instanceof Point) {
      publicKey.assertValidity();
      return publicKey;
    } else if (publicKey instanceof Uint8Array || typeof publicKey === 'string') {
      return Point.fromHex(publicKey);
      // This can happen because PointType can be instance of different class
    } else throw new Error(`Unknown type of public key: ${publicKey}`);
  }

  function isBiggerThanHalfOrder(number: bigint) {
    const HALF = CURVE_ORDER >> _1n;
    return number > HALF;
  }

  function normalizeS(s: bigint) {
    return isBiggerThanHalfOrder(s) ? mod.mod(-s, CURVE_ORDER) : s;
  }

  // Ensures ECDSA message hashes are 32 bytes and < curve order
  function _truncateHash(hash: Uint8Array, truncateOnly = false): bigint {
    const { n, nBitLength } = CURVE;
    const byteLength = hash.length;
    const delta = byteLength * 8 - nBitLength; // size of curve.n (252 bits)
    let h = bytesToNumberBE(hash);
    if (delta > 0) h = h >> BigInt(delta);
    if (!truncateOnly && h >= n) h -= n;
    return h;
  }
  const truncateHash = CURVE.truncateHash || _truncateHash;

  /**
   * ECDSA signature with its (r, s) properties. Supports DER & compact representations.
   */
  class Signature implements SignatureType {
    constructor(readonly r: bigint, readonly s: bigint, readonly recovery?: number) {
      this.assertValidity();
    }

    // pair (32 bytes of r, 32 bytes of s)
    static fromCompact(hex: Hex) {
      const arr = hex instanceof Uint8Array;
      const name = 'Signature.fromCompact';
      if (typeof hex !== 'string' && !arr)
        throw new TypeError(`${name}: Expected string or Uint8Array`);
      const str = arr ? bytesToHex(hex) : hex;
      if (str.length !== 128) throw new Error(`${name}: Expected 64-byte hex`);
      return new Signature(hexToNumber(str.slice(0, 64)), hexToNumber(str.slice(64, 128)));
    }

    // DER encoded ECDSA signature
    // https://bitcoin.stackexchange.com/questions/57644/what-are-the-parts-of-a-bitcoin-transaction-input-script
    static fromDER(hex: Hex) {
      const arr = hex instanceof Uint8Array;
      if (typeof hex !== 'string' && !arr)
        throw new TypeError(`Signature.fromDER: Expected string or Uint8Array`);
      const { r, s } = parseDERSignature(arr ? hex : hexToBytes(hex));
      return new Signature(r, s);
    }

    assertValidity(): void {
      const { r, s } = this;
      if (!isWithinCurveOrder(r)) throw new Error('Invalid Signature: r must be 0 < r < n');
      if (!isWithinCurveOrder(s)) throw new Error('Invalid Signature: s must be 0 < s < n');
    }

    copyWithRecoveryBit(recovery: number) {
      return new Signature(this.r, this.s, recovery);
    }

    /**
     * Recovers public key from signature with recovery bit. Throws on invalid hash.
     * https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Public_key_recovery
     *
     * ```
     * recover(r, s, h) where
     *   u1 = hs^-1 mod n
     *   u2 = sr^-1 mod n
     *   Q = u1⋅G + u2⋅R
     * ```
     *
     * @param msgHash message hash
     * @returns Point corresponding to public key
     */
    recoverPublicKey(msgHash: Hex): Point {
      const { r, s, recovery } = this;
      if (recovery == null) throw new Error('Cannot recover: recovery bit is not present');
      if (recovery !== 0 && recovery !== 1) throw new Error('Cannot recover: invalid recovery bit');
      const h = truncateHash(ensureBytes(msgHash));
      const { n } = CURVE;
      const rinv = mod.invert(r, n);
      // Q = u1⋅G + u2⋅R
      const u1 = mod.mod(-h * rinv, n);
      const u2 = mod.mod(s * rinv, n);
      const prefix = recovery & 1 ? '03' : '02';
      const R = Point.fromHex(prefix + numToFieldStr(r));
      const Q = Point.BASE.multiplyAndAddUnsafe(R, u1, u2);
      if (!Q) throw new Error('Cannot recover: point at infinify');
      Q.assertValidity();
      return Q;
    }

    /**
     * Default signatures are always low-s, to prevent malleability.
     * `sign(lowS: true)` always produces low-s sigs.
     * `verify(lowS: true)` always fails for high-s.
     */
    hasHighS(): boolean {
      return isBiggerThanHalfOrder(this.s);
    }

    normalizeS() {
      return this.hasHighS()
        ? new Signature(this.r, mod.mod(-this.s, CURVE_ORDER), this.recovery)
        : this;
    }

    // DER-encoded
    toDERRawBytes(isCompressed = false) {
      return hexToBytes(this.toDERHex(isCompressed));
    }
    toDERHex(isCompressed = false) {
      const sHex = sliceDER(numberToHexUnpadded(this.s));
      if (isCompressed) return sHex;
      const rHex = sliceDER(numberToHexUnpadded(this.r));
      const rLen = numberToHexUnpadded(rHex.length / 2);
      const sLen = numberToHexUnpadded(sHex.length / 2);
      const length = numberToHexUnpadded(rHex.length / 2 + sHex.length / 2 + 4);
      return `30${length}02${rLen}${rHex}02${sLen}${sHex}`;
    }

    // 32 bytes of r, then 32 bytes of s
    toCompactRawBytes() {
      return hexToBytes(this.toCompactHex());
    }
    toCompactHex() {
      return numToFieldStr(this.r) + numToFieldStr(this.s);
    }
  }

  const utils = {
    mod: (n: bigint, modulo = Fp.ORDER) => mod.mod(n, modulo),
    invert: Fp.invert,
    isValidPrivateKey(privateKey: PrivKey) {
      try {
        normalizePrivateKey(privateKey);
        return true;
      } catch (error) {
        return false;
      }
    },
    _bigintToBytes: numToField,
    _bigintToString: numToFieldStr,
    _normalizePrivateKey: normalizePrivateKey,
    _normalizePublicKey: normalizePublicKey,
    _isWithinCurveOrder: isWithinCurveOrder,
    _isValidFieldElement: isValidFieldElement,
    _weierstrassEquation: weierstrassEquation,

    /**
     * Converts some bytes to a valid private key. Needs at least (nBitLength+64) bytes.
     */
    hashToPrivateKey: (hash: Hex): Uint8Array => numToField(hashToPrivateScalar(hash, CURVE_ORDER)),

    /**
     * Produces cryptographically secure private key from random of size (nBitLength+64)
     * as per FIPS 186 B.4.1 with modulo bias being neglible.
     */
    randomPrivateKey: (): Uint8Array => utils.hashToPrivateKey(CURVE.randomBytes(Fp.BYTES + 8)),

    /**
     * 1. Returns cached point which you can use to pass to `getSharedSecret` or `#multiply` by it.
     * 2. Precomputes point multiplication table. Is done by default on first `getPublicKey()` call.
     * If you want your first getPublicKey to take 0.16ms instead of 20ms, make sure to call
     * utils.precompute() somewhere without arguments first.
     * @param windowSize 2, 4, 8, 16
     * @returns cached point
     */
    precompute(windowSize = 8, point = Point.BASE): Point {
      const cached = point === Point.BASE ? point : new Point(point.x, point.y);
      cached._setWindowSize(windowSize);
      cached.multiply(_3n);
      return cached;
    },
  };

  /**
   * Computes public key for a private key.
   * @param privateKey private key
   * @param isCompressed whether to return compact, or full key
   * @returns Public key, full by default; short when isCompressed=true
   */
  function getPublicKey(privateKey: PrivKey, isCompressed = false): Uint8Array {
    return Point.fromPrivateKey(privateKey).toRawBytes(isCompressed);
  }

  /**
   * Quick and dirty check for item being public key. Does not validate hex, or being on-curve.
   */
  function isProbPub(item: PrivKey | PubKey): boolean {
    const arr = item instanceof Uint8Array;
    const str = typeof item === 'string';
    const len = (arr || str) && (item as Hex).length;
    if (arr) return len === compressedLen || len === uncompressedLen;
    if (str) return len === 2 * compressedLen || len === 2 * uncompressedLen;
    if (item instanceof Point) return true;
    return false;
  }

  /**
   * ECDH (Elliptic Curve Diffie Hellman) implementation.
   * 1. Checks for validity of private key
   * 2. Checks for the public key of being on-curve
   * @param privateA private key
   * @param publicB different public key
   * @param isCompressed whether to return compact (33-byte), or full (65-byte) key
   * @returns shared public key
   */
  function getSharedSecret(privateA: PrivKey, publicB: PubKey, isCompressed = false): Uint8Array {
    if (isProbPub(privateA)) throw new TypeError('getSharedSecret: first arg must be private key');
    if (!isProbPub(publicB)) throw new TypeError('getSharedSecret: second arg must be public key');
    const b = normalizePublicKey(publicB);
    b.assertValidity();
    return b.multiply(normalizePrivateKey(privateA)).toRawBytes(isCompressed);
  }

  // RFC6979 methods
  function bits2int(bytes: Uint8Array) {
    const slice = bytes.length > Fp.BYTES ? bytes.slice(0, Fp.BYTES) : bytes;
    return bytesToNumberBE(slice);
  }
  function bits2octets(bytes: Uint8Array): Uint8Array {
    const z1 = bits2int(bytes);
    const z2 = mod.mod(z1, CURVE_ORDER);
    return int2octets(z2 < _0n ? z1 : z2);
  }
  function int2octets(num: bigint): Uint8Array {
    return numToField(num); // prohibits >32 bytes
  }
  // Steps A, D of RFC6979 3.2
  // Creates RFC6979 seed; converts msg/privKey to numbers.
  function initSigArgs(msgHash: Hex, privateKey: PrivKey, extraEntropy?: Entropy) {
    if (msgHash == null) throw new Error(`sign: expected valid message hash, not "${msgHash}"`);
    // Step A is ignored, since we already provide hash instead of msg
    const h1 = numToField(truncateHash(ensureBytes(msgHash)));
    const d = normalizePrivateKey(privateKey);
    // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1) || k')
    const seedArgs = [int2octets(d), bits2octets(h1)];
    // RFC6979 3.6: additional k' could be provided
    if (extraEntropy != null) {
      if (extraEntropy === true) extraEntropy = CURVE.randomBytes(Fp.BYTES);
      const e = ensureBytes(extraEntropy);
      if (e.length !== Fp.BYTES) throw new Error(`sign: Expected ${Fp.BYTES} bytes of extra data`);
      seedArgs.push(e);
    }
    // seed is constructed from private key and message
    // Step D
    // V, 0x00 are done in HmacDRBG constructor.
    const seed = concatBytes(...seedArgs);
    const m = bits2int(h1);
    return { seed, m, d };
  }

  /**
   * Converts signature params into point & r/s, checks them for validity.
   * k must be in range [1, n-1]
   * @param k signature's k param: deterministic in our case, random in non-rfc6979 sigs
   * @param m message that would be signed
   * @param d private key
   * @returns Signature with its point on curve Q OR undefined if params were invalid
   */
  function kmdToSig(kBytes: Uint8Array, m: bigint, d: bigint, lowS = true): Signature | undefined {
    const { n } = CURVE;
    const k = truncateHash(kBytes, true);
    if (!isWithinCurveOrder(k)) return;
    // Important: all mod() calls in the function must be done over `n`
    const kinv = mod.invert(k, n);
    const q = Point.BASE.multiply(k);
    // r = x mod n
    const r = mod.mod(q.x, n);
    if (r === _0n) return;
    // s = (1/k * (m + dr) mod n
    const s = mod.mod(kinv * mod.mod(m + mod.mod(d * r, n), n), n);
    if (s === _0n) return;
    let recovery = (q.x === r ? 0 : 2) | Number(q.y & _1n);
    let normS = s;
    if (lowS && isBiggerThanHalfOrder(s)) {
      normS = normalizeS(s);
      recovery ^= 1;
    }
    return new Signature(r, normS, recovery);
  }

  /**
   * Signs message hash (not message: you need to hash it by yourself).
   * @param opts `lowS, extraEntropy`
   */
  function sign(msgHash: Hex, privKey: PrivKey, opts: SignOpts = { lowS: CURVE.lowS }): Signature {
    // Steps A, D of RFC6979 3.2.
    const { seed, m, d } = initSigArgs(msgHash, privKey, opts.extraEntropy);
    // Steps B, C, D, E, F, G
    const drbg = new HmacDrbg(CURVE.hash.outputLen, CURVE.nByteLength, CURVE.hmac);
    drbg.reseedSync(seed);
    // Step H3, repeat until k is in range [1, n-1]
    let sig: Signature | undefined;
    while (!(sig = kmdToSig(drbg.generateSync(), m, d, opts.lowS))) drbg.reseedSync();
    return sig;
  }
  // Enable precomputes. Slows down first publicKey computation by 20ms.
  Point.BASE._setWindowSize(8);

  /**
   * Verifies a signature against message hash and public key.
   * Rejects lowS signatures by default: to override,
   * specify option `{lowS: false}`. Implements section 4.1.4 from https://www.secg.org/sec1-v2.pdf:
   *
   * ```
   * verify(r, s, h, P) where
   *   U1 = hs^-1 mod n
   *   U2 = rs^-1 mod n
   *   R = U1⋅G - U2⋅P
   *   mod(R.x, n) == r
   * ```
   */
  function verify(
    signature: Hex | SignatureType,
    msgHash: Hex,
    publicKey: PubKey,
    opts: { lowS?: boolean } = { lowS: CURVE.lowS }
  ): boolean {
    try {
      if (signature instanceof Signature) {
        signature.assertValidity();
      } else {
        // Signature can be represented in 2 ways: compact (64-byte) & DER (variable-length).
        // Since DER can also be 64 bytes, we check for it first.
        try {
          signature = Signature.fromDER(signature as Hex);
        } catch (derError) {
          if (!(derError instanceof DERError)) throw derError;
          signature = Signature.fromCompact(signature as Hex);
        }
      }
      msgHash = ensureBytes(msgHash);
    } catch (error) {
      return false;
    }
    if (opts.lowS && signature.hasHighS()) return false;
    let P;
    try {
      P = normalizePublicKey(publicKey);
    } catch (error) {
      return false;
    }
    const { n } = CURVE;
    const { r, s } = signature;
    const h = truncateHash(msgHash);
    const sinv = mod.invert(s, n); // s^-1
    // R = u1⋅G - u2⋅P
    const u1 = mod.mod(h * sinv, n);
    const u2 = mod.mod(r * sinv, n);

    // Some implementations compare R.x in projective, without inversion.
    // The speed-up is <5%, so we don't complicate the code.
    const R = Point.BASE.multiplyAndAddUnsafe(P, u1, u2);
    if (!R) return false;
    const v = mod.mod(R.x, n);
    return v === r;
  }
  return {
    CURVE,
    getPublicKey,
    getSharedSecret,
    sign,
    verify,
    Point,
    ProjectivePoint,
    Signature,
    utils,
  };
}
