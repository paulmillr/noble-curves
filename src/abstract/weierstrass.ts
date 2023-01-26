/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// Short Weierstrass curve. The formula is: y² = x³ + ax + b
import * as mod from './modular.js';
import * as ut from './utils.js';
import { Hex, PrivKey, ensureBytes, CHash } from './utils.js';
import {
  Group,
  GroupConstructor,
  wNAF,
  AbstractCurve,
  validateAbsOpts,
  AffinePoint,
} from './curve.js';

export type { AffinePoint };
type HmacFnSync = (key: Uint8Array, ...messages: Uint8Array[]) => Uint8Array;
type EndomorphismOpts = {
  beta: bigint;
  splitScalar: (k: bigint) => { k1neg: boolean; k1: bigint; k2neg: boolean; k2: bigint };
};
export type BasicCurve<T> = AbstractCurve<T> & {
  // Params: a, b
  a: T;
  b: T;

  // Optional params
  // Executed before privkey validation. Useful for P521 with var-length priv key
  normalizePrivateKey?: (key: PrivKey) => PrivKey;
  // Whether to execute modular division on a private key, useful for bls curves with cofactor > 1
  wrapPrivateKey?: boolean;
  // Endomorphism options for Koblitz curves
  endo?: EndomorphismOpts;
  // When a cofactor != 1, there can be an effective methods to:
  // 1. Determine whether a point is torsion-free
  isTorsionFree?: (c: ProjConstructor<T>, point: ProjPointType<T>) => boolean;
  // 2. Clear torsion component
  clearCofactor?: (c: ProjConstructor<T>, point: ProjPointType<T>) => ProjPointType<T>;
};

type Entropy = Hex | true;
export type SignOpts = { lowS?: boolean; extraEntropy?: Entropy; prehash?: boolean };
export type VerOpts = { lowS?: boolean; prehash?: boolean };

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

// Instance for 3d XYZ points
export interface ProjPointType<T> extends Group<ProjPointType<T>> {
  readonly px: T;
  readonly py: T;
  readonly pz: T;
  multiply(scalar: bigint): ProjPointType<T>;
  multiplyUnsafe(scalar: bigint): ProjPointType<T>;
  multiplyAndAddUnsafe(Q: ProjPointType<T>, a: bigint, b: bigint): ProjPointType<T> | undefined;
  _setWindowSize(windowSize: number): void;
  toAffine(iz?: T): AffinePoint<T>;
  isTorsionFree(): boolean;
  clearCofactor(): ProjPointType<T>;
  assertValidity(): void;
  hasEvenY(): boolean;
  toRawBytes(isCompressed?: boolean): Uint8Array;
  toHex(isCompressed?: boolean): string;
}
// Static methods for 3d XYZ points
export interface ProjConstructor<T> extends GroupConstructor<ProjPointType<T>> {
  new (x: T, y: T, z: T): ProjPointType<T>;
  fromAffine(p: AffinePoint<T>): ProjPointType<T>;
  fromHex(hex: Hex): ProjPointType<T>;
  fromPrivateKey(privateKey: PrivKey): ProjPointType<T>;
  normalizeZ(points: ProjPointType<T>[]): ProjPointType<T>[];
}

export type CurvePointsType<T> = BasicCurve<T> & {
  // Bytes
  fromBytes: (bytes: Uint8Array) => AffinePoint<T>;
  toBytes: (c: ProjConstructor<T>, point: ProjPointType<T>, compressed: boolean) => Uint8Array;
};

function validatePointOpts<T>(curve: CurvePointsType<T>) {
  const opts = validateAbsOpts(curve);
  const Fp = opts.Fp;
  for (const i of ['a', 'b'] as const) {
    if (!Fp.isValid(curve[i]))
      throw new Error(`Invalid curve param ${i}=${opts[i]} (${typeof opts[i]})`);
  }
  for (const i of ['isTorsionFree', 'clearCofactor'] as const) {
    if (curve[i] === undefined) continue; // Optional
    if (typeof curve[i] !== 'function') throw new Error(`Invalid ${i} function`);
  }
  const endo = opts.endo;
  if (endo) {
    if (!Fp.eql(opts.a, Fp.ZERO)) {
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
  // Set defaults
  return Object.freeze({ ...opts } as const);
}

export type CurvePointsRes<T> = {
  ProjectivePoint: ProjConstructor<T>;
  normalizePrivateKey: (key: PrivKey) => bigint;
  weierstrassEquation: (x: T) => T;
  isWithinCurveOrder: (num: bigint) => boolean;
};

// ASN.1 DER encoding utilities
const { bytesToNumberBE: b2n, hexToBytes: h2b } = ut;
const DER = {
  // asn.1 DER encoding utils
  Err: class DERErr extends Error {
    constructor(m = '') {
      super(m);
    }
  },
  _parseInt(data: Uint8Array): { d: bigint; l: Uint8Array } {
    const { Err: E } = DER;
    if (data.length < 2 || data[0] !== 0x02) throw new E('Invalid signature integer tag');
    const len = data[1];
    const res = data.subarray(2, len + 2);
    if (!len || res.length !== len) throw new E('Invalid signature integer: wrong length');
    if (res[0] === 0x00 && res[1] <= 0x7f)
      throw new E('Invalid signature integer: trailing length');
    // ^ Weird condition: not about length, but about first bytes of number.
    return { d: b2n(res), l: data.subarray(len + 2) }; // d is data, l is left
  },
  toSig(hex: string | Uint8Array): { r: bigint; s: bigint } {
    // parse DER signature
    const { Err: E } = DER;
    const data = typeof hex === 'string' ? h2b(hex) : hex;
    if (!(data instanceof Uint8Array)) throw new Error('ui8a expected');
    let l = data.length;
    if (l < 2 || data[0] != 0x30) throw new E('Invalid signature tag');
    if (data[1] !== l - 2) throw new E('Invalid signature: incorrect length');
    const { d: r, l: sBytes } = DER._parseInt(data.subarray(2));
    const { d: s, l: rBytesLeft } = DER._parseInt(sBytes);
    if (rBytesLeft.length) throw new E('Invalid signature: left bytes after parsing');
    return { r, s };
  },
  hexFromSig(sig: { r: bigint; s: bigint }): string {
    const slice = (s: string): string => (Number.parseInt(s[0], 16) >= 8 ? '00' + s : s); // slice DER
    const h = (num: number | bigint) => {
      const hex = num.toString(16);
      return hex.length & 1 ? `0${hex}` : hex;
    };
    const s = slice(h(sig.s));
    const r = slice(h(sig.r));
    const shl = s.length / 2;
    const rhl = r.length / 2;
    const sl = h(shl);
    const rl = h(rhl);
    return `30${h(rhl + shl + 4)}02${rl}${r}02${sl}${s}`;
  },
};

// Be friendly to bad ECMAScript parsers by not using bigint literals like 123n
const _0n = BigInt(0);
const _1n = BigInt(1);

export function weierstrassPoints<T>(opts: CurvePointsType<T>) {
  const CURVE = validatePointOpts(opts);
  const { Fp } = CURVE; // All curves has same field / group length as for now, but they can differ

  /**
   * y² = x³ + ax + b: Short weierstrass curve formula
   * @returns y²
   */
  function weierstrassEquation(x: T): T {
    const { a, b } = CURVE;
    const x2 = Fp.sqr(x); // x * x
    const x3 = Fp.mul(x2, x); // x2 * x
    return Fp.add(Fp.add(x3, Fp.mul(x, a)), b); // x3 + a * x + b
  }

  // Valid group elements reside in range 1..n-1
  function isWithinCurveOrder(num: bigint): boolean {
    return typeof num === 'bigint' && _0n < num && num < CURVE.n;
  }
  function assertGE(num: bigint) {
    if (!isWithinCurveOrder(num)) throw new Error('Expected valid bigint: 0 < bigint < curve.n');
  }
  /**
   * Validates if a private key is valid and converts it to bigint form.
   * Supports two options, that are passed when CURVE is initialized:
   * - `normalizePrivateKey()` executed before all checks
   * - `wrapPrivateKey` when true, executed after most checks, but before `0 < key < n`
   */
  function normalizePrivateKey(key: PrivKey): bigint {
    const { normalizePrivateKey: custom, nByteLength: groupLen, wrapPrivateKey, n } = CURVE;
    if (typeof custom === 'function') key = custom(key);
    let num: bigint;
    if (typeof key === 'bigint') {
      // Curve order check is done below
      num = key;
    } else if (typeof key === 'string') {
      if (key.length !== 2 * groupLen) throw new Error(`must be ${groupLen} bytes`);
      // Validates individual octets
      num = ut.bytesToNumberBE(ensureBytes(key));
    } else if (key instanceof Uint8Array) {
      if (key.length !== groupLen) throw new Error(`must be ${groupLen} bytes`);
      num = ut.bytesToNumberBE(key);
    } else {
      throw new Error('private key must be bytes, hex or bigint, not ' + typeof key);
    }
    // Useful for curves with cofactor != 1
    if (wrapPrivateKey) num = mod.mod(num, n);
    assertGE(num);
    return num;
  }

  const pointPrecomputes = new Map<Point, Point[]>();
  function assertPrjPoint(other: unknown) {
    if (!(other instanceof Point)) throw new Error('ProjectivePoint expected');
  }
  /**
   * Projective Point works in 3d / projective (homogeneous) coordinates: (x, y, z) ∋ (x=x/z, y=y/z)
   * Default Point works in 2d / affine coordinates: (x, y)
   * We're doing calculations in projective, because its operations don't require costly inversion.
   */
  class Point implements ProjPointType<T> {
    static readonly BASE = new Point(CURVE.Gx, CURVE.Gy, Fp.ONE);
    static readonly ZERO = new Point(Fp.ZERO, Fp.ONE, Fp.ZERO);

    constructor(readonly px: T, readonly py: T, readonly pz: T) {
      if (px == null || !Fp.isValid(px)) throw new Error('x required');
      if (py == null || !Fp.isValid(py)) throw new Error('y required');
      if (pz == null || !Fp.isValid(pz)) throw new Error('z required');
    }

    static fromAffine(p: AffinePoint<T>): Point {
      const { x, y } = p || {};
      if (!p || !Fp.isValid(x) || !Fp.isValid(y)) throw new Error('invalid affine point');
      if (p instanceof Point) throw new Error('projective point not allowed');
      const is0 = (i: T) => Fp.eql(i, Fp.ZERO);
      // fromAffine(x:0, y:0) would produce (x:0, y:0, z:1), but we need (x:0, y:1, z:0)
      if (is0(x) && is0(y)) return Point.ZERO;
      return new Point(x, y, Fp.ONE);
    }

    get x(): T {
      return this.toAffine().x;
    }
    get y(): T {
      return this.toAffine().y;
    }

    /**
     * Takes a bunch of Projective Points but executes only one
     * inversion on all of them. Inversion is very slow operation,
     * so this improves performance massively.
     * Optimization: converts a list of projective points to a list of identical points with Z=1.
     */
    static normalizeZ(points: Point[]): Point[] {
      const toInv = Fp.invertBatch(points.map((p) => p.pz));
      return points.map((p, i) => p.toAffine(toInv[i])).map(Point.fromAffine);
    }

    /**
     * Converts hash string or Uint8Array to Point.
     * @param hex short/long ECDSA hex
     */
    static fromHex(hex: Hex): Point {
      const P = Point.fromAffine(CURVE.fromBytes(ensureBytes(hex)));
      P.assertValidity();
      return P;
    }

    // Multiplies generator point by privateKey.
    static fromPrivateKey(privateKey: PrivKey) {
      return Point.BASE.multiply(normalizePrivateKey(privateKey));
    }

    // We calculate precomputes for elliptic curve point multiplication
    // using windowed method. This specifies window size and
    // stores precomputed values. Usually only base point would be precomputed.
    _WINDOW_SIZE?: number;

    // "Private method", don't use it directly
    _setWindowSize(windowSize: number) {
      this._WINDOW_SIZE = windowSize;
      pointPrecomputes.delete(this);
    }

    // A point on curve is valid if it conforms to equation.
    assertValidity(): void {
      // Zero is valid point too!
      if (this.is0()) {
        if (CURVE.allowInfinityPoint) return;
        throw new Error('bad point: ZERO');
      }
      // Some 3rd-party test vectors require different wording between here & `fromCompressedHex`
      const { x, y } = this.toAffine();
      // Check if x, y are valid field elements
      if (!Fp.isValid(x) || !Fp.isValid(y)) throw new Error('bad point: x or y not FE');
      const left = Fp.sqr(y); // y²
      const right = weierstrassEquation(x); // x³ + ax + b
      if (!Fp.eql(left, right)) throw new Error('bad point: equation left != right');
      if (!this.isTorsionFree()) throw new Error('bad point: not in prime-order subgroup');
    }
    hasEvenY(): boolean {
      const { y } = this.toAffine();
      if (Fp.isOdd) return !Fp.isOdd(y);
      throw new Error("Field doesn't support isOdd");
    }

    /**
     * Compare one point to another.
     */
    equals(other: Point): boolean {
      assertPrjPoint(other);
      const { px: X1, py: Y1, pz: Z1 } = this;
      const { px: X2, py: Y2, pz: Z2 } = other;
      const U1 = Fp.eql(Fp.mul(X1, Z2), Fp.mul(X2, Z1));
      const U2 = Fp.eql(Fp.mul(Y1, Z2), Fp.mul(Y2, Z1));
      return U1 && U2;
    }

    /**
     * Flips point to one corresponding to (x, -y) in Affine coordinates.
     */
    negate(): Point {
      return new Point(this.px, Fp.neg(this.py), this.pz);
    }

    // Renes-Costello-Batina exception-free doubling formula.
    // There is 30% faster Jacobian formula, but it is not complete.
    // https://eprint.iacr.org/2015/1060, algorithm 3
    // Cost: 8M + 3S + 3*a + 2*b3 + 15add.
    double() {
      const { a, b } = CURVE;
      const b3 = Fp.mul(b, 3n);
      const { px: X1, py: Y1, pz: Z1 } = this;
      let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO; // prettier-ignore
      let t0 = Fp.mul(X1, X1); // step 1
      let t1 = Fp.mul(Y1, Y1);
      let t2 = Fp.mul(Z1, Z1);
      let t3 = Fp.mul(X1, Y1);
      t3 = Fp.add(t3, t3); // step 5
      Z3 = Fp.mul(X1, Z1);
      Z3 = Fp.add(Z3, Z3);
      X3 = Fp.mul(a, Z3);
      Y3 = Fp.mul(b3, t2);
      Y3 = Fp.add(X3, Y3); // step 10
      X3 = Fp.sub(t1, Y3);
      Y3 = Fp.add(t1, Y3);
      Y3 = Fp.mul(X3, Y3);
      X3 = Fp.mul(t3, X3);
      Z3 = Fp.mul(b3, Z3); // step 15
      t2 = Fp.mul(a, t2);
      t3 = Fp.sub(t0, t2);
      t3 = Fp.mul(a, t3);
      t3 = Fp.add(t3, Z3);
      Z3 = Fp.add(t0, t0); // step 20
      t0 = Fp.add(Z3, t0);
      t0 = Fp.add(t0, t2);
      t0 = Fp.mul(t0, t3);
      Y3 = Fp.add(Y3, t0);
      t2 = Fp.mul(Y1, Z1); // step 25
      t2 = Fp.add(t2, t2);
      t0 = Fp.mul(t2, t3);
      X3 = Fp.sub(X3, t0);
      Z3 = Fp.mul(t2, t1);
      Z3 = Fp.add(Z3, Z3); // step 30
      Z3 = Fp.add(Z3, Z3);
      return new Point(X3, Y3, Z3);
    }

    // Renes-Costello-Batina exception-free addition formula.
    // There is 30% faster Jacobian formula, but it is not complete.
    // https://eprint.iacr.org/2015/1060, algorithm 1
    // Cost: 12M + 0S + 3*a + 3*b3 + 23add.
    add(other: Point): Point {
      assertPrjPoint(other);
      const { px: X1, py: Y1, pz: Z1 } = this;
      const { px: X2, py: Y2, pz: Z2 } = other;
      let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO; // prettier-ignore
      const a = CURVE.a;
      const b3 = Fp.mul(CURVE.b, 3n);
      let t0 = Fp.mul(X1, X2); // step 1
      let t1 = Fp.mul(Y1, Y2);
      let t2 = Fp.mul(Z1, Z2);
      let t3 = Fp.add(X1, Y1);
      let t4 = Fp.add(X2, Y2); // step 5
      t3 = Fp.mul(t3, t4);
      t4 = Fp.add(t0, t1);
      t3 = Fp.sub(t3, t4);
      t4 = Fp.add(X1, Z1);
      let t5 = Fp.add(X2, Z2); // step 10
      t4 = Fp.mul(t4, t5);
      t5 = Fp.add(t0, t2);
      t4 = Fp.sub(t4, t5);
      t5 = Fp.add(Y1, Z1);
      X3 = Fp.add(Y2, Z2); // step 15
      t5 = Fp.mul(t5, X3);
      X3 = Fp.add(t1, t2);
      t5 = Fp.sub(t5, X3);
      Z3 = Fp.mul(a, t4);
      X3 = Fp.mul(b3, t2); // step 20
      Z3 = Fp.add(X3, Z3);
      X3 = Fp.sub(t1, Z3);
      Z3 = Fp.add(t1, Z3);
      Y3 = Fp.mul(X3, Z3);
      t1 = Fp.add(t0, t0); // step 25
      t1 = Fp.add(t1, t0);
      t2 = Fp.mul(a, t2);
      t4 = Fp.mul(b3, t4);
      t1 = Fp.add(t1, t2);
      t2 = Fp.sub(t0, t2); // step 30
      t2 = Fp.mul(a, t2);
      t4 = Fp.add(t4, t2);
      t0 = Fp.mul(t1, t4);
      Y3 = Fp.add(Y3, t0);
      t0 = Fp.mul(t5, t4); // step 35
      X3 = Fp.mul(t3, X3);
      X3 = Fp.sub(X3, t0);
      t0 = Fp.mul(t3, t1);
      Z3 = Fp.mul(t5, Z3);
      Z3 = Fp.add(Z3, t0); // step 40
      return new Point(X3, Y3, Z3);
    }

    subtract(other: Point) {
      return this.add(other.negate());
    }

    private is0() {
      return this.equals(Point.ZERO);
    }
    private wNAF(n: bigint): { p: Point; f: Point } {
      return wnaf.wNAFCached(this, pointPrecomputes, n, (comp: Point[]) => {
        const toInv = Fp.invertBatch(comp.map((p) => p.pz));
        return comp.map((p, i) => p.toAffine(toInv[i])).map(Point.fromAffine);
      });
    }

    /**
     * Non-constant-time multiplication. Uses double-and-add algorithm.
     * It's faster, but should only be used when you don't care about
     * an exposed private key e.g. sig verification, which works over *public* keys.
     */
    multiplyUnsafe(n: bigint): Point {
      const I = Point.ZERO;
      if (n === _0n) return I;
      assertGE(n); // Will throw on 0
      if (n === _1n) return this;
      const { endo } = CURVE;
      if (!endo) return wnaf.unsafeLadder(this, n);

      // Apply endomorphism
      let { k1neg, k1, k2neg, k2 } = endo.splitScalar(n);
      let k1p = I;
      let k2p = I;
      let d: Point = this;
      while (k1 > _0n || k2 > _0n) {
        if (k1 & _1n) k1p = k1p.add(d);
        if (k2 & _1n) k2p = k2p.add(d);
        d = d.double();
        k1 >>= _1n;
        k2 >>= _1n;
      }
      if (k1neg) k1p = k1p.negate();
      if (k2neg) k2p = k2p.negate();
      k2p = new Point(Fp.mul(k2p.px, endo.beta), k2p.py, k2p.pz);
      return k1p.add(k2p);
    }

    /**
     * Constant time multiplication.
     * Uses wNAF method. Windowed method may be 10% faster,
     * but takes 2x longer to generate and consumes 2x memory.
     * @param scalar by which the point would be multiplied
     * @param affinePoint optional point ot save cached precompute windows on it
     * @returns New point
     */
    multiply(scalar: bigint): Point {
      assertGE(scalar);
      let n = scalar;
      let point: Point, fake: Point; // Fake point is used to const-time mult
      const { endo } = CURVE;
      if (endo) {
        const { k1neg, k1, k2neg, k2 } = endo.splitScalar(n);
        let { p: k1p, f: f1p } = this.wNAF(k1);
        let { p: k2p, f: f2p } = this.wNAF(k2);
        k1p = wnaf.constTimeNegate(k1neg, k1p);
        k2p = wnaf.constTimeNegate(k2neg, k2p);
        k2p = new Point(Fp.mul(k2p.px, endo.beta), k2p.py, k2p.pz);
        point = k1p.add(k2p);
        fake = f1p.add(f2p);
      } else {
        const { p, f } = this.wNAF(n);
        point = p;
        fake = f;
      }
      // Normalize `z` for both points, but return only real one
      return Point.normalizeZ([point, fake])[0];
    }

    /**
     * Efficiently calculate `aP + bQ`. Unsafe, can expose private key, if used incorrectly.
     * @returns non-zero affine point
     */
    multiplyAndAddUnsafe(Q: Point, a: bigint, b: bigint): Point | undefined {
      const G = Point.BASE; // No Strauss-Shamir trick: we have 10% faster G precomputes
      const mul = (
        P: Point,
        a: bigint // Select faster multiply() method
      ) => (a === _0n || a === _1n || !P.equals(G) ? P.multiplyUnsafe(a) : P.multiply(a));
      const sum = mul(this, a).add(mul(Q, b));
      return sum.is0() ? undefined : sum;
    }

    // Converts Projective point to affine (x, y) coordinates.
    // Can accept precomputed Z^-1 - for example, from invertBatch.
    // (x, y, z) ∋ (x=x/z, y=y/z)
    toAffine(iz?: T): AffinePoint<T> {
      const { px: x, py: y, pz: z } = this;
      const is0 = this.is0();
      // If invZ was 0, we return zero point. However we still want to execute
      // all operations, so we replace invZ with a random number, 1.
      if (iz == null) iz = is0 ? Fp.ONE : Fp.inv(z);
      const ax = Fp.mul(x, iz);
      const ay = Fp.mul(y, iz);
      const zz = Fp.mul(z, iz);
      if (is0) return { x: Fp.ZERO, y: Fp.ZERO };
      if (!Fp.eql(zz, Fp.ONE)) throw new Error('invZ was invalid');
      return { x: ax, y: ay };
    }
    isTorsionFree(): boolean {
      const { h: cofactor, isTorsionFree } = CURVE;
      if (cofactor === _1n) return true; // No subgroups, always torsion-free
      if (isTorsionFree) return isTorsionFree(Point, this);
      throw new Error('isTorsionFree() has not been declared for the elliptic curve');
    }
    clearCofactor(): Point {
      const { h: cofactor, clearCofactor } = CURVE;
      if (cofactor === _1n) return this; // Fast-path
      if (clearCofactor) return clearCofactor(Point, this) as Point;
      return this.multiplyUnsafe(CURVE.h);
    }

    toRawBytes(isCompressed = true): Uint8Array {
      this.assertValidity();
      return CURVE.toBytes(Point, this, isCompressed);
    }

    toHex(isCompressed = true): string {
      return ut.bytesToHex(this.toRawBytes(isCompressed));
    }
  }
  const _bits = CURVE.nBitLength;
  const wnaf = wNAF(Point, CURVE.endo ? Math.ceil(_bits / 2) : _bits);

  return {
    ProjectivePoint: Point as ProjConstructor<T>,
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
  addRecoveryBit(recovery: number): SignatureType;
  hasHighS(): boolean;
  normalizeS(): SignatureType;
  recoverPublicKey(msgHash: Hex): ProjPointType<bigint>;
  toCompactRawBytes(): Uint8Array;
  toCompactHex(): string;
  // DER-encoded
  toDERRawBytes(isCompressed?: boolean): Uint8Array;
  toDERHex(isCompressed?: boolean): string;
}
// Static methods
export type SignatureConstructor = {
  new (r: bigint, s: bigint): SignatureType;
  fromCompact(hex: Hex): SignatureType;
  fromDER(hex: Hex): SignatureType;
};
type SignatureLike = { r: bigint; s: bigint };

export type PubKey = Hex | ProjPointType<bigint>;

export type CurveType = BasicCurve<bigint> & {
  // Default options
  lowS?: boolean;
  // Hashes
  hash: CHash; // Because we need outputLen for DRBG
  hmac: HmacFnSync;
  randomBytes: (bytesLength?: number) => Uint8Array;
  // truncateHash?: (hash: Uint8Array, truncateOnly?: boolean) => Uint8Array;
  bits2int?: (bytes: Uint8Array) => bigint;
  bits2int_modN?: (bytes: Uint8Array) => bigint;
};

function validateOpts(curve: CurveType) {
  const opts = validateAbsOpts(curve);
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
  getSharedSecret: (privateA: PrivKey, publicB: Hex, isCompressed?: boolean) => Uint8Array;
  sign: (msgHash: Hex, privKey: PrivKey, opts?: SignOpts) => SignatureType;
  verify: (signature: Hex | SignatureLike, msgHash: Hex, publicKey: Hex, opts?: VerOpts) => boolean;
  ProjectivePoint: ProjConstructor<bigint>;
  Signature: SignatureConstructor;
  utils: {
    _normalizePrivateKey: (key: PrivKey) => bigint;
    isValidPrivateKey(privateKey: PrivKey): boolean;
    hashToPrivateKey: (hash: Hex) => Uint8Array;
    randomPrivateKey: () => Uint8Array;
  };
};

const u8n = (data?: any) => new Uint8Array(data); // creates Uint8Array
const u8fr = (arr: any) => Uint8Array.from(arr); // another shortcut
// Minimal HMAC-DRBG from NIST 800-90 for RFC6979 sigs.
type Pred<T> = (v: Uint8Array) => T | undefined;
function hmacDrbg<T>(
  hashLen: number,
  qByteLen: number,
  hmacFn: HmacFnSync
): (seed: Uint8Array, predicate: Pred<T>) => T {
  if (typeof hashLen !== 'number' || hashLen < 2) throw new Error('hashLen must be a number');
  if (typeof qByteLen !== 'number' || qByteLen < 2) throw new Error('qByteLen must be a number');
  if (typeof hmacFn !== 'function') throw new Error('hmacFn must be a function');
  // Step B, Step C: set hashLen to 8*ceil(hlen/8)
  let v = u8n(hashLen); // Minimal non-full-spec HMAC-DRBG from NIST 800-90 for RFC6979 sigs.
  let k = u8n(hashLen); // Steps B and C of RFC6979 3.2: set hashLen, in our case always same
  let i = 0; // Iterations counter, will throw when over 1000
  const reset = () => {
    v.fill(1);
    k.fill(0);
    i = 0;
  };
  const h = (...b: Uint8Array[]) => hmacFn(k, v, ...b); // hmac(k)(v, ...values)
  const reseed = (seed = u8n()) => {
    // HMAC-DRBG reseed() function. Steps D-G
    k = h(u8fr([0x00]), seed); // k = hmac(k || v || 0x00 || seed)
    v = h(); // v = hmac(k || v)
    if (seed.length === 0) return;
    k = h(u8fr([0x01]), seed); // k = hmac(k || v || 0x01 || seed)
    v = h(); // v = hmac(k || v)
  };
  const gen = () => {
    // HMAC-DRBG generate() function
    if (i++ >= 1000) throw new Error('drbg: tried 1000 values');
    let len = 0;
    const out: Uint8Array[] = [];
    while (len < qByteLen) {
      v = h();
      const sl = v.slice();
      out.push(sl);
      len += v.length;
    }
    return ut.concatBytes(...out);
  };
  const genUntil = (seed: Uint8Array, pred: Pred<T>): T => {
    reset();
    reseed(seed); // Steps D-G
    let res: T | undefined = undefined; // Step H: grind until k is in [1..n-1]
    while (!(res = pred(gen()))) reseed();
    reset();
    return res;
  };
  return genUntil;
}
export function weierstrass(curveDef: CurveType): CurveFn {
  const CURVE = validateOpts(curveDef) as ReturnType<typeof validateOpts>;
  const CURVE_ORDER = CURVE.n;
  const Fp = CURVE.Fp;
  const compressedLen = Fp.BYTES + 1; // e.g. 33 for 32
  const uncompressedLen = 2 * Fp.BYTES + 1; // e.g. 65 for 32

  function isValidFieldElement(num: bigint): boolean {
    return _0n < num && num < Fp.ORDER; // 0 is banned since it's not invertible FE
  }
  function modN(a: bigint) {
    return mod.mod(a, CURVE_ORDER);
  }
  function invN(a: bigint) {
    return mod.invert(a, CURVE_ORDER);
  }

  const {
    ProjectivePoint: Point,
    normalizePrivateKey,
    weierstrassEquation,
    isWithinCurveOrder,
  } = weierstrassPoints({
    ...CURVE,
    toBytes(c, point, isCompressed: boolean): Uint8Array {
      const a = point.toAffine();
      const x = Fp.toBytes(a.x);
      const cat = ut.concatBytes;
      if (isCompressed) {
        // TODO: hasEvenY
        return cat(Uint8Array.from([point.hasEvenY() ? 0x02 : 0x03]), x);
      } else {
        return cat(Uint8Array.from([0x04]), x, Fp.toBytes(a.y));
      }
    },
    fromBytes(bytes: Uint8Array) {
      const len = bytes.length;
      const head = bytes[0];
      const tail = bytes.subarray(1);
      // this.assertValidity() is done inside of fromHex
      if (len === compressedLen && (head === 0x02 || head === 0x03)) {
        const x = ut.bytesToNumberBE(tail);
        if (!isValidFieldElement(x)) throw new Error('Point is not on curve');
        const y2 = weierstrassEquation(x); // y² = x³ + ax + b
        let y = Fp.sqrt(y2); // y = y² ^ (p+1)/4
        const isYOdd = (y & _1n) === _1n;
        // ECDSA
        const isHeadOdd = (head & 1) === 1;
        if (isHeadOdd !== isYOdd) y = Fp.neg(y);
        return { x, y };
      } else if (len === uncompressedLen && head === 0x04) {
        const x = Fp.fromBytes(tail.subarray(0, Fp.BYTES));
        const y = Fp.fromBytes(tail.subarray(Fp.BYTES, 2 * Fp.BYTES));
        return { x, y };
      } else {
        throw new Error(
          `Point.fromHex: received invalid point. Expected ${compressedLen} compressed bytes or ${uncompressedLen} uncompressed bytes, not ${len}`
        );
      }
    },
  });
  const numToNByteStr = (num: bigint): string =>
    ut.bytesToHex(ut.numberToBytesBE(num, CURVE.nByteLength));

  function isBiggerThanHalfOrder(number: bigint) {
    const HALF = CURVE_ORDER >> _1n;
    return number > HALF;
  }

  function normalizeS(s: bigint) {
    return isBiggerThanHalfOrder(s) ? modN(-s) : s;
  }
  // slice bytes num
  const slcNum = (b: Uint8Array, from: number, to: number) => ut.bytesToNumberBE(b.slice(from, to));

  /**
   * ECDSA signature with its (r, s) properties. Supports DER & compact representations.
   */
  class Signature implements SignatureType {
    constructor(readonly r: bigint, readonly s: bigint, readonly recovery?: number) {
      this.assertValidity();
    }

    // pair (bytes of r, bytes of s)
    static fromCompact(hex: Hex) {
      const gl = CURVE.nByteLength;
      hex = ensureBytes(hex, gl * 2);
      return new Signature(slcNum(hex, 0, gl), slcNum(hex, gl, 2 * gl));
    }

    // DER encoded ECDSA signature
    // https://bitcoin.stackexchange.com/questions/57644/what-are-the-parts-of-a-bitcoin-transaction-input-script
    static fromDER(hex: Hex) {
      if (typeof hex !== 'string' && !(hex instanceof Uint8Array))
        throw new Error(`Signature.fromDER: Expected string or Uint8Array`);
      const { r, s } = DER.toSig(ensureBytes(hex));
      return new Signature(r, s);
    }

    assertValidity(): void {
      // can use assertGE here
      if (!isWithinCurveOrder(this.r)) throw new Error('r must be 0 < r < n');
      if (!isWithinCurveOrder(this.s)) throw new Error('s must be 0 < s < n');
    }

    addRecoveryBit(recovery: number) {
      return new Signature(this.r, this.s, recovery);
    }

    recoverPublicKey(msgHash: Hex): typeof Point.BASE {
      const { n: N } = CURVE; // ECDSA public key recovery secg.org/sec1-v2.pdf 4.1.6
      const { r, s, recovery: rec } = this;
      const h = bits2int_modN(ensureBytes(msgHash)); // Truncate hash
      if (rec == null || ![0, 1, 2, 3].includes(rec)) throw new Error('recovery id invalid');
      const radj = rec === 2 || rec === 3 ? r + N : r;
      if (radj >= Fp.ORDER) throw new Error('recovery id 2 or 3 invalid');
      const prefix = (rec & 1) === 0 ? '02' : '03';
      const R = Point.fromHex(prefix + numToNByteStr(radj));
      const ir = invN(radj); // r^-1
      const u1 = modN(-h * ir); // -hr^-1
      const u2 = modN(s * ir); // sr^-1
      const Q = Point.BASE.multiplyAndAddUnsafe(R, u1, u2); //  (sr^-1)R-(hr^-1)G = -(hr^-1)G + (sr^-1)
      if (!Q) throw new Error('point at infinify'); // unsafe is fine: no priv data leaked
      Q.assertValidity();
      return Q;
    }

    // Signatures should be low-s, to prevent malleability.
    hasHighS(): boolean {
      return isBiggerThanHalfOrder(this.s);
    }

    normalizeS() {
      return this.hasHighS() ? new Signature(this.r, modN(-this.s), this.recovery) : this;
    }

    // DER-encoded
    toDERRawBytes() {
      return ut.hexToBytes(this.toDERHex());
    }
    toDERHex() {
      return DER.hexFromSig({ r: this.r, s: this.s });
    }

    // padded bytes of r, then padded bytes of s
    toCompactRawBytes() {
      return ut.hexToBytes(this.toCompactHex());
    }
    toCompactHex() {
      return numToNByteStr(this.r) + numToNByteStr(this.s);
    }
  }

  const utils = {
    isValidPrivateKey(privateKey: PrivKey) {
      try {
        normalizePrivateKey(privateKey);
        return true;
      } catch (error) {
        return false;
      }
    },
    _normalizePrivateKey: normalizePrivateKey,

    /**
     * Converts some bytes to a valid private key. Needs at least (nBitLength+64) bytes.
     */
    hashToPrivateKey: (hash: Hex): Uint8Array =>
      ut.numberToBytesBE(mod.hashToPrivateScalar(hash, CURVE_ORDER), CURVE.nByteLength),

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
    precompute(windowSize = 8, point = Point.BASE): typeof Point.BASE {
      point._setWindowSize(windowSize);
      point.multiply(BigInt(3));
      return point;
    },
  };

  /**
   * Computes public key for a private key. Checks for validity of the private key.
   * @param privateKey private key
   * @param isCompressed whether to return compact (default), or full key
   * @returns Public key, full when isCompressed=false; short when isCompressed=true
   */
  function getPublicKey(privateKey: PrivKey, isCompressed = true): Uint8Array {
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
   * ECDH (Elliptic Curve Diffie Hellman).
   * Computes shared public key from private key and public key.
   * Checks: 1) private key validity 2) shared key is on-curve
   * @param privateA private key
   * @param publicB different public key
   * @param isCompressed whether to return compact (default), or full key
   * @returns shared public key
   */
  function getSharedSecret(privateA: PrivKey, publicB: Hex, isCompressed = true): Uint8Array {
    if (isProbPub(privateA)) throw new Error('first arg must be private key');
    if (!isProbPub(publicB)) throw new Error('second arg must be public key');
    const b = Point.fromHex(publicB); // check for being on-curve
    return b.multiply(normalizePrivateKey(privateA)).toRawBytes(isCompressed);
  }

  // RFC6979: ensure ECDSA msg is X bytes and < N. RFC suggests optional truncating via bits2octets.
  // FIPS 186-4 4.6 suggests the leftmost min(nBitLen, outLen) bits, which matches bits2int.
  // bits2int can produce res>N, we can do mod(res, N) since the bitLen is the same.
  // int2octets can't be used; pads small msgs with 0: unacceptatble for trunc as per RFC vectors
  const bits2int =
    CURVE.bits2int ||
    function (bytes: Uint8Array): bigint {
      // For curves with nBitLength % 8 !== 0: bits2octets(bits2octets(m)) !== bits2octets(m)
      // for some cases, since bytes.length * 8 is not actual bitLength.
      const delta = bytes.length * 8 - CURVE.nBitLength; // truncate to nBitLength leftmost bits
      const num = ut.bytesToNumberBE(bytes); // check for == u8 done here
      return delta > 0 ? num >> BigInt(delta) : num;
    };
  const bits2int_modN =
    CURVE.bits2int_modN ||
    function (bytes: Uint8Array): bigint {
      return modN(bits2int(bytes)); // can't use bytesToNumberBE here
    };
  // NOTE: pads output with zero as per spec
  const ORDER_MASK = ut.bitMask(CURVE.nBitLength);
  function int2octets(num: bigint): Uint8Array {
    if (typeof num !== 'bigint') throw new Error('Expected bigint');
    if (!(_0n <= num && num < ORDER_MASK))
      throw new Error(`Expected number < 2^${CURVE.nBitLength}`);
    // works with order, can have different size than numToField!
    return ut.numberToBytesBE(num, CURVE.nByteLength);
  }

  // Steps A, D of RFC6979 3.2
  // Creates RFC6979 seed; converts msg/privKey to numbers.
  // Used only in sign, not in verify.
  // NOTE: we cannot assume here that msgHash has same amount of bytes as curve order, this will be wrong at least for P521.
  // Also it can be bigger for P224 + SHA256
  function prepSig(msgHash: Hex, privateKey: PrivKey, opts = defaultSigOpts) {
    if (msgHash == null) throw new Error(`sign: expected valid message hash, not "${msgHash}"`);
    if (['recovered', 'canonical'].some((k) => k in opts))
      // Ban legacy options
      throw new Error('sign() legacy options not supported');
    let { lowS, prehash, extraEntropy: ent } = opts; // generates low-s sigs by default
    if (prehash) msgHash = CURVE.hash(ensureBytes(msgHash));
    if (lowS == null) lowS = true; // RFC6979 3.2: we skip step A, because
    // Step A is ignored, since we already provide hash instead of msg

    // NOTE: instead of bits2int, we calling here truncateHash, since we need
    // custom truncation for stark. For other curves it is essentially same as calling bits2int + mod
    // However, we cannot later call bits2octets (which is truncateHash + int2octets), since nested bits2int is broken
    // for curves where nBitLength % 8 !== 0, so we unwrap it here as int2octets call.
    // const bits2octets = (bits)=>int2octets(bytesToNumberBE(truncateHash(bits)))
    const h1int = bits2int_modN(ensureBytes(msgHash));
    const h1octets = int2octets(h1int);

    const d = normalizePrivateKey(privateKey);
    // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1) || k')
    const seedArgs = [int2octets(d), h1octets];
    if (ent != null) {
      // RFC6979 3.6: additional k' (optional)
      if (ent === true) ent = CURVE.randomBytes(Fp.BYTES);
      const e = ensureBytes(ent);
      if (e.length !== Fp.BYTES) throw new Error(`sign: Expected ${Fp.BYTES} bytes of extra data`);
      seedArgs.push(e);
    }
    const seed = ut.concatBytes(...seedArgs); // Step D of RFC6979 3.2
    const m = h1int; // NOTE: no need to call bits2int second time here, it is inside truncateHash!
    // Converts signature params into point w r/s, checks result for validity.
    function k2sig(kBytes: Uint8Array): Signature | undefined {
      // RFC 6979 Section 3.2, step 3: k = bits2int(T)
      const k = bits2int(kBytes); // Cannot use fields methods, since it is group element
      if (!isWithinCurveOrder(k)) return; // Important: all mod() calls here must be done over N
      const ik = invN(k); // k^-1 mod n
      const q = Point.BASE.multiply(k).toAffine(); // q = Gk
      const r = modN(q.x); // r = q.x mod n
      if (r === _0n) return;
      const s = modN(ik * modN(m + modN(d * r))); // s = k^-1(m + rd) mod n
      if (s === _0n) return;
      let recovery = (q.x === r ? 0 : 2) | Number(q.y & _1n); // recovery bit (2 or 3, when q.x > n)
      let normS = s;
      if (lowS && isBiggerThanHalfOrder(s)) {
        normS = normalizeS(s); // if lowS was passed, ensure s is always
        recovery ^= 1; // // in the bottom half of N
      }
      return new Signature(r, normS, recovery); // use normS, not s
    }
    return { seed, k2sig };
  }
  const defaultSigOpts: SignOpts = { lowS: CURVE.lowS, prehash: false };
  const defaultVerOpts: VerOpts = { lowS: CURVE.lowS, prehash: false };

  /**
   * Signs message hash (not message: you need to hash it by yourself).
   * ```
   * sign(m, d, k) where
   *   (x, y) = G × k
   *   r = x mod n
   *   s = (m + dr)/k mod n
   * ```
   * @param opts `lowS, extraEntropy, prehash`
   */
  function sign(msgHash: Hex, privKey: PrivKey, opts = defaultSigOpts): Signature {
    const { seed, k2sig } = prepSig(msgHash, privKey, opts); // Steps A, D of RFC6979 3.2.
    const genUntil = hmacDrbg<Signature>(CURVE.hash.outputLen, CURVE.nByteLength, CURVE.hmac);
    return genUntil(seed, k2sig); // Steps B, C, D, E, F, G
  }

  // Enable precomputes. Slows down first publicKey computation by 20ms.
  Point.BASE._setWindowSize(8);
  // utils.precompute(8, ProjectivePoint.BASE)

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
    signature: Hex | { r: bigint; s: bigint },
    msgHash: Hex,
    publicKey: Hex,
    opts = defaultVerOpts
  ): boolean {
    let P: ProjPointType<bigint>;
    let _sig: Signature | undefined = undefined;
    if (publicKey instanceof Point) throw new Error('publicKey must be hex');
    try {
      if (signature && typeof signature === 'object' && !(signature instanceof Uint8Array)) {
        const { r, s } = signature;
        _sig = new Signature(r, s); // assertValidity() is executed on creation
      } else {
        // Signature can be represented in 2 ways: compact (2*nByteLength) & DER (variable-length).
        // Since DER can also be 2*nByteLength bytes, we check for it first.
        try {
          _sig = Signature.fromDER(signature as Hex);
        } catch (derError) {
          if (!(derError instanceof DER.Err)) throw derError;
          _sig = Signature.fromCompact(signature as Hex);
        }
      }
      msgHash = ensureBytes(msgHash);
      P = Point.fromHex(publicKey);
    } catch (error) {
      return false;
    }
    if (opts.lowS && _sig.hasHighS()) return false;
    if (opts.prehash) msgHash = CURVE.hash(msgHash);
    const { r, s } = _sig;
    const h = bits2int_modN(msgHash); // Cannot use fields methods, since it is group element
    const is = invN(s); // s^-1
    const u1 = modN(h * is); // u1 = hs^-1 mod n
    const u2 = modN(r * is); // u2 = rs^-1 mod n
    const R = Point.BASE.multiplyAndAddUnsafe(P, u1, u2)?.toAffine(); // R = u1⋅G + u2⋅P
    if (!R) return false;
    const v = modN(R.x);
    return v === r;
  }
  return {
    CURVE,
    getPublicKey,
    getSharedSecret,
    sign,
    verify,
    // Point,
    ProjectivePoint: Point,
    Signature,
    utils,
  };
}

// Implementation of the Shallue and van de Woestijne method for any Weierstrass curve

// TODO: check if there is a way to merge this with uvRatio in Edwards && move to modular?
// b = True and y = sqrt(u / v) if (u / v) is square in F, and
// b = False and y = sqrt(Z * (u / v)) otherwise.
export function SWUFpSqrtRatio<T>(Fp: mod.Field<T>, Z: T) {
  // Generic implementation
  const q = Fp.ORDER;
  let l = 0n;
  for (let o = q - 1n; o % 2n === 0n; o /= 2n) l += 1n;
  const c1 = l; // 1. c1, the largest integer such that 2^c1 divides q - 1.
  const c2 = (q - 1n) / 2n ** c1; // 2. c2 = (q - 1) / (2^c1)        # Integer arithmetic
  const c3 = (c2 - 1n) / 2n; // 3. c3 = (c2 - 1) / 2            # Integer arithmetic
  const c4 = 2n ** c1 - 1n; // 4. c4 = 2^c1 - 1                # Integer arithmetic
  const c5 = 2n ** (c1 - 1n); // 5. c5 = 2^(c1 - 1)              # Integer arithmetic
  const c6 = Fp.pow(Z, c2); // 6. c6 = Z^c2
  const c7 = Fp.pow(Z, (c2 + 1n) / 2n); // 7. c7 = Z^((c2 + 1) / 2)
  let sqrtRatio = (u: T, v: T): { isValid: boolean; value: T } => {
    let tv1 = c6; // 1. tv1 = c6
    let tv2 = Fp.pow(v, c4); // 2. tv2 = v^c4
    let tv3 = Fp.sqr(tv2); // 3. tv3 = tv2^2
    tv3 = Fp.mul(tv3, v); // 4. tv3 = tv3 * v
    let tv5 = Fp.mul(u, tv3); // 5. tv5 = u * tv3
    tv5 = Fp.pow(tv5, c3); // 6. tv5 = tv5^c3
    tv5 = Fp.mul(tv5, tv2); // 7. tv5 = tv5 * tv2
    tv2 = Fp.mul(tv5, v); // 8. tv2 = tv5 * v
    tv3 = Fp.mul(tv5, u); // 9. tv3 = tv5 * u
    let tv4 = Fp.mul(tv3, tv2); // 10. tv4 = tv3 * tv2
    tv5 = Fp.pow(tv4, c5); // 11. tv5 = tv4^c5
    let isQR = Fp.eql(tv5, Fp.ONE); // 12. isQR = tv5 == 1
    tv2 = Fp.mul(tv3, c7); // 13. tv2 = tv3 * c7
    tv5 = Fp.mul(tv4, tv1); // 14. tv5 = tv4 * tv1
    tv3 = Fp.cmov(tv2, tv3, isQR); // 15. tv3 = CMOV(tv2, tv3, isQR)
    tv4 = Fp.cmov(tv5, tv4, isQR); // 16. tv4 = CMOV(tv5, tv4, isQR)
    // 17. for i in (c1, c1 - 1, ..., 2):
    for (let i = c1; i > 1; i--) {
      let tv5 = 2n ** (i - 2n); // 18.    tv5 = i - 2;    19.    tv5 = 2^tv5
      let tvv5 = Fp.pow(tv4, tv5); // 20.    tv5 = tv4^tv5
      const e1 = Fp.eql(tvv5, Fp.ONE); // 21.    e1 = tv5 == 1
      tv2 = Fp.mul(tv3, tv1); // 22.    tv2 = tv3 * tv1
      tv1 = Fp.mul(tv1, tv1); // 23.    tv1 = tv1 * tv1
      tvv5 = Fp.mul(tv4, tv1); // 24.    tv5 = tv4 * tv1
      tv3 = Fp.cmov(tv2, tv3, e1); // 25.    tv3 = CMOV(tv2, tv3, e1)
      tv4 = Fp.cmov(tvv5, tv4, e1); // 26.    tv4 = CMOV(tv5, tv4, e1)
    }
    return { isValid: isQR, value: tv3 };
  };
  if (Fp.ORDER % 4n === 3n) {
    // sqrt_ratio_3mod4(u, v)
    const c1 = (Fp.ORDER - 3n) / 4n; // 1. c1 = (q - 3) / 4     # Integer arithmetic
    const c2 = Fp.sqrt(Fp.neg(Z)); // 2. c2 = sqrt(-Z)
    sqrtRatio = (u: T, v: T) => {
      let tv1 = Fp.sqr(v); // 1. tv1 = v^2
      const tv2 = Fp.mul(u, v); // 2. tv2 = u * v
      tv1 = Fp.mul(tv1, tv2); // 3. tv1 = tv1 * tv2
      let y1 = Fp.pow(tv1, c1); // 4. y1 = tv1^c1
      y1 = Fp.mul(y1, tv2); // 5. y1 = y1 * tv2
      const y2 = Fp.mul(y1, c2); // 6. y2 = y1 * c2
      const tv3 = Fp.mul(Fp.sqr(y1), v); // 7. tv3 = y1^2; 8. tv3 = tv3 * v
      const isQR = Fp.eql(tv3, u); // 9. isQR = tv3 == u
      let y = Fp.cmov(y2, y1, isQR); // 10. y = CMOV(y2, y1, isQR)
      return { isValid: isQR, value: y }; // 11. return (isQR, y) isQR ? y : y*c2
    };
  }
  // No curves uses that
  // if (Fp.ORDER % 8n === 5n) // sqrt_ratio_5mod8
  return sqrtRatio;
}
// From draft-irtf-cfrg-hash-to-curve-16
export function mapToCurveSimpleSWU<T>(
  Fp: mod.Field<T>,
  opts: {
    A: T;
    B: T;
    Z: T;
  }
) {
  mod.validateField(Fp);
  if (!Fp.isValid(opts.A) || !Fp.isValid(opts.B) || !Fp.isValid(opts.Z))
    throw new Error('mapToCurveSimpleSWU: invalid opts');
  const sqrtRatio = SWUFpSqrtRatio(Fp, opts.Z);
  if (!Fp.isOdd) throw new Error('Fp.isOdd is not implemented!');
  // Input: u, an element of F.
  // Output: (x, y), a point on E.
  return (u: T): { x: T; y: T } => {
    // prettier-ignore
    let tv1, tv2, tv3, tv4, tv5, tv6, x, y;
    tv1 = Fp.sqr(u); // 1.  tv1 = u^2
    tv1 = Fp.mul(tv1, opts.Z); // 2.  tv1 = Z * tv1
    tv2 = Fp.sqr(tv1); // 3.  tv2 = tv1^2
    tv2 = Fp.add(tv2, tv1); // 4.  tv2 = tv2 + tv1
    tv3 = Fp.add(tv2, Fp.ONE); // 5.  tv3 = tv2 + 1
    tv3 = Fp.mul(tv3, opts.B); // 6.  tv3 = B * tv3
    tv4 = Fp.cmov(opts.Z, Fp.neg(tv2), !Fp.eql(tv2, Fp.ZERO)); // 7.  tv4 = CMOV(Z, -tv2, tv2 != 0)
    tv4 = Fp.mul(tv4, opts.A); // 8.  tv4 = A * tv4
    tv2 = Fp.sqr(tv3); // 9.  tv2 = tv3^2
    tv6 = Fp.sqr(tv4); // 10. tv6 = tv4^2
    tv5 = Fp.mul(tv6, opts.A); // 11. tv5 = A * tv6
    tv2 = Fp.add(tv2, tv5); // 12. tv2 = tv2 + tv5
    tv2 = Fp.mul(tv2, tv3); // 13. tv2 = tv2 * tv3
    tv6 = Fp.mul(tv6, tv4); // 14. tv6 = tv6 * tv4
    tv5 = Fp.mul(tv6, opts.B); // 15. tv5 = B * tv6
    tv2 = Fp.add(tv2, tv5); // 16. tv2 = tv2 + tv5
    x = Fp.mul(tv1, tv3); // 17.   x = tv1 * tv3
    const { isValid, value } = sqrtRatio(tv2, tv6); // 18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)
    y = Fp.mul(tv1, u); // 19.   y = tv1 * u  -> Z * u^3 * y1
    y = Fp.mul(y, value); // 20.   y = y * y1
    x = Fp.cmov(x, tv3, isValid); // 21.   x = CMOV(x, tv3, is_gx1_square)
    y = Fp.cmov(y, value, isValid); // 22.   y = CMOV(y, y1, is_gx1_square)
    const e1 = Fp.isOdd!(u) === Fp.isOdd!(y); // 23.  e1 = sgn0(u) == sgn0(y)
    y = Fp.cmov(Fp.neg(y), y, e1); // 24.   y = CMOV(-y, y, e1)
    x = Fp.div(x, tv4); // 25.   x = x / tv4
    return { x, y };
  };
}
