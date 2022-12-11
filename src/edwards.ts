/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// Implementation of Twisted Edwards curve. The formula is: ax² + y² = 1 + dx²y²

// Differences with @noble/ed25519:
// 1. EDDSA & ECDH have different field element lengths (for ed448/x448 only)
//     https://www.rfc-editor.org/rfc/rfc8032.html says bitLength is 456 (57 bytes)
//     https://www.rfc-editor.org/rfc/rfc7748 says bitLength is 448 (56 bytes)
// 2. Different addition formula (doubling is same)
// 3. uvRatio differs between curves (half-expected, not only pow fn changes)
// 4. Point decompression code is different too (unexpected), now using generalized formula
// 5. Domain function was no-op for ed25519, but adds some data even with empty context for ed448

import * as mod from './modular.js';
import {
  bytesToHex,
  concatBytes,
  ensureBytes,
  numberToBytesLE,
  nLength,
  hashToPrivateScalar,
} from './utils.js';
import { wNAF } from './group.js';

// Be friendly to bad ECMAScript parsers by not using bigint literals like 123n
const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);
const _8n = BigInt(8);

export type CHash = {
  (message: Uint8Array | string): Uint8Array;
  blockLen: number;
  outputLen: number;
  create(): any;
};

export type CurveType = {
  // Params: a, d
  a: bigint;
  d: bigint;
  // Field over which we'll do calculations. Verify with:
  P: bigint;
  // Subgroup order: how many points ed25519 has
  n: bigint; // in rfc8032 called l
  // Cofactor
  h: bigint;
  nBitLength?: number;
  nByteLength?: number;
  // Base point (x, y) aka generator point
  Gx: bigint;
  Gy: bigint;
  // Hashes
  hash: CHash; // Because we need outputLen for DRBG
  randomBytes: (bytesLength?: number) => Uint8Array;
  adjustScalarBytes?: (bytes: Uint8Array) => Uint8Array;
  domain?: (data: Uint8Array, ctx: Uint8Array, phflag: boolean) => Uint8Array;
  uvRatio?: (u: bigint, v: bigint) => { isValid: boolean; value: bigint };
  preHash?: CHash;
  // ECDH related
  // Other constants
  a24: bigint; // Related to d, but cannot be derived from it
  // ECDH bits (can be different from N bits)
  montgomeryBits?: number;
  basePointU?: string; // TODO: why not bigint?
  powPminus2?: (x: bigint) => bigint;
  UfromPoint?: (p: PointType) => Uint8Array;
};

// We accept hex strings besides Uint8Array for simplicity
type Hex = Uint8Array | string;
// Very few implementations accept numbers, we do it to ease learning curve
type PrivKey = Hex | bigint | number;

// Should be separate from overrides, since overrides can use information about curve (for example nBits)
function validateOpts(curve: CurveType) {
  if (typeof curve.hash !== 'function' || !Number.isSafeInteger(curve.hash.outputLen))
    throw new Error('Invalid hash function');
  for (const i of ['a', 'd', 'P', 'n', 'h', 'Gx', 'Gy', 'a24'] as const) {
    if (typeof curve[i] !== 'bigint')
      throw new Error(`Invalid curve param ${i}=${curve[i]} (${typeof curve[i]})`);
  }
  for (const i of ['nBitLength', 'nByteLength', 'montgomeryBits'] as const) {
    if (curve[i] === undefined) continue; // Optional
    if (!Number.isSafeInteger(curve[i]))
      throw new Error(`Invalid curve param ${i}=${curve[i]} (${typeof curve[i]})`);
  }
  for (const fn of ['randomBytes'] as const) {
    if (typeof curve[fn] !== 'function') throw new Error(`Invalid ${fn} function`);
  }
  for (const fn of [
    'adjustScalarBytes',
    'domain',
    'uvRatio',
    'powPminus2',
    'UfromPoint',
  ] as const) {
    if (curve[fn] === undefined) continue; // Optional
    if (typeof curve[fn] !== 'function') throw new Error(`Invalid ${fn} function`);
  }
  for (const i of ['basePointU'] as const) {
    if (curve[i] === undefined) continue; // Optional
    if (typeof curve[i] !== 'string')
      throw new Error(`Invalid curve param ${i}=${curve[i]} (${typeof curve[i]})`);
  }
  // Set defaults
  return Object.freeze({ ...nLength(curve.n, curve.nBitLength), ...curve } as const);
}

// Instance
export interface SignatureType {
  readonly r: PointType;
  readonly s: bigint;
  assertValidity(): SignatureType;
  toRawBytes(): Uint8Array;
  toHex(): string;
}
// Static methods
export type SignatureConstructor = {
  new (r: PointType, s: bigint): SignatureType;
  fromHex(hex: Hex): SignatureType;
};

// Instance
export interface ExtendedPointType {
  readonly x: bigint;
  readonly y: bigint;
  readonly z: bigint;
  readonly t: bigint;
  equals(other: ExtendedPointType): boolean;
  negate(): ExtendedPointType;
  double(): ExtendedPointType;
  add(other: ExtendedPointType): ExtendedPointType;
  subtract(other: ExtendedPointType): ExtendedPointType;
  multiply(scalar: number | bigint, affinePoint?: PointType): ExtendedPointType;
  multiplyUnsafe(scalar: number | bigint): ExtendedPointType;
  isSmallOrder(): boolean;
  isTorsionFree(): boolean;
  toAffine(invZ?: bigint): PointType;
}
// Static methods
export type ExtendedPointConstructor = {
  new (x: bigint, y: bigint, z: bigint, t: bigint): ExtendedPointType;
  BASE: ExtendedPointType;
  ZERO: ExtendedPointType;
  fromAffine(p: PointType): ExtendedPointType;
  toAffineBatch(points: ExtendedPointType[]): PointType[];
  normalizeZ(points: ExtendedPointType[]): ExtendedPointType[];
};

// Instance
export interface PointType {
  readonly x: bigint;
  readonly y: bigint;
  _setWindowSize(windowSize: number): void;
  toRawBytes(isCompressed?: boolean): Uint8Array;
  toHex(isCompressed?: boolean): string;
  isTorsionFree(): boolean;
  equals(other: PointType): boolean;
  negate(): PointType;
  add(other: PointType): PointType;
  subtract(other: PointType): PointType;
  multiply(scalar: number | bigint): PointType;
}
// Static methods
export type PointConstructor = {
  BASE: PointType;
  ZERO: PointType;
  new (x: bigint, y: bigint): PointType;
  fromHex(hex: Hex): PointType;
  fromPrivateKey(privateKey: PrivKey): PointType;
};

export type PubKey = Hex | PointType;
export type SigType = Hex | SignatureType;

export type CurveFn = {
  CURVE: ReturnType<typeof validateOpts>;
  getPublicKey: (privateKey: PrivKey, isCompressed?: boolean) => Uint8Array;
  getSharedSecret: (privateKey: PrivKey, publicKey: Hex) => Uint8Array;
  sign: (message: Hex, privateKey: Hex) => Uint8Array;
  verify: (sig: SigType, message: Hex, publicKey: PubKey) => boolean;
  Point: PointConstructor;
  ExtendedPoint: ExtendedPointConstructor;
  Signature: SignatureConstructor;
  montgomeryCurve: {
    BASE_POINT_U: string;
    UfromPoint: (p: PointType) => Uint8Array;
    scalarMult: (u: Hex, scalar: Hex) => Uint8Array;
    scalarMultBase: (scalar: Hex) => Uint8Array;
    getPublicKey: (privateKey: Hex) => Uint8Array;
    getSharedSecret: (privateKey: Hex, publicKey: Hex) => Uint8Array;
  };
  utils: {
    mod: (a: bigint, b?: bigint) => bigint;
    invert: (number: bigint, modulo?: bigint) => bigint;
    randomPrivateKey: () => Uint8Array;
    getExtendedPublicKey: (key: PrivKey) => {
      head: Uint8Array;
      prefix: Uint8Array;
      scalar: bigint;
      point: PointType;
      pointBytes: Uint8Array;
    };
  };
};

// NOTE: it is not generic twisted curve for now, but ed25519/ed448 generic implementation
export function twistedEdwards(curveDef: CurveType): CurveFn {
  const CURVE = validateOpts(curveDef) as ReturnType<typeof validateOpts>;
  const CURVE_ORDER = CURVE.n;
  const fieldLen = CURVE.nByteLength; // 32 (length of one field element)
  if (fieldLen > 2048) throw new Error('Field lengths over 2048 are not supported');
  const groupLen = CURVE.nByteLength;
  // (2n ** 256n).toString(16);
  const maxGroupElement = _2n ** BigInt(groupLen * 8); // previous POW_2_256

  // Function overrides
  const { P, randomBytes } = CURVE;
  const modP = (a: bigint) => mod.mod(a, P);

  // sqrt(u/v)
  function _uvRatio(u: bigint, v: bigint) {
    try {
      const value = mod.sqrt(u * mod.invert(v, P), P);
      return { isValid: true, value };
    } catch (e) {
      return { isValid: false, value: _0n };
    }
  }
  const uvRatio = CURVE.uvRatio || _uvRatio;

  const _powPminus2 = (x: bigint) => mod.pow(x, P - _2n, P);
  const powPminus2 = CURVE.powPminus2 || _powPminus2;
  const _adjustScalarBytes = (bytes: Uint8Array) => bytes; // NOOP
  const adjustScalarBytes = CURVE.adjustScalarBytes || _adjustScalarBytes;
  function _domain(data: Uint8Array, ctx: Uint8Array, phflag: boolean) {
    if (ctx.length || phflag) throw new Error('Contexts/pre-hash are not supported');
    return data;
  }
  const domain = CURVE.domain || _domain; // NOOP

  /**
   * Extended Point works in extended coordinates: (x, y, z, t) ∋ (x=x/z, y=y/z, t=xy).
   * Default Point works in affine coordinates: (x, y)
   * https://en.wikipedia.org/wiki/Twisted_Edwards_curve#Extended_coordinates
   */
  class ExtendedPoint implements ExtendedPointType {
    constructor(readonly x: bigint, readonly y: bigint, readonly z: bigint, readonly t: bigint) {}

    static BASE = new ExtendedPoint(CURVE.Gx, CURVE.Gy, _1n, modP(CURVE.Gx * CURVE.Gy));
    static ZERO = new ExtendedPoint(_0n, _1n, _1n, _0n);
    static fromAffine(p: Point): ExtendedPoint {
      if (!(p instanceof Point)) {
        throw new TypeError('ExtendedPoint#fromAffine: expected Point');
      }
      if (p.equals(Point.ZERO)) return ExtendedPoint.ZERO;
      return new ExtendedPoint(p.x, p.y, _1n, modP(p.x * p.y));
    }
    // Takes a bunch of Jacobian Points but executes only one
    // invert on all of them. invert is very slow operation,
    // so this improves performance massively.
    static toAffineBatch(points: ExtendedPoint[]): Point[] {
      const toInv = mod.invertBatch(
        points.map((p) => p.z),
        P
      );
      return points.map((p, i) => p.toAffine(toInv[i]));
    }

    static normalizeZ(points: ExtendedPoint[]): ExtendedPoint[] {
      return this.toAffineBatch(points).map(this.fromAffine);
    }

    // Compare one point to another.
    equals(other: ExtendedPoint): boolean {
      assertExtPoint(other);
      const { x: X1, y: Y1, z: Z1 } = this;
      const { x: X2, y: Y2, z: Z2 } = other;
      const X1Z2 = modP(X1 * Z2);
      const X2Z1 = modP(X2 * Z1);
      const Y1Z2 = modP(Y1 * Z2);
      const Y2Z1 = modP(Y2 * Z1);
      return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
    }

    // Inverses point to one corresponding to (x, -y) in Affine coordinates.
    negate(): ExtendedPoint {
      return new ExtendedPoint(modP(-this.x), this.y, this.z, modP(-this.t));
    }

    // Fast algo for doubling Extended Point.
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#doubling-dbl-2008-hwcd
    // Cost: 4M + 4S + 1*a + 6add + 1*2.
    double(): ExtendedPoint {
      const { a } = CURVE;
      const { x: X1, y: Y1, z: Z1 } = this;
      const A = modP(X1 * X1); // A = X12
      const B = modP(Y1 * Y1); // B = Y12
      const C = modP(_2n * modP(Z1 * Z1)); // C = 2*Z12
      const D = modP(a * A); // D = a*A
      const x1y1 = X1 + Y1;
      const E = modP(modP(x1y1 * x1y1) - A - B); // E = (X1+Y1)2-A-B
      const G = D + B; // G = D+B
      const F = G - C; // F = G-C
      const H = D - B; // H = D-B
      const X3 = modP(E * F); // X3 = E*F
      const Y3 = modP(G * H); // Y3 = G*H
      const T3 = modP(E * H); // T3 = E*H
      const Z3 = modP(F * G); // Z3 = F*G
      return new ExtendedPoint(X3, Y3, Z3, T3);
    }

    // Fast algo for adding 2 Extended Points.
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#addition-add-2008-hwcd
    // Cost: 9M + 1*a + 1*d + 7add.
    add(other: ExtendedPoint) {
      assertExtPoint(other);
      const { a, d } = CURVE;
      const { x: X1, y: Y1, z: Z1, t: T1 } = this;
      const { x: X2, y: Y2, z: Z2, t: T2 } = other;
      const A = modP(X1 * X2); // A = X1*X2
      const B = modP(Y1 * Y2); // B = Y1*Y2
      const C = modP(T1 * d * T2); // C = T1*d*T2
      const D = modP(Z1 * Z2); // D = Z1*Z2
      const E = modP((X1 + Y1) * (X2 + Y2) - A - B); // E = (X1+Y1)*(X2+Y2)-A-B
      // TODO: do we need to check for same point here? Looks like working without it
      const F = D - C; // F = D-C
      const G = D + C; // G = D+C
      const H = modP(B - a * A); // H = B-a*A
      const X3 = modP(E * F); // X3 = E*F
      const Y3 = modP(G * H); // Y3 = G*H
      const T3 = modP(E * H); // T3 = E*H
      const Z3 = modP(F * G); // Z3 = F*G

      return new ExtendedPoint(X3, Y3, Z3, T3);
    }

    subtract(other: ExtendedPoint): ExtendedPoint {
      return this.add(other.negate());
    }

    private wNAF(n: bigint, affinePoint?: Point): ExtendedPoint {
      if (!affinePoint && this.equals(ExtendedPoint.BASE)) affinePoint = Point.BASE;
      const W = (affinePoint && affinePoint._WINDOW_SIZE) || 1;
      let precomputes = affinePoint && pointPrecomputes.get(affinePoint);
      if (!precomputes) {
        precomputes = wnaf.precomputeWindow(this, W) as ExtendedPoint[];
        if (affinePoint && W !== 1) {
          precomputes = ExtendedPoint.normalizeZ(precomputes);
          pointPrecomputes.set(affinePoint, precomputes);
        }
      }
      const { p, f } = wnaf.wNAF(W, precomputes, n);
      return ExtendedPoint.normalizeZ([p, f])[0];
    }

    // Constant time multiplication.
    // Uses wNAF method. Windowed method may be 10% faster,
    // but takes 2x longer to generate and consumes 2x memory.
    multiply(scalar: number | bigint, affinePoint?: Point): ExtendedPoint {
      return this.wNAF(normalizeScalar(scalar, CURVE_ORDER), affinePoint);
    }

    // Non-constant-time multiplication. Uses double-and-add algorithm.
    // It's faster, but should only be used when you don't care about
    // an exposed private key e.g. sig verification.
    // Allows scalar bigger than curve order, but less than 2^256
    multiplyUnsafe(scalar: number | bigint): ExtendedPoint {
      let n = normalizeScalar(scalar, CURVE_ORDER, false);
      const G = ExtendedPoint.BASE;
      const P0 = ExtendedPoint.ZERO;
      if (n === _0n) return P0;
      if (this.equals(P0) || n === _1n) return this;
      if (this.equals(G)) return this.wNAF(n);
      return wnaf.unsafeLadder(this, n);
    }

    // Multiplies point by cofactor and checks if the result is 0.
    isSmallOrder(): boolean {
      return this.multiplyUnsafe(CURVE.h).equals(ExtendedPoint.ZERO);
    }

    // Multiplies point by a very big scalar n and checks if the result is 0.
    isTorsionFree(): boolean {
      return this.multiplyUnsafe(CURVE_ORDER).equals(ExtendedPoint.ZERO);
    }

    // Converts Extended point to default (x, y) coordinates.
    // Can accept precomputed Z^-1 - for example, from invertBatch.
    toAffine(invZ?: bigint): Point {
      const { x, y, z } = this;
      const is0 = this.equals(ExtendedPoint.ZERO);
      if (invZ == null) invZ = is0 ? _8n : mod.invert(z, P); // 8 was chosen arbitrarily
      const ax = modP(x * invZ);
      const ay = modP(y * invZ);
      const zz = modP(z * invZ);
      if (is0) return Point.ZERO;
      if (zz !== _1n) throw new Error('invZ was invalid');
      return new Point(ax, ay);
    }
  }
  const wnaf = wNAF(ExtendedPoint, groupLen * 8);

  function assertExtPoint(other: unknown) {
    if (!(other instanceof ExtendedPoint)) throw new TypeError('ExtendedPoint expected');
  }
  // Stores precomputed values for points.
  const pointPrecomputes = new WeakMap<Point, ExtendedPoint[]>();

  /**
   * Default Point works in affine coordinates: (x, y)
   */
  class Point implements PointType {
    // Base point aka generator
    // public_key = Point.BASE * private_key
    static BASE: Point = new Point(CURVE.Gx, CURVE.Gy);
    // Identity point aka point at infinity
    // point = point + zero_point
    static ZERO: Point = new Point(_0n, _1n);
    // We calculate precomputes for elliptic curve point multiplication
    // using windowed method. This specifies window size and
    // stores precomputed values. Usually only base point would be precomputed.
    _WINDOW_SIZE?: number;

    constructor(readonly x: bigint, readonly y: bigint) {}

    // "Private method", don't use it directly.
    _setWindowSize(windowSize: number) {
      this._WINDOW_SIZE = windowSize;
      pointPrecomputes.delete(this);
    }

    // Converts hash string or Uint8Array to Point.
    // Uses algo from RFC8032 5.1.3.
    static fromHex(hex: Hex, strict = true) {
      const { d, P, a } = CURVE;
      hex = ensureBytes(hex, fieldLen);
      // 1.  First, interpret the string as an integer in little-endian
      // representation. Bit 255 of this number is the least significant
      // bit of the x-coordinate and denote this value x_0.  The
      // y-coordinate is recovered simply by clearing this bit.  If the
      // resulting value is >= p, decoding fails.
      const normed = hex.slice();
      const lastByte = hex[fieldLen - 1];
      normed[fieldLen - 1] = lastByte & ~0x80;
      const y = bytesToNumberLE(normed);

      if (strict && y >= P) throw new Error('Expected 0 < hex < P');
      if (!strict && y >= maxGroupElement) throw new Error('Expected 0 < hex < 2**256');

      // 2.  To recover the x-coordinate, the curve equation implies
      // Ed25519: x² = (y² - 1) / (d y² + 1) (mod p).
      // Ed448: x² = (y² - 1) / (d y² - 1) (mod p).
      // For generic case:
      // a*x²+y²=1+d*x²*y²
      // -> y²-1 = d*x²*y²-a*x²
      // -> y²-1 = x² (d*y²-a)
      // -> x² = (y²-1) / (d*y²-a)

      // The denominator is always non-zero mod p.  Let u = y² - 1 and v = d y² + 1.
      const y2 = modP(y * y);
      const u = modP(y2 - _1n);
      const v = modP(d * y2 - a);
      let { isValid, value: x } = uvRatio(u, v);
      if (!isValid) throw new Error('Point.fromHex: invalid y coordinate');
      // 4.  Finally, use the x_0 bit to select the right square root.  If
      // x = 0, and x_0 = 1, decoding fails.  Otherwise, if x_0 != x mod
      // 2, set x <-- p - x.  Return the decoded point (x,y).
      const isXOdd = (x & _1n) === _1n;
      const isLastByteOdd = (lastByte & 0x80) !== 0;
      if (isLastByteOdd !== isXOdd) x = modP(-x);
      return new Point(x, y);
    }

    static fromPrivateKey(privateKey: PrivKey) {
      return getExtendedPublicKey(privateKey).point;
    }

    // There can always be only two x values (x, -x) for any y
    // When compressing point, it's enough to only store its y coordinate
    // and use the last byte to encode sign of x.
    toRawBytes(): Uint8Array {
      const bytes = numberToBytesLE(this.y, fieldLen);
      bytes[fieldLen - 1] |= this.x & _1n ? 0x80 : 0;
      return bytes;
    }

    // Same as toRawBytes, but returns string.
    toHex(): string {
      return bytesToHex(this.toRawBytes());
    }

    isTorsionFree(): boolean {
      return ExtendedPoint.fromAffine(this).isTorsionFree();
    }

    equals(other: Point): boolean {
      return this.x === other.x && this.y === other.y;
    }

    negate() {
      return new Point(modP(-this.x), this.y);
    }

    add(other: Point) {
      return ExtendedPoint.fromAffine(this).add(ExtendedPoint.fromAffine(other)).toAffine();
    }

    subtract(other: Point) {
      return this.add(other.negate());
    }

    /**
     * Constant time multiplication.
     * @param scalar Big-Endian number
     * @returns new point
     */
    multiply(scalar: number | bigint): Point {
      return ExtendedPoint.fromAffine(this).multiply(scalar, this).toAffine();
    }
  }

  /**
   * EDDSA signature.
   */
  class Signature implements SignatureType {
    constructor(readonly r: Point, readonly s: bigint) {
      this.assertValidity();
    }

    static fromHex(hex: Hex) {
      const bytes = ensureBytes(hex, 2 * fieldLen);
      const r = Point.fromHex(bytes.slice(0, fieldLen), false);
      const s = bytesToNumberLE(bytes.slice(fieldLen, 2 * fieldLen));
      return new Signature(r, s);
    }

    assertValidity() {
      const { r, s } = this;
      if (!(r instanceof Point)) throw new Error('Expected Point instance');
      // 0 <= s < l
      normalizeScalar(s, CURVE_ORDER, false);
      return this;
    }

    toRawBytes() {
      return concatBytes(this.r.toRawBytes(), numberToBytesLE(this.s, fieldLen));
    }

    toHex() {
      return bytesToHex(this.toRawBytes());
    }
  }

  // Little Endian
  function bytesToNumberLE(uint8a: Uint8Array): bigint {
    if (!(uint8a instanceof Uint8Array)) throw new Error('Expected Uint8Array');
    return BigInt('0x' + bytesToHex(Uint8Array.from(uint8a).reverse()));
  }

  // -------------------------
  // Little-endian SHA512 with modulo n
  function modlLE(hash: Uint8Array): bigint {
    return mod.mod(bytesToNumberLE(hash), CURVE_ORDER);
  }

  /**
   * Checks for num to be in range:
   * For strict == true:  `0 <  num < max`.
   * For strict == false: `0 <= num < max`.
   * Converts non-float safe numbers to bigints.
   */
  function normalizeScalar(num: number | bigint, max: bigint, strict = true): bigint {
    if (!max) throw new TypeError('Specify max value');
    if (typeof num === 'number' && Number.isSafeInteger(num)) num = BigInt(num);
    if (typeof num === 'bigint' && num < max) {
      if (strict) {
        if (_0n < num) return num;
      } else {
        if (_0n <= num) return num;
      }
    }
    throw new TypeError('Expected valid scalar: 0 < scalar < max');
  }

  function checkPrivateKey(key: PrivKey) {
    // Normalize bigint / number / string to Uint8Array
    key =
      typeof key === 'bigint' || typeof key === 'number'
        ? numberToBytesLE(normalizeScalar(key, maxGroupElement), groupLen)
        : ensureBytes(key);
    if (key.length !== groupLen) throw new Error(`Expected ${groupLen} bytes, got ${key.length}`);
    return key;
  }

  // Takes 64 bytes
  function getKeyFromHash(hashed: Uint8Array) {
    // First 32 bytes of 64b uniformingly random input are taken,
    // clears 3 bits of it to produce a random field element.
    const head = adjustScalarBytes(hashed.slice(0, groupLen));
    // Second 32 bytes is called key prefix (5.1.6)
    const prefix = hashed.slice(groupLen, 2 * groupLen);
    // The actual private scalar
    const scalar = modlLE(head);
    // Point on Edwards curve aka public key
    const point = Point.BASE.multiply(scalar);
    const pointBytes = point.toRawBytes();
    return { head, prefix, scalar, point, pointBytes };
  }

  /** Convenience method that creates public key and other stuff. RFC8032 5.1.5 */
  function getExtendedPublicKey(key: PrivKey) {
    return getKeyFromHash(CURVE.hash(checkPrivateKey(key)));
  }

  /**
   * Calculates ed25519 public key. RFC8032 5.1.5
   * 1. private key is hashed with sha512, then first 32 bytes are taken from the hash
   * 2. 3 least significant bits of the first byte are cleared
   */
  function getPublicKey(privateKey: PrivKey): Uint8Array {
    return getExtendedPublicKey(privateKey).pointBytes;
  }

  const EMPTY = new Uint8Array();
  function hashDomainToScalar(message: Uint8Array, context: Hex = EMPTY) {
    context = ensureBytes(context);
    return modlLE(CURVE.hash(domain(message, context, !!CURVE.preHash)));
  }

  /** Signs message with privateKey. RFC8032 5.1.6 */
  function sign(message: Hex, privateKey: Hex, context?: Hex): Uint8Array {
    message = ensureBytes(message);
    if (CURVE.preHash) message = CURVE.preHash(message);
    const { prefix, scalar, pointBytes } = getExtendedPublicKey(privateKey);
    const r = hashDomainToScalar(concatBytes(prefix, message), context);
    const R = Point.BASE.multiply(r); // R = rG
    const k = hashDomainToScalar(concatBytes(R.toRawBytes(), pointBytes, message), context); // k = hash(R+P+msg)
    const s = mod.mod(r + k * scalar, CURVE_ORDER); // s = r + kp
    return new Signature(R, s).toRawBytes();
  }

  /**
   * Verifies EdDSA signature against message and public key.
   * An extended group equation is checked.
   * RFC8032 5.1.7
   * Compliant with ZIP215:
   * 0 <= sig.R/publicKey < 2**256 (can be >= curve.P)
   * 0 <= sig.s < l
   * Not compliant with RFC8032: it's not possible to comply to both ZIP & RFC at the same time.
   */
  function verify(sig: SigType, message: Hex, publicKey: PubKey, context?: Hex): boolean {
    message = ensureBytes(message);
    if (CURVE.preHash) message = CURVE.preHash(message);
    // When hex is passed, we check public key fully.
    // When Point instance is passed, we assume it has already been checked, for performance.
    // If user passes Point/Sig instance, we assume it has been already verified.
    // We don't check its equations for performance. We do check for valid bounds for s though
    // We always check for: a) s bounds. b) hex validity
    if (publicKey instanceof Point) {
      // ignore
    } else if (publicKey instanceof Uint8Array || typeof publicKey === 'string') {
      publicKey = Point.fromHex(publicKey, false);
    } else {
      throw new Error(`Invalid publicKey: ${publicKey}`);
    }

    if (sig instanceof Signature) sig.assertValidity();
    else if (sig instanceof Uint8Array || typeof sig === 'string') sig = Signature.fromHex(sig);
    else throw new Error(`Wrong signature: ${sig}`);

    const { r, s } = sig;
    const SB = ExtendedPoint.BASE.multiplyUnsafe(s);
    const k = hashDomainToScalar(
      concatBytes(r.toRawBytes(), publicKey.toRawBytes(), message),
      context
    );
    const kA = ExtendedPoint.fromAffine(publicKey).multiplyUnsafe(k);
    const RkA = ExtendedPoint.fromAffine(r).add(kA);
    // [8][S]B = [8]R + [8][k]A'
    return RkA.subtract(SB).multiplyUnsafe(CURVE.h).equals(ExtendedPoint.ZERO);
  }

  // Enable precomputes. Slows down first publicKey computation by 20ms.
  Point.BASE._setWindowSize(8);

  // ECDH (X22519/X448)
  // https://datatracker.ietf.org/doc/html/rfc7748
  // Every twisted Edwards curve is birationally equivalent to an elliptic curve in Montgomery form and vice versa.
  const montgomeryBits = CURVE.montgomeryBits || CURVE.nBitLength;
  const montgomeryBytes = Math.ceil(montgomeryBits / 8);

  // cswap from RFC7748
  function cswap(swap: bigint, x_2: bigint, x_3: bigint): [bigint, bigint] {
    const dummy = modP(swap * (x_2 - x_3));
    x_2 = modP(x_2 - dummy);
    x_3 = modP(x_3 + dummy);
    return [x_2, x_3];
  }

  // x25519 from 4
  /**
   *
   * @param pointU u coordinate (x) on Montgomery Curve 25519
   * @param scalar by which the point would be multiplied
   * @returns new Point on Montgomery curve
   */
  function montgomeryLadder(pointU: bigint, scalar: bigint): bigint {
    const { P } = CURVE;
    const u = normalizeScalar(pointU, P);
    // Section 5: Implementations MUST accept non-canonical values and process them as
    // if they had been reduced modulo the field prime.
    const k = normalizeScalar(scalar, P);
    // The constant a24 is (486662 - 2) / 4 = 121665 for curve25519/X25519
    const a24 = CURVE.a24;
    const x_1 = u;
    let x_2 = _1n;
    let z_2 = _0n;
    let x_3 = u;
    let z_3 = _1n;
    let swap = _0n;
    let sw: [bigint, bigint];
    for (let t = BigInt(montgomeryBits - 1); t >= _0n; t--) {
      const k_t = (k >> t) & _1n;
      swap ^= k_t;
      sw = cswap(swap, x_2, x_3);
      x_2 = sw[0];
      x_3 = sw[1];
      sw = cswap(swap, z_2, z_3);
      z_2 = sw[0];
      z_3 = sw[1];
      swap = k_t;

      const A = x_2 + z_2;
      const AA = modP(A * A);
      const B = x_2 - z_2;
      const BB = modP(B * B);
      const E = AA - BB;
      const C = x_3 + z_3;
      const D = x_3 - z_3;
      const DA = modP(D * A);
      const CB = modP(C * B);
      const dacb = DA + CB;
      const da_cb = DA - CB;
      x_3 = modP(dacb * dacb);
      z_3 = modP(x_1 * modP(da_cb * da_cb));
      x_2 = modP(AA * BB);
      z_2 = modP(E * (AA + modP(a24 * E)));
    }
    // (x_2, x_3) = cswap(swap, x_2, x_3)
    sw = cswap(swap, x_2, x_3);
    x_2 = sw[0];
    x_3 = sw[1];
    // (z_2, z_3) = cswap(swap, z_2, z_3)
    sw = cswap(swap, z_2, z_3);
    z_2 = sw[0];
    z_3 = sw[1];
    // z_2^(p - 2)
    const z2 = powPminus2(z_2);
    // Return x_2 * (z_2^(p - 2))
    return modP(x_2 * z2);
  }

  function encodeUCoordinate(u: bigint): Uint8Array {
    return numberToBytesLE(modP(u), montgomeryBytes);
  }

  function decodeUCoordinate(uEnc: Hex): bigint {
    const u = ensureBytes(uEnc, montgomeryBytes);
    // Section 5: When receiving such an array, implementations of X25519
    // MUST mask the most significant bit in the final byte.
    // This is very ugly way, but it works because fieldLen-1 is outside of bounds for X448, so this becomes NOOP
    // fieldLen - scalaryBytes = 1 for X448 and = 0 for X25519
    u[fieldLen - 1] &= 127; // 0b0111_1111
    return bytesToNumberLE(u);
  }

  function decodeScalar(n: Hex): bigint {
    const bytes = ensureBytes(n);
    if (bytes.length !== montgomeryBytes && bytes.length !== fieldLen)
      throw new Error(`Expected ${montgomeryBytes} or ${fieldLen} bytes, got ${bytes.length}`);
    return bytesToNumberLE(adjustScalarBytes(bytes));
  }
  /*
    Converts Point to Montgomery Curve
    - u, v: curve25519 coordinates
    - x, y: ed25519 coordinates
    RFC 7748 (https://www.rfc-editor.org/rfc/rfc7748) says
    - The birational maps are (25519):
     (u, v) = ((1+y)/(1-y), sqrt(-486664)*u/x)
     (x, y) = (sqrt(-486664)*u/v, (u-1)/(u+1))
    - The birational maps are (448):
     (u, v) = ((y-1)/(y+1), sqrt(156324)*u/x)
     (x, y) = (sqrt(156324)*u/v, (1+u)/(1-u))

    But original Twisted Edwards paper (https://eprint.iacr.org/2008/013.pdf) and hyperelliptics (http://hyperelliptic.org/EFD/g1p/data/twisted/coordinates)
    says that mapping is always:
    - u = (1+y)/(1-y)
    - v = 2 (1+y)/(x(1-y))
    - x = 2 u/v
    - y = (u-1)/(u+1)

    Which maps correctly, but to completely different curve. There is different mapping for ed448 (which done with replaceble function).
    Returns 'u' coordinate of curve25519 point.

    NOTE: jubjub will need full mapping, for now only Point -> U is enough
    */
  function _UfromPoint(p: Point): Uint8Array {
    if (!(p instanceof Point)) throw new Error('Wrong point');
    const { y } = p;
    const u = modP((y + _1n) * mod.invert(_1n - y, P));
    return numberToBytesLE(u, montgomeryBytes);
  }
  const UfromPoint = CURVE.UfromPoint || _UfromPoint;

  const BASE_POINT_U = CURVE.basePointU || bytesToHex(UfromPoint(Point.BASE));
  // Multiply point u by scalar
  function scalarMult(u: Hex, scalar: Hex): Uint8Array {
    const pointU = decodeUCoordinate(u);
    const _scalar = decodeScalar(scalar);
    const pu = montgomeryLadder(pointU, _scalar);
    // The result was not contributory
    // https://cr.yp.to/ecdh.html#validate
    if (pu === _0n) throw new Error('Invalid private or public key received');
    return encodeUCoordinate(pu);
  }
  // Multiply base point by scalar
  const scalarMultBase = (scalar: Hex): Uint8Array =>
    montgomeryCurve.scalarMult(montgomeryCurve.BASE_POINT_U, scalar);

  const montgomeryCurve = {
    BASE_POINT_U,
    UfromPoint,
    // NOTE: we can get 'y' coordinate from 'u', but Point.fromHex also wants 'x' coordinate oddity flag, and we cannot get 'x' without knowing 'v'
    // Need to add generic conversion between twisted edwards and complimentary curve for JubJub
    scalarMult,
    scalarMultBase,
    // NOTE: these function work on complimentary montgomery curve
    getSharedSecret: (privateKey: Hex, publicKey: Hex) => scalarMult(publicKey, privateKey),
    getPublicKey: (privateKey: Hex): Uint8Array => scalarMultBase(privateKey),
  };

  /**
   * Calculates X25519 DH shared secret from ed25519 private & public keys.
   * Curve25519 used in X25519 consumes private keys as-is, while ed25519 hashes them with sha512.
   * Which means we will need to normalize ed25519 seeds to "hashed repr".
   * @param privateKey ed25519 private key
   * @param publicKey ed25519 public key
   * @returns X25519 shared key
   */
  function getSharedSecret(privateKey: PrivKey, publicKey: Hex): Uint8Array {
    const { head } = getExtendedPublicKey(privateKey);
    const u = montgomeryCurve.UfromPoint(Point.fromHex(publicKey));
    return montgomeryCurve.getSharedSecret(head, u);
  }

  const utils = {
    getExtendedPublicKey,
    mod: modP,
    invert: (a: bigint, m = CURVE.P) => mod.invert(a, m),

    /**
     * Can take 40 or more bytes of uniform input e.g. from CSPRNG or KDF
     * and convert them into private scalar, with the modulo bias being neglible.
     * As per FIPS 186 B.4.1.
     * Not needed for ed25519 private keys. Needed if you use scalars directly (rare).
     * @param hash hash output from sha512, or a similar function
     * @returns valid private scalar
     */
    hashToPrivateScalar: (hash: Hex): bigint => hashToPrivateScalar(hash, CURVE_ORDER, true),

    /**
     * ed25519 private keys are uniform 32-bit strings. We do not need to check for
     * modulo bias like we do in noble-secp256k1 randomPrivateKey()
     */
    randomPrivateKey: (): Uint8Array => randomBytes(fieldLen),

    /**
     * We're doing scalar multiplication (used in getPublicKey etc) with precomputed BASE_POINT
     * values. This slows down first getPublicKey() by milliseconds (see Speed section),
     * but allows to speed-up subsequent getPublicKey() calls up to 20x.
     * @param windowSize 2, 4, 8, 16
     */
    precompute(windowSize = 8, point = Point.BASE): Point {
      const cached = point.equals(Point.BASE) ? point : new Point(point.x, point.y);
      cached._setWindowSize(windowSize);
      cached.multiply(_2n);
      return cached;
    },
  };

  return {
    CURVE,
    montgomeryCurve,
    getSharedSecret,
    ExtendedPoint,
    Point,
    Signature,
    getPublicKey,
    utils,
    sign,
    verify,
  };
}
