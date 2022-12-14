/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// Implementation of Twisted Edwards curve. The formula is: ax² + y² = 1 + dx²y²

// Differences from @noble/ed25519 1.7:
// 1. Different field element lengths in ed448:
//   EDDSA (RFC8032) is 456 bits / 57 bytes, ECDH (RFC7748) is 448 bits / 56 bytes
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
  bytesToNumberLE,
  hashToPrivateScalar,
  BasicCurve,
  validateOpts as utilOpts,
  Hex,
  PrivKey,
} from './utils.js'; // TODO: import * as u from './utils.js'?
import { Group, GroupConstructor, wNAF } from './group.js';

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

export type CurveType = BasicCurve & {
  // Params: a, d
  a: bigint;
  d: bigint;
  // Hashes
  hash: CHash; // Because we need outputLen for DRBG
  randomBytes: (bytesLength?: number) => Uint8Array;
  adjustScalarBytes?: (bytes: Uint8Array) => Uint8Array;
  domain?: (data: Uint8Array, ctx: Uint8Array, phflag: boolean) => Uint8Array;
  uvRatio?: (u: bigint, v: bigint) => { isValid: boolean; value: bigint };
  preHash?: CHash;
};

// Should be separate from overrides, since overrides can use information about curve (for example nBits)
function validateOpts(curve: CurveType) {
  const opts = utilOpts(curve);
  if (typeof opts.hash !== 'function' || !Number.isSafeInteger(opts.hash.outputLen))
    throw new Error('Invalid hash function');
  for (const i of ['a', 'd'] as const) {
    if (typeof opts[i] !== 'bigint')
      throw new Error(`Invalid curve param ${i}=${opts[i]} (${typeof opts[i]})`);
  }
  for (const fn of ['randomBytes'] as const) {
    if (typeof opts[fn] !== 'function') throw new Error(`Invalid ${fn} function`);
  }
  for (const fn of ['adjustScalarBytes', 'domain', 'uvRatio'] as const) {
    if (opts[fn] === undefined) continue; // Optional
    if (typeof opts[fn] !== 'function') throw new Error(`Invalid ${fn} function`);
  }
  // Set defaults
  return Object.freeze({ ...opts } as const);
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
export interface ExtendedPointType extends Group<ExtendedPointType> {
  readonly x: bigint;
  readonly y: bigint;
  readonly z: bigint;
  readonly t: bigint;
  multiply(scalar: number | bigint, affinePoint?: PointType): ExtendedPointType;
  multiplyUnsafe(scalar: number | bigint): ExtendedPointType;
  isSmallOrder(): boolean;
  isTorsionFree(): boolean;
  toAffine(invZ?: bigint): PointType;
}
// Static methods
export interface ExtendedPointConstructor extends GroupConstructor<ExtendedPointType> {
  new (x: bigint, y: bigint, z: bigint, t: bigint): ExtendedPointType;
  fromAffine(p: PointType): ExtendedPointType;
  toAffineBatch(points: ExtendedPointType[]): PointType[];
  normalizeZ(points: ExtendedPointType[]): ExtendedPointType[];
}

// Instance
export interface PointType extends Group<PointType> {
  readonly x: bigint;
  readonly y: bigint;
  _setWindowSize(windowSize: number): void;
  toRawBytes(isCompressed?: boolean): Uint8Array;
  toHex(isCompressed?: boolean): string;
  isTorsionFree(): boolean;
}
// Static methods
export interface PointConstructor extends GroupConstructor<PointType> {
  new (x: bigint, y: bigint): PointType;
  fromHex(hex: Hex): PointType;
  fromPrivateKey(privateKey: PrivKey): PointType;
}

export type PubKey = Hex | PointType;
export type SigType = Hex | SignatureType;

export type CurveFn = {
  CURVE: ReturnType<typeof validateOpts>;
  getPublicKey: (privateKey: PrivKey, isCompressed?: boolean) => Uint8Array;
  sign: (message: Hex, privateKey: Hex) => Uint8Array;
  verify: (sig: SigType, message: Hex, publicKey: PubKey) => boolean;
  Point: PointConstructor;
  ExtendedPoint: ExtendedPointConstructor;
  Signature: SignatureConstructor;
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
      // Faster algo for adding 2 Extended Points when curve's a=-1.
      // http://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-4
      // Cost: 8M + 8add + 2*2.
      // Note: It does not check whether the `other` point is valid.
      if (a === BigInt(-1)) {
        const A = modP((Y1 - X1) * (Y2 + X2));
        const B = modP((Y1 + X1) * (Y2 - X2));
        const F = modP(B - A);
        if (F === _0n) return this.double(); // Same point.
        const C = modP(Z1 * _2n * T2);
        const D = modP(T1 * _2n * Z2);
        const E = D + C;
        const G = B + A;
        const H = D - C;
        const X3 = modP(E * F);
        const Y3 = modP(G * H);
        const T3 = modP(E * H);
        const Z3 = modP(F * G);
        return new ExtendedPoint(X3, Y3, Z3, T3);
      }
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
      if (!(other instanceof Point)) throw new TypeError('Point#equals: expected Point');
      return this.x === other.x && this.y === other.y;
    }

    negate(): Point {
      return new Point(modP(-this.x), this.y);
    }

    double(): Point {
      return ExtendedPoint.fromAffine(this).double().toAffine();
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

  const utils = {
    getExtendedPublicKey,
    mod: modP,
    invert: (a: bigint, m = CURVE.P) => mod.invert(a, m),

    /**
     * Not needed for ed25519 private keys. Needed if you use scalars directly (rare).
     */
    hashToPrivateScalar: (hash: Hex): bigint => hashToPrivateScalar(hash, CURVE_ORDER, true),

    /**
     * ed25519 private keys are uniform 32-bit strings. We do not need to check for
     * modulo bias like we do in secp256k1 randomPrivateKey()
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
    getPublicKey,
    sign,
    verify,
    ExtendedPoint,
    Point,
    Signature,
    utils,
  };
}
