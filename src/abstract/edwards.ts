/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// Twisted Edwards curve. The formula is: ax² + y² = 1 + dx²y²

// Differences from @noble/ed25519 1.7:
// 1. Variable field element lengths between EDDSA/ECDH:
//   EDDSA (RFC8032) is 456 bits / 57 bytes, ECDH (RFC7748) is 448 bits / 56 bytes
// 2. Different addition formula (doubling is same)
// 3. uvRatio differs between curves (half-expected, not only pow fn changes)
// 4. Point decompression code is different (unexpected), now using generalized formula
// 5. Domain function was no-op for ed25519, but adds some data even with empty context for ed448

import * as mod from './modular.js';
import * as ut from './utils.js';
import { ensureBytes, Hex, PrivKey } from './utils.js';
import { Group, GroupConstructor, wNAF } from './group.js';

// Be friendly to bad ECMAScript parsers by not using bigint literals like 123n
const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);
const _8n = BigInt(8);

// Edwards curves must declare params a & d.
export type CurveType = ut.BasicCurve<bigint> & {
  // Params: a, d
  a: bigint;
  d: bigint;
  // Hashes
  // The interface, because we need outputLen for DRBG
  hash: ut.CHash;
  // CSPRNG
  randomBytes: (bytesLength?: number) => Uint8Array;
  // Probably clears bits in a byte array to produce a valid field element
  adjustScalarBytes?: (bytes: Uint8Array) => Uint8Array;
  // Used during hashing
  domain?: (data: Uint8Array, ctx: Uint8Array, phflag: boolean) => Uint8Array;
  // Ratio √(u/v)
  uvRatio?: (u: bigint, v: bigint) => { isValid: boolean; value: bigint };
  // RFC 8032 pre-hashing of messages to sign() / verify()
  preHash?: ut.CHash;
  mapToCurve?: (scalar: bigint[]) => { x: bigint; y: bigint };
};

function validateOpts(curve: CurveType) {
  const opts = ut.validateOpts(curve);
  if (typeof opts.hash !== 'function' || !ut.isPositiveInt(opts.hash.outputLen))
    throw new Error('Invalid hash function');
  for (const i of ['a', 'd'] as const) {
    const val = opts[i];
    if (typeof val !== 'bigint') throw new Error(`Invalid curve param ${i}=${val} (${typeof val})`);
  }
  for (const fn of ['randomBytes'] as const) {
    if (typeof opts[fn] !== 'function') throw new Error(`Invalid ${fn} function`);
  }
  for (const fn of ['adjustScalarBytes', 'domain', 'uvRatio', 'mapToCurve'] as const) {
    if (opts[fn] === undefined) continue; // Optional
    if (typeof opts[fn] !== 'function') throw new Error(`Invalid ${fn} function`);
  }
  // Set defaults
  return Object.freeze({ ...opts } as const);
}

// 2d point in XY coords
export interface AffinePoint {
  x: bigint;
  y: bigint;
}

// Instance of Extended Point with coordinates in X, Y, Z, T
export interface ExtendedPointType extends Group<ExtendedPointType> {
  readonly x: bigint;
  readonly y: bigint;
  readonly z: bigint;
  readonly t: bigint;
  multiply(scalar: bigint): ExtendedPointType;
  multiplyUnsafe(scalar: bigint): ExtendedPointType;
  isSmallOrder(): boolean;
  isTorsionFree(): boolean;
  toAffine(invZ?: bigint): AffinePoint;
  clearCofactor(): ExtendedPointType;
}
// Static methods of Extended Point with coordinates in X, Y, Z, T
export interface ExtendedPointConstructor extends GroupConstructor<ExtendedPointType> {
  new (x: bigint, y: bigint, z: bigint, t: bigint): ExtendedPointType;
  fromAffine(p: AffinePoint): ExtendedPointType;
  toAffineBatch(points: ExtendedPointType[]): AffinePoint[];
  fromHex(hex: Hex): ExtendedPointType;
  fromPrivateKey(privateKey: PrivKey): ExtendedPointType; // TODO: remove
}

export type CurveFn = {
  CURVE: ReturnType<typeof validateOpts>;
  getPublicKey: (privateKey: PrivKey, isCompressed?: boolean) => Uint8Array;
  sign: (message: Hex, privateKey: Hex) => Uint8Array;
  verify: (sig: Hex, message: Hex, publicKey: Hex) => boolean;
  // Point: PointConstructor;
  ExtendedPoint: ExtendedPointConstructor;
  utils: {
    randomPrivateKey: () => Uint8Array;
    getExtendedPublicKey: (key: PrivKey) => {
      head: Uint8Array;
      prefix: Uint8Array;
      scalar: bigint;
      point: ExtendedPointType;
      pointBytes: Uint8Array;
    };
  };
};

// NOTE: it is not generic twisted curve for now, but ed25519/ed448 generic implementation
export function twistedEdwards(curveDef: CurveType): CurveFn {
  const CURVE = validateOpts(curveDef) as ReturnType<typeof validateOpts>;
  const Fp = CURVE.Fp;
  const CURVE_ORDER = CURVE.n;
  const MASK = _2n ** BigInt(CURVE.nByteLength * 8);

  // Function overrides
  const { randomBytes } = CURVE;
  const modP = Fp.create;

  // sqrt(u/v)
  const uvRatio =
    CURVE.uvRatio ||
    ((u: bigint, v: bigint) => {
      try {
        return { isValid: true, value: Fp.sqrt(u * Fp.invert(v)) };
      } catch (e) {
        return { isValid: false, value: _0n };
      }
    });
  const adjustScalarBytes = CURVE.adjustScalarBytes || ((bytes: Uint8Array) => bytes); // NOOP
  const domain =
    CURVE.domain ||
    ((data: Uint8Array, ctx: Uint8Array, phflag: boolean) => {
      if (ctx.length || phflag) throw new Error('Contexts/pre-hash are not supported');
      return data;
    }); // NOOP
  function inBig(n: bigint) {
    return typeof n === 'bigint' && 0n < n;
  }
  function assertInMask(n: bigint) {
    if (inBig(n) && n < MASK) return n;
    throw new Error(`Expected valid scalar < MASK, got ${typeof n} ${n}`);
  }
  function assertFE(n: bigint) {
    if (inBig(n) && n < Fp.ORDER) return n;
    throw new Error(`Expected valid scalar < P, got ${typeof n} ${n}`);
  }
  function assertGE(n: bigint) {
    // GE = subgroup element, not full group
    if (inBig(n) && n < CURVE_ORDER) return n;
    throw new Error(`Expected valid scalar < N, got ${typeof n} ${n}`);
  }
  function assertGE0(n: bigint) {
    // GE = subgroup element, not full group
    return n === _0n ? n : assertGE(n);
  }

  /**
   * Extended Point works in extended coordinates: (x, y, z, t) ∋ (x=x/z, y=y/z, t=xy).
   * Default Point works in affine coordinates: (x, y)
   * https://en.wikipedia.org/wiki/Twisted_Edwards_curve#Extended_coordinates
   */
  class ExtendedPoint implements ExtendedPointType {
    constructor(
      readonly x: bigint,
      readonly y: bigint,
      readonly z = _1n,
      readonly t = modP(x * y)
    ) {}

    static BASE = new ExtendedPoint(CURVE.Gx, CURVE.Gy);
    static ZERO = new ExtendedPoint(_0n, _1n); // 0, 1, 1, 0
    static fromAffine(p: AffinePoint): ExtendedPoint {
      if (!(p && typeof p === 'object' && typeof p.x === 'bigint' && typeof p.y === 'bigint'))
        throw new Error('fromAffine error');
      if (p.x === 0n && p.y === 1n) return ExtendedPoint.ZERO;
      return new ExtendedPoint(p.x, p.y);
    }
    // Takes a bunch of Jacobian Points but executes only one
    // invert on all of them. invert is very slow operation,
    // so this improves performance massively.
    static toAffineBatch(points: ExtendedPoint[]): AffinePoint[] {
      const toInv = Fp.invertBatch(points.map((p) => p.z));
      return points.map((p, i) => p.toAffine(toInv[i]));
    }
    static normalizeZ(denorm: ExtendedPoint[]): ExtendedPoint[] {
      return ExtendedPoint.toAffineBatch(denorm).map(ExtendedPoint.fromAffine);
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
        if (F === _0n) return this.double(); // Same point. Tests say it doesn't affect timing
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

    // Constant time multiplication.
    // Uses wNAF method. Windowed method may be 10% faster,
    // but takes 2x longer to generate and consumes 2x memory.
    multiply(scalar: bigint): ExtendedPoint {
      return wNAF_TMP_FN(this, assertGE(scalar));
    }

    // Non-constant-time multiplication. Uses double-and-add algorithm.
    // It's faster, but should only be used when you don't care about
    // an exposed private key e.g. sig verification.
    multiplyUnsafe(scalar: bigint): ExtendedPoint {
      let n = assertGE0(scalar);
      if (n === _0n) return I;
      if (this.equals(I) || n === _1n) return this;
      if (this.equals(G)) return wNAF_TMP_FN(this, n);
      return wnaf.unsafeLadder(this, n);
    }

    // Checks if point is of small order.
    // If you add something to small order point, you will have "dirty"
    // point with torsion component.
    // Multiplies point by cofactor and checks if the result is 0.
    isSmallOrder(): boolean {
      return this.multiplyUnsafe(CURVE.h).equals(ExtendedPoint.ZERO);
    }

    // Multiplies point by curve order (very big scalar CURVE.n) and checks if the result is 0.
    // Returns `false` is the point is dirty.
    isTorsionFree(): boolean {
      return wnaf.unsafeLadder(this, CURVE_ORDER).equals(ExtendedPoint.ZERO);
    }

    // Converts Extended point to default (x, y) coordinates.
    // Can accept precomputed Z^-1 - for example, from invertBatch.
    toAffine(iz?: bigint): AffinePoint {
      const { x, y, z } = this;
      const is0 = this.equals(ExtendedPoint.ZERO);
      if (iz == null) iz = is0 ? _8n : (Fp.invert(z) as bigint); // 8 was chosen arbitrarily
      const ax = modP(x * iz);
      const ay = modP(y * iz);
      const zz = modP(z * iz);
      if (is0) return { x: _0n, y: _1n };
      if (zz !== _1n) throw new Error('invZ was invalid');
      return { x: ax, y: ay };
    }
    clearCofactor(): ExtendedPoint {
      const { h: cofactor } = CURVE;
      if (cofactor === _1n) return this;
      return this.multiplyUnsafe(cofactor);
    }

    // Converts hash string or Uint8Array to Point.
    // Uses algo from RFC8032 5.1.3.
    static fromHex(hex: Hex, strict = true) {
      const { d, a } = CURVE;
      const len = Fp.BYTES;
      hex = ensureBytes(hex, len);
      // 1.  First, interpret the string as an integer in little-endian
      // representation. Bit 255 of this number is the least significant
      // bit of the x-coordinate and denote this value x_0.  The
      // y-coordinate is recovered simply by clearing this bit.  If the
      // resulting value is >= p, decoding fails.
      const normed = hex.slice();
      const lastByte = hex[len - 1];
      normed[len - 1] = lastByte & ~0x80;
      const y = ut.bytesToNumberLE(normed);

      if (y === _0n) {
        // y=0 is allowed
      } else {
        if (strict) assertFE(y); // strict=true [0..CURVE.Fp.P] (2^255-19 for ed25519)
        else assertInMask(y); // strict=false [0..MASK] (2^256 for ed25519)
      }

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
      return new ExtendedPoint(x, y);
    }
    static fromPrivateKey(privateKey: PrivKey) {
      return getExtendedPublicKey(privateKey).point;
    }
    toRawBytes(): Uint8Array {
      const { x, y } = this.toAffine();
      const len = Fp.BYTES;
      const bytes = ut.numberToBytesLE(y, len); // each y has 2 x values (x, -y)
      bytes[len - 1] |= x & _1n ? 0x80 : 0; // when compressing, it's enough to store y
      return bytes; // and use the last byte to encode sign of x
    }
    toHex(): string {
      return ut.bytesToHex(this.toRawBytes()); // Same as toRawBytes, but returns string.
    }
  }
  const { BASE: G, ZERO: I } = ExtendedPoint;
  let Gpows: ExtendedPoint[] | undefined = undefined; // precomputes for base point G
  const wnaf = wNAF(ExtendedPoint, CURVE.nByteLength * 8);
  function wNAF_TMP_FN(P: ExtendedPoint, n: bigint): ExtendedPoint {
    if (P.equals(G)) {
      const W = 8;
      if (!Gpows) {
        const denorm = wnaf.precomputeWindow(P, W) as ExtendedPoint[];
        const norm = ExtendedPoint.toAffineBatch(denorm).map(ExtendedPoint.fromAffine);
        Gpows = norm;
      }
      const comp = Gpows;
      const { p, f } = wnaf.wNAF(W, comp, n);
      return ExtendedPoint.normalizeZ([p, f])[0];
    }
    const W = 1;
    const denorm = wnaf.precomputeWindow(P, W) as ExtendedPoint[];
    const norm = ExtendedPoint.toAffineBatch(denorm).map(ExtendedPoint.fromAffine);
    const { p, f } = wnaf.wNAF(W, norm, n);
    return ExtendedPoint.normalizeZ([p, f])[0];
  }
  function assertExtPoint(other: unknown) {
    if (!(other instanceof ExtendedPoint)) throw new TypeError('ExtendedPoint expected');
  }
  // Little-endian SHA512 with modulo n
  function modnLE(hash: Uint8Array): bigint {
    return mod.mod(ut.bytesToNumberLE(hash), CURVE_ORDER);
  }

  /** Convenience method that creates public key and other stuff. RFC8032 5.1.5 */
  function getExtendedPublicKey(key: PrivKey) {
    const groupLen = CURVE.nByteLength;
    // Normalize bigint / number / string to Uint8Array
    const keyb = typeof key === 'bigint' ? ut.numberToBytesLE(assertInMask(key), groupLen) : key;
    // Hash private key with curve's hash function to produce uniformingly random input
    // We check byte lengths e.g.: ensureBytes(64, hash(ensureBytes(32, key)))
    const hashed = ensureBytes(CURVE.hash(ensureBytes(keyb, groupLen)), 2 * groupLen);

    // First half's bits are cleared to produce a random field element.
    const head = adjustScalarBytes(hashed.slice(0, groupLen));
    // Second half is called key prefix (5.1.6)
    const prefix = hashed.slice(groupLen, 2 * groupLen);
    // The actual private scalar
    const scalar = modnLE(head);
    // Point on Edwards curve aka public key
    const point = G.multiply(scalar);
    // Uint8Array representation
    const pointBytes = point.toRawBytes();
    return { head, prefix, scalar, point, pointBytes };
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
    return modnLE(CURVE.hash(domain(message, context, !!CURVE.preHash)));
  }

  /** Signs message with privateKey. RFC8032 5.1.6 */
  function sign(message: Hex, privateKey: Hex, context?: Hex): Uint8Array {
    message = ensureBytes(message);
    if (CURVE.preHash) message = CURVE.preHash(message);
    const { prefix, scalar, pointBytes } = getExtendedPublicKey(privateKey);
    const r = hashDomainToScalar(ut.concatBytes(prefix, message), context);
    const R = G.multiply(r); // R = rG
    const k = hashDomainToScalar(ut.concatBytes(R.toRawBytes(), pointBytes, message), context); // k = hash(R+P+msg)
    const s = mod.mod(r + k * scalar, CURVE_ORDER); // s = r + kp
    assertGE0(s); // 0 <= s < l
    return ut.concatBytes(R.toRawBytes(), ut.numberToBytesLE(s, Fp.BYTES));
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
  function verify(sig: Hex, message: Hex, publicKey: Hex, context?: Hex): boolean {
    const len = Fp.BYTES;
    sig = ensureBytes(sig, 2 * len);
    message = ensureBytes(message);
    if (CURVE.preHash) message = CURVE.preHash(message);
    const R = ExtendedPoint.fromHex(sig.slice(0, len), false); // non-strict; allows 0..MASK
    const s = ut.bytesToNumberLE(sig.slice(len, 2 * len));
    const A = ExtendedPoint.fromHex(publicKey, false); // Check for s bounds, hex validity
    const SB = G.multiplyUnsafe(s);
    const k = hashDomainToScalar(ut.concatBytes(R.toRawBytes(), A.toRawBytes(), message), context);
    const kA = A.multiplyUnsafe(k);
    const RkA = R.add(kA);
    // [8][S]B = [8]R + [8][k]A'
    return RkA.subtract(SB).clearCofactor().equals(ExtendedPoint.ZERO);
  }

  // Enable precomputes. Slows down first publicKey computation by 20ms.
  // G._setWindowSize(8);

  const utils = {
    getExtendedPublicKey,
    /**
     * Not needed for ed25519 private keys. Needed if you use scalars directly (rare).
     */
    hashToPrivateScalar: (hash: Hex): bigint => ut.hashToPrivateScalar(hash, CURVE_ORDER, true),

    /**
     * ed25519 private keys are uniform 32-bit strings. We do not need to check for
     * modulo bias like we do in secp256k1 randomPrivateKey()
     */
    randomPrivateKey: (): Uint8Array => randomBytes(Fp.BYTES),

    /**
     * We're doing scalar multiplication (used in getPublicKey etc) with precomputed BASE_POINT
     * values. This slows down first getPublicKey() by milliseconds (see Speed section),
     * but allows to speed-up subsequent getPublicKey() calls up to 20x.
     * @param windowSize 2, 4, 8, 16
     */
    precompute(windowSize = 8, point = G): ExtendedPoint {
      return G.multiply(2n);
      // const cached = point.equals(Point.BASE) ? point : new Point(point.x, point.y);
      // cached._setWindowSize(windowSize);
      // cached.multiply(_2n);
      // return cached;
    },
  };

  return {
    CURVE,
    getPublicKey,
    sign,
    verify,
    ExtendedPoint,
    // Point: ExtendedPoint,
    utils,
  };
}
