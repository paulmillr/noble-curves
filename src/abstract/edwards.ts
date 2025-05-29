/**
 * Twisted Edwards curve. The formula is: ax² + y² = 1 + dx²y².
 * For design rationale of types / exports, see weierstrass module documentation.
 * Untwisted Edwards curves exist, but they aren't used in real-world protocols.
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import {
  _validateObject,
  abool,
  abytes,
  aInRange,
  bytesToHex,
  bytesToNumberLE,
  concatBytes,
  ensureBytes,
  memoized,
  numberToBytesLE,
  randomBytes,
  type FHash,
  type Hex,
} from '../utils.ts';
import {
  _createCurveFields,
  normalizeZ,
  pippenger,
  wNAF,
  type AffinePoint,
  type BasicCurve,
  type Group,
  type GroupConstructor,
} from './curve.ts';
import { Field, type IField, type NLength } from './modular.ts';

// Be friendly to bad ECMAScript parsers by not using bigint literals
// prettier-ignore
const _0n = BigInt(0), _1n = BigInt(1), _2n = BigInt(2), _8n = BigInt(8);

export type UVRatio = (u: bigint, v: bigint) => { isValid: boolean; value: bigint };

/** Edwards curves must declare params a & d. */
export type CurveType = BasicCurve<bigint> & {
  a: bigint; // curve param a
  d: bigint; // curve param d
  hash: FHash; // Hashing
  randomBytes?: (bytesLength?: number) => Uint8Array; // CSPRNG
  adjustScalarBytes?: (bytes: Uint8Array) => Uint8Array; // clears bits to get valid field elemtn
  domain?: (data: Uint8Array, ctx: Uint8Array, phflag: boolean) => Uint8Array; // Used for hashing
  uvRatio?: UVRatio; // Ratio √(u/v)
  prehash?: FHash; // RFC 8032 pre-hashing of messages to sign() / verify()
  mapToCurve?: (scalar: bigint[]) => AffinePoint<bigint>; // for hash-to-curve standard
};

export type CurveTypeWithLength = Readonly<CurveType & Partial<NLength>>;

// verification rule is either zip215 or rfc8032 / nist186-5. Consult fromHex:
const VERIFY_DEFAULT = { zip215: true };

/** Instance of Extended Point with coordinates in X, Y, Z, T. */
export interface ExtPointType extends Group<ExtPointType> {
  readonly ex: bigint;
  readonly ey: bigint;
  readonly ez: bigint;
  readonly et: bigint;
  get x(): bigint;
  get y(): bigint;
  assertValidity(): void;
  multiply(scalar: bigint): ExtPointType;
  multiplyUnsafe(scalar: bigint): ExtPointType;
  is0(): boolean;
  isSmallOrder(): boolean;
  isTorsionFree(): boolean;
  clearCofactor(): ExtPointType;
  toAffine(iz?: bigint): AffinePoint<bigint>;
  toBytes(): Uint8Array;
  /** @deprecated use `toBytes` */
  toRawBytes(): Uint8Array;
  toHex(): string;
  precompute(windowSize?: number, isLazy?: boolean): ExtPointType;
  /** @deprecated use `p.precompute(windowSize)` */
  _setWindowSize(windowSize: number): void;
}
/** Static methods of Extended Point with coordinates in X, Y, Z, T. */
export interface ExtPointConstructor extends GroupConstructor<ExtPointType> {
  new (x: bigint, y: bigint, z: bigint, t: bigint): ExtPointType;
  Fp: IField<bigint>;
  Fn: IField<bigint>;
  fromAffine(p: AffinePoint<bigint>): ExtPointType;
  fromBytes(bytes: Uint8Array, zip215?: boolean): ExtPointType;
  fromHex(hex: Hex, zip215?: boolean): ExtPointType;
  msm(points: ExtPointType[], scalars: bigint[]): ExtPointType;
}

/**
 * Twisted Edwards curve options.
 *
 * * a: formula param
 * * d: formula param
 * * p: prime characteristic (order) of finite field, in which arithmetics is done
 * * n: order of prime subgroup a.k.a total amount of valid curve points
 * * h: cofactor. h*n is group order; n is subgroup order
 * * Gx: x coordinate of generator point a.k.a. base point
 * * Gy: y coordinate of generator point
 */
export type EdwardsOpts = Readonly<{
  a: bigint;
  d: bigint;
  p: bigint;
  n: bigint;
  h: bigint;
  Gx: bigint;
  Gy: bigint;
}>;

/**
 * Extra curve options for Twisted Edwards.
 *
 * * Fp: redefined Field over curve.p
 * * Fn: redefined Field over curve.n
 * * uvRatio: helper function for decompression, calculating √(u/v)
 */
export type EdwardsExtraOpts = Partial<{
  Fp: IField<bigint>;
  Fn: IField<bigint>;
  uvRatio: (u: bigint, v: bigint) => { isValid: boolean; value: bigint };
}>;

/**
 * EdDSA (Edwards Digital Signature algorithm) options.
 *
 * * hash: hash function used to hash private keys and messages
 * * adjustScalarBytes: clears bits to get valid field element
 * * domain: Used for hashing
 * * mapToCurve: for hash-to-curve standard
 * * prehash: RFC 8032 pre-hashing of messages to sign() / verify()
 * * randomBytes: function generating random bytes, used for randomPrivateKey
 */
export type EdDSAOpts = {
  hash: FHash;
  adjustScalarBytes?: (bytes: Uint8Array) => Uint8Array;
  domain?: (data: Uint8Array, ctx: Uint8Array, phflag: boolean) => Uint8Array;
  mapToCurve?: (scalar: bigint[]) => AffinePoint<bigint>;
  prehash?: FHash;
  randomBytes?: (bytesLength?: number) => Uint8Array;
};

/**
 * EdDSA (Edwards Digital Signature algorithm) interface.
 *
 * Allows to create and verify signatures, create public and private keys.
 */
export interface EdDSA {
  getPublicKey: (privateKey: Hex) => Uint8Array;
  sign: (message: Hex, privateKey: Hex, options?: { context?: Hex }) => Uint8Array;
  verify: (
    sig: Hex,
    message: Hex,
    publicKey: Hex,
    options?: { context?: Hex; zip215: boolean }
  ) => boolean;
  Point: ExtPointConstructor;
  utils: {
    randomPrivateKey: () => Uint8Array;
    getExtendedPublicKey: (key: Hex) => {
      head: Uint8Array;
      prefix: Uint8Array;
      scalar: bigint;
      point: ExtPointType;
      pointBytes: Uint8Array;
    };
    /** @deprecated use `point.precompute()` */
    precompute: (windowSize?: number, point?: ExtPointType) => ExtPointType;
  };
}

// Legacy params. TODO: remove
export type CurveFn = {
  CURVE: CurveType;
  getPublicKey: (privateKey: Hex) => Uint8Array;
  sign: (message: Hex, privateKey: Hex, options?: { context?: Hex }) => Uint8Array;
  verify: (
    sig: Hex,
    message: Hex,
    publicKey: Hex,
    options?: { context?: Hex; zip215: boolean }
  ) => boolean;
  Point: ExtPointConstructor;
  /** @deprecated use `Point` */
  ExtendedPoint: ExtPointConstructor;
  utils: {
    randomPrivateKey: () => Uint8Array;
    getExtendedPublicKey: (key: Hex) => {
      head: Uint8Array;
      prefix: Uint8Array;
      scalar: bigint;
      point: ExtPointType;
      pointBytes: Uint8Array;
    };
    precompute: (windowSize?: number, point?: ExtPointType) => ExtPointType;
  };
};

function isEdValidXY(Fp: IField<bigint>, CURVE: EdwardsOpts, x: bigint, y: bigint): boolean {
  const x2 = Fp.sqr(x);
  const y2 = Fp.sqr(y);
  const left = Fp.add(Fp.mul(CURVE.a, x2), y2);
  const right = Fp.add(Fp.ONE, Fp.mul(CURVE.d, Fp.mul(x2, y2)));
  return Fp.eql(left, right);
}

export function edwards(CURVE: EdwardsOpts, curveOpts: EdwardsExtraOpts = {}): ExtPointConstructor {
  const { Fp, Fn } = _createCurveFields('edwards', CURVE, curveOpts);
  const { h: cofactor, n: CURVE_ORDER } = CURVE;
  _validateObject(curveOpts, {}, { uvRatio: 'function' });

  // Important:
  // There are some places where Fp.BYTES is used instead of nByteLength.
  // So far, everything has been tested with curves of Fp.BYTES == nByteLength.
  // TODO: test and find curves which behave otherwise.
  const MASK = _2n << (BigInt(Fn.BYTES * 8) - _1n);
  const modP = (n: bigint) => Fp.create(n); // Function overrides

  // sqrt(u/v)
  const uvRatio =
    curveOpts.uvRatio ||
    ((u: bigint, v: bigint) => {
      try {
        return { isValid: true, value: Fp.sqrt(Fp.div(u, v)) };
      } catch (e) {
        return { isValid: false, value: _0n };
      }
    });

  // Validate whether the passed curve params are valid.
  // equation ax² + y² = 1 + dx²y² should work for generator point.
  if (!isEdValidXY(Fp, CURVE, CURVE.Gx, CURVE.Gy))
    throw new Error('bad curve params: generator point');

  /**
   * Asserts coordinate is valid: 0 <= n < MASK.
   * Coordinates >= Fp.ORDER are allowed for zip215.
   */
  function acoord(title: string, n: bigint, banZero = false) {
    const min = banZero ? _1n : _0n;
    aInRange('coordinate ' + title, n, min, MASK);
    return n;
  }

  function aextpoint(other: unknown) {
    if (!(other instanceof Point)) throw new Error('ExtendedPoint expected');
  }
  // Converts Extended point to default (x, y) coordinates.
  // Can accept precomputed Z^-1 - for example, from invertBatch.
  const toAffineMemo = memoized((p: Point, iz?: bigint): AffinePoint<bigint> => {
    const { ex: x, ey: y, ez: z } = p;
    const is0 = p.is0();
    if (iz == null) iz = is0 ? _8n : (Fp.inv(z) as bigint); // 8 was chosen arbitrarily
    const ax = modP(x * iz);
    const ay = modP(y * iz);
    const zz = modP(z * iz);
    if (is0) return { x: _0n, y: _1n };
    if (zz !== _1n) throw new Error('invZ was invalid');
    return { x: ax, y: ay };
  });
  const assertValidMemo = memoized((p: Point) => {
    const { a, d } = CURVE;
    if (p.is0()) throw new Error('bad point: ZERO'); // TODO: optimize, with vars below?
    // Equation in affine coordinates: ax² + y² = 1 + dx²y²
    // Equation in projective coordinates (X/Z, Y/Z, Z):  (aX² + Y²)Z² = Z⁴ + dX²Y²
    const { ex: X, ey: Y, ez: Z, et: T } = p;
    const X2 = modP(X * X); // X²
    const Y2 = modP(Y * Y); // Y²
    const Z2 = modP(Z * Z); // Z²
    const Z4 = modP(Z2 * Z2); // Z⁴
    const aX2 = modP(X2 * a); // aX²
    const left = modP(Z2 * modP(aX2 + Y2)); // (aX² + Y²)Z²
    const right = modP(Z4 + modP(d * modP(X2 * Y2))); // Z⁴ + dX²Y²
    if (left !== right) throw new Error('bad point: equation left != right (1)');
    // In Extended coordinates we also have T, which is x*y=T/Z: check X*Y == Z*T
    const XY = modP(X * Y);
    const ZT = modP(Z * T);
    if (XY !== ZT) throw new Error('bad point: equation left != right (2)');
    return true;
  });

  // Extended Point works in extended coordinates: (X, Y, Z, T) ∋ (x=X/Z, y=Y/Z, T=xy).
  // https://en.wikipedia.org/wiki/Twisted_Edwards_curve#Extended_coordinates
  class Point implements ExtPointType {
    // base / generator point
    static readonly BASE = new Point(CURVE.Gx, CURVE.Gy, _1n, modP(CURVE.Gx * CURVE.Gy));
    // zero / infinity / identity point
    static readonly ZERO = new Point(_0n, _1n, _1n, _0n); // 0, 1, 1, 0
    // fields
    static readonly Fp = Fp;
    static readonly Fn = Fn;

    readonly ex: bigint;
    readonly ey: bigint;
    readonly ez: bigint;
    readonly et: bigint;

    constructor(ex: bigint, ey: bigint, ez: bigint, et: bigint) {
      this.ex = acoord('x', ex);
      this.ey = acoord('y', ey);
      this.ez = acoord('z', ez, true);
      this.et = acoord('t', et);
      Object.freeze(this);
    }

    get x(): bigint {
      return this.toAffine().x;
    }
    get y(): bigint {
      return this.toAffine().y;
    }

    static fromAffine(p: AffinePoint<bigint>): Point {
      if (p instanceof Point) throw new Error('extended point not allowed');
      const { x, y } = p || {};
      acoord('x', x);
      acoord('y', y);
      return new Point(x, y, _1n, modP(x * y));
    }
    static normalizeZ(points: Point[]): Point[] {
      return normalizeZ(Point, 'ez', points);
    }
    // Multiscalar Multiplication
    static msm(points: Point[], scalars: bigint[]): Point {
      return pippenger(Point, Fn, points, scalars);
    }

    // "Private method", don't use it directly
    _setWindowSize(windowSize: number) {
      this.precompute(windowSize);
    }
    precompute(windowSize: number = 8, isLazy = true) {
      wnaf.setWindowSize(this, windowSize);
      if (!isLazy) this.multiply(_2n); // random number
      return this;
    }
    // Not required for fromHex(), which always creates valid points.
    // Could be useful for fromAffine().
    assertValidity(): void {
      assertValidMemo(this);
    }

    // Compare one point to another.
    equals(other: Point): boolean {
      aextpoint(other);
      const { ex: X1, ey: Y1, ez: Z1 } = this;
      const { ex: X2, ey: Y2, ez: Z2 } = other;
      const X1Z2 = modP(X1 * Z2);
      const X2Z1 = modP(X2 * Z1);
      const Y1Z2 = modP(Y1 * Z2);
      const Y2Z1 = modP(Y2 * Z1);
      return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
    }

    is0(): boolean {
      return this.equals(Point.ZERO);
    }

    negate(): Point {
      // Flips point sign to a negative one (-x, y in affine coords)
      return new Point(modP(-this.ex), this.ey, this.ez, modP(-this.et));
    }

    // Fast algo for doubling Extended Point.
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#doubling-dbl-2008-hwcd
    // Cost: 4M + 4S + 1*a + 6add + 1*2.
    double(): Point {
      const { a } = CURVE;
      const { ex: X1, ey: Y1, ez: Z1 } = this;
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
      return new Point(X3, Y3, Z3, T3);
    }

    // Fast algo for adding 2 Extended Points.
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#addition-add-2008-hwcd
    // Cost: 9M + 1*a + 1*d + 7add.
    add(other: Point) {
      aextpoint(other);
      const { a, d } = CURVE;
      const { ex: X1, ey: Y1, ez: Z1, et: T1 } = this;
      const { ex: X2, ey: Y2, ez: Z2, et: T2 } = other;
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
      return new Point(X3, Y3, Z3, T3);
    }

    subtract(other: Point): Point {
      return this.add(other.negate());
    }

    // Constant-time multiplication.
    multiply(scalar: bigint): Point {
      const n = scalar;
      aInRange('scalar', n, _1n, CURVE_ORDER); // 1 <= scalar < L
      const { p, f } = wnaf.wNAFCached(this, n, Point.normalizeZ);
      return Point.normalizeZ([p, f])[0];
    }

    // Non-constant-time multiplication. Uses double-and-add algorithm.
    // It's faster, but should only be used when you don't care about
    // an exposed private key e.g. sig verification.
    // Does NOT allow scalars higher than CURVE.n.
    // Accepts optional accumulator to merge with multiply (important for sparse scalars)
    multiplyUnsafe(scalar: bigint, acc = Point.ZERO): Point {
      const n = scalar;
      aInRange('scalar', n, _0n, CURVE_ORDER); // 0 <= scalar < L
      if (n === _0n) return Point.ZERO;
      if (this.is0() || n === _1n) return this;
      return wnaf.wNAFCachedUnsafe(this, n, Point.normalizeZ, acc);
    }

    // Checks if point is of small order.
    // If you add something to small order point, you will have "dirty"
    // point with torsion component.
    // Multiplies point by cofactor and checks if the result is 0.
    isSmallOrder(): boolean {
      return this.multiplyUnsafe(cofactor).is0();
    }

    // Multiplies point by curve order and checks if the result is 0.
    // Returns `false` is the point is dirty.
    isTorsionFree(): boolean {
      return wnaf.wNAFCachedUnsafe(this, CURVE_ORDER).is0();
    }

    // Converts Extended point to default (x, y) coordinates.
    // Can accept precomputed Z^-1 - for example, from invertBatch.
    toAffine(invertedZ?: bigint): AffinePoint<bigint> {
      return toAffineMemo(this, invertedZ);
    }

    clearCofactor(): Point {
      if (cofactor === _1n) return this;
      return this.multiplyUnsafe(cofactor);
    }

    static fromBytes(bytes: Uint8Array, zip215 = false): Point {
      abytes(bytes);
      return this.fromHex(bytes, zip215);
    }

    // Converts hash string or Uint8Array to Point.
    // Uses algo from RFC8032 5.1.3.
    static fromHex(hex: Hex, zip215 = false): Point {
      const { d, a } = CURVE;
      const len = Fp.BYTES;
      hex = ensureBytes('pointHex', hex, len); // copy hex to a new array
      abool('zip215', zip215);
      const normed = hex.slice(); // copy again, we'll manipulate it
      const lastByte = hex[len - 1]; // select last byte
      normed[len - 1] = lastByte & ~0x80; // clear last bit
      const y = bytesToNumberLE(normed);

      // zip215=true is good for consensus-critical apps. =false follows RFC8032 / NIST186-5.
      // RFC8032 prohibits >= p, but ZIP215 doesn't
      // zip215=true:  0 <= y < MASK (2^256 for ed25519)
      // zip215=false: 0 <= y < P (2^255-19 for ed25519)
      const max = zip215 ? MASK : Fp.ORDER;
      aInRange('pointHex.y', y, _0n, max);

      // Ed25519: x² = (y²-1)/(dy²+1) mod p. Ed448: x² = (y²-1)/(dy²-1) mod p. Generic case:
      // ax²+y²=1+dx²y² => y²-1=dx²y²-ax² => y²-1=x²(dy²-a) => x²=(y²-1)/(dy²-a)
      const y2 = modP(y * y); // denominator is always non-0 mod p.
      const u = modP(y2 - _1n); // u = y² - 1
      const v = modP(d * y2 - a); // v = d y² + 1.
      let { isValid, value: x } = uvRatio(u, v); // √(u/v)
      if (!isValid) throw new Error('Point.fromHex: invalid y coordinate');
      const isXOdd = (x & _1n) === _1n; // There are 2 square roots. Use x_0 bit to select proper
      const isLastByteOdd = (lastByte & 0x80) !== 0; // x_0, last bit
      if (!zip215 && x === _0n && isLastByteOdd)
        // if x=0 and x_0 = 1, fail
        throw new Error('Point.fromHex: x=0 and x_0=1');
      if (isLastByteOdd !== isXOdd) x = modP(-x); // if x_0 != x mod 2, set x = p-x
      return Point.fromAffine({ x, y });
    }
    static fromPrivateScalar(scalar: bigint): Point {
      return Point.BASE.multiply(scalar);
    }
    toBytes(): Uint8Array {
      const { x, y } = this.toAffine();
      const bytes = numberToBytesLE(y, Fp.BYTES); // each y has 2 x values (x, -y)
      bytes[bytes.length - 1] |= x & _1n ? 0x80 : 0; // when compressing, it's enough to store y
      return bytes; // and use the last byte to encode sign of x
    }
    /** @deprecated use `toBytes` */
    toRawBytes(): Uint8Array {
      return this.toBytes();
    }
    toHex(): string {
      return bytesToHex(this.toBytes());
    }

    toString() {
      return `<Point ${this.is0() ? 'ZERO' : this.toHex()}>`;
    }
  }
  const wnaf = wNAF(Point, Fn.BYTES * 8); // Fn.BITS?
  return Point;
}

/**
 * Initializes EdDSA signatures over given Edwards curve.
 */
export function eddsa(Point: ExtPointConstructor, eddsaOpts: EdDSAOpts): EdDSA {
  _validateObject(
    eddsaOpts,
    {
      hash: 'function',
    },
    {
      adjustScalarBytes: 'function',
      randomBytes: 'function',
      domain: 'function',
      prehash: 'function',
      mapToCurve: 'function',
    }
  );

  const { prehash, hash: cHash } = eddsaOpts;
  const { BASE: G, Fp, Fn } = Point;
  const CURVE_ORDER = Fn.ORDER;

  const randomBytes_ = eddsaOpts.randomBytes || randomBytes;
  const adjustScalarBytes = eddsaOpts.adjustScalarBytes || ((bytes: Uint8Array) => bytes); // NOOP
  const domain =
    eddsaOpts.domain ||
    ((data: Uint8Array, ctx: Uint8Array, phflag: boolean) => {
      abool('phflag', phflag);
      if (ctx.length || phflag) throw new Error('Contexts/pre-hash are not supported');
      return data;
    }); // NOOP

  function modN(a: bigint) {
    return Fn.create(a);
  }
  // Little-endian SHA512 with modulo n
  function modN_LE(hash: Uint8Array): bigint {
    // Not using Fn.fromBytes: hash can be 2*Fn.BYTES
    return modN(bytesToNumberLE(hash));
  }

  // Get the hashed private scalar per RFC8032 5.1.5
  function getPrivateScalar(key: Hex) {
    const len = Fp.BYTES;
    key = ensureBytes('private key', key, len);
    // Hash private key with curve's hash function to produce uniformingly random input
    // Check byte lengths: ensure(64, h(ensure(32, key)))
    const hashed = ensureBytes('hashed private key', cHash(key), 2 * len);
    const head = adjustScalarBytes(hashed.slice(0, len)); // clear first half bits, produce FE
    const prefix = hashed.slice(len, 2 * len); // second half is called key prefix (5.1.6)
    const scalar = modN_LE(head); // The actual private scalar
    return { head, prefix, scalar };
  }

  // Convenience method that creates public key from scalar. RFC8032 5.1.5
  function getExtendedPublicKey(key: Hex) {
    const { head, prefix, scalar } = getPrivateScalar(key);
    const point = G.multiply(scalar); // Point on Edwards curve aka public key
    const pointBytes = point.toBytes();
    return { head, prefix, scalar, point, pointBytes };
  }

  // Calculates EdDSA pub key. RFC8032 5.1.5. Privkey is hashed. Use first half with 3 bits cleared
  function getPublicKey(privKey: Hex): Uint8Array {
    return getExtendedPublicKey(privKey).pointBytes;
  }

  // int('LE', SHA512(dom2(F, C) || msgs)) mod N
  function hashDomainToScalar(context: Hex = Uint8Array.of(), ...msgs: Uint8Array[]) {
    const msg = concatBytes(...msgs);
    return modN_LE(cHash(domain(msg, ensureBytes('context', context), !!prehash)));
  }

  /** Signs message with privateKey. RFC8032 5.1.6 */
  function sign(msg: Hex, privKey: Hex, options: { context?: Hex } = {}): Uint8Array {
    msg = ensureBytes('message', msg);
    if (prehash) msg = prehash(msg); // for ed25519ph etc.
    const { prefix, scalar, pointBytes } = getExtendedPublicKey(privKey);
    const r = hashDomainToScalar(options.context, prefix, msg); // r = dom2(F, C) || prefix || PH(M)
    const R = G.multiply(r).toBytes(); // R = rG
    const k = hashDomainToScalar(options.context, R, pointBytes, msg); // R || A || PH(M)
    const s = modN(r + k * scalar); // S = (r + k * s) mod L
    aInRange('signature.s', s, _0n, CURVE_ORDER); // 0 <= s < l
    const L = Fp.BYTES;
    const res = concatBytes(R, numberToBytesLE(s, L));
    return ensureBytes('result', res, L * 2); // 64-byte signature
  }

  const verifyOpts: { context?: Hex; zip215?: boolean } = VERIFY_DEFAULT;

  /**
   * Verifies EdDSA signature against message and public key. RFC8032 5.1.7.
   * An extended group equation is checked.
   */
  function verify(sig: Hex, msg: Hex, publicKey: Hex, options = verifyOpts): boolean {
    const { context, zip215 } = options;
    const len = Fp.BYTES; // Verifies EdDSA signature against message and public key. RFC8032 5.1.7.
    sig = ensureBytes('signature', sig, 2 * len); // An extended group equation is checked.
    msg = ensureBytes('message', msg);
    publicKey = ensureBytes('publicKey', publicKey, len);
    if (zip215 !== undefined) abool('zip215', zip215);
    if (prehash) msg = prehash(msg); // for ed25519ph, etc

    const s = bytesToNumberLE(sig.slice(len, 2 * len));
    let A, R, SB;
    try {
      // zip215=true is good for consensus-critical apps. =false follows RFC8032 / NIST186-5.
      // zip215=true:  0 <= y < MASK (2^256 for ed25519)
      // zip215=false: 0 <= y < P (2^255-19 for ed25519)
      A = Point.fromHex(publicKey, zip215);
      R = Point.fromHex(sig.slice(0, len), zip215);
      SB = G.multiplyUnsafe(s); // 0 <= s < l is done inside
    } catch (error) {
      return false;
    }
    if (!zip215 && A.isSmallOrder()) return false;

    const k = hashDomainToScalar(context, R.toBytes(), A.toBytes(), msg);
    const RkA = R.add(A.multiplyUnsafe(k));
    // Extended group equation
    // [8][S]B = [8]R + [8][k]A'
    return RkA.subtract(SB).clearCofactor().is0();
  }

  G.precompute(8); // Enable precomputes. Slows down first publicKey computation by 20ms.

  const utils = {
    getExtendedPublicKey,
    /** ed25519 priv keys are uniform 32b. No need to check for modulo bias, like in secp256k1. */
    randomPrivateKey: (): Uint8Array => randomBytes_!(Fp.BYTES),

    /**
     * We're doing scalar multiplication (used in getPublicKey etc) with precomputed BASE_POINT
     * values. This slows down first getPublicKey() by milliseconds (see Speed section),
     * but allows to speed-up subsequent getPublicKey() calls up to 20x.
     * @param windowSize 2, 4, 8, 16
     */
    precompute(windowSize = 8, point: ExtPointType = Point.BASE): ExtPointType {
      return point.precompute(windowSize, false);
    },
  };

  return { getPublicKey, sign, verify, utils, Point };
}

export type EdComposed = {
  CURVE: EdwardsOpts;
  curveOpts: EdwardsExtraOpts;
  eddsaOpts: EdDSAOpts;
};
function _eddsa_legacy_opts_to_new(c: CurveTypeWithLength): EdComposed {
  const CURVE: EdwardsOpts = {
    a: c.a,
    d: c.d,
    p: c.Fp.ORDER,
    n: c.n,
    h: c.h,
    Gx: c.Gx,
    Gy: c.Gy,
  };
  const Fp = c.Fp;
  const Fn = Field(CURVE.n, c.nBitLength, true);
  const curveOpts: EdwardsExtraOpts = { Fp, Fn, uvRatio: c.uvRatio };
  const eddsaOpts: EdDSAOpts = {
    hash: c.hash,
    randomBytes: c.randomBytes,
    adjustScalarBytes: c.adjustScalarBytes,
    domain: c.domain,
    prehash: c.prehash,
    mapToCurve: c.mapToCurve,
  };
  return { CURVE, curveOpts, eddsaOpts };
}
function _eddsa_new_output_to_legacy(c: CurveTypeWithLength, eddsa: EdDSA): CurveFn {
  const legacy = Object.assign({}, eddsa, { ExtendedPoint: eddsa.Point, CURVE: c });
  return legacy;
}
// TODO: remove. Use eddsa
export function twistedEdwards(c: CurveTypeWithLength): CurveFn {
  const { CURVE, curveOpts, eddsaOpts } = _eddsa_legacy_opts_to_new(c);
  const Point = edwards(CURVE, curveOpts);
  const EDDSA = eddsa(Point, eddsaOpts);
  return _eddsa_new_output_to_legacy(c, EDDSA);
}
