/**
 * Twisted Edwards curve. The formula is: ax² + y² = 1 + dx²y².
 * For design rationale of types / exports, see weierstrass module documentation.
 * Untwisted Edwards curves exist, but they aren't used in real-world protocols.
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import {
  abool,
  abytes,
  aInRange,
  asafenumber,
  bytesToHex,
  bytesToNumberLE,
  concatBytes,
  copyBytes,
  hexToBytes,
  isBytes,
  notImplemented,
  validateObject,
  randomBytes as wcRandomBytes,
  type FHash,
  type Signer,
  type TArg,
  type TRet,
} from '../utils.ts';
import {
  createCurveFields,
  createKeygen,
  normalizeZ,
  wNAF,
  type AffinePoint,
  type CurveLengths,
  type CurvePoint,
  type CurvePointCons,
} from './curve.ts';
import { type IField } from './modular.ts';

// Be friendly to bad ECMAScript parsers by not using bigint literals
// prettier-ignore
const _0n = /* @__PURE__ */ BigInt(0), _1n = /* @__PURE__ */ BigInt(1), _2n = /* @__PURE__ */ BigInt(2), _8n = /* @__PURE__ */ BigInt(8);

/** Extended Edwards point with X/Y/Z/T coordinates. */
export interface EdwardsPoint extends CurvePoint<bigint, EdwardsPoint> {
  /** extended X coordinate. Different from affine x. */
  readonly X: bigint;
  /** extended Y coordinate. Different from affine y. */
  readonly Y: bigint;
  /** extended Z coordinate */
  readonly Z: bigint;
  /** extended T coordinate */
  readonly T: bigint;
}
/** Constructor and decoding helpers for extended Edwards points. */
export interface EdwardsPointCons extends CurvePointCons<EdwardsPoint> {
  /** Create a point from extended X/Y/Z/T coordinates without validation. */
  new (X: bigint, Y: bigint, Z: bigint, T: bigint): EdwardsPoint;
  /**
   * Return the curve parameters used by this point constructor.
   * @returns Curve parameters.
   */
  CURVE(): EdwardsOpts;
  /**
   * Decode a point from bytes, optionally using ZIP-215 rules.
   * @param bytes - Encoded point bytes.
   * @param zip215 - Whether to accept ZIP-215 encodings.
   * @returns Decoded Edwards point.
   */
  fromBytes(bytes: Uint8Array, zip215?: boolean): EdwardsPoint;
  /**
   * Decode a point from hex, optionally using ZIP-215 rules.
   * @param hex - Encoded point hex.
   * @param zip215 - Whether to accept ZIP-215 encodings.
   * @returns Decoded Edwards point.
   */
  fromHex(hex: string, zip215?: boolean): EdwardsPoint;
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
  /** Base-field modulus. */
  p: bigint;
  /** Prime subgroup order. */
  n: bigint;
  /** Curve cofactor. */
  h: bigint;
  /** Edwards curve parameter `a`. */
  a: bigint;
  /** Edwards curve parameter `d`. */
  d: bigint;
  /** Generator x coordinate. */
  Gx: bigint;
  /** Generator y coordinate. */
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
  /** Optional base-field override. */
  Fp: IField<bigint>;
  /** Optional scalar-field override. */
  Fn: IField<bigint>;
  /** Whether field encodings are little-endian. */
  FpFnLE: boolean;
  /** Square-root ratio helper used during point decompression. */
  uvRatio: (u: bigint, v: bigint) => { isValid: boolean; value: bigint };
}>;

/**
 * EdDSA (Edwards Digital Signature algorithm) options.
 *
 * * hash: hash function used to hash secret keys and messages
 * * adjustScalarBytes: clears bits to get valid field element
 * * domain: Used for hashing
 * * mapToCurve: for hash-to-curve standard
 * * prehash: RFC 8032 pre-hashing of messages to sign() / verify()
 * * randomBytes: function generating random bytes, used for randomSecretKey
 */
export type EdDSAOpts = Partial<{
  /** Clamp or otherwise normalize secret-scalar bytes before reducing mod `n`. */
  adjustScalarBytes: (bytes: TArg<Uint8Array>) => TRet<Uint8Array>;
  /** Domain-separation helper for contexts and prehash mode. */
  domain: (data: TArg<Uint8Array>, ctx: TArg<Uint8Array>, phflag: boolean) => TRet<Uint8Array>;
  /** Optional hash-to-curve mapper for protocols like Ristretto hash-to-group. */
  mapToCurve: (scalar: bigint[]) => AffinePoint<bigint>;
  /** Optional prehash function used before signing or verifying messages. */
  prehash: FHash;
  /** Default verification decoding policy. ZIP-215 is more permissive than RFC 8032 / NIST. */
  zip215: boolean;
  /** RNG override used by helper constructors. */
  randomBytes: (bytesLength?: number) => TRet<Uint8Array>;
}>;

/**
 * EdDSA (Edwards Digital Signature algorithm) helper namespace.
 * Allows creating and verifying signatures, and deriving public keys.
 */
export interface EdDSA {
  /**
   * Generate a secret/public key pair.
   * @param seed - Optional seed material.
   * @returns Secret/public key pair.
   */
  keygen: (seed?: TArg<Uint8Array>) => { secretKey: TRet<Uint8Array>; publicKey: TRet<Uint8Array> };
  /**
   * Derive the public key from a secret key.
   * @param secretKey - Secret key bytes.
   * @returns Encoded public key.
   */
  getPublicKey: (secretKey: TArg<Uint8Array>) => TRet<Uint8Array>;
  /**
   * Sign a message with an EdDSA secret key.
   * @param message - Message bytes.
   * @param secretKey - Secret key bytes.
   * @param options - Optional signature tweaks:
   *   - `context` (optional): Domain-separation context for Ed25519ctx/Ed448.
   * @returns Encoded signature bytes.
   */
  sign: (
    message: TArg<Uint8Array>,
    secretKey: TArg<Uint8Array>,
    options?: TArg<{ context?: Uint8Array }>
  ) => TRet<Uint8Array>;
  /**
   * Verify a signature against a message and public key.
   * @param sig - Encoded signature bytes.
   * @param message - Message bytes.
   * @param publicKey - Encoded public key.
   * @param options - Optional verification tweaks:
   *   - `context` (optional): Domain-separation context for Ed25519ctx/Ed448.
   *   - `zip215` (optional): Whether to accept ZIP-215 encodings.
   * @returns Whether the signature is valid.
   */
  verify: (
    sig: TArg<Uint8Array>,
    message: TArg<Uint8Array>,
    publicKey: TArg<Uint8Array>,
    options?: TArg<{ context?: Uint8Array; zip215?: boolean }>
  ) => boolean;
  /** Point constructor used by this signature scheme. */
  Point: EdwardsPointCons;
  /** Helper utilities for key validation and Montgomery conversion. */
  utils: {
    /**
     * Generate a valid random secret key.
     * Optional seed bytes are only length-checked and returned unchanged.
     */
    randomSecretKey: (seed?: TArg<Uint8Array>) => TRet<Uint8Array>;
    /** Check whether a secret key has the expected encoding. */
    isValidSecretKey: (secretKey: TArg<Uint8Array>) => boolean;
    /** Check whether a public key decodes to a valid point. */
    isValidPublicKey: (publicKey: TArg<Uint8Array>, zip215?: boolean) => boolean;

    /**
     * Converts ed public key to x public key.
     *
     * There is NO `fromMontgomery`:
     * - There are 2 valid ed25519 points for every x25519, with flipped coordinate
     * - Sometimes there are 0 valid ed25519 points, because x25519 *additionally*
     *   accepts inputs on the quadratic twist, which can't be moved to ed25519
     *
     * @example
     * Converts ed public key to x public key.
     *
     * ```js
     * const someonesPub_ed = ed25519.getPublicKey(ed25519.utils.randomSecretKey());
     * const someonesPub = ed25519.utils.toMontgomery(someonesPub);
     * const aPriv = x25519.utils.randomSecretKey();
     * const shared = x25519.getSharedSecret(aPriv, someonesPub)
     * ```
     */
    toMontgomery: (publicKey: TArg<Uint8Array>) => TRet<Uint8Array>;
    /**
     * Converts ed secret key to x secret key.
     * @example
     * Converts ed secret key to x secret key.
     *
     * ```js
     * const someonesPub = x25519.getPublicKey(x25519.utils.randomSecretKey());
     * const aPriv_ed = ed25519.utils.randomSecretKey();
     * const aPriv = ed25519.utils.toMontgomerySecret(aPriv_ed);
     * const shared = x25519.getSharedSecret(aPriv, someonesPub)
     * ```
     */
    toMontgomerySecret: (secretKey: TArg<Uint8Array>) => TRet<Uint8Array>;
    /** Return the expanded private key components used by RFC8032 signing. */
    getExtendedPublicKey: (key: TArg<Uint8Array>) => {
      head: TRet<Uint8Array>;
      prefix: TRet<Uint8Array>;
      scalar: bigint;
      point: EdwardsPoint;
      pointBytes: TRet<Uint8Array>;
    };
  };
  /** Byte lengths for keys and signatures exposed by this scheme. */
  lengths: CurveLengths;
}

// Affine Edwards-equation check only; this does not prove subgroup membership, canonical
// encoding, prime-order base-point requirements, or identity exclusion.
function isEdValidXY(Fp: TArg<IField<bigint>>, CURVE: EdwardsOpts, x: bigint, y: bigint): boolean {
  const x2 = Fp.sqr(x);
  const y2 = Fp.sqr(y);
  const left = Fp.add(Fp.mul(CURVE.a, x2), y2);
  const right = Fp.add(Fp.ONE, Fp.mul(CURVE.d, Fp.mul(x2, y2)));
  return Fp.eql(left, right);
}

/**
 * @param params - Curve parameters. See {@link EdwardsOpts}.
 * @param extraOpts - Optional helpers and overrides. See {@link EdwardsExtraOpts}.
 * @returns Edwards point constructor. Generator validation here only checks
 *   that `(Gx, Gy)` satisfies the affine Edwards equation.
 *   RFC 8032 base-point constraints like `B != (0,1)` and `[L]B = 0`
 *   are left to the caller's chosen parameters, since eager subgroup
 *   validation here adds about 10-15ms to heavyweight imports like ed448.
 *   The returned constructor also eagerly marks `Point.BASE` for W=8
 *   precompute caching. Some code paths still assume
 *   `Fp.BYTES === Fn.BYTES`, so mismatched byte lengths are not fully audited here.
 * @throws If the curve parameters or Edwards overrides are invalid. {@link Error}
 * @example
 * ```ts
 * import { edwards } from '@noble/curves/abstract/edwards.js';
 * import { jubjub } from '@noble/curves/misc.js';
 * // Build a point constructor from explicit curve parameters, then use its base point.
 * const Point = edwards(jubjub.Point.CURVE());
 * Point.BASE.toHex();
 * ```
 */
export function edwards(
  params: TArg<EdwardsOpts>,
  extraOpts: TArg<EdwardsExtraOpts> = {}
): EdwardsPointCons {
  const opts = extraOpts as EdwardsExtraOpts;
  const validated = createCurveFields('edwards', params as EdwardsOpts, opts, opts.FpFnLE);
  const { Fp, Fn } = validated;
  let CURVE = validated.CURVE as EdwardsOpts;
  const { h: cofactor } = CURVE;
  validateObject(opts, {}, { uvRatio: 'function' });

  // Important:
  // There are some places where Fp.BYTES is used instead of nByteLength.
  // So far, everything has been tested with curves of Fp.BYTES == nByteLength.
  // TODO: test and find curves which behave otherwise.
  const MASK = _2n << (BigInt(Fn.BYTES * 8) - _1n);
  const modP = (n: bigint) => Fp.create(n); // Function overrides

  // sqrt(u/v)
  const uvRatio =
    opts.uvRatio === undefined
      ? (u: bigint, v: bigint) => {
          try {
            return { isValid: true, value: Fp.sqrt(Fp.div(u, v)) };
          } catch (e) {
            return { isValid: false, value: _0n };
          }
        }
      : opts.uvRatio;

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

  function aedpoint(other: unknown) {
    if (!(other instanceof Point)) throw new Error('EdwardsPoint expected');
  }

  // Extended Point works in extended coordinates: (X, Y, Z, T) ∋ (x=X/Z, y=Y/Z, T=xy).
  // https://en.wikipedia.org/wiki/Twisted_Edwards_curve#Extended_coordinates
  class Point implements EdwardsPoint {
    // base / generator point
    static readonly BASE = new Point(CURVE.Gx, CURVE.Gy, _1n, modP(CURVE.Gx * CURVE.Gy));
    // zero / infinity / identity point
    static readonly ZERO = new Point(_0n, _1n, _1n, _0n); // 0, 1, 1, 0
    // math field
    static readonly Fp = Fp;
    // scalar field
    static readonly Fn = Fn;

    readonly X: bigint;
    readonly Y: bigint;
    readonly Z: bigint;
    readonly T: bigint;

    constructor(X: bigint, Y: bigint, Z: bigint, T: bigint) {
      this.X = acoord('x', X);
      this.Y = acoord('y', Y);
      this.Z = acoord('z', Z, true);
      this.T = acoord('t', T);
      Object.freeze(this);
    }

    static CURVE(): EdwardsOpts {
      return CURVE;
    }

    /**
     * Create one extended Edwards point from affine coordinates.
     * Does NOT validate that the point is on-curve or torsion-free.
     * Use `.assertValidity()` on adversarial inputs.
     */
    static fromAffine(p: AffinePoint<bigint>): Point {
      if (p instanceof Point) throw new Error('extended point not allowed');
      const { x, y } = p || {};
      acoord('x', x);
      acoord('y', y);
      return new Point(x, y, _1n, modP(x * y));
    }

    // Uses algo from RFC8032 5.1.3.
    static fromBytes(bytes: Uint8Array, zip215 = false): Point {
      const len = Fp.BYTES;
      const { a, d } = CURVE;
      bytes = copyBytes(abytes(bytes, len, 'point'));
      abool(zip215, 'zip215');
      const normed = copyBytes(bytes); // copy again, we'll manipulate it
      const lastByte = bytes[len - 1]; // select last byte
      normed[len - 1] = lastByte & ~0x80; // clear last bit
      const y = bytesToNumberLE(normed);

      // zip215=true is good for consensus-critical apps. =false follows RFC8032 / NIST186-5.
      // RFC8032 prohibits >= p, but ZIP215 doesn't
      // zip215=true:  0 <= y < MASK (2^256 for ed25519)
      // zip215=false: 0 <= y < P (2^255-19 for ed25519)
      const max = zip215 ? MASK : Fp.ORDER;
      aInRange('point.y', y, _0n, max);

      // Ed25519: x² = (y²-1)/(dy²+1) mod p. Ed448: x² = (y²-1)/(dy²-1) mod p. Generic case:
      // ax²+y²=1+dx²y² => y²-1=dx²y²-ax² => y²-1=x²(dy²-a) => x²=(y²-1)/(dy²-a)
      const y2 = modP(y * y); // denominator is always non-0 mod p.
      const u = modP(y2 - _1n); // u = y² - 1
      const v = modP(d * y2 - a); // v = d y² + 1.
      let { isValid, value: x } = uvRatio(u, v); // √(u/v)
      if (!isValid) throw new Error('bad point: invalid y coordinate');
      const isXOdd = (x & _1n) === _1n; // There are 2 square roots. Use x_0 bit to select proper
      const isLastByteOdd = (lastByte & 0x80) !== 0; // x_0, last bit
      if (!zip215 && x === _0n && isLastByteOdd)
        // if x=0 and x_0 = 1, fail
        throw new Error('bad point: x=0 and x_0=1');
      if (isLastByteOdd !== isXOdd) x = modP(-x); // if x_0 != x mod 2, set x = p-x
      return Point.fromAffine({ x, y });
    }

    static fromHex(hex: string, zip215 = false): Point {
      return Point.fromBytes(hexToBytes(hex), zip215);
    }

    get x(): bigint {
      return this.toAffine().x;
    }
    get y(): bigint {
      return this.toAffine().y;
    }

    precompute(windowSize: number = 8, isLazy = true) {
      wnaf.createCache(this, windowSize);
      if (!isLazy) this.multiply(_2n); // random number
      return this;
    }

    // Useful in fromAffine() - not for fromBytes(), which always created valid points.
    assertValidity(): void {
      const p = this;
      const { a, d } = CURVE;
      // Keep generic Edwards validation fail-closed on the neutral point.
      // Even though ZERO is algebraically valid and can roundtrip through encodings, higher-level
      // callers often reach it only through broken hash/scalar plumbing; rejecting it here avoids
      // silently treating that degenerate state as an ordinary public point.
      if (p.is0()) throw new Error('bad point: ZERO'); // TODO: optimize, with vars below?
      // Equation in affine coordinates: ax² + y² = 1 + dx²y²
      // Equation in projective coordinates (X/Z, Y/Z, Z):  (aX² + Y²)Z² = Z⁴ + dX²Y²
      const { X, Y, Z, T } = p;
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
    }

    // Compare one point to another.
    equals(other: Point): boolean {
      aedpoint(other);
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const { X: X2, Y: Y2, Z: Z2 } = other;
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
      return new Point(modP(-this.X), this.Y, this.Z, modP(-this.T));
    }

    // Fast algo for doubling Extended Point.
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#doubling-dbl-2008-hwcd
    // Cost: 4M + 4S + 1*a + 6add + 1*2.
    double(): Point {
      const { a } = CURVE;
      const { X: X1, Y: Y1, Z: Z1 } = this;
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
      aedpoint(other);
      const { a, d } = CURVE;
      const { X: X1, Y: Y1, Z: Z1, T: T1 } = this;
      const { X: X2, Y: Y2, Z: Z2, T: T2 } = other;
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
      // Validate before calling `negate()` so wrong inputs fail with the point guard
      // instead of leaking a foreign `negate()` error.
      aedpoint(other);
      return this.add(other.negate());
    }

    // Constant-time multiplication.
    multiply(scalar: bigint): Point {
      // 1 <= scalar < L
      // Keep the subgroup-scalar contract strict instead of reducing 0 / n to ZERO.
      // In keygen/signing-style callers, those values usually mean broken hash/scalar plumbing,
      // and failing closed is safer than silently producing the identity point.
      if (!Fn.isValidNot0(scalar))
        throw new RangeError('invalid scalar: expected 1 <= sc < curve.n');
      const { p, f } = wnaf.cached(this, scalar, (p) => normalizeZ(Point, p));
      return normalizeZ(Point, [p, f])[0];
    }

    // Non-constant-time multiplication. Uses double-and-add algorithm.
    // It's faster, but should only be used when you don't care about
    // an exposed private key e.g. sig verification.
    // Keeps the same subgroup-scalar contract: 0 is allowed for public-scalar callers, but
    // n and larger values are rejected instead of being reduced mod n to the identity point.
    multiplyUnsafe(scalar: bigint): Point {
      // 0 <= scalar < L
      if (!Fn.isValid(scalar)) throw new RangeError('invalid scalar: expected 0 <= sc < curve.n');
      if (scalar === _0n) return Point.ZERO;
      if (this.is0() || scalar === _1n) return this;
      return wnaf.unsafe(this, scalar, (p) => normalizeZ(Point, p));
    }

    // Checks if point is of small order.
    // If you add something to small order point, you will have "dirty"
    // point with torsion component.
    // Clears cofactor and checks if the result is 0.
    isSmallOrder(): boolean {
      return this.clearCofactor().is0();
    }

    // Multiplies point by curve order and checks if the result is 0.
    // Returns `false` is the point is dirty.
    isTorsionFree(): boolean {
      return wnaf.unsafe(this, CURVE.n).is0();
    }

    // Converts Extended point to default (x, y) coordinates.
    // Can accept precomputed Z^-1 - for example, from invertBatch.
    toAffine(invertedZ?: bigint): AffinePoint<bigint> {
      const p = this;
      let iz = invertedZ;
      const { X, Y, Z } = p;
      const is0 = p.is0();
      if (iz == null) iz = is0 ? _8n : (Fp.inv(Z) as bigint); // 8 was chosen arbitrarily
      const x = modP(X * iz);
      const y = modP(Y * iz);
      const zz = Fp.mul(Z, iz);
      if (is0) return { x: _0n, y: _1n };
      if (zz !== _1n) throw new Error('invZ was invalid');
      return { x, y };
    }

    clearCofactor(): Point {
      if (cofactor === _1n) return this;
      return this.multiplyUnsafe(cofactor);
    }

    toBytes(): Uint8Array {
      const { x, y } = this.toAffine();
      // Fp.toBytes() allows non-canonical encoding of y (>= p).
      const bytes = Fp.toBytes(y);
      // Each y has 2 valid points: (x, y), (x,-y).
      // When compressing, it's enough to store y and use the last byte to encode sign of x
      bytes[bytes.length - 1] |= x & _1n ? 0x80 : 0;
      return bytes;
    }
    toHex(): string {
      return bytesToHex(this.toBytes());
    }

    toString() {
      return `<Point ${this.is0() ? 'ZERO' : this.toHex()}>`;
    }
  }
  const wnaf = new wNAF(Point, Fn.BITS);
  // Keep constructor work cheap: subgroup/generator validation belongs to the caller's curve
  // parameters, and doing the extra checks here adds about 10-15ms to heavy module imports.
  // Callers that construct custom curves are responsible for supplying the correct base point.
  // try {
  //   Point.BASE.assertValidity();
  //   if (!Point.BASE.isTorsionFree()) throw new Error('bad point: not in prime-order subgroup');
  // } catch {
  //   throw new Error('bad curve params: generator point');
  // }
  // Tiny toy curves can have scalar fields narrower than 8 bits. Skip the
  // eager W=8 cache there instead of rejecting an otherwise valid constructor.
  if (Fn.BITS >= 8) Point.BASE.precompute(8); // Enable precomputes. Slows down first publicKey computation by 20ms.
  Object.freeze(Point.prototype);
  Object.freeze(Point);
  return Point;
}

/**
 * Base class for prime-order points like Ristretto255 and Decaf448.
 * These points eliminate cofactor issues by representing equivalence classes
 * of Edwards curve points. Multiple Edwards representatives can describe the
 * same abstract wrapper element, so wrapper validity is not the same thing as
 * the hidden representative being torsion-free.
 * @param ep - Backing Edwards point.
 * @example
 * Base class for prime-order points like Ristretto255 and Decaf448.
 *
 * ```ts
 * import { ristretto255 } from '@noble/curves/ed25519.js';
 * const point = ristretto255.Point.BASE.multiply(2n);
 * ```
 */
export abstract class PrimeEdwardsPoint<T extends PrimeEdwardsPoint<T>>
  implements CurvePoint<bigint, T>
{
  static BASE: PrimeEdwardsPoint<any>;
  static ZERO: PrimeEdwardsPoint<any>;
  static Fp: IField<bigint>;
  static Fn: IField<bigint>;

  protected readonly ep: EdwardsPoint;

  /**
   * Wrap one internal Edwards representative directly.
   * This is not a canonical encoding boundary: alternate Edwards
   * representatives may still describe the same abstract wrapper element.
   */
  constructor(ep: EdwardsPoint) {
    this.ep = ep;
  }

  // Abstract methods that must be implemented by subclasses
  abstract toBytes(): Uint8Array;
  abstract equals(other: T): boolean;

  // Static methods that must be implemented by subclasses
  static fromBytes(_bytes: Uint8Array): any {
    notImplemented();
  }

  static fromHex(_hex: string): any {
    notImplemented();
  }

  get x(): bigint {
    return this.toAffine().x;
  }
  get y(): bigint {
    return this.toAffine().y;
  }

  // Common implementations
  clearCofactor(): T {
    // no-op for the abstract prime-order wrapper group; this is about the
    // wrapper element, not the hidden Edwards representative.
    return this as any;
  }

  assertValidity(): void {
    // Keep wrapper validity at the abstract-group boundary. Canonical decode
    // may choose Edwards representatives that differ by small torsion, so
    // checking `this.ep.isTorsionFree()` here would reject valid wrapper points.
    this.ep.assertValidity();
  }

  /**
   * Return affine coordinates of the current internal Edwards representative.
   * This is a convenience helper, not a canonical Ristretto/Decaf encoding.
   * Equal abstract elements may expose different `x` / `y`; use
   * `toBytes()` / `fromBytes()` for canonical roundtrips.
   */
  toAffine(invertedZ?: bigint): AffinePoint<bigint> {
    return this.ep.toAffine(invertedZ);
  }

  toHex(): string {
    return bytesToHex(this.toBytes());
  }

  toString(): string {
    return this.toHex();
  }

  isTorsionFree(): boolean {
    // Abstract Ristretto/Decaf elements are already prime-order even when the
    // hidden Edwards representative is not torsion-free.
    return true;
  }

  isSmallOrder(): boolean {
    return false;
  }

  add(other: T): T {
    this.assertSame(other);
    return this.init(this.ep.add(other.ep));
  }

  subtract(other: T): T {
    this.assertSame(other);
    return this.init(this.ep.subtract(other.ep));
  }

  multiply(scalar: bigint): T {
    return this.init(this.ep.multiply(scalar));
  }

  multiplyUnsafe(scalar: bigint): T {
    return this.init(this.ep.multiplyUnsafe(scalar));
  }

  double(): T {
    return this.init(this.ep.double());
  }

  negate(): T {
    return this.init(this.ep.negate());
  }

  precompute(windowSize?: number, isLazy?: boolean): T {
    this.ep.precompute(windowSize, isLazy);
    // Keep the wrapper identity stable like the backing Edwards API instead of
    // allocating a fresh wrapper around the same cached point.
    return this as unknown as T;
  }

  // Helper methods
  abstract is0(): boolean;
  protected abstract assertSame(other: T): void;
  protected abstract init(ep: EdwardsPoint): T;
}

/**
 * Initializes EdDSA signatures over given Edwards curve.
 * @param Point - Edwards point constructor.
 * @param cHash - Hash function.
 * @param eddsaOpts - Optional signature helpers. See {@link EdDSAOpts}.
 * @returns EdDSA helper namespace.
 * @throws If the hash function, options, or derived point operations are invalid. {@link Error}
 * @example
 * Initializes EdDSA signatures over given Edwards curve.
 *
 * ```ts
 * import { eddsa } from '@noble/curves/abstract/edwards.js';
 * import { jubjub } from '@noble/curves/misc.js';
 * import { sha512 } from '@noble/hashes/sha2.js';
 * const sigs = eddsa(jubjub.Point, sha512);
 * const { secretKey, publicKey } = sigs.keygen();
 * const msg = new TextEncoder().encode('hello noble');
 * const sig = sigs.sign(msg, secretKey);
 * const isValid = sigs.verify(sig, msg, publicKey);
 * ```
 */
export function eddsa(
  Point: EdwardsPointCons,
  cHash: TArg<FHash>,
  eddsaOpts: TArg<EdDSAOpts> = {}
): EdDSA {
  if (typeof cHash !== 'function') throw new Error('"hash" function param is required');
  const hash = cHash as FHash;
  const opts = eddsaOpts as EdDSAOpts;
  validateObject(
    opts,
    {},
    {
      adjustScalarBytes: 'function',
      randomBytes: 'function',
      domain: 'function',
      prehash: 'function',
      zip215: 'boolean',
      mapToCurve: 'function',
    }
  );

  const { prehash } = opts;
  const { BASE, Fp, Fn } = Point;
  const outputLen = (hash as FHash & { outputLen?: number }).outputLen;
  const expectedLen = 2 * Fp.BYTES;
  // When hash metadata is available, reject incompatible EdDSA wrappers at construction time
  // instead of deferring the mismatch until the first keygen/sign call.
  if (outputLen !== undefined) {
    asafenumber(outputLen, 'hash.outputLen');
    if (outputLen !== expectedLen)
      throw new Error(`hash.outputLen must be ${expectedLen}, got ${outputLen}`);
  }

  const randomBytes = opts.randomBytes === undefined ? wcRandomBytes : opts.randomBytes;
  const adjustScalarBytes =
    opts.adjustScalarBytes === undefined
      ? (bytes: TArg<Uint8Array>) => bytes as TRet<Uint8Array>
      : opts.adjustScalarBytes;
  const domain =
    opts.domain === undefined
      ? (data: TArg<Uint8Array>, ctx: TArg<Uint8Array>, phflag: boolean) => {
          abool(phflag, 'phflag');
          if (ctx.length || phflag) throw new Error('Contexts/pre-hash are not supported');
          return data as TRet<Uint8Array>;
        }
      : opts.domain; // NOOP

  // Parse an EdDSA digest as a little-endian integer and reduce it modulo the scalar field order.
  function modN_LE(hash: TArg<Uint8Array>): bigint {
    return Fn.create(bytesToNumberLE(hash)); // Not Fn.fromBytes: it has length limit
  }

  // Get the hashed private scalar per RFC8032 5.1.5
  function getPrivateScalar(key: TArg<Uint8Array>) {
    const len = lengths.secretKey;
    abytes(key, lengths.secretKey, 'secretKey');
    // Hash private key with curve's hash function to produce uniformingly random input
    // Check byte lengths: ensure(64, h(ensure(32, key)))
    const hashed = abytes(hash(key), 2 * len, 'hashedSecretKey');
    // Slice before clamping so in-place adjustors don't corrupt the prefix half.
    const head = adjustScalarBytes(hashed.slice(0, len)); // clear first half bits, produce FE
    const prefix = hashed.slice(len, 2 * len) as TRet<Uint8Array>; // second half is called key prefix (5.1.6)
    const scalar = modN_LE(head); // The actual private scalar
    return { head, prefix, scalar };
  }

  /** Convenience method that creates public key from scalar. RFC8032 5.1.5
   * Also exposes the derived scalar/prefix tuple and point form reused by sign().
   */
  function getExtendedPublicKey(secretKey: TArg<Uint8Array>) {
    const { head, prefix, scalar } = getPrivateScalar(secretKey);
    const point = BASE.multiply(scalar); // Point on Edwards curve aka public key
    const pointBytes = point.toBytes() as TRet<Uint8Array>;
    return { head, prefix, scalar, point, pointBytes };
  }

  /** Calculates EdDSA pub key. RFC8032 5.1.5. */
  function getPublicKey(secretKey: TArg<Uint8Array>): TRet<Uint8Array> {
    return getExtendedPublicKey(secretKey).pointBytes;
  }

  // Hash domain-separated chunks into a little-endian scalar modulo the group order.
  function hashDomainToScalar(
    context: TArg<Uint8Array> = Uint8Array.of(),
    ...msgs: TArg<Uint8Array[]>
  ) {
    const msg = concatBytes(...msgs);
    return modN_LE(hash(domain(msg, abytes(context, undefined, 'context'), !!prehash)));
  }

  /** Signs message with secret key. RFC8032 5.1.6 */
  function sign(
    msg: TArg<Uint8Array>,
    secretKey: TArg<Uint8Array>,
    options: TArg<{ context?: Uint8Array }> = {}
  ): TRet<Uint8Array> {
    msg = abytes(msg, undefined, 'message');
    if (prehash) msg = prehash(msg); // for ed25519ph etc.
    const { prefix, scalar, pointBytes } = getExtendedPublicKey(secretKey);
    const r = hashDomainToScalar(options.context, prefix, msg); // r = dom2(F, C) || prefix || PH(M)
    // RFC 8032 5.1.6 allows r mod L = 0, and SUPERCOP ref10 accepts the resulting identity-point
    // signature.
    // We intentionally keep the safe multiply() rejection here so a miswired all-zero hash provider
    // fails loudly instead of silently producing a degenerate signature.
    const R = BASE.multiply(r).toBytes(); // R = rG
    const k = hashDomainToScalar(options.context, R, pointBytes, msg); // R || A || PH(M)
    const s = Fn.create(r + k * scalar); // S = (r + k * s) mod L
    if (!Fn.isValid(s)) throw new Error('sign failed: invalid s'); // 0 <= s < L
    const rs = concatBytes(R, Fn.toBytes(s));
    return abytes(rs, lengths.signature, 'result') as TRet<Uint8Array>;
  }

  // Keep the shared helper strict by default: RFC 8032 / NIST-style wrappers should reject
  // non-canonical encodings unless they explicitly opt into ZIP-215's more permissive decode rules.
  const verifyOpts: TArg<{ context?: Uint8Array; zip215?: boolean }> = {
    zip215: opts.zip215,
  };

  /**
   * Verifies EdDSA signature against message and public key. RFC 8032 §§5.1.7 and 5.2.7.
   * A cofactored verification equation is checked.
   */
  function verify(
    sig: TArg<Uint8Array>,
    msg: TArg<Uint8Array>,
    publicKey: TArg<Uint8Array>,
    options = verifyOpts
  ): boolean {
    // Preserve the wrapper-selected default for `{}` / `{ zip215: undefined }`, not just omitted opts.
    const { context } = options;
    const zip215 = options.zip215 === undefined ? !!verifyOpts.zip215 : options.zip215;
    const len = lengths.signature;
    sig = abytes(sig, len, 'signature');
    msg = abytes(msg, undefined, 'message');
    publicKey = abytes(publicKey, lengths.publicKey, 'publicKey');
    if (zip215 !== undefined) abool(zip215, 'zip215');
    if (prehash) msg = prehash(msg); // for ed25519ph, etc

    const mid = len / 2;
    const r = sig.subarray(0, mid);
    const s = bytesToNumberLE(sig.subarray(mid, len));
    let A, R, SB;
    try {
      // ZIP-215 is more permissive than RFC 8032 / NIST186-5. Use it only for wrappers that
      // explicitly want consensus-style unreduced encoding acceptance.
      // zip215=true:  0 <= y < MASK (2^256 for ed25519)
      // zip215=false: 0 <= y < P (2^255-19 for ed25519)
      A = Point.fromBytes(publicKey, zip215);
      R = Point.fromBytes(r, zip215);
      SB = BASE.multiplyUnsafe(s); // 0 <= s < l is done inside
    } catch (error) {
      return false;
    }
    // RFC 8032 §§5.1.7/5.2.7 and FIPS 186-5 §§7.7.2/7.8.2 only decode A' and check the cofactored
    // verification equation; they do not add a separate low-order-public-key rejection here.
    // Strict mode still rejects small-order A' intentionally for SBS-style non-repudiation and to
    // avoid ambiguous verification outcomes where unusual low-order keys can make distinct
    // key/signature/message combinations verify.
    if (!zip215 && A.isSmallOrder()) return false;

    // ZIP-215 accepts noncanonical / unreduced point encodings, so the challenge hash must use the
    // exact signature/public-key bytes rather than canonicalized re-encodings of the decoded points.
    const k = hashDomainToScalar(context, r, publicKey, msg);
    const RkA = R.add(A.multiplyUnsafe(k));
    // Check the cofactored verification equation via the curve cofactor h.
    // [h][S]B = [h]R + [h][k]A'
    return RkA.subtract(SB).clearCofactor().is0();
  }

  const _size = Fp.BYTES; // 32 for ed25519, 57 for ed448
  const lengths = {
    secretKey: _size,
    publicKey: _size,
    signature: 2 * _size,
    seed: _size,
  };
  function randomSecretKey(seed?: TArg<Uint8Array>): TRet<Uint8Array> {
    seed = seed === undefined ? randomBytes(lengths.seed) : seed;
    return abytes(seed, lengths.seed, 'seed') as TRet<Uint8Array>;
  }

  function isValidSecretKey(key: TArg<Uint8Array>): boolean {
    return isBytes(key) && key.length === lengths.secretKey;
  }

  function isValidPublicKey(key: TArg<Uint8Array>, zip215?: boolean): boolean {
    try {
      // Preserve the wrapper-selected default for omitted / `undefined` ZIP-215 flags here too.
      return !!Point.fromBytes(key, zip215 === undefined ? verifyOpts.zip215 : zip215);
    } catch (error) {
      return false;
    }
  }

  const utils = {
    getExtendedPublicKey,
    randomSecretKey,
    isValidSecretKey,
    isValidPublicKey,
    /**
     * Converts ed public key to x public key. Uses formula:
     * - ed25519:
     *   - `(u, v) = ((1+y)/(1-y), sqrt(-486664)*u/x)`
     *   - `(x, y) = (sqrt(-486664)*u/v, (u-1)/(u+1))`
     * - ed448:
     *   - `(u, v) = ((y-1)/(y+1), sqrt(156324)*u/x)`
     *   - `(x, y) = (sqrt(156324)*u/v, (1+u)/(1-u))`
     */
    toMontgomery(publicKey: TArg<Uint8Array>): TRet<Uint8Array> {
      const { y } = Point.fromBytes(publicKey);
      const size = lengths.publicKey;
      const is25519 = size === 32;
      if (!is25519 && size !== 57) throw new Error('only defined for 25519 and 448');
      const u = is25519 ? Fp.div(_1n + y, _1n - y) : Fp.div(y - _1n, y + _1n);
      return Fp.toBytes(u) as TRet<Uint8Array>;
    },
    toMontgomerySecret(secretKey: TArg<Uint8Array>): TRet<Uint8Array> {
      const size = lengths.secretKey;
      abytes(secretKey, size);
      const hashed = hash(secretKey.subarray(0, size));
      return adjustScalarBytes(hashed).subarray(0, size) as TRet<Uint8Array>;
    },
  };
  Object.freeze(lengths);
  Object.freeze(utils);

  return Object.freeze({
    keygen: createKeygen(randomSecretKey, getPublicKey),
    getPublicKey,
    sign,
    verify,
    utils,
    Point,
    lengths,
  }) satisfies Signer;
}
