/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// Implementation of Short Weierstrass curve. The formula is: y² = x³ + ax + b

// TODO: sync vs async naming
// TODO: default randomBytes
// Differences from noble/secp256k1:
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
  nLength,
  hashToPrivateScalar,
} from './utils.js';
import { wNAF } from './group.js';

export type CHash = {
  (message: Uint8Array | string): Uint8Array;
  blockLen: number;
  outputLen: number;
  create(): any;
};
type HmacFnSync = (key: Uint8Array, ...messages: Uint8Array[]) => Uint8Array;
type EndomorphismOpts = {
  beta: bigint;
  splitScalar: (k: bigint) => { k1neg: boolean; k1: bigint; k2neg: boolean; k2: bigint };
};

export type CurveType = {
  // Params: a, b
  a: bigint;
  b: bigint;
  // Field over which we'll do calculations. Verify with:
  P: bigint;
  // Curve order, total count of valid points in the field. Verify with:
  n: bigint;
  nBitLength?: number;
  nByteLength?: number;
  // Base point (x, y) aka generator point
  Gx: bigint;
  Gy: bigint;

  // Default options
  lowS?: boolean;

  // Hashes
  hash: CHash; // Because we need outputLen for DRBG
  hmac: HmacFnSync;
  randomBytes: (bytesLength?: number) => Uint8Array;

  truncateHash?: (hash: Uint8Array, truncateOnly?: boolean) => bigint;
  // Some fields can have specialized fast case
  sqrtMod?: (n: bigint) => bigint;

  // TODO: move into options?
  // Endomorphism options for Koblitz curves
  endo?: EndomorphismOpts;
};

// We accept hex strings besides Uint8Array for simplicity
type Hex = Uint8Array | string;
// Very few implementations accept numbers, we do it to ease learning curve
type PrivKey = Hex | bigint | number;

// Should be separate from overrides, since overrides can use information about curve (for example nBits)
function validateOpts(curve: CurveType) {
  if (typeof curve.hash !== 'function' || !Number.isSafeInteger(curve.hash.outputLen))
    throw new Error('Invalid hash function');
  if (typeof curve.hmac !== 'function') throw new Error('Invalid hmac function');
  if (typeof curve.randomBytes !== 'function') throw new Error('Invalid randomBytes function');

  for (const i of ['a', 'b', 'P', 'n', 'Gx', 'Gy'] as const) {
    if (typeof curve[i] !== 'bigint')
      throw new Error(`Invalid curve param ${i}=${curve[i]} (${typeof curve[i]})`);
  }
  for (const i of ['nBitLength', 'nByteLength'] as const) {
    if (curve[i] === undefined) continue; // Optional
    if (!Number.isSafeInteger(curve[i]))
      throw new Error(`Invalid curve param ${i}=${curve[i]} (${typeof curve[i]})`);
  }
  const endo = curve.endo;
  if (endo) {
    if (curve.a !== _0n) {
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
  // Set defaults
  return Object.freeze({ lowS: true, ...nLength(curve.n, curve.nBitLength), ...curve } as const);
}

// TODO: convert bits to bytes aligned to 32 bits? (224 for example)

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
const _2n = BigInt(2);
const _3n = BigInt(3);
const _8n = BigInt(8);

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
export interface SignatureType {
  readonly r: bigint;
  readonly s: bigint;
  readonly recovery?: number;
  assertValidity(): void;
  copyWithRecoveryBit(recovery: number): SignatureType;
  hasHighS(): boolean;
  normalizeS(): SignatureType;
  recoverPublicKey(msgHash: Hex): PointType;
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

// Instance
export interface JacobianPointType {
  readonly x: bigint;
  readonly y: bigint;
  readonly z: bigint;
  equals(other: JacobianPointType): boolean;
  negate(): JacobianPointType;
  double(): JacobianPointType;
  add(other: JacobianPointType): JacobianPointType;
  subtract(other: JacobianPointType): JacobianPointType;
  multiply(scalar: number | bigint, affinePoint?: PointType): JacobianPointType;
  multiplyUnsafe(scalar: bigint): JacobianPointType;
  toAffine(invZ?: bigint): PointType;
}
// Static methods
export type JacobianPointConstructor = {
  new (x: bigint, y: bigint, z: bigint): JacobianPointType;
  BASE: JacobianPointType;
  ZERO: JacobianPointType;
  fromAffine(p: PointType): JacobianPointType;
  toAffineBatch(points: JacobianPointType[]): PointType[];
  normalizeZ(points: JacobianPointType[]): JacobianPointType[];
};
// Instance
export interface PointType {
  readonly x: bigint;
  readonly y: bigint;
  _setWindowSize(windowSize: number): void;
  hasEvenY(): boolean;
  toRawBytes(isCompressed?: boolean): Uint8Array;
  toHex(isCompressed?: boolean): string;
  assertValidity(): void;
  equals(other: PointType): boolean;
  negate(): PointType;
  double(): PointType;
  add(other: PointType): PointType;
  subtract(other: PointType): PointType;
  multiply(scalar: number | bigint): PointType;
  multiplyAndAddUnsafe(Q: PointType, a: bigint, b: bigint): PointType | undefined;
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
  Point: PointConstructor;
  JacobianPoint: JacobianPointConstructor;
  Signature: SignatureConstructor;
  utils: {
    mod: (a: bigint, b?: bigint) => bigint;
    invert: (number: bigint, modulo?: bigint) => bigint;
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

// Use only input from curveOpts!
export function weierstrass(curveDef: CurveType): CurveFn {
  const CURVE = validateOpts(curveDef) as ReturnType<typeof validateOpts>;
  const CURVE_ORDER = CURVE.n;
  // Lengths
  // All curves has same field / group length as for now, but it can be different for other curves
  const groupLen = CURVE.nByteLength;
  const fieldLen = CURVE.nByteLength; // 32 (length of one field element)
  if (fieldLen > 2048) throw new Error('Field lengths over 2048 are not supported');

  const compressedLen = fieldLen + 1; // 33
  const uncompressedLen = 2 * fieldLen + 1; // 65
  // Not using ** operator with bigints for old engines.
  // 2n ** (8n * 32n) == 2n << (8n * 32n - 1n)
  const FIELD_MASK = _2n << (_8n * BigInt(fieldLen) - _1n);
  function numToFieldStr(num: bigint): string {
    if (typeof num !== 'bigint') throw new Error('Expected bigint');
    if (!(_0n <= num && num < FIELD_MASK)) throw new Error(`Expected number < 2^${fieldLen * 8}`);
    return num.toString(16).padStart(2 * fieldLen, '0');
  }

  function numToField(num: bigint): Uint8Array {
    const b = hexToBytes(numToFieldStr(num));
    if (b.length !== fieldLen) throw new Error(`Error: expected ${fieldLen} bytes`);
    return b;
  }

  function modP(n: bigint, m = CURVE.P) {
    return mod.mod(n, m);
  }

  /**
   * y² = x³ + ax + b: Short weierstrass curve formula
   * @returns y²
   */
  function weierstrassEquation(x: bigint): bigint {
    const { a, b } = CURVE;
    const x2 = modP(x * x);
    const x3 = modP(x2 * x);
    return modP(x3 + a * x + b);
  }

  function isWithinCurveOrder(num: bigint): boolean {
    return _0n < num && num < CURVE.n;
  }

  function isValidFieldElement(num: bigint): boolean {
    return _0n < num && num < CURVE.P;
  }

  function normalizePrivateKey(key: PrivKey): bigint {
    let num: bigint;
    if (typeof key === 'bigint') {
      num = key;
    } else if (typeof key === 'number' && Number.isSafeInteger(key) && key > 0) {
      num = BigInt(key);
    } else if (typeof key === 'string') {
      key = key.padStart(2 * groupLen, '0'); // Eth-like hexes
      if (key.length !== 2 * groupLen) throw new Error(`Expected ${groupLen} bytes of private key`);
      num = hexToNumber(key);
    } else if (key instanceof Uint8Array) {
      if (key.length !== groupLen) throw new Error(`Expected ${groupLen} bytes of private key`);
      num = bytesToNumberBE(key);
    } else {
      throw new TypeError('Expected valid private key');
    }
    if (!isWithinCurveOrder(num)) throw new Error('Expected private key: 0 < key < n');
    return num;
  }

  /**
   * Normalizes hex, bytes, Point to Point. Checks for curve equation.
   */
  function normalizePublicKey(publicKey: PubKey): Point {
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

  function normalizeScalar(num: number | bigint): bigint {
    if (typeof num === 'number' && Number.isSafeInteger(num) && num > 0) return BigInt(num);
    if (typeof num === 'bigint' && isWithinCurveOrder(num)) return num;
    throw new TypeError('Expected valid private scalar: 0 < scalar < curve.n');
  }

  const sqrtModCurve = CURVE.sqrtMod || mod.sqrt;

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
   * Jacobian Point works in 3d / jacobi coordinates: (x, y, z) ∋ (x=x/z², y=y/z³)
   * Default Point works in 2d / affine coordinates: (x, y)
   * We're doing calculations in jacobi, because its operations don't require costly inversion.
   */
  class JacobianPoint implements JacobianPointType {
    constructor(readonly x: bigint, readonly y: bigint, readonly z: bigint) {}

    static readonly BASE = new JacobianPoint(CURVE.Gx, CURVE.Gy, _1n);
    static readonly ZERO = new JacobianPoint(_0n, _1n, _0n);

    static fromAffine(p: Point): JacobianPoint {
      if (!(p instanceof Point)) {
        throw new TypeError('JacobianPoint#fromAffine: expected Point');
      }
      // fromAffine(x:0, y:0) would produce (x:0, y:0, z:1), but we need (x:0, y:1, z:0)
      if (p.equals(Point.ZERO)) return JacobianPoint.ZERO;
      return new JacobianPoint(p.x, p.y, _1n);
    }

    /**
     * Takes a bunch of Jacobian Points but executes only one
     * invert on all of them. invert is very slow operation,
     * so this improves performance massively.
     */
    static toAffineBatch(points: JacobianPoint[]): Point[] {
      const toInv = mod.invertBatch(
        points.map((p) => p.z),
        CURVE.P
      );
      return points.map((p, i) => p.toAffine(toInv[i]));
    }

    static normalizeZ(points: JacobianPoint[]): JacobianPoint[] {
      return JacobianPoint.toAffineBatch(points).map(JacobianPoint.fromAffine);
    }

    /**
     * Compare one point to another.
     */
    equals(other: JacobianPoint): boolean {
      if (!(other instanceof JacobianPoint)) throw new TypeError('JacobianPoint expected');
      const { x: X1, y: Y1, z: Z1 } = this;
      const { x: X2, y: Y2, z: Z2 } = other;
      const Z1Z1 = modP(Z1 * Z1);
      const Z2Z2 = modP(Z2 * Z2);
      const U1 = modP(X1 * Z2Z2);
      const U2 = modP(X2 * Z1Z1);
      const S1 = modP(modP(Y1 * Z2) * Z2Z2);
      const S2 = modP(modP(Y2 * Z1) * Z1Z1);
      return U1 === U2 && S1 === S2;
    }

    /**
     * Flips point to one corresponding to (x, -y) in Affine coordinates.
     */
    negate(): JacobianPoint {
      return new JacobianPoint(this.x, modP(-this.y), this.z);
    }

    // Fast algo for doubling 2 Jacobian Points.
    // From: https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-2007-bl
    // Cost: 1M + 8S + 1*a + 10add + 2*2 + 1*3 + 1*8.
    double(): JacobianPoint {
      const { x: X1, y: Y1, z: Z1 } = this;
      const { a } = CURVE;

      // // Faster algorithm: when a=0
      // // From: https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
      // // Cost: 2M + 5S + 6add + 3*2 + 1*3 + 1*8.
      if (a === _0n) {
        const A = modP(X1 * X1);
        const B = modP(Y1 * Y1);
        const C = modP(B * B);
        const x1b = X1 + B;
        const D = modP(_2n * (modP(x1b * x1b) - A - C));
        const E = modP(_3n * A);
        const F = modP(E * E);
        const X3 = modP(F - _2n * D);
        const Y3 = modP(E * (D - X3) - _8n * C);
        const Z3 = modP(_2n * Y1 * Z1);
        return new JacobianPoint(X3, Y3, Z3);
      }
      const XX = modP(X1 * X1);
      const YY = modP(Y1 * Y1);
      const YYYY = modP(YY * YY);
      const ZZ = modP(Z1 * Z1);
      const tmp1 = modP(X1 + YY);
      const S = modP(_2n * (modP(tmp1 * tmp1) - XX - YYYY)); // 2*((X1+YY)^2-XX-YYYY)
      const M = modP(_3n * XX + a * modP(ZZ * ZZ));
      const T = modP(modP(M * M) - _2n * S); // M^2-2*S
      const X3 = T;
      const Y3 = modP(M * (S - T) - _8n * YYYY); // M*(S-T)-8*YYYY
      const y1az1 = modP(Y1 + Z1); // (Y1+Z1)
      const Z3 = modP(modP(y1az1 * y1az1) - YY - ZZ); // (Y1+Z1)^2-YY-ZZ
      return new JacobianPoint(X3, Y3, Z3);
    }

    // Fast algo for adding 2 Jacobian Points.
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-add-1998-cmo-2
    // Cost: 12M + 4S + 6add + 1*2
    // Note: 2007 Bernstein-Lange (11M + 5S + 9add + 4*2) is actually 10% slower.
    add(other: JacobianPoint): JacobianPoint {
      if (!(other instanceof JacobianPoint)) throw new TypeError('JacobianPoint expected');
      const { x: X1, y: Y1, z: Z1 } = this;
      const { x: X2, y: Y2, z: Z2 } = other;
      if (X2 === _0n || Y2 === _0n) return this;
      if (X1 === _0n || Y1 === _0n) return other;
      // We're using same code in equals()
      const Z1Z1 = modP(Z1 * Z1); // Z1Z1 = Z1^2
      const Z2Z2 = modP(Z2 * Z2); // Z2Z2 = Z2^2;
      const U1 = modP(X1 * Z2Z2); // X1 * Z2Z2
      const U2 = modP(X2 * Z1Z1); // X2 * Z1Z1
      const S1 = modP(modP(Y1 * Z2) * Z2Z2); // Y1 * Z2 * Z2Z2
      const S2 = modP(modP(Y2 * Z1) * Z1Z1); // Y2 * Z1 * Z1Z1
      const H = modP(U2 - U1); // H = U2 - U1
      const r = modP(S2 - S1); // S2 - S1
      // H = 0 meaning it's the same point.
      if (H === _0n) return r === _0n ? this.double() : JacobianPoint.ZERO;
      const HH = modP(H * H); // HH = H2
      const HHH = modP(H * HH); // HHH = H * HH
      const V = modP(U1 * HH); // V = U1 * HH
      const X3 = modP(r * r - HHH - _2n * V); // X3 = r^2 - HHH - 2 * V;
      const Y3 = modP(r * (V - X3) - S1 * HHH); // Y3 = r * (V - X3) - S1 * HHH;
      const Z3 = modP(Z1 * Z2 * H); // Z3 = Z1 * Z2 * H;
      return new JacobianPoint(X3, Y3, Z3);
    }

    subtract(other: JacobianPoint) {
      return this.add(other.negate());
    }

    /**
     * Non-constant-time multiplication. Uses double-and-add algorithm.
     * It's faster, but should only be used when you don't care about
     * an exposed private key e.g. sig verification, which works over *public* keys.
     */
    multiplyUnsafe(scalar: bigint): JacobianPoint {
      const P0 = JacobianPoint.ZERO;
      if (typeof scalar === 'bigint' && scalar === _0n) return P0;
      // Will throw on 0
      let n = normalizeScalar(scalar);
      if (n === _1n) return this;

      if (!CURVE.endo) return wnaf.unsafeLadder(this, n);

      // Apply endomorphism
      let { k1neg, k1, k2neg, k2 } = CURVE.endo.splitScalar(n);
      let k1p = P0;
      let k2p = P0;
      let d: JacobianPoint = this;
      while (k1 > _0n || k2 > _0n) {
        if (k1 & _1n) k1p = k1p.add(d);
        if (k2 & _1n) k2p = k2p.add(d);
        d = d.double();
        k1 >>= _1n;
        k2 >>= _1n;
      }
      if (k1neg) k1p = k1p.negate();
      if (k2neg) k2p = k2p.negate();
      k2p = new JacobianPoint(modP(k2p.x * CURVE.endo.beta), k2p.y, k2p.z);
      return k1p.add(k2p);
    }

    /**
     * Implements w-ary non-adjacent form for calculating ec multiplication.
     */
    private wNAF(n: bigint, affinePoint?: Point): { p: JacobianPoint; f: JacobianPoint } {
      if (!affinePoint && this.equals(JacobianPoint.BASE)) affinePoint = Point.BASE;
      const W = (affinePoint && affinePoint._WINDOW_SIZE) || 1;
      // Calculate precomputes on a first run, reuse them after
      let precomputes = affinePoint && pointPrecomputes.get(affinePoint);
      if (!precomputes) {
        precomputes = wnaf.precomputeWindow(this, W) as JacobianPoint[];
        if (affinePoint && W !== 1) {
          precomputes = JacobianPoint.normalizeZ(precomputes);
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
    multiply(scalar: number | bigint, affinePoint?: Point): JacobianPoint {
      let n = normalizeScalar(scalar);

      // Real point.
      let point: JacobianPoint;
      // Fake point, we use it to achieve constant-time multiplication.
      let fake: JacobianPoint;
      if (CURVE.endo) {
        const { k1neg, k1, k2neg, k2 } = CURVE.endo.splitScalar(n);
        let { p: k1p, f: f1p } = this.wNAF(k1, affinePoint);
        let { p: k2p, f: f2p } = this.wNAF(k2, affinePoint);
        k1p = wnaf.constTimeNegate(k1neg, k1p);
        k2p = wnaf.constTimeNegate(k2neg, k2p);
        k2p = new JacobianPoint(modP(k2p.x * CURVE.endo.beta), k2p.y, k2p.z);
        point = k1p.add(k2p);
        fake = f1p.add(f2p);
      } else {
        const { p, f } = this.wNAF(n, affinePoint);
        point = p;
        fake = f;
      }
      // Normalize `z` for both points, but return only real one
      return JacobianPoint.normalizeZ([point, fake])[0];
    }

    // Converts Jacobian point to affine (x, y) coordinates.
    // Can accept precomputed Z^-1 - for example, from invertBatch.
    // (x, y, z) ∋ (x=x/z², y=y/z³)
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#scaling-z
    toAffine(invZ?: bigint): Point {
      const { x, y, z } = this;
      const is0 = this.equals(JacobianPoint.ZERO);
      // If invZ was 0, we return zero point. However we still want to execute
      // all operations, so we replace invZ with a random number, 8.
      if (invZ == null) invZ = is0 ? _8n : mod.invert(z, CURVE.P);
      const iz1 = invZ;
      const iz2 = modP(iz1 * iz1);
      const iz3 = modP(iz2 * iz1);
      const ax = modP(x * iz2);
      const ay = modP(y * iz3);
      const zz = modP(z * iz1);
      if (is0) return Point.ZERO;
      if (zz !== _1n) throw new Error('invZ was invalid');
      return new Point(ax, ay);
    }
  }
  const wnaf = wNAF(JacobianPoint, CURVE.endo ? CURVE.nBitLength / 2 : CURVE.nBitLength);

  // Stores precomputed values for points.
  const pointPrecomputes = new WeakMap<Point, JacobianPoint[]>();

  /**
   * Default Point works in default aka affine coordinates: (x, y)
   */
  class Point implements PointType {
    /**
     * Base point aka generator. public_key = Point.BASE * private_key
     */
    static BASE: Point = new Point(CURVE.Gx, CURVE.Gy);
    /**
     * Identity point aka point at infinity. point = point + zero_point
     */
    static ZERO: Point = new Point(_0n, _0n);

    // We calculate precomputes for elliptic curve point multiplication
    // using windowed method. This specifies window size and
    // stores precomputed values. Usually only base point would be precomputed.
    _WINDOW_SIZE?: number;

    constructor(readonly x: bigint, readonly y: bigint) {}

    // "Private method", don't use it directly
    _setWindowSize(windowSize: number) {
      this._WINDOW_SIZE = windowSize;
      pointPrecomputes.delete(this);
    }

    // Checks for y % 2 == 0
    hasEvenY() {
      return this.y % _2n === _0n;
    }

    /**
     * Supports compressed ECDSA points
     * @returns Point instance
     */
    private static fromCompressedHex(bytes: Uint8Array) {
      const P = CURVE.P;
      const x = bytesToNumberBE(bytes.subarray(1));
      if (!isValidFieldElement(x)) throw new Error('Point is not on curve');
      const y2 = weierstrassEquation(x); // y² = x³ + ax + b
      let y = sqrtModCurve(y2, P); // y = y² ^ (p+1)/4
      const isYOdd = (y & _1n) === _1n;
      // ECDSA
      const isFirstByteOdd = (bytes[0] & 1) === 1;
      if (isFirstByteOdd !== isYOdd) y = modP(-y);
      const point = new Point(x, y);
      point.assertValidity();
      return point;
    }

    private static fromUncompressedHex(bytes: Uint8Array) {
      const x = bytesToNumberBE(bytes.subarray(1, fieldLen + 1));
      const y = bytesToNumberBE(bytes.subarray(fieldLen + 1, 2 * fieldLen + 1));
      const point = new Point(x, y);
      point.assertValidity();
      return point;
    }

    /**
     * Converts hash string or Uint8Array to Point.
     * @param hex short/long ECDSA hex
     */
    static fromHex(hex: Hex): Point {
      const bytes = ensureBytes(hex);
      const len = bytes.length;
      const header = bytes[0];
      // this.assertValidity() is done inside of those two functions
      if (len === compressedLen && (header === 0x02 || header === 0x03))
        return this.fromCompressedHex(bytes);
      if (len === uncompressedLen && header === 0x04) return this.fromUncompressedHex(bytes);
      throw new Error(
        `Point.fromHex: received invalid point. Expected ${compressedLen} compressed bytes or ${uncompressedLen} uncompressed bytes, not ${len}`
      );
    }

    // Multiplies generator point by privateKey.
    static fromPrivateKey(privateKey: PrivKey) {
      return Point.BASE.multiply(normalizePrivateKey(privateKey));
    }

    toRawBytes(isCompressed = false): Uint8Array {
      return hexToBytes(this.toHex(isCompressed));
    }

    toHex(isCompressed = false): string {
      const x = numToFieldStr(this.x);
      if (isCompressed) {
        const prefix = this.hasEvenY() ? '02' : '03';
        return `${prefix}${x}`;
      } else {
        return `04${x}${numToFieldStr(this.y)}`;
      }
    }

    // A point on curve is valid if it conforms to equation.
    assertValidity(): void {
      const msg = 'Point is not on curve';
      const { x, y } = this;
      if (!isValidFieldElement(x) || !isValidFieldElement(y)) throw new Error(msg);
      const left = modP(y * y);
      const right = weierstrassEquation(x);
      if (modP(left - right) !== _0n) throw new Error(msg);
    }

    equals(other: Point): boolean {
      return this.x === other.x && this.y === other.y;
    }

    // Returns the same point with inverted `y`
    negate() {
      return new Point(this.x, modP(-this.y));
    }

    // Adds point to itself
    double() {
      return JacobianPoint.fromAffine(this).double().toAffine();
    }

    // Adds point to other point
    add(other: Point) {
      return JacobianPoint.fromAffine(this).add(JacobianPoint.fromAffine(other)).toAffine();
    }

    // Subtracts other point from the point
    subtract(other: Point) {
      return this.add(other.negate());
    }

    multiply(scalar: number | bigint) {
      return JacobianPoint.fromAffine(this).multiply(scalar, this).toAffine();
    }

    /**
     * Efficiently calculate `aP + bQ`.
     * Unsafe, can expose private key, if used incorrectly.
     * TODO: Utilize Shamir's trick
     * @returns non-zero affine point
     */
    multiplyAndAddUnsafe(Q: Point, a: bigint, b: bigint): Point | undefined {
      const P = JacobianPoint.fromAffine(this);
      const aP =
        a === _0n || a === _1n || this !== Point.BASE ? P.multiplyUnsafe(a) : P.multiply(a);
      const bQ = JacobianPoint.fromAffine(Q).multiplyUnsafe(b);
      const sum = aP.add(bQ);
      return sum.equals(JacobianPoint.ZERO) ? undefined : sum.toAffine();
    }
  }

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
    mod: modP,
    invert: (n: bigint, m: bigint = CURVE.P) => mod.invert(n, m),
    isValidPrivateKey(privateKey: PrivKey) {
      try {
        normalizePrivateKey(privateKey);
        return true;
      } catch (error) {
        return false;
      }
    },
    _bigintToBytes: numToField,
    _normalizePrivateKey: normalizePrivateKey,

    /**
     * Can take (keyLength + 8) or more bytes of uniform input e.g. from CSPRNG or KDF
     * and convert them into private key, with the modulo bias being neglible.
     * As per FIPS 186 B.4.1.
     * https://research.kudelskisecurity.com/2020/07/28/the-definitive-guide-to-modulo-bias-and-how-to-avoid-it/
     * @param hash hash output from sha512, or a similar function
     * @returns valid private key
     */
    hashToPrivateKey: (hash: Hex): Uint8Array => numToField(hashToPrivateScalar(hash, CURVE_ORDER)),

    // Takes curve order + 64 bits from CSPRNG
    // so that modulo bias is neglible, matches FIPS 186 B.4.1.
    randomPrivateKey: (): Uint8Array => utils.hashToPrivateKey(CURVE.randomBytes(fieldLen + 8)),

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
    const slice = bytes.length > fieldLen ? bytes.slice(0, fieldLen) : bytes;
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
      if (extraEntropy === true) extraEntropy = CURVE.randomBytes(fieldLen);
      const e = ensureBytes(extraEntropy);
      if (e.length !== fieldLen) throw new Error(`sign: Expected ${fieldLen} bytes of extra data`);
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
    const k = truncateHash(kBytes, true);
    if (!isWithinCurveOrder(k)) return;
    // Important: all mod() calls in the function must be done over `n`
    const { n } = CURVE;
    const q = Point.BASE.multiply(k);
    // r = x mod n
    const r = mod.mod(q.x, n);
    if (r === _0n) return;
    // s = (1/k * (m + dr) mod n
    const s = mod.mod(mod.invert(k, n) * mod.mod(m + d * r, n), n);
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

    // Some implementations compare R.x in jacobian, without inversion.
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
    JacobianPoint,
    Signature,
    utils,
  };
}
