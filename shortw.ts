/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// Implementation of Short weierstrass curve. The formula is: y² = x³ + ax + b

// TODO: Starknet 0x
// TODO: checks for operations between points of different curves
// TODO: search for other mentions of TODO in the file

export type CHash = {
  (message: Uint8Array | string): Uint8Array;
  blockLen: number;
  outputLen: number;
  create(): any;
};
type HmacFnSync = (key: Uint8Array, ...messages: Uint8Array[]) => Uint8Array;

export type CurveType = {
  // Params: a, b
  a: bigint;
  b: bigint;
  // Field over which we'll do calculations. Verify with:
  P: bigint;
  // Curve order, total count of valid points in the field. Verify with:
  n: bigint;
  nBits?: number; // len(bin(N).replace('0b',''))
  nBytes?: number;
  // Base point (x, y) aka generator point
  Gx: bigint;
  Gy: bigint;
  // Default options
  signOpts?: { canonical: boolean };
  verifyOpts?: { strict: boolean };
  // Hashes
  hmac: HmacFnSync;
  hash: CHash; // Because we need outputLen for DRBG
  randomBytes: (bytesLength?: number) => Uint8Array;
};

// We accept hex strings besides Uint8Array for simplicity
type Hex = Uint8Array | string;
// Very few implementations accept numbers, we do it to ease learning curve
type PrivKey = Hex | bigint | number;

// Should be separate from overrides, since overrides can use information about curve (for example nBits)
export function curveOpts(curve: Readonly<CurveType>) {
  if (typeof curve.hash !== 'function' || !Number.isSafeInteger(curve.hash.outputLen))
    throw new Error('Invalid hash function');
  if (typeof curve.hmac !== 'function') throw new Error('Invalid hmac function');
  if (typeof curve.randomBytes !== 'function') throw new Error('Invalid randomBytes function');

  for (const i of ['a', 'b', 'P', 'n', 'Gx', 'Gy'] as const) {
    if (typeof curve[i] !== 'bigint')
      throw new Error(`Invalid curve param ${i}=${curve[i]} (${typeof curve[i]})`);
  }
  for (const i of ['nBits', 'nBytes'] as const) {
    if (curve[i] === undefined) continue; // Optional
    if (!Number.isSafeInteger(curve[i]))
      throw new Error(`Invalid curve param ${i}=${curve[i]} (${typeof curve[i]})`);
  }
  return Object.freeze({
    // Default opts
    signOpts: { canonical: true },
    verifyOpts: { strict: true },
    nBits: bitLen(curve.n), // Bit size of CURVE.n
    nBytes: bitToBytes(bitLen(curve.n)), // Byte size of CURVE.n
    ...curve,
  } as const);
}

export type CurveOverrides = {
  truncateHash?: (hash: Uint8Array, truncateOnly?: boolean) => bigint;
  // Some fields can have specialized fast case
  sqrtMod?: (n: bigint) => bigint;
};

function bitLen(n: number | bigint) {
  return n.toString(2).length;
}

function bitToBytes(n: number) {
  return Math.ceil(n / 8);
}

// TODO: convert bits to bytes aligned to 32 bits? (224 for example)

// DER encoding utilities
function sliceDER(s: string): string {
  // Proof: any([(i>=0x80) == (int(hex(i).replace('0x', '').zfill(2)[0], 16)>=8)  for i in range(0, 256)])
  // Padding done by numberToHex
  return Number.parseInt(s[0], 16) >= 8 ? '00' + s : s;
}

function parseDERInt(data: Uint8Array) {
  if (data.length < 2 || data[0] !== 0x02) {
    throw new Error(`Invalid signature integer tag: ${bytesToHex(data)}`);
  }
  const len = data[1];
  const res = data.subarray(2, len + 2);
  if (!len || res.length !== len) {
    throw new Error(`Invalid signature integer: wrong length`);
  }
  // Strange condition, its not about length, but about first bytes of number.
  if (res[0] === 0x00 && res[1] <= 0x7f) {
    throw new Error('Invalid signature integer: trailing length');
  }
  return { data: bytesToNumber(res), left: data.subarray(len + 2) };
}

function parseDERSignature(data: Uint8Array) {
  if (data.length < 2 || data[0] != 0x30) {
    throw new Error(`Invalid signature tag: ${bytesToHex(data)}`);
  }
  if (data[1] !== data.length - 2) {
    throw new Error('Invalid signature: incorrect length');
  }
  const { data: r, left: sBytes } = parseDERInt(data.subarray(2));
  const { data: s, left: rBytesLeft } = parseDERInt(sBytes);
  if (rBytesLeft.length) {
    throw new Error(`Invalid signature: left bytes after parsing: ${bytesToHex(rBytesLeft)}`);
  }
  return { r, s };
}

// Copies several Uint8Arrays into one.
function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  if (!arrays.every((b) => b instanceof Uint8Array)) throw new Error('Uint8Array list expected');
  if (arrays.length === 1) return arrays[0];
  const length = arrays.reduce((a, arr) => a + arr.length, 0);
  const result = new Uint8Array(length);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const arr = arrays[i];
    result.set(arr, pad);
    pad += arr.length;
  }
  return result;
}

// Convert between types
// ---------------------

const hexes = Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
function bytesToHex(uint8a: Uint8Array): string {
  if (!(uint8a instanceof Uint8Array)) throw new Error('Expected Uint8Array');
  // pre-caching improves the speed 6x
  let hex = '';
  for (let i = 0; i < uint8a.length; i++) {
    hex += hexes[uint8a[i]];
  }
  return hex;
}

function numberToHexUnpadded(num: number | bigint): string {
  const hex = num.toString(16);
  return hex.length & 1 ? `0${hex}` : hex;
}

function hexToNumber(hex: string): bigint {
  if (typeof hex !== 'string') {
    throw new TypeError('hexToNumber: expected string, got ' + typeof hex);
  }
  // Big Endian
  // TODO: strip vs no strip?
  return BigInt(`0x${strip0x(hex)}`);
}

function strip0x(hex: string) {
  return hex.replace(/^0x/i, '');
}

// TODO: strip vs no strip
// Stakware has eth-like hexes
// hex = strip0x(hex);
// if (hex.length & 1) hex = '0' + hex; // padding
// Caching slows it down 2-3x
function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string') {
    throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
  }
  if (hex.length % 2) throw new Error('hexToBytes: received invalid unpadded hex ' + hex.length);
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < array.length; i++) {
    const j = i * 2;
    const hexByte = hex.slice(j, j + 2);
    const byte = Number.parseInt(hexByte, 16);
    if (Number.isNaN(byte) || byte < 0) throw new Error('Invalid byte sequence');
    array[i] = byte;
  }
  return array;
}

// Big Endian
function bytesToNumber(bytes: Uint8Array): bigint {
  return hexToNumber(bytesToHex(bytes));
}

function ensureBytes(hex: Hex): Uint8Array {
  // Uint8Array.from() instead of hash.slice() because node.js Buffer
  // is instance of Uint8Array, and its slice() creates **mutable** copy
  return hex instanceof Uint8Array ? Uint8Array.from(hex) : hexToBytes(hex);
}

// Be friendly to bad ECMAScript parsers by not using bigint literals like 123n
const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);
const _3n = BigInt(3);
const _4n = BigInt(4);
const _8n = BigInt(8);

// Arithmetics
// Calculates a modulo b
function mod(a: bigint, b: bigint): bigint {
  const result = a % b;
  return result >= _0n ? result : b + result;
}
/**
 * Efficiently exponentiate num to power and do modular division.
 * @example
 * powMod(2n, 6n, 11n) // 64n % 11n == 9n
 */
function powMod(num: bigint, power: bigint, modulo: bigint): bigint {
  if (modulo <= _0n || power < _0n) throw new Error('Expected power/modulo > 0');
  if (modulo === _1n) return _0n;
  let res = _1n;
  while (power > _0n) {
    if (power & _1n) res = (res * num) % modulo;
    num = (num * num) % modulo;
    power >>= _1n;
  }
  return res;
}

// Inverses number over modulo
function invert(number: bigint, modulo: bigint): bigint {
  if (number === _0n || modulo <= _0n) {
    throw new Error(`invert: expected positive integers, got n=${number} mod=${modulo}`);
  }
  // Eucledian GCD https://brilliant.org/wiki/extended-euclidean-algorithm/
  let a = mod(number, modulo);
  let b = modulo;
  // prettier-ignore
  let x = _0n, y = _1n, u = _1n, v = _0n;
  while (a !== _0n) {
    const q = b / a;
    const r = b % a;
    const m = x - u * q;
    const n = y - v * q;
    // prettier-ignore
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  const gcd = b;
  if (gcd !== _1n) throw new Error('invert: does not exist');
  return mod(x, modulo);
}

/**
 * Takes a list of numbers, efficiently inverts all of them.
 * @param nums list of bigints
 * @param p modulo
 * @returns list of inverted bigints
 * @example
 * invertBatch([1n, 2n, 4n], 21n);
 * // => [1n, 11n, 16n]
 */
function invertBatch(nums: bigint[], modulo: bigint): bigint[] {
  const scratch = new Array(nums.length);
  // Walk from first to last, multiply them by each other MOD p
  const lastMultiplied = nums.reduce((acc, num, i) => {
    if (num === _0n) return acc;
    scratch[i] = acc;
    return mod(acc * num, modulo);
  }, _1n);
  // Invert last element
  const inverted = invert(lastMultiplied, modulo);
  // Walk from last to first, multiply them by inverted each other MOD p
  nums.reduceRight((acc, num, i) => {
    if (num === _0n) return acc;
    scratch[i] = mod(acc * scratch[i], modulo);
    return mod(acc * num, modulo);
  }, inverted);
  return scratch;
}

// Calculates Legendre symbol: num^((P-1)/2)
function legendre(num: bigint, fieldPrime: bigint): bigint {
  return powMod(num, (fieldPrime - _1n) / _2n, fieldPrime);
}

// Used to calculate y - the square root of y².
// Exponentiates it to very big number (P+1)/4.
// Uses Tonelli-Shanks algorithm.
// TODO: calculate legendre symbol & sqrt in one step
function _sqrtMod(n: bigint, modulo: bigint): bigint {
  // const { P } = CURVE;
  const P = modulo;
  if (legendre(n, P) !== _1n) throw new Error('Cannot find square root');
  let q, s, z;
  for (q = P - _1n, s = 0; q % _2n === _0n; q /= _2n, s++);
  if (s === 1) return powMod(n, (P + _1n) / _4n, P);
  for (z = _2n; z < P && legendre(z, P) !== P - _1n; z++);

  let c = powMod(z, q, P);
  let r = powMod(n, (q + _1n) / _2n, P);
  let t = powMod(n, q, P);

  let t2 = _0n;
  while (mod(t - _1n, P) !== _0n) {
    t2 = mod(t * t, P);
    let i;
    for (i = 1; i < s; i++) {
      if (mod(t2 - _1n, P) === _0n) break;
      t2 = mod(t2 * t2, P);
    }
    let b = powMod(c, BigInt(1 << (s - i - 1)), P);
    r = mod(r * b, P);
    c = mod(b * b, P);
    t = mod(t * c, P);
    s = i;
  }
  return r;
}


// RFC6979 related code
// --------------------
/**
 * Minimal HMAC-DRBG (NIST 800-90) for signatures.
 * Used only for RFC6979, does not fully implement DRBG spec.
 */
class HmacDrbg {
  k: Uint8Array;
  v: Uint8Array;
  counter: number;
  constructor(public hashLen: number, public qByteLen: number, public hmacFn: HmacFnSync) {
    // TODO: validate params
    // Step B, Step C: set hashLen to 8*ceil(hlen/8)
    this.v = new Uint8Array(this.hashLen).fill(1);
    this.k = new Uint8Array(this.hashLen).fill(0);
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
  // TODO
  generateSync(): Uint8Array {
    this.incr();

    let len = 0;
    const out = [];
    while (len < this.qByteLen) {
      this.v = this.hmacSync(this.v);
      out.push(this.v.slice());
      len += this.v.length;
    }
    return concatBytes(...out);
  }
  // There is no need in clean() method
  // It's useless, there are no guarantees with JS GC
  // whether bigints are removed even if you clean Uint8Arrays.
}

type Entropy = Hex | true;
type OptsOther = { canonical?: boolean; der?: boolean; extraEntropy?: Entropy };
type OptsRecov = { recovered: true } & OptsOther;
type OptsNoRecov = { recovered?: false } & OptsOther;
type Opts = { recovered?: boolean } & OptsOther;
type SignOutput = Uint8Array | [Uint8Array, number];

// Design rationale for types:
// - Most important thing here is interaction between classes for different curves: secp.Point.BASE.add(nist.Point.BASE) should fail
// - We want to create classes on function call (that way instanceof is fast/easy way to verify that Point is belong to same curve),
//   this allows us to easily detect classes for different curves at runtime
// - Different calls will return different classes (so if somebody decided to monkey-patch their curve, it won't affect others)
// - Unfortunatly, TypeScript cannot handle this case and infer types for classes created inside function
// - Classes is one instance of nominative types in TS, interfaces checks only shape, so it is pretty hard to create unique type for each
//   function call
// - We can do generic types via some param (like curve opts), but that means:
//   1) Curve will be allowed to interact with curve with same params (rare, hard to debug)
//   2) Params can be generic and we cannot enforce it to be constant value ->
//      if somebody creates curve of non-const params it will be allowed to interact with other curves with non-const params
// TODO: https://www.typescriptlang.org/docs/handbook/release-notes/typescript-2-7.html#unique-symbol

// Instance
export interface SignatureType {
  readonly r: bigint;
  readonly s: bigint;
  assertValidity(): void;
  hasHighS(): boolean;
  normalizeS(): SignatureType;
  // DER-encoded
  toDERRawBytes(isCompressed?: boolean): Uint8Array;
  toDERHex(isCompressed?: boolean): string;
  // toRawBytes(): Uint8Array;
  // toHex(): string;
  toCompactRawBytes(): Uint8Array;
  toCompactHex(): string;
}
// Static methods
export type SignatureConstructor = {
  new (r: bigint, s: bigint): SignatureType;
  fromCompact(hex: Hex): SignatureType;
  fromDER(hex: Hex): SignatureType;
  // fromHex(hex: Hex): SignatureType;
};
type Sig = Hex | SignatureType;
// TODO: clarify whether to allow ui8a
type RecoveredSig = { signature: SignatureType; recovery: number };

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
  multiplyUnsafe(scalar: bigint): JacobianPointType;
  multiply(scalar: number | bigint, affinePoint?: PointType): JacobianPointType;
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
  toHexX(): string;
  toRawX(): Uint8Array;
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
  fromSignature(msgHash: Hex, signature: RecoveredSig): PointType;
};

export type PubKey = Hex | PointType;

export type CurveFn = {
  Point: PointConstructor;
  Signature: SignatureConstructor;
  JacobianPoint: JacobianPointConstructor;
  utils: {
    bytesToHex: (uint8a: Uint8Array) => string;
    hexToBytes: (hex: string) => Uint8Array;
    concatBytes: (...arrays: Uint8Array[]) => Uint8Array;
    mod: (a: bigint, b?: bigint) => bigint;
    invert: (number: bigint, modulo?: bigint) => bigint;
    isValidPrivateKey(privateKey: PrivKey): boolean;
    _bigintToBytes: (num: bigint) => Uint8Array;
    _normalizePrivateKey: (key: PrivKey) => bigint;
    hashToPrivateKey: (hash: Hex) => Uint8Array;
    randomPrivateKey: () => Uint8Array;
    precompute(windowSize?: number, point?: PointType): PointType;
    ensureBytes: (hex: Hex) => Uint8Array;
    bytesToNumber: (bytes: Uint8Array) => bigint;
    numberToHexUnpadded: (num: number | bigint) => string;
    hexToNumber: (hex: string) => bigint;
  };
  getPublicKey: (privateKey: PrivKey, isCompressed?: boolean) => Uint8Array;
  recoverPublicKey: (
    msgHash: Hex,
    signature: Sig,
    recovery: number,
    isCompressed?: boolean
  ) => Uint8Array;
  getSharedSecret: (privateA: PrivKey, publicB: PubKey, isCompressed?: boolean) => Uint8Array;
  sign: {
    (msgHash: Hex, privKey: PrivKey, opts: OptsRecov): [Uint8Array, number];
    (msgHash: Hex, privKey: PrivKey, opts?: OptsNoRecov): Uint8Array;
  };
  verify: (
    signature: Sig,
    msgHash: Hex,
    publicKey: PubKey,
    opts?: {
      strict?: boolean;
    }
  ) => boolean;
};

// Use only input from curveOpts!
export function weierstrass(
  CURVE: ReturnType<typeof curveOpts>,
  overrides: CurveOverrides = {}
): CurveFn {
  // Lengths
  const fieldLen = CURVE.nBytes; // 32 (length of one field element)
  const compressedLen = CURVE.nBytes + 1; // 33
  const uncompressedLen = 2 * CURVE.nBytes + 1; // 65
  // Not using ** operator.
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
    return mod(n, m);
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

  function normalizeScalar(num: number | bigint): bigint {
    if (typeof num === 'number' && Number.isSafeInteger(num) && num > 0) return BigInt(num);
    if (typeof num === 'bigint' && isWithinCurveOrder(num)) return num;
    throw new TypeError('Expected valid private scalar: 0 < scalar < curve.n');
  }

  const sqrtMod = overrides.sqrtMod || _sqrtMod;

  // Ensures ECDSA message hashes are 32 bytes and < curve order
  function _truncateHash(hash: Uint8Array, truncateOnly = false): bigint {
    const { n, nBits } = CURVE;
    const byteLength = hash.length;
    const delta = byteLength * 8 - nBits; // size of curve.n (252 bits)
    let h = bytesToNumber(hash);
    if (delta > 0) h = h >> BigInt(delta);
    if (!truncateOnly && h >= n) h -= n;
    return h;
  }
  const truncateHash = overrides.truncateHash || _truncateHash;

  /**
   * Jacobian Point works in 3d / jacobi coordinates: (x, y, z) ∋ (x=x/z², y=y/z³)
   * Default Point works in 2d / affine coordinates: (x, y)
   * We're doing calculations in jacobi, because its operations don't require costly inversion.
   */
  class JacobianPoint implements JacobianPointType {
    constructor(readonly x: bigint, readonly y: bigint, readonly z: bigint) {}

    static readonly BASE = new JacobianPoint(CURVE.Gx, CURVE.Gy, _1n);
    static readonly ZERO = new JacobianPoint(_0n, _1n, _0n);
    static readonly _ORDER = CURVE.P;

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
      const toInv = invertBatch(
        points.map((p) => p.z),
        JacobianPoint._ORDER
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
      return new JacobianPoint(this.x, mod(-this.y, JacobianPoint._ORDER), this.z);
    }

    // Fast algo for doubling 2 Jacobian Points.
    // From: https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-2007-bl
    // Cost: 1M + 8S + 1*a + 10add + 2*2 + 1*3 + 1*8.
    double(): JacobianPoint {
      const { x: X1, y: Y1, z: Z1 } = this;
      const { a } = CURVE;
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
      // TODO: remove
      if (this.equals(JacobianPoint.ZERO)) return other;
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
      if (H === _0n) {
        if (r === _0n) {
          return this.double();
        } else {
          return JacobianPoint.ZERO;
        }
      }
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
      let p = P0;
      let d: JacobianPoint = this;
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
     * Which means we are caching 65536 points: 256 points for every bit from 0 to 256.
     * @returns 65K precomputed points, depending on W
     */
    private precomputeWindow(W: number): JacobianPoint[] {
      const windows = CURVE.nBits / W + 1;
      const points: JacobianPoint[] = [];
      let p: JacobianPoint = this;
      let base = p;
      for (let window = 0; window < windows; window++) {
        base = p;
        points.push(base);
        for (let i = 1; i < 2 ** (W - 1); i++) {
          base = base.add(p);
          points.push(base);
        }
        p = base.double();
      }
      return points;
    }

    /**
     * Implements w-ary non-adjacent form for calculating ec multiplication.
     * @param n
     * @param affinePoint optional 2d point to save cached precompute windows on it.
     * @returns real and fake (for const-time) points
     */
    private wNAF(n: bigint, affinePoint?: Point): { p: JacobianPoint; f: JacobianPoint } {
      if (!affinePoint && this.equals(JacobianPoint.BASE)) affinePoint = Point.BASE;
      const W = (affinePoint && affinePoint._WINDOW_SIZE) || 1;
      if (256 % W) {
        throw new Error('Point#wNAF: Invalid precomputation window, must be power of 2');
      }

      // Calculate precomputes on a first run, reuse them after
      let precomputes = affinePoint && pointPrecomputes.get(affinePoint);
      if (!precomputes) {
        precomputes = this.precomputeWindow(W);
        if (affinePoint && W !== 1) {
          precomputes = JacobianPoint.normalizeZ(precomputes);
          pointPrecomputes.set(affinePoint, precomputes);
        }
      }

      // Initialize real and fake points for const-time
      let p = JacobianPoint.ZERO;
      // Should be G (base) point, since otherwise f can be infinity point in the end
      let f = JacobianPoint.BASE;

      const windows = 1 + Math.ceil(CURVE.nBits / W); // W=8 17
      const windowSize = 2 ** (W - 1); // W=8 128
      const mask = BigInt(2 ** W - 1); // Create mask with W ones: 0b11111111 for W=8
      const maxNumber = 2 ** W; // W=8 256
      const shiftBy = BigInt(W); // W=8 8

      for (let window = 0; window < windows; window++) {
        const offset = window * windowSize;
        // Extract W bits.
        let wbits = Number(n & mask);

        // Shift number by W bits.
        n >>= shiftBy;

        // If the bits are bigger than max size, we'll split those.
        // +224 => 256 - 32
        if (wbits > windowSize) {
          wbits -= maxNumber;
          n += _1n;
        }

        // This code was first written with assumption that 'f' and 'p' will never be infinity point:
        // since each addition is multiplied by 2 ** W, it cannot cancel each other. However,
        // there is negate now: it is possible that negated element from low value
        // would be the same as high element, which will create carry into next window.
        // It's not obvious how this can fail, but still worth investigating later.

        // Check if we're onto Zero point.
        // Add random point inside current window to f.
        const offset1 = offset;
        const offset2 = offset + Math.abs(wbits) - 1;
        const cond1 = window % 2 !== 0;
        const cond2 = wbits < 0;
        if (wbits === 0) {
          // The most important part for const-time getPublicKey
          f = f.add(constTimeNegate(cond1, precomputes[offset1]));
        } else {
          p = p.add(constTimeNegate(cond2, precomputes[offset2]));
        }
      }
      // JIT-compiler should not eliminate f here, since it will later be used in normalizeZ()
      // Even if the variable is still unused, there are some checks which will
      // throw an exception, so compiler needs to prove they won't happen, which is hard.
      // At this point there is a way to F be infinity-point even if p is not,
      // which makes it less const-time: around 1 bigint multiply.
      return { p, f };
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
      const { p, f } = this.wNAF(n, affinePoint);
      point = p;
      fake = f;
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
      if (invZ == null) invZ = is0 ? _8n : invert(z, JacobianPoint._ORDER);
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
  // Const-time utility for wNAF
  function constTimeNegate(condition: boolean, item: JacobianPoint) {
    const neg = item.negate();
    return condition ? neg : item;
  }
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
     * Supports compressed ECDSA (33-byte) points
     * @param bytes 33 bytes
     * @returns Point instance
     */
    private static fromCompressedHex(bytes: Uint8Array) {
      const { P } = CURVE;
      const x = bytesToNumber(bytes.subarray(1));
      if (!isValidFieldElement(x)) throw new Error('Point is not on curve');
      const y2 = weierstrassEquation(x); // y² = x³ + ax + b
      let y = sqrtMod(y2, P); // y = y² ^ (p+1)/4
      const isYOdd = (y & _1n) === _1n;
      // ECDSA
      const isFirstByteOdd = (bytes[0] & 1) === 1;
      if (isFirstByteOdd !== isYOdd) y = mod(-y, P);
      const point = new Point(x, y);
      point.assertValidity();
      return point;
    }

    private static fromUncompressedHex(bytes: Uint8Array) {
      const x = bytesToNumber(bytes.subarray(1, fieldLen + 1));
      const y = bytesToNumber(bytes.subarray(fieldLen + 1, 2 * fieldLen + 1));
      const point = new Point(x, y);
      point.assertValidity();
      return point;
    }

    /**
     * Converts hash string or Uint8Array to Point.
     * @param hex 33/65-byte (ECDSA) hex
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

    /**
     * Recovers public key from ECDSA signature.
     * https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Public_key_recovery
     * ```
     * recover(r, s, h) where
     *   u1 = hs^-1 mod n
     *   u2 = sr^-1 mod n
     *   Q = u1⋅G + u2⋅R
     * ```
     */
    static fromSignature(msgHash: Hex, signature: RecoveredSig): Point {
      msgHash = ensureBytes(msgHash);
      const h = truncateHash(msgHash);
      const {
        signature: { r, s },
        recovery,
      } = signature;
      // const { r, s } = normalizeSignature(signature);
      if (recovery !== 0 && recovery !== 1) {
        throw new Error('Cannot recover signature: invalid recovery bit');
      }
      const prefix = recovery & 1 ? '03' : '02';
      const R = Point.fromHex(prefix + numToFieldStr(r));
      const { n } = CURVE;
      const rinv = invert(r, n);
      // Q = u1⋅G + u2⋅R
      const u1 = mod(-h * rinv, n);
      const u2 = mod(s * rinv, n);
      const Q = Point.BASE.multiplyAndAddUnsafe(R, u1, u2);
      if (!Q) throw new Error('Cannot recover signature: point at infinify');
      Q.assertValidity();
      return Q;
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

    toHexX() {
      return numToFieldStr(this.x);
    }

    toRawX() {
      return hexToBytes(this.toHexX());
    }

    // A point on curve is valid if it conforms to equation.
    assertValidity(): void {
      const msg = 'Point is not on elliptic curve';
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
    static readonly _ORDER = CURVE.n;
    constructor(readonly r: bigint, readonly s: bigint) {
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

    /**
     * Default signatures are always low-s, to prevent malleability.
     * `sign(canonical: true)` always produces low-s sigs.
     * `verify(strict: true)` always fails for high-s.
     */
    hasHighS(): boolean {
      const HALF = JacobianPoint._ORDER >> _1n;
      return this.s > HALF;
    }

    normalizeS(): SignatureType {
      return this.hasHighS() ? new Signature(this.r, JacobianPoint._ORDER - this.s) : this;
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

  // TODO: move utils out of the closure
  const utils = {
    bytesToHex,
    hexToBytes,
    concatBytes,
    mod: modP,
    invert: (n: bigint, m: bigint = CURVE.P) => invert(n, m),
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
    hashToPrivateKey: (hash: Hex): Uint8Array => {
      hash = ensureBytes(hash);
      const minLen = fieldLen + 8;
      if (hash.length < minLen || hash.length > 1024) {
        throw new Error(`Expected ${minLen}-1024 bytes of private key as per FIPS 186`);
      }
      const num = mod(bytesToNumber(hash), CURVE.n - _1n) + _1n;
      return numToField(num);
    },

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
    ensureBytes,
    bytesToNumber,
    numberToHexUnpadded,
    hexToNumber,
  };

  function isWithinCurveOrder(num: bigint): boolean {
    return _0n < num && num < CURVE.n;
  }

  function isValidFieldElement(num: bigint): boolean {
    return _0n < num && num < CURVE.P;
  }
  /**
   * Converts signature params into point & r/s, checks them for validity.
   * k must be in range [1, n-1]
   * @param k signature's k param: deterministic in our case, random in non-rfc6979 sigs
   * @param m message that would be signed
   * @param d private key
   * @returns Signature with its point on curve Q OR undefined if params were invalid
   */
  function kmdToSig(kBytes: Uint8Array, m: bigint, d: bigint): RecoveredSig | undefined {
    const k = truncateHash(kBytes, true);
    if (!isWithinCurveOrder(k)) return;
    // Important: all mod() calls in the function must be done over `n`
    const { n } = CURVE;
    const q = Point.BASE.multiply(k);
    // r = x mod n
    const r = mod(q.x, n);
    if (r === _0n) return;
    // s = (1/k * (m + dr) mod n
    const s = mod(invert(k, n) * mod(m + d * r, n), n);
    if (s === _0n) return;
    const sig = new Signature(r, s);
    const recovery = (q.x === sig.r ? 0 : 2) | Number(q.y & _1n);

    return { signature: sig, recovery };
  }

  function normalizePrivateKey(key: PrivKey): bigint {
    let num: bigint;
    if (typeof key === 'bigint') {
      num = key;
    } else if (typeof key === 'number' && Number.isSafeInteger(key) && key > 0) {
      num = BigInt(key);
    } else if (typeof key === 'string') {
      key = strip0x(key).padStart(2 * fieldLen, '0'); // Eth-like hexes
      if (key.length !== 2 * fieldLen) throw new Error(`Expected ${fieldLen} bytes of private key`);
      num = hexToNumber(key);
    } else if (key instanceof Uint8Array) {
      if (key.length !== fieldLen) throw new Error(`Expected ${fieldLen} bytes of private key`);
      num = bytesToNumber(key);
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

  /**
   * // TODO: clarify if we need `type` param.
   * Signatures can be in 64-byte compact representation,
   * or in (variable-length)-byte DER representation.
   * Since DER could also be 64 bytes, we check for it first.
   */
  function normalizeSignature(signature: Sig): SignatureType {
    if (signature instanceof Signature) {
      signature.assertValidity();
      return signature;
    }
    // if (type === 'compact') return Signature.fromCompact(signature as Hex);
    // if (type === 'der') return Signature.fromDER(signature as Hex);
    try {
      return Signature.fromDER(signature as Hex);
    } catch (error) {
      return Signature.fromCompact(signature as Hex);
    }
    // throw new Error('Unknown signature type, expected compact or der');
  }
  /**
   * Computes public key for secp256k1 private key.
   * @param privateKey 32-byte private key
   * @param isCompressed whether to return compact (33-byte), or full (65-byte) key
   * @returns Public key, full by default; short when isCompressed=true
   */
  function getPublicKey(privateKey: PrivKey, isCompressed = false): Uint8Array {
    return Point.fromPrivateKey(privateKey).toRawBytes(isCompressed);
  }
  /**
   * Recovers public key from signature and recovery bit. Throws on invalid sig/hash.
   * @param msgHash message hash
   * @param signature DER or compact sig
   * @param recovery 0 or 1
   * @param isCompressed whether to return compact (33-byte), or full (65-byte) key
   * @returns Public key, full by default; short when isCompressed=true
   */
  function recoverPublicKey(
    msgHash: Hex,
    signature: Sig,
    recovery: number,
    isCompressed = false
  ): Uint8Array {
    const instance =
      signature instanceof Signature ? signature : Signature.fromDER(signature as Hex);
    return Point.fromSignature(msgHash, { signature: instance, recovery }).toRawBytes(isCompressed);
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
    return bytesToNumber(slice);
  }
  function bits2octets(bytes: Uint8Array): Uint8Array {
    const z1 = bits2int(bytes);
    const z2 = mod(z1, CURVE.n);
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
  // Takes signature with its recovery bit, normalizes it
  // Produces DER/compact signature and proper recovery bit
  function finalizeSig(recSig: RecoveredSig, opts: OptsNoRecov | OptsRecov): SignOutput {
    let { signature: sig, recovery } = recSig;
    const { canonical, der, recovered } = Object.assign({ canonical: true, der: true }, opts);
    if (canonical && sig.hasHighS()) {
      sig = sig.normalizeS();
      recovery ^= 1;
    }
    const hashed = der ? sig.toDERRawBytes() : sig.toCompactRawBytes();
    return recovered ? [hashed, recovery] : hashed;
  }

  // TODO: clarify return type RecoveredSignature vs [Uint8Array, number]
  /**
   * Signs message hash (not message: you need to hash it by yourself).
   * @param opts `recovered, canonical, der, extraEntropy`
   */
  function sign(msgHash: Hex, privKey: PrivKey, opts: OptsRecov): [Uint8Array, number];
  function sign(msgHash: Hex, privKey: PrivKey, opts?: OptsNoRecov): Uint8Array;
  function sign(msgHash: Hex, privKey: PrivKey, opts: Opts = CURVE.signOpts): SignOutput {
    // Steps A, D of RFC6979 3.2.
    const { seed, m, d } = initSigArgs(msgHash, privKey, opts.extraEntropy);
    let sig: RecoveredSig | undefined;
    // Steps B, C, D, E, F, G
    const drbg = new HmacDrbg(CURVE.hash.outputLen, CURVE.nBytes, CURVE.hmac);
    drbg.reseedSync(seed);
    // Step H3, repeat until k is in range [1, n-1]
    while (!(sig = kmdToSig(drbg.generateSync(), m, d))) drbg.reseedSync();
    return finalizeSig(sig, opts);
  }
  // Enable precomputes. Slows down first publicKey computation by 20ms.
  Point.BASE._setWindowSize(8);
  /**
   * Verifies a signature against message hash and public key.
   * Rejects non-canonical / high-s signatures by default: to override,
   * specify option `{strict: false}`. Implements section 4.1.4 from https://www.secg.org/sec1-v2.pdf:
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
    signature: Sig,
    msgHash: Hex,
    publicKey: PubKey,
    opts: { strict?: boolean } = CURVE.verifyOpts
  ): boolean {
    let sig;
    try {
      sig = normalizeSignature(signature);
      msgHash = ensureBytes(msgHash);
    } catch (error) {
      return false;
    }
    const { r, s } = sig;
    if (opts.strict && sig.hasHighS()) return false;
    const h = truncateHash(msgHash);
    let P;
    try {
      P = normalizePublicKey(publicKey);
    } catch (error) {
      return false;
    }
    const { n } = CURVE;
    const sinv = invert(s, n); // s^-1
    // R = u1⋅G - u2⋅P
    const u1 = mod(h * sinv, n);
    const u2 = mod(r * sinv, n);

    // Some implementations compare R.x in jacobian, without inversion.
    // The speed-up is <5%, so we don't complicate the code.
    const R = Point.BASE.multiplyAndAddUnsafe(P, u1, u2);
    if (!R) return false;
    const v = mod(R.x, n);
    return v === r;
  }
  return {
    Point,
    Signature,
    JacobianPoint,
    utils,
    getPublicKey,
    recoverPublicKey,
    getSharedSecret,
    sign,
    verify,
  };
}
