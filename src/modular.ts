/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import * as utils from './utils.js';
// Utilities for modular arithmetics and finite fields
const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);

// Calculates a modulo b
export function mod(a: bigint, b: bigint): bigint {
  const result = a % b;
  return result >= _0n ? result : b + result;
}
/**
 * Efficiently exponentiate num to power and do modular division.
 * Unsafe in some contexts: uses ladder, so can expose bigint bits.
 * @example
 * powMod(2n, 6n, 11n) // 64n % 11n == 9n
 */
// TODO: use field version && remove
export function pow(num: bigint, power: bigint, modulo: bigint): bigint {
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

// Does x ^ (2 ^ power) mod p. pow2(30, 4) == 30 ^ (2 ^ 4)
// TODO: Fp version?
export function pow2(x: bigint, power: bigint, modulo: bigint): bigint {
  let res = x;
  while (power-- > _0n) {
    res *= res;
    res %= modulo;
  }
  return res;
}

// Inverses number over modulo
export function invert(number: bigint, modulo: bigint): bigint {
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
 * Calculates Legendre symbol (a | p), which denotes the value of a^((p-1)/2) (mod p).
 * * (a | p) ≡ 1    if a is a square (mod p)
 * * (a | p) ≡ -1   if a is not a square (mod p)
 * * (a | p) ≡ 0    if a ≡ 0 (mod p)
 */
export function legendre(num: bigint, fieldPrime: bigint): bigint {
  return pow(num, (fieldPrime - _1n) / _2n, fieldPrime);
}

/**
 * Calculates square root of a number in a finite field.
 * √a mod P
 */
// TODO: rewrite as generic Fp function && remove bls versions
export function sqrt(number: bigint, modulo: bigint): bigint {
  // prettier-ignore
  const _3n = BigInt(3), _4n = BigInt(4), _5n = BigInt(5), _8n = BigInt(8);
  const n = number;
  const P = modulo;
  const p1div4 = (P + _1n) / _4n;

  // P ≡ 3 (mod 4)
  // √n = n^((P+1)/4)
  if (P % _4n === _3n) {
    // Not all roots possible!
    // const ORDER =
    //   0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn;
    // const NUM = 72057594037927816n;
    // TODO: fix sqrtMod in secp256k1
    const root = pow(n, p1div4, P);
    if (mod(root * root, modulo) !== number) throw new Error('Cannot find square root');
    return root;
  }

  // P ≡ 5 (mod 8)
  if (P % _8n === _5n) {
    const n2 = mod(n * _2n, P);
    const v = pow(n2, (P - _5n) / _8n, P);
    const nv = mod(n * v, P);
    const i = mod(_2n * nv * v, P);
    const r = mod(nv * (i - _1n), P);
    return r;
  }

  // Other cases: Tonelli-Shanks algorithm
  if (legendre(n, P) !== _1n) throw new Error('Cannot find square root');
  let q: bigint, s: number, z: bigint;
  for (q = P - _1n, s = 0; q % _2n === _0n; q /= _2n, s++);
  if (s === 1) return pow(n, p1div4, P);
  for (z = _2n; z < P && legendre(z, P) !== P - _1n; z++);

  let c = pow(z, q, P);
  let r = pow(n, (q + _1n) / _2n, P);
  let t = pow(n, q, P);

  let t2 = _0n;
  while (mod(t - _1n, P) !== _0n) {
    t2 = mod(t * t, P);
    let i;
    for (i = 1; i < s; i++) {
      if (mod(t2 - _1n, P) === _0n) break;
      t2 = mod(t2 * t2, P);
    }
    let b = pow(c, BigInt(1 << (s - i - 1)), P);
    r = mod(r * b, P);
    c = mod(b * b, P);
    t = mod(t * c, P);
    s = i;
  }
  return r;
}

// Little-endian check for first LE bit (last BE bit);
export const isNegativeLE = (num: bigint, modulo: bigint) => (mod(num, modulo) & _1n) === _1n;

// Currently completly inconsistent naming:
// - readable: add, mul, sqr, sqrt, inv, div, pow, eq, sub
// - unreadable mess: addition, multiply, square, squareRoot, inversion, divide, power, equals, subtract

export interface Field<T> {
  ORDER: bigint;
  BYTES: number;
  BITS: number;
  MASK: bigint;
  ZERO: T;
  ONE: T;
  // 1-arg
  create: (num: T) => T;
  isValid: (num: T) => boolean;
  isZero: (num: T) => boolean;
  negate(num: T): T;
  invert(num: T): T;
  sqrt(num: T): T;
  square(num: T): T;
  // 2-args
  equals(lhs: T, rhs: T): boolean;
  add(lhs: T, rhs: T): T;
  sub(lhs: T, rhs: T): T;
  mul(lhs: T, rhs: T | bigint): T;
  pow(lhs: T, power: bigint): T;
  div(lhs: T, rhs: T | bigint): T;
  // N for NonNormalized (for now)
  addN(lhs: T, rhs: T): T;
  subN(lhs: T, rhs: T): T;
  mulN(lhs: T, rhs: T | bigint): T;
  squareN(num: T): T;

  // Optional
  isOdd?(num: T): boolean; // Odd instead of even since we have it for Fp2
  legendre?(num: T): T;
  pow(lhs: T, power: bigint): T;
  invertBatch: (lst: T[]) => T[];
  toBytes(num: T): Uint8Array;
  fromBytes(bytes: Uint8Array): T;
}
// prettier-ignore
const FIELD_FIELDS = [
  'create', 'isValid', 'isZero', 'negate', 'invert', 'sqrt', 'square',
  'equals', 'add', 'sub', 'mul', 'pow', 'div',
  'addN', 'subN', 'mulN', 'squareN'
] as const;
export function validateField<T>(field: Field<T>) {
  for (const i of ['ORDER', 'MASK'] as const) {
    if (typeof field[i] !== 'bigint')
      throw new Error(`Invalid field param ${i}=${field[i]} (${typeof field[i]})`);
  }
  for (const i of ['BYTES', 'BITS'] as const) {
    if (typeof field[i] !== 'number')
      throw new Error(`Invalid field param ${i}=${field[i]} (${typeof field[i]})`);
  }
  for (const i of FIELD_FIELDS) {
    if (typeof field[i] !== 'function')
      throw new Error(`Invalid field param ${i}=${field[i]} (${typeof field[i]})`);
  }
}

// Generic field functions
export function FpPow<T>(f: Field<T>, num: T, power: bigint): T {
  // Should have same speed as pow for bigints
  // TODO: benchmark!
  if (power < _0n) throw new Error('Expected power > 0');
  if (power === _0n) return f.ONE;
  if (power === _1n) return num;
  let p = f.ONE;
  let d = num;
  while (power > _0n) {
    if (power & _1n) p = f.mul(p, d);
    d = f.square(d);
    power >>= 1n;
  }
  return p;
}

export function FpInvertBatch<T>(f: Field<T>, nums: T[]): T[] {
  const tmp = new Array(nums.length);
  // Walk from first to last, multiply them by each other MOD p
  const lastMultiplied = nums.reduce((acc, num, i) => {
    if (f.isZero(num)) return acc;
    tmp[i] = acc;
    return f.mul(acc, num);
  }, f.ONE);
  // Invert last element
  const inverted = f.invert(lastMultiplied);
  // Walk from last to first, multiply them by inverted each other MOD p
  nums.reduceRight((acc, num, i) => {
    if (f.isZero(num)) return acc;
    tmp[i] = f.mul(acc, tmp[i]);
    return f.mul(acc, num);
  }, inverted);
  return tmp;
}

export function FpDiv<T>(f: Field<T>, lhs: T, rhs: T | bigint): T {
  return f.mul(lhs, typeof rhs === 'bigint' ? invert(rhs, f.ORDER) : f.invert(rhs));
}

// NOTE: very fragile, always bench. Major performance points:
// - NonNormalized ops
// - Object.freeze
// - same shape of object (don't add/remove keys)
export function Fp(
  ORDER: bigint,
  bitLen?: number,
  isLE = false,
  redef: Partial<Field<bigint>> = {}
): Readonly<Field<bigint>> {
  if (ORDER <= _0n) throw new Error(`Expected Fp ORDER > 0, got ${ORDER}`);
  const { nBitLength: BITS, nByteLength: BYTES } = utils.nLength(ORDER, bitLen);
  if (BYTES > 2048) throw new Error('Field lengths over 2048 bytes are not supported');
  const sqrtP = (num: bigint) => sqrt(num, ORDER);
  const f: Field<bigint> = Object.freeze({
    ORDER,
    BITS,
    BYTES,
    MASK: utils.bitMask(BITS),
    ZERO: _0n,
    ONE: _1n,
    create: (num) => mod(num, ORDER),
    isValid: (num) => {
      if (typeof num !== 'bigint')
        throw new Error(`Invalid field element: expected bigint, got ${typeof num}`);
      return _0n <= num && num < ORDER;
    },
    isZero: (num) => num === _0n,
    isOdd: (num) => (num & _1n) === _1n,
    negate: (num) => mod(-num, ORDER),
    equals: (lhs, rhs) => lhs === rhs,

    square: (num) => mod(num * num, ORDER),
    add: (lhs, rhs) => mod(lhs + rhs, ORDER),
    sub: (lhs, rhs) => mod(lhs - rhs, ORDER),
    mul: (lhs, rhs) => mod(lhs * rhs, ORDER),
    pow: (num, power) => FpPow(f, num, power),
    div: (lhs, rhs) => mod(lhs * invert(rhs, ORDER), ORDER),

    // Same as above, but doesn't normalize
    squareN: (num) => num * num,
    addN: (lhs, rhs) => lhs + rhs,
    subN: (lhs, rhs) => lhs - rhs,
    mulN: (lhs, rhs) => lhs * rhs,

    invert: (num) => invert(num, ORDER),
    sqrt: redef.sqrt || sqrtP,
    invertBatch: (lst) => FpInvertBatch(f, lst),

    toBytes: (num) =>
      isLE ? utils.numberToBytesLE(num, BYTES) : utils.numberToBytesBE(num, BYTES),

    fromBytes: (bytes) => {
      if (bytes.length !== BYTES)
        throw new Error(`Fp.fromBytes: expected ${BYTES}, got ${bytes.length}`);
      return isLE ? utils.bytesToNumberLE(bytes) : utils.bytesToNumberBE(bytes);
    },
  } as Field<bigint>);
  return Object.freeze(f);
}
