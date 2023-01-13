/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// TODO: remove circular imports
import * as utils from './utils.js';
// Utilities for modular arithmetics and finite fields
// prettier-ignore
const _0n = BigInt(0), _1n = BigInt(1), _2n = BigInt(2), _3n = BigInt(3);
// prettier-ignore
const _4n = BigInt(4), _5n = BigInt(5), _8n = BigInt(8);
// prettier-ignore
const _9n = BigInt(9), _16n = BigInt(16);

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
    // JIT applies optimization if those two lines follow each other
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

// Tonelli-Shanks algorithm
// Paper 1: https://eprint.iacr.org/2012/685.pdf (page 12)
// Paper 2: Square Roots from 1; 24, 51, 10 to Dan Shanks
export function tonelliShanks(P: bigint) {
  // Legendre constant: used to calculate Legendre symbol (a | p),
  // which denotes the value of a^((p-1)/2) (mod p).
  // (a | p) ≡ 1    if a is a square (mod p)
  // (a | p) ≡ -1   if a is not a square (mod p)
  // (a | p) ≡ 0    if a ≡ 0 (mod p)
  const legendreC = (P - _1n) / _2n;

  let Q: bigint, S: number, Z: bigint;
  // Step 1: By factoring out powers of 2 from p - 1,
  // find q and s such that p - 1 = q*(2^s) with q odd
  for (Q = P - _1n, S = 0; Q % _2n === _0n; Q /= _2n, S++);

  // Step 2: Select a non-square z such that (z | p) ≡ -1 and set c ≡ zq
  for (Z = _2n; Z < P && pow(Z, legendreC, P) !== P - _1n; Z++);

  // Fast-path
  if (S === 1) {
    const p1div4 = (P + _1n) / _4n;
    return function tonelliFast<T>(Fp: Field<T>, n: T) {
      const root = Fp.pow(n, p1div4);
      if (!Fp.equals(Fp.square(root), n)) throw new Error('Cannot find square root');
      return root;
    };
  }

  // Slow-path
  const Q1div2 = (Q + _1n) / _2n;
  return function tonelliSlow<T>(Fp: Field<T>, n: T): T {
    // Step 0: Check that n is indeed a square: (n | p) should not be ≡ -1
    if (Fp.pow(n, legendreC) === Fp.negate(Fp.ONE)) throw new Error('Cannot find square root');
    let r = S;
    // TODO: will fail at Fp2/etc
    let g = Fp.pow(Fp.mul(Fp.ONE, Z), Q); // will update both x and b
    let x = Fp.pow(n, Q1div2); // first guess at the square root
    let b = Fp.pow(n, Q); // first guess at the fudge factor

    while (!Fp.equals(b, Fp.ONE)) {
      if (Fp.equals(b, Fp.ZERO)) return Fp.ZERO; // https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm (4. If t = 0, return r = 0)
      // Find m such b^(2^m)==1
      let m = 1;
      for (let t2 = Fp.square(b); m < r; m++) {
        if (Fp.equals(t2, Fp.ONE)) break;
        t2 = Fp.square(t2); // t2 *= t2
      }
      // NOTE: r-m-1 can be bigger than 32, need to convert to bigint before shift, otherwise there will be overflow
      const ge = Fp.pow(g, _1n << BigInt(r - m - 1)); // ge = 2^(r-m-1)
      g = Fp.square(ge); // g = ge * ge
      x = Fp.mul(x, ge); // x *= ge
      b = Fp.mul(b, g); // b *= g
      r = m;
    }
    return x;
  };
}

export function FpSqrt(P: bigint) {
  // NOTE: different algorithms can give different roots, it is up to user to decide which one they want.
  // For example there is FpSqrtOdd/FpSqrtEven to choice root based on oddness (used for hash-to-curve).

  // P ≡ 3 (mod 4)
  // √n = n^((P+1)/4)
  if (P % _4n === _3n) {
    // Not all roots possible!
    // const ORDER =
    //   0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn;
    // const NUM = 72057594037927816n;
    const p1div4 = (P + _1n) / _4n;
    return function sqrt3mod4<T>(Fp: Field<T>, n: T) {
      const root = Fp.pow(n, p1div4);
      // Throw if root**2 != n
      if (!Fp.equals(Fp.square(root), n)) throw new Error('Cannot find square root');
      return root;
    };
  }

  // Atkin algorithm for q ≡ 5 (mod 8), https://eprint.iacr.org/2012/685.pdf (page 10)
  if (P % _8n === _5n) {
    const c1 = (P - _5n) / _8n;
    return function sqrt5mod8<T>(Fp: Field<T>, n: T) {
      const n2 = Fp.mul(n, _2n);
      const v = Fp.pow(n2, c1);
      const nv = Fp.mul(n, v);
      const i = Fp.mul(Fp.mul(nv, _2n), v);
      const root = Fp.mul(nv, Fp.sub(i, Fp.ONE));
      if (!Fp.equals(Fp.square(root), n)) throw new Error('Cannot find square root');
      return root;
    };
  }

  // P ≡ 9 (mod 16)
  if (P % _16n === _9n) {
    // NOTE: tonelli is too slow for bls-Fp2 calculations even on start
    // Means we cannot use sqrt for constants at all!
    //
    // const c1 = Fp.sqrt(Fp.negate(Fp.ONE)); //  1. c1 = sqrt(-1) in F, i.e., (c1^2) == -1 in F
    // const c2 = Fp.sqrt(c1);                //  2. c2 = sqrt(c1) in F, i.e., (c2^2) == c1 in F
    // const c3 = Fp.sqrt(Fp.negate(c1));     //  3. c3 = sqrt(-c1) in F, i.e., (c3^2) == -c1 in F
    // const c4 = (P + _7n) / _16n;           //  4. c4 = (q + 7) / 16        # Integer arithmetic
    // sqrt = (x) => {
    //   let tv1 = Fp.pow(x, c4);             //  1. tv1 = x^c4
    //   let tv2 = Fp.mul(c1, tv1);           //  2. tv2 = c1 * tv1
    //   const tv3 = Fp.mul(c2, tv1);         //  3. tv3 = c2 * tv1
    //   let tv4 = Fp.mul(c3, tv1);           //  4. tv4 = c3 * tv1
    //   const e1 = Fp.equals(Fp.square(tv2), x); //  5.  e1 = (tv2^2) == x
    //   const e2 = Fp.equals(Fp.square(tv3), x); //  6.  e2 = (tv3^2) == x
    //   tv1 = Fp.cmov(tv1, tv2, e1); //  7. tv1 = CMOV(tv1, tv2, e1)  # Select tv2 if (tv2^2) == x
    //   tv2 = Fp.cmov(tv4, tv3, e2); //  8. tv2 = CMOV(tv4, tv3, e2)  # Select tv3 if (tv3^2) == x
    //   const e3 = Fp.equals(Fp.square(tv2), x); //  9.  e3 = (tv2^2) == x
    //   return Fp.cmov(tv1, tv2, e3); //  10.  z = CMOV(tv1, tv2, e3)  # Select the sqrt from tv1 and tv2
    // }
  }

  // Other cases: Tonelli-Shanks algorithm
  return tonelliShanks(P);
}

// Little-endian check for first LE bit (last BE bit);
export const isNegativeLE = (num: bigint, modulo: bigint) => (mod(num, modulo) & _1n) === _1n;

// Currently completly inconsistent naming:
// - readable: add, mul, sqr, sqrt, inv, div, pow, eq, sub
// - unreadable mess: addition, multiply, square, squareRoot, inversion, divide, power, equals, subtract

// Field is not always over prime, Fp2 for example has ORDER(q)=p^m
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
  // Should be same as sgn0 function in https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/
  // NOTE: sgn0 is 'negative in LE', which is same as odd. And negative in LE is kinda strange definition anyway.
  isOdd?(num: T): boolean; // Odd instead of even since we have it for Fp2
  legendre?(num: T): T;
  pow(lhs: T, power: bigint): T;
  invertBatch: (lst: T[]) => T[];
  toBytes(num: T): Uint8Array;
  fromBytes(bytes: Uint8Array): T;
  // If c is False, CMOV returns a, otherwise it returns b.
  cmov(a: T, b: T, c: boolean): T;
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

// This function returns True whenever the value x is a square in the field F.
export function FpIsSquare<T>(f: Field<T>) {
  const legendreConst = (f.ORDER - _1n) / _2n; // Integer arithmetic
  return (x: T): boolean => {
    const p = f.pow(x, legendreConst);
    return f.equals(p, f.ZERO) || f.equals(p, f.ONE);
  };
}

// NOTE: very fragile, always bench. Major performance points:
// - NonNormalized ops
// - Object.freeze
// - same shape of object (don't add/remove keys)
type FpField = Field<bigint> & Required<Pick<Field<bigint>, 'isOdd'>>;
export function Fp(
  ORDER: bigint,
  bitLen?: number,
  isLE = false,
  redef: Partial<Field<bigint>> = {}
): Readonly<FpField> {
  if (ORDER <= _0n) throw new Error(`Expected Fp ORDER > 0, got ${ORDER}`);
  const { nBitLength: BITS, nByteLength: BYTES } = utils.nLength(ORDER, bitLen);
  if (BYTES > 2048) throw new Error('Field lengths over 2048 bytes are not supported');
  const sqrtP = FpSqrt(ORDER);
  const f: Readonly<FpField> = Object.freeze({
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
    sqrt: redef.sqrt || ((n) => sqrtP(f, n)),
    invertBatch: (lst) => FpInvertBatch(f, lst),
    // TODO: do we really need constant cmov?
    // We don't have const-time bigints anyway, so probably will be not very useful
    cmov: (a, b, c) => (c ? b : a),
    toBytes: (num) =>
      isLE ? utils.numberToBytesLE(num, BYTES) : utils.numberToBytesBE(num, BYTES),

    fromBytes: (bytes) => {
      if (bytes.length !== BYTES)
        throw new Error(`Fp.fromBytes: expected ${BYTES}, got ${bytes.length}`);
      return isLE ? utils.bytesToNumberLE(bytes) : utils.bytesToNumberBE(bytes);
    },
  } as FpField);
  return Object.freeze(f);
}

export function FpSqrtOdd<T>(Fp: Field<T>, elm: T) {
  if (!Fp.isOdd) throw new Error(`Field doesn't have isOdd`);
  const root = Fp.sqrt(elm);
  return Fp.isOdd(root) ? root : Fp.negate(root);
}

export function FpSqrtEven<T>(Fp: Field<T>, elm: T) {
  if (!Fp.isOdd) throw new Error(`Field doesn't have isOdd`);
  const root = Fp.sqrt(elm);
  return Fp.isOdd(root) ? Fp.negate(root) : root;
}
