/*! @noble/curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */

// Utilities for modular arithmetics
const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);
const _3n = BigInt(3);
const _4n = BigInt(4);
const _5n = BigInt(5);
const _8n = BigInt(8);

// Calculates a modulo b
export function mod(a: bigint, b: bigint): bigint {
  const result = a % b;
  return result >= _0n ? result : b + result;
}
/**
 * Efficiently exponentiate num to power and do modular division.
 * @example
 * powMod(2n, 6n, 11n) // 64n % 11n == 9n
 */
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
 * Division over finite field.
 * `a/b mod p == a * invert(b) mod p`
 */
export function div(numerator: bigint, denominator: bigint, modulo: bigint): bigint {
  const num = mod(numerator, modulo);
  const iden = invert(denominator, modulo);
  return mod(num * iden, modulo);
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
export function invertBatch(nums: bigint[], modulo: bigint): bigint[] {
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
export function legendre(num: bigint, fieldPrime: bigint): bigint {
  return pow(num, (fieldPrime - _1n) / _2n, fieldPrime);
}

/**
 * Calculates square root of a number in a finite field.
 */
export function sqrt(number: bigint, modulo: bigint): bigint {
  const n = number;
  const P = modulo;
  const p1div4 = (P + _1n) / _4n;

  // P = 3 (mod 4)
  // sqrt n = n^((P+1)/4)
  if (P % _4n === _3n) return pow(n, p1div4, P);

  // P = 5 (mod 8)
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

// An idea on modular arithmetic for bls12-381:
// const FIELD = {add, pow, sqrt, mul};
// Functions will take field elements, no need for an additional class
// Could be faster. 1 bigint field will just do operations and mod later:
// instead of 'r = mod(r * b, P)' we will write r = mul(r, b);
// Could be insecure without shape check, so it needs to be done.
// Functions could be inlined by JIT.
