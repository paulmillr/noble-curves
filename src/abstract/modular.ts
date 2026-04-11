/**
 * Utils for modular division and fields.
 * Field over 11 is a finite (Galois) field is integer number operations `mod 11`.
 * There is no division: it is replaced by modular multiplicative inverse.
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import {
  abool,
  abytes,
  anumber,
  asafenumber,
  bitLen,
  bytesToNumberBE,
  bytesToNumberLE,
  numberToBytesBE,
  numberToBytesLE,
  validateObject,
  type TArg,
  type TRet,
} from '../utils.ts';

// Numbers aren't used in x25519 / x448 builds
// prettier-ignore
const _0n = /* @__PURE__ */ BigInt(0), _1n = /* @__PURE__ */ BigInt(1), _2n = /* @__PURE__ */ BigInt(2);
// prettier-ignore
const _3n = /* @__PURE__ */ BigInt(3), _4n = /* @__PURE__ */ BigInt(4), _5n = /* @__PURE__ */ BigInt(5);
// prettier-ignore
const _7n = /* @__PURE__ */ BigInt(7), _8n = /* @__PURE__ */ BigInt(8), _9n = /* @__PURE__ */ BigInt(9);
const _16n = /* @__PURE__ */ BigInt(16);

/**
 * @param a - Dividend value.
 * @param b - Positive modulus.
 * @returns Reduced value in `[0, b)` only when `b` is positive.
 * @throws If the modulus is not positive. {@link Error}
 * @example
 * Normalize a bigint into one field residue.
 *
 * ```ts
 * mod(-1n, 5n);
 * ```
 */
export function mod(a: bigint, b: bigint): bigint {
  if (b <= _0n) throw new Error('mod: expected positive modulus, got ' + b);
  const result = a % b;
  return result >= _0n ? result : b + result;
}
/**
 * Efficiently raise num to a power with modular reduction.
 * Unsafe in some contexts: uses ladder, so can expose bigint bits.
 * Low-level helper: callers that need canonical residues must pass a valid `num` for the chosen
 * modulus instead of relying on the `power===0/1` fast paths to normalize it.
 * @param num - Base value.
 * @param power - Exponent value.
 * @param modulo - Reduction modulus.
 * @returns Modular exponentiation result.
 * @throws If the modulus or exponent is invalid. {@link Error}
 * @example
 * Raise one bigint to a modular power.
 *
 * ```ts
 * pow(2n, 6n, 11n) // 64n % 11n == 9n
 * ```
 */
export function pow(num: bigint, power: bigint, modulo: bigint): bigint {
  return FpPow(Field(modulo), num, power);
}

/**
 * Does `x^(2^power)` mod p. `pow2(30, 4)` == `30^(2^4)`.
 * Low-level helper: callers that need canonical residues must pass a valid `x` for the chosen
 * modulus; the `power===0` fast path intentionally returns the input unchanged.
 * @param x - Base value.
 * @param power - Number of squarings.
 * @param modulo - Reduction modulus.
 * @returns Repeated-squaring result.
 * @throws If the exponent is negative. {@link Error}
 * @example
 * Apply repeated squaring inside one field.
 *
 * ```ts
 * pow2(3n, 2n, 11n);
 * ```
 */
export function pow2(x: bigint, power: bigint, modulo: bigint): bigint {
  if (power < _0n) throw new Error('pow2: expected non-negative exponent, got ' + power);
  let res = x;
  while (power-- > _0n) {
    res *= res;
    res %= modulo;
  }
  return res;
}

/**
 * Inverses number over modulo.
 * Implemented using the {@link https://brilliant.org/wiki/extended-euclidean-algorithm/ | extended Euclidean algorithm}.
 * @param number - Value to invert.
 * @param modulo - Positive modulus.
 * @returns Multiplicative inverse.
 * @throws If the modulus is invalid or the inverse does not exist. {@link Error}
 * @example
 * Compute one modular inverse with the extended Euclidean algorithm.
 *
 * ```ts
 * invert(3n, 11n);
 * ```
 */
export function invert(number: bigint, modulo: bigint): bigint {
  if (number === _0n) throw new Error('invert: expected non-zero number');
  if (modulo <= _0n) throw new Error('invert: expected positive modulus, got ' + modulo);
  // Fermat's little theorem "CT-like" version inv(n) = n^(m-2) mod m is 30x slower.
  let a = mod(number, modulo);
  let b = modulo;
  // prettier-ignore
  let x = _0n, y = _1n, u = _1n, v = _0n;
  while (a !== _0n) {
    const q = b / a;
    const r = b - a * q;
    const m = x - u * q;
    const n = y - v * q;
    // prettier-ignore
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  const gcd = b;
  if (gcd !== _1n) throw new Error('invert: does not exist');
  return mod(x, modulo);
}

function assertIsSquare<T>(Fp: TArg<IField<T>>, root: T, n: T): void {
  const F = Fp as IField<T>;
  if (!F.eql(F.sqr(root), n)) throw new Error('Cannot find square root');
}

// Not all roots are possible! Example which will throw:
// const NUM =
// n = 72057594037927816n;
// Fp = Field(BigInt('0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab'));
function sqrt3mod4<T>(Fp: TArg<IField<T>>, n: T) {
  const F = Fp as IField<T>;
  const p1div4 = (F.ORDER + _1n) / _4n;
  const root = F.pow(n, p1div4);
  assertIsSquare(F, root, n);
  return root;
}

// Equivalent `q = 5 (mod 8)` square-root formula (Atkin-style), not the RFC Appendix I.2 CMOV
// pseudocode verbatim.
function sqrt5mod8<T>(Fp: TArg<IField<T>>, n: T) {
  const F = Fp as IField<T>;
  const p5div8 = (F.ORDER - _5n) / _8n;
  const n2 = F.mul(n, _2n);
  const v = F.pow(n2, p5div8);
  const nv = F.mul(n, v);
  const i = F.mul(F.mul(nv, _2n), v);
  const root = F.mul(nv, F.sub(i, F.ONE));
  assertIsSquare(F, root, n);
  return root;
}

// Based on RFC9380, Kong algorithm
// prettier-ignore
function sqrt9mod16(P: bigint): TRet<<T>(Fp: IField<T>, n: T) => T> {
  const Fp_ = Field(P);
  const tn = tonelliShanks(P);
  const c1 = tn(Fp_, Fp_.neg(Fp_.ONE));//  1. c1 = sqrt(-1) in F, i.e., (c1^2) == -1 in F
  const c2 = tn(Fp_, c1);              //  2. c2 = sqrt(c1) in F, i.e., (c2^2) == c1 in F
  const c3 = tn(Fp_, Fp_.neg(c1));     //  3. c3 = sqrt(-c1) in F, i.e., (c3^2) == -c1 in F
  const c4 = (P + _7n) / _16n;         //  4. c4 = (q + 7) / 16        # Integer arithmetic
  return (<T>(Fp: TArg<IField<T>>, n: T): T => {
    const F = Fp as IField<T>;
    let tv1 = F.pow(n, c4);            //  1. tv1 = x^c4
    let tv2 = F.mul(tv1, c1);          //  2. tv2 = c1 * tv1
    const tv3 = F.mul(tv1, c2);        //  3. tv3 = c2 * tv1
    const tv4 = F.mul(tv1, c3);        //  4. tv4 = c3 * tv1
    const e1 = F.eql(F.sqr(tv2), n);   //  5.  e1 = (tv2^2) == x
    const e2 = F.eql(F.sqr(tv3), n);   //  6.  e2 = (tv3^2) == x
    tv1 = F.cmov(tv1, tv2, e1);        //  7. tv1 = CMOV(tv1, tv2, e1)  # Select tv2 if (tv2^2) == x
    tv2 = F.cmov(tv4, tv3, e2);        //  8. tv2 = CMOV(tv4, tv3, e2)  # Select tv3 if (tv3^2) == x
    const e3 = F.eql(F.sqr(tv2), n);   //  9.  e3 = (tv2^2) == x
    const root = F.cmov(tv1, tv2, e3); // 10.  z = CMOV(tv1, tv2, e3)   # Select sqrt from tv1 & tv2
    assertIsSquare(F, root, n);
    return root;
  }) as TRet<<T>(Fp: IField<T>, n: T) => T>;
}

/**
 * Tonelli-Shanks square root search algorithm.
 * This implementation is variable-time: it searches data-dependently for the first non-residue `Z`
 * and for the smallest `i` in the main loop, unlike RFC 9380 Appendix I.4's constant-time shape.
 * 1. {@link https://eprint.iacr.org/2012/685.pdf | eprint 2012/685}, page 12
 * 2. Square Roots from 1; 24, 51, 10 to Dan Shanks
 * @param P - field order
 * @returns function that takes field Fp (created from P) and number n
 * @throws If the field is too small, non-prime, or the square root does not exist. {@link Error}
 * @example
 * Construct a square-root helper for primes that need Tonelli-Shanks.
 *
 * ```ts
 * import { Field, tonelliShanks } from '@noble/curves/abstract/modular.js';
 * const Fp = Field(17n);
 * const sqrt = tonelliShanks(17n)(Fp, 4n);
 * ```
 */
export function tonelliShanks(P: bigint): TRet<<T>(Fp: IField<T>, n: T) => T> {
  // Initialization (precomputation).
  // Caching initialization could boost perf by 7%.
  if (P < _3n) throw new Error('sqrt is not defined for small field');
  // Factor P - 1 = Q * 2^S, where Q is odd
  let Q = P - _1n;
  let S = 0;
  while (Q % _2n === _0n) {
    Q /= _2n;
    S++;
  }

  // Find the first quadratic non-residue Z >= 2
  let Z = _2n;
  const _Fp = Field(P);
  while (FpLegendre(_Fp, Z) === 1) {
    // Basic primality test for P. After x iterations, chance of
    // not finding quadratic non-residue is 2^x, so 2^1000.
    if (Z++ > 1000) throw new Error('Cannot find square root: probably non-prime P');
  }
  // Fast-path; usually done before Z, but we do "primality test".
  if (S === 1) return sqrt3mod4 as TRet<<T>(Fp: IField<T>, n: T) => T>;

  // Slow-path
  // TODO: test on Fp2 and others
  let cc = _Fp.pow(Z, Q); // c = z^Q
  const Q1div2 = (Q + _1n) / _2n;
  return function tonelliSlow<T>(Fp: TArg<IField<T>>, n: T): T {
    const F = Fp as IField<T>;
    if (F.is0(n)) return n;
    // Check if n is a quadratic residue using Legendre symbol
    if (FpLegendre(F, n) !== 1) throw new Error('Cannot find square root');

    // Initialize variables for the main loop
    let M = S;
    let c = F.mul(F.ONE, cc); // c = z^Q, move cc from field _Fp into field Fp
    let t = F.pow(n, Q); // t = n^Q, first guess at the fudge factor
    let R = F.pow(n, Q1div2); // R = n^((Q+1)/2), first guess at the square root

    // Main loop
    // while t != 1
    while (!F.eql(t, F.ONE)) {
      if (F.is0(t)) return F.ZERO; // if t=0 return R=0
      let i = 1;

      // Find the smallest i >= 1 such that t^(2^i) ≡ 1 (mod P)
      let t_tmp = F.sqr(t); // t^(2^1)
      while (!F.eql(t_tmp, F.ONE)) {
        i++;
        t_tmp = F.sqr(t_tmp); // t^(2^2)...
        if (i === M) throw new Error('Cannot find square root');
      }

      // Calculate the exponent for b: 2^(M - i - 1)
      const exponent = _1n << BigInt(M - i - 1); // bigint is important
      const b = F.pow(c, exponent); // b = 2^(M - i - 1)

      // Update variables
      M = i;
      c = F.sqr(b); // c = b^2
      t = F.mul(t, c); // t = (t * b^2)
      R = F.mul(R, b); // R = R*b
    }
    return R;
  } as TRet<<T>(Fp: IField<T>, n: T) => T>;
}

/**
 * Square root for a finite field. Will try optimized versions first:
 *
 * 1. P ≡ 3 (mod 4)
 * 2. P ≡ 5 (mod 8)
 * 3. P ≡ 9 (mod 16)
 * 4. Tonelli-Shanks algorithm
 *
 * Different algorithms can give different roots, it is up to user to decide which one they want.
 * For example there is FpSqrtOdd/FpSqrtEven to choose a root by oddness
 * (used for hash-to-curve).
 * @param P - Field order.
 * @returns Square-root helper. The generic fallback inherits Tonelli-Shanks' variable-time
 *   behavior and this selector assumes prime-field-style integer moduli.
 * @throws If the field is unsupported or the square root does not exist. {@link Error}
 * @example
 * Choose the square-root helper appropriate for one field modulus.
 *
 * ```ts
 * import { Field, FpSqrt } from '@noble/curves/abstract/modular.js';
 * const Fp = Field(17n);
 * const sqrt = FpSqrt(17n)(Fp, 4n);
 * ```
 */
export function FpSqrt(P: bigint): TRet<<T>(Fp: IField<T>, n: T) => T> {
  // P ≡ 3 (mod 4) => √n = n^((P+1)/4)
  if (P % _4n === _3n) return sqrt3mod4 as TRet<<T>(Fp: IField<T>, n: T) => T>;
  // P ≡ 5 (mod 8) => Atkin algorithm, page 10 of https://eprint.iacr.org/2012/685.pdf
  if (P % _8n === _5n) return sqrt5mod8 as TRet<<T>(Fp: IField<T>, n: T) => T>;
  // P ≡ 9 (mod 16) => Kong algorithm, page 11 of https://eprint.iacr.org/2012/685.pdf (algorithm 4)
  if (P % _16n === _9n) return sqrt9mod16(P);
  // Tonelli-Shanks algorithm
  return tonelliShanks(P);
}

/**
 * @param num - Value to inspect.
 * @param modulo - Field modulus.
 * @returns `true` when the least-significant little-endian bit is set.
 * @throws If the modulus is invalid for `mod(...)`. {@link Error}
 * @example
 * Inspect the low bit used by little-endian sign conventions.
 *
 * ```ts
 * isNegativeLE(3n, 11n);
 * ```
 */
export const isNegativeLE = (num: bigint, modulo: bigint): boolean =>
  (mod(num, modulo) & _1n) === _1n;

/** Generic field interface used by prime and extension fields alike.
 * Generic helpers treat field operations as pure functions: implementations MUST treat provided
 * values/byte buffers as read-only and return detached results instead of mutating arguments.
 */
export interface IField<T> {
  /** Field order `q`, which may be prime or a prime power. */
  ORDER: bigint;
  /** Canonical encoded byte length. */
  BYTES: number;
  /** Canonical encoded bit length. */
  BITS: number;
  /** Whether encoded field elements use little-endian bytes. */
  isLE: boolean;
  /** Additive identity. */
  ZERO: T;
  /** Multiplicative identity. */
  ONE: T;
  // 1-arg
  /**
   * Normalize one value into the field.
   * @param num - Input value.
   * @returns Normalized field value.
   */
  create: (num: T) => T;
  /**
   * Check whether one value already belongs to the field.
   * @param num - Input value.
   * Implementations may throw `TypeError` on malformed input types instead of returning `false`.
   * @returns Whether the value already belongs to the field.
   */
  isValid: (num: T) => boolean;
  /**
   * Check whether one value is zero.
   * @param num - Input value.
   * @returns Whether the value is zero.
   */
  is0: (num: T) => boolean;
  /**
   * Check whether one value is non-zero and belongs to the field.
   * @param num - Input value.
   * Implementations may throw `TypeError` on malformed input types instead of returning `false`.
   * @returns Whether the value is non-zero and valid.
   */
  isValidNot0: (num: T) => boolean;
  /**
   * Negate one value.
   * @param num - Input value.
   * @returns Negated value.
   */
  neg(num: T): T;
  /**
   * Invert one value multiplicatively.
   * @param num - Input value.
   * @returns Multiplicative inverse.
   */
  inv(num: T): T;
  /**
   * Compute one square root when it exists.
   * @param num - Input value.
   * @returns Square root.
   */
  sqrt(num: T): T;
  /**
   * Square one value.
   * @param num - Input value.
   * @returns Squared value.
   */
  sqr(num: T): T;
  // 2-args
  /**
   * Compare two field values.
   * @param lhs - Left value.
   * @param rhs - Right value.
   * @returns Whether both values are equal.
   */
  eql(lhs: T, rhs: T): boolean;
  /**
   * Add two normalized field values.
   * @param lhs - Left value.
   * @param rhs - Right value.
   * @returns Sum value.
   */
  add(lhs: T, rhs: T): T;
  /**
   * Subtract two normalized field values.
   * @param lhs - Left value.
   * @param rhs - Right value.
   * @returns Difference value.
   */
  sub(lhs: T, rhs: T): T;
  /**
   * Multiply two field values.
   * @param lhs - Left value.
   * @param rhs - Right value or scalar.
   * @returns Product value.
   */
  mul(lhs: T, rhs: T | bigint): T;
  /**
   * Raise one field value to a power.
   * @param lhs - Base value.
   * @param power - Exponent.
   * @returns Power value.
   */
  pow(lhs: T, power: bigint): T;
  /**
   * Divide one field value by another.
   * @param lhs - Dividend.
   * @param rhs - Divisor or scalar.
   * @returns Quotient value.
   */
  div(lhs: T, rhs: T | bigint): T;
  // N for NonNormalized (for now)
  /**
   * Add two values without re-normalizing the result.
   * @param lhs - Left value.
   * @param rhs - Right value.
   * @returns Non-normalized sum.
   */
  addN(lhs: T, rhs: T): T;
  /**
   * Subtract two values without re-normalizing the result.
   * @param lhs - Left value.
   * @param rhs - Right value.
   * @returns Non-normalized difference.
   */
  subN(lhs: T, rhs: T): T;
  /**
   * Multiply two values without re-normalizing the result.
   * @param lhs - Left value.
   * @param rhs - Right value or scalar.
   * @returns Non-normalized product.
   */
  mulN(lhs: T, rhs: T | bigint): T;
  /**
   * Square one value without re-normalizing the result.
   * @param num - Input value.
   * @returns Non-normalized square.
   */
  sqrN(num: T): T;

  // Optional
  // Should be same as sgn0 function in
  // [RFC9380](https://www.rfc-editor.org/rfc/rfc9380#section-4.1).
  // NOTE: sgn0 is "negative in LE", which is the same as odd.
  // Negative in LE is a somewhat strange definition anyway.
  /**
   * Return the RFC 9380 `sgn0`-style oddness bit when supported.
   * This uses oddness instead of evenness so extension fields like Fp2 can expose the same hook.
   * Returns whether the value is odd under the field encoding.
   */
  isOdd?(num: T): boolean;
  // legendre?(num: T): T;
  /**
   * Invert many field elements in one batch.
   * @param lst - Values to invert.
   * @returns Batch of inverses.
   */
  invertBatch: (lst: T[]) => T[];
  /**
   * Encode one field value into fixed-width bytes.
   * Callers that need canonical encodings MUST supply a valid field element.
   * Low-level protocols may also use this to serialize raw / non-canonical residues.
   * @param num - Input value.
   * @returns Fixed-width byte encoding.
   */
  toBytes(num: T): Uint8Array;
  /**
   * Decode one field value from fixed-width bytes.
   * @param bytes - Fixed-width byte encoding.
   * @param skipValidation - Whether to skip range validation.
   * Implementations MUST treat `bytes` as read-only.
   * @returns Decoded field value.
   */
  fromBytes(bytes: Uint8Array, skipValidation?: boolean): T;
  // If c is False, CMOV returns a, otherwise it returns b.
  /**
   * Constant-time conditional move.
   * @param a - Value used when the condition is false.
   * @param b - Value used when the condition is true.
   * @param c - Selection bit.
   * @returns Selected value.
   */
  cmov(a: T, b: T, c: boolean): T;
}
// prettier-ignore
// Arithmetic-only subset checked by validateField(). This is intentionally not the full runtime
// IField contract: helpers like `isValidNot0`, `invertBatch`, `toBytes`, `fromBytes`, `cmov`, and
// field-specific extras like `isOdd` are left to the callers that actually need them.
const FIELD_FIELDS = [
  'create', 'isValid', 'is0', 'neg', 'inv', 'sqrt', 'sqr',
  'eql', 'add', 'sub', 'mul', 'pow', 'div',
  'addN', 'subN', 'mulN', 'sqrN'
] as const;
/**
 * @param field - Field implementation.
 * @returns Validated field. This only checks the arithmetic subset needed by generic helpers; it
 *   does not guarantee full runtime-method coverage for serialization, batching, `cmov`, or
 *   field-specific extras beyond positive `BYTES` / `BITS`.
 * @throws If the field shape or numeric metadata are invalid. {@link Error}
 * @example
 * Check that a field implementation exposes the operations curve code expects.
 *
 * ```ts
 * import { Field, validateField } from '@noble/curves/abstract/modular.js';
 * const Fp = validateField(Field(17n));
 * ```
 */
export function validateField<T>(field: TArg<IField<T>>): TRet<IField<T>> {
  const initial = {
    ORDER: 'bigint',
    BYTES: 'number',
    BITS: 'number',
  } as Record<string, string>;
  const opts = FIELD_FIELDS.reduce((map, val: string) => {
    map[val] = 'function';
    return map;
  }, initial);
  validateObject(field, opts);
  // Runtime field implementations must expose real integer byte/bit sizes; fractional / NaN /
  // infinite metadata leaks through validateObject(type='number') but breaks encoders and caches.
  asafenumber(field.BYTES, 'BYTES');
  asafenumber(field.BITS, 'BITS');
  // Runtime field implementations must expose positive byte/bit sizes; zero leaks through the
  // numeric shape checks above but still breaks encoding helpers and cached-length assumptions.
  if (field.BYTES < 1 || field.BITS < 1) throw new Error('invalid field: expected BYTES/BITS > 0');
  if (field.ORDER <= _1n) throw new Error('invalid field: expected ORDER > 1, got ' + field.ORDER);
  return field as TRet<IField<T>>;
}

// Generic field functions

/**
 * Same as `pow` but for Fp: non-constant-time.
 * Unsafe in some contexts: uses ladder, so can expose bigint bits.
 * @param Fp - Field implementation.
 * @param num - Base value.
 * @param power - Exponent value.
 * @returns Powered field element.
 * @throws If the exponent is negative. {@link Error}
 * @example
 * Raise one field element to a public exponent.
 *
 * ```ts
 * import { Field, FpPow } from '@noble/curves/abstract/modular.js';
 * const Fp = Field(17n);
 * const x = FpPow(Fp, 3n, 5n);
 * ```
 */
export function FpPow<T>(Fp: TArg<IField<T>>, num: T, power: bigint): T {
  const F = Fp as IField<T>;
  if (power < _0n) throw new Error('invalid exponent, negatives unsupported');
  if (power === _0n) return F.ONE;
  if (power === _1n) return num;
  let p = F.ONE;
  let d = num;
  while (power > _0n) {
    if (power & _1n) p = F.mul(p, d);
    d = F.sqr(d);
    power >>= _1n;
  }
  return p;
}

/**
 * Efficiently invert an array of Field elements.
 * Exception-free. Zero-valued field elements stay `undefined` unless `passZero` is enabled.
 * @param Fp - Field implementation.
 * @param nums - Values to invert.
 * @param passZero - map 0 to 0 (instead of undefined)
 * @returns Inverted values.
 * @example
 * Invert several field elements with one shared inversion.
 *
 * ```ts
 * import { Field, FpInvertBatch } from '@noble/curves/abstract/modular.js';
 * const Fp = Field(17n);
 * const inv = FpInvertBatch(Fp, [1n, 2n, 4n]);
 * ```
 */
export function FpInvertBatch<T>(Fp: TArg<IField<T>>, nums: T[], passZero = false): T[] {
  const F = Fp as IField<T>;
  const inverted = new Array(nums.length).fill(passZero ? F.ZERO : undefined) as T[];
  // Walk from first to last, multiply them by each other MOD p
  const multipliedAcc = nums.reduce((acc, num, i) => {
    if (F.is0(num)) return acc;
    inverted[i] = acc;
    return F.mul(acc, num);
  }, F.ONE);
  // Invert last element
  const invertedAcc = F.inv(multipliedAcc);
  // Walk from last to first, multiply them by inverted each other MOD p
  nums.reduceRight((acc, num, i) => {
    if (F.is0(num)) return acc;
    inverted[i] = F.mul(acc, inverted[i]);
    return F.mul(acc, num);
  }, invertedAcc);
  return inverted;
}

/**
 * @param Fp - Field implementation.
 * @param lhs - Dividend value.
 * @param rhs - Divisor value.
 * @returns Division result.
 * @throws If the divisor is non-invertible. {@link Error}
 * @example
 * Divide one field element by another.
 *
 * ```ts
 * import { Field, FpDiv } from '@noble/curves/abstract/modular.js';
 * const Fp = Field(17n);
 * const x = FpDiv(Fp, 6n, 3n);
 * ```
 */
export function FpDiv<T>(Fp: TArg<IField<T>>, lhs: T, rhs: T | bigint): T {
  const F = Fp as IField<T>;
  return F.mul(lhs, typeof rhs === 'bigint' ? invert(rhs, F.ORDER) : F.inv(rhs));
}

/**
 * Legendre symbol.
 * Legendre constant is used to calculate Legendre symbol (a | p)
 * which denotes the value of a^((p-1)/2) (mod p).
 *
 * * (a | p) ≡ 1    if a is a square (mod p), quadratic residue
 * * (a | p) ≡ -1   if a is not a square (mod p), quadratic non residue
 * * (a | p) ≡ 0    if a ≡ 0 (mod p)
 * @param Fp - Field implementation.
 * @param n - Value to inspect.
 * @returns Legendre symbol.
 * @throws If the field returns an invalid Legendre symbol value. {@link Error}
 * @example
 * Compute the Legendre symbol of one field element.
 *
 * ```ts
 * import { Field, FpLegendre } from '@noble/curves/abstract/modular.js';
 * const Fp = Field(17n);
 * const symbol = FpLegendre(Fp, 4n);
 * ```
 */
export function FpLegendre<T>(Fp: TArg<IField<T>>, n: T): -1 | 0 | 1 {
  const F = Fp as IField<T>;
  // We can use 3rd argument as optional cache of this value
  // but seems unneeded for now. The operation is very fast.
  const p1mod2 = (F.ORDER - _1n) / _2n;
  const powered = F.pow(n, p1mod2);
  const yes = F.eql(powered, F.ONE);
  const zero = F.eql(powered, F.ZERO);
  const no = F.eql(powered, F.neg(F.ONE));
  if (!yes && !zero && !no) throw new Error('invalid Legendre symbol result');
  return yes ? 1 : zero ? 0 : -1;
}

/**
 * @param Fp - Field implementation.
 * @param n - Value to inspect.
 * @returns `true` when `Fp.sqrt(n)` exists. This includes `0`, even though strict "quadratic
 *   residue" terminology often reserves that name for the non-zero square class.
 * @throws If the field returns an invalid Legendre symbol value. {@link Error}
 * @example
 * Check whether one field element has a square root in the field.
 *
 * ```ts
 * import { Field, FpIsSquare } from '@noble/curves/abstract/modular.js';
 * const Fp = Field(17n);
 * const isSquare = FpIsSquare(Fp, 4n);
 * ```
 */
export function FpIsSquare<T>(Fp: TArg<IField<T>>, n: T): boolean {
  const l = FpLegendre(Fp as IField<T>, n);
  // Zero is a square too: 0 = 0^2, and Fp.sqrt(0) already returns 0.
  return l !== -1;
}

/** Byte and bit lengths derived from one scalar order. */
export type NLength = {
  /** Canonical byte length. */
  nByteLength: number;
  /** Canonical bit length. */
  nBitLength: number;
};
/**
 * @param n - Curve order. Callers are expected to pass a positive order.
 * @param nBitLength - Optional cached bit length. Callers are expected to pass a positive cached
 *   value when overriding the derived bit length.
 * @returns Byte and bit lengths.
 * @throws If the order or cached bit length is invalid. {@link Error}
 * @example
 * Measure the encoding sizes needed for one modulus.
 *
 * ```ts
 * nLength(255n);
 * ```
 */
export function nLength(n: bigint, nBitLength?: number): NLength {
  // Bit size, byte size of CURVE.n
  if (nBitLength !== undefined) anumber(nBitLength);
  if (n <= _0n) throw new Error('invalid n length: expected positive n, got ' + n);
  if (nBitLength !== undefined && nBitLength < 1)
    throw new Error('invalid n length: expected positive bit length, got ' + nBitLength);
  const bits = bitLen(n);
  // Cached bit lengths smaller than ORDER would truncate serialized scalars/elements and poison
  // any math that relies on the derived field metadata.
  if (nBitLength !== undefined && nBitLength < bits)
    throw new Error(`invalid n length: expected bit length (${bits}) >= n.length (${nBitLength})`);
  const _nBitLength = nBitLength !== undefined ? nBitLength : bits;
  const nByteLength = Math.ceil(_nBitLength / 8);
  return { nBitLength: _nBitLength, nByteLength };
}

type FpField = IField<bigint> & Required<Pick<IField<bigint>, 'isOdd'>>;
type SqrtFn = (n: bigint) => bigint;
type FieldOpts = Partial<{
  isLE: boolean;
  BITS: number;
  sqrt: SqrtFn;
  allowedLengths?: readonly number[]; // for P521 (adds padding for smaller sizes); must stay > 0
  modFromBytes: boolean; // bls12-381 requires mod(n) instead of rejecting keys >= n
}>;
// Keep the lazy sqrt cache off-instance so Field(...) can return a frozen object. Otherwise the
// cached helper write would keep the field surface externally mutable.
const FIELD_SQRT = new WeakMap<object, ReturnType<typeof FpSqrt>>();
class _Field implements IField<bigint> {
  readonly ORDER: bigint;
  readonly BITS: number;
  readonly BYTES: number;
  readonly isLE: boolean;
  readonly ZERO = _0n;
  readonly ONE = _1n;
  readonly _lengths?: readonly number[];
  private readonly _mod?: boolean;
  constructor(ORDER: bigint, opts: FieldOpts = {}) {
    // ORDER <= 1 is degenerate: ONE would not be a valid field element and helpers like pow/inv
    // would stop modeling field arithmetic.
    if (ORDER <= _1n) throw new Error('invalid field: expected ORDER > 1, got ' + ORDER);
    let _nbitLength: number | undefined = undefined;
    this.isLE = false;
    if (opts != null && typeof opts === 'object') {
      // Cached bit lengths are trusted here and should already be positive / consistent with ORDER.
      if (typeof opts.BITS === 'number') _nbitLength = opts.BITS;
      if (typeof opts.sqrt === 'function')
        // `_Field.prototype` is frozen below, so custom sqrt hooks must become own properties
        // explicitly instead of relying on writable prototype shadowing via assignment.
        Object.defineProperty(this, 'sqrt', { value: opts.sqrt, enumerable: true });
      if (typeof opts.isLE === 'boolean') this.isLE = opts.isLE;
      if (opts.allowedLengths) this._lengths = Object.freeze(opts.allowedLengths.slice());
      if (typeof opts.modFromBytes === 'boolean') this._mod = opts.modFromBytes;
    }
    const { nBitLength, nByteLength } = nLength(ORDER, _nbitLength);
    if (nByteLength > 2048) throw new Error('invalid field: expected ORDER of <= 2048 bytes');
    this.ORDER = ORDER;
    this.BITS = nBitLength;
    this.BYTES = nByteLength;
    Object.freeze(this);
  }

  create(num: bigint) {
    return mod(num, this.ORDER);
  }
  isValid(num: bigint) {
    if (typeof num !== 'bigint')
      throw new TypeError('invalid field element: expected bigint, got ' + typeof num);
    return _0n <= num && num < this.ORDER; // 0 is valid element, but it's not invertible
  }
  is0(num: bigint) {
    return num === _0n;
  }
  // is valid and invertible
  isValidNot0(num: bigint) {
    return !this.is0(num) && this.isValid(num);
  }
  isOdd(num: bigint) {
    return (num & _1n) === _1n;
  }
  neg(num: bigint) {
    return mod(-num, this.ORDER);
  }
  eql(lhs: bigint, rhs: bigint) {
    return lhs === rhs;
  }

  sqr(num: bigint) {
    return mod(num * num, this.ORDER);
  }
  add(lhs: bigint, rhs: bigint) {
    return mod(lhs + rhs, this.ORDER);
  }
  sub(lhs: bigint, rhs: bigint) {
    return mod(lhs - rhs, this.ORDER);
  }
  mul(lhs: bigint, rhs: bigint) {
    return mod(lhs * rhs, this.ORDER);
  }
  pow(num: bigint, power: bigint): bigint {
    return FpPow(this, num, power);
  }
  div(lhs: bigint, rhs: bigint) {
    return mod(lhs * invert(rhs, this.ORDER), this.ORDER);
  }

  // Same as above, but doesn't normalize
  sqrN(num: bigint) {
    return num * num;
  }
  addN(lhs: bigint, rhs: bigint) {
    return lhs + rhs;
  }
  subN(lhs: bigint, rhs: bigint) {
    return lhs - rhs;
  }
  mulN(lhs: bigint, rhs: bigint) {
    return lhs * rhs;
  }

  inv(num: bigint) {
    return invert(num, this.ORDER);
  }
  sqrt(num: bigint): bigint {
    // Caching sqrt helpers speeds up sqrt9mod16 by 5x and Tonelli-Shanks by about 10% without keeping
    // the field instance itself mutable.
    let sqrt = FIELD_SQRT.get(this);
    if (!sqrt) FIELD_SQRT.set(this, (sqrt = FpSqrt(this.ORDER)));
    return sqrt(this, num);
  }
  toBytes(num: bigint) {
    // Serialize fixed-width limbs without re-validating the field range. Callers that need a
    // canonical encoding must pass a valid element; some protocols intentionally serialize raw
    // residues here and reduce or validate them elsewhere.
    return this.isLE ? numberToBytesLE(num, this.BYTES) : numberToBytesBE(num, this.BYTES);
  }
  fromBytes(bytes: Uint8Array, skipValidation = false) {
    abytes(bytes);
    const { _lengths: allowedLengths, BYTES, isLE, ORDER, _mod: modFromBytes } = this;
    if (allowedLengths) {
      // `allowedLengths` must list real positive byte lengths; otherwise empty input would get
      // padded into zero and silently decode as a field element.
      if (bytes.length < 1 || !allowedLengths.includes(bytes.length) || bytes.length > BYTES) {
        throw new Error(
          'Field.fromBytes: expected ' + allowedLengths + ' bytes, got ' + bytes.length
        );
      }
      const padded = new Uint8Array(BYTES);
      // isLE add 0 to right, !isLE to the left.
      padded.set(bytes, isLE ? 0 : padded.length - bytes.length);
      bytes = padded;
    }
    if (bytes.length !== BYTES)
      throw new Error('Field.fromBytes: expected ' + BYTES + ' bytes, got ' + bytes.length);
    let scalar = isLE ? bytesToNumberLE(bytes) : bytesToNumberBE(bytes);
    if (modFromBytes) scalar = mod(scalar, ORDER);
    if (!skipValidation)
      if (!this.isValid(scalar))
        throw new Error('invalid field element: outside of range 0..ORDER');
    // Range validation is optional here because some protocols intentionally decode raw residues
    // and reduce or validate them elsewhere.
    return scalar;
  }
  // TODO: we don't need it here, move out to separate fn
  invertBatch(lst: bigint[]): bigint[] {
    return FpInvertBatch(this, lst);
  }
  // We can't move this out because Fp6, Fp12 implement it
  // and it's unclear what to return in there.
  cmov(a: bigint, b: bigint, condition: boolean) {
    // Field elements have `isValid(...)`; the CMOV branch bit is a direct runtime input, so reject
    // non-boolean selectors here instead of letting JS truthiness silently change arithmetic.
    abool(condition, 'condition');
    return condition ? b : a;
  }
}
// Freeze the shared method surface too; otherwise callers can still poison every Field instance by
// monkey-patching `_Field.prototype` even if each instance is frozen.
Object.freeze(_Field.prototype);

/**
 * Creates a finite field. Major performance optimizations:
 * * 1. Denormalized operations like mulN instead of mul.
 * * 2. Identical object shape: never add or remove keys.
 * * 3. Frozen stable object shape; the lazy sqrt cache lives in a module-level `WeakMap`.
 * Fragile: always run a benchmark on a change.
 * Security note: operations and low-level serializers like `toBytes` don't check `isValid` for
 * all elements for performance and protocol-flexibility reasons; callers are responsible for
 * supplying valid elements when they need canonical field behavior.
 * This is low-level code, please make sure you know what you're doing.
 *
 * Note about field properties:
 * * CHARACTERISTIC p = prime number, number of elements in main subgroup.
 * * ORDER q = similar to cofactor in curves, may be composite `q = p^m`.
 *
 * @param ORDER - field order, probably prime, or could be composite
 * @param opts - Field options such as bit length or endianness. See {@link FieldOpts}.
 * @returns Frozen field instance with a stable object shape. This wrapper forwards `opts` straight
 *   into `_Field`, so it inherits `_Field`'s assumptions about cached sizes and `allowedLengths`.
 * @example
 * Construct one prime field with optional overrides.
 *
 * ```ts
 * Field(11n);
 * ```
 */
export function Field(ORDER: bigint, opts: FieldOpts = {}): TRet<Readonly<FpField>> {
  return new _Field(ORDER, opts);
}

// Generic random scalar, we can do same for other fields if via Fp2.mul(Fp2.ONE, Fp2.random)?
// This allows unsafe methods like ignore bias or zero. These unsafe, but often used in different protocols (if deterministic RNG).
// which mean we cannot force this via opts.
// Not sure what to do with randomBytes, we can accept it inside opts if wanted.
// Probably need to export getMinHashLength somewhere?
// random(bytes?: Uint8Array, unsafeAllowZero = false, unsafeAllowBias = false) {
//   const LEN = !unsafeAllowBias ? getMinHashLength(ORDER) : BYTES;
//   if (bytes === undefined) bytes = randomBytes(LEN); // _opts.randomBytes?
//   const num = isLE ? bytesToNumberLE(bytes) : bytesToNumberBE(bytes);
//   // `mod(x, 11)` can sometimes produce 0. `mod(x, 10) + 1` is the same, but no 0
//   const reduced = unsafeAllowZero ? mod(num, ORDER) : mod(num, ORDER - _1n) + _1n;
//   return reduced;
// },

/**
 * @param Fp - Field implementation.
 * @param elm - Value to square-root.
 * @returns Odd square root when two roots exist. The special case `elm = 0` still returns `0`,
 *   which is the only square root but is not odd.
 * @throws If the field lacks oddness checks or the square root does not exist. {@link Error}
 * @example
 * Select the odd square root when two roots exist.
 *
 * ```ts
 * import { Field, FpSqrtOdd } from '@noble/curves/abstract/modular.js';
 * const Fp = Field(17n);
 * const root = FpSqrtOdd(Fp, 4n);
 * ```
 */
export function FpSqrtOdd<T>(Fp: TArg<IField<T>>, elm: T): T {
  const F = Fp as IField<T>;
  if (!F.isOdd) throw new Error("Field doesn't have isOdd");
  const root = F.sqrt(elm);
  return F.isOdd(root) ? root : F.neg(root);
}

/**
 * @param Fp - Field implementation.
 * @param elm - Value to square-root.
 * @returns Even square root.
 * @throws If the field lacks oddness checks or the square root does not exist. {@link Error}
 * @example
 * Select the even square root when two roots exist.
 *
 * ```ts
 * import { Field, FpSqrtEven } from '@noble/curves/abstract/modular.js';
 * const Fp = Field(17n);
 * const root = FpSqrtEven(Fp, 4n);
 * ```
 */
export function FpSqrtEven<T>(Fp: TArg<IField<T>>, elm: T): T {
  const F = Fp as IField<T>;
  if (!F.isOdd) throw new Error("Field doesn't have isOdd");
  const root = F.sqrt(elm);
  return F.isOdd(root) ? F.neg(root) : root;
}

/**
 * Returns total number of bytes consumed by the field element.
 * For example, 32 bytes for usual 256-bit weierstrass curve.
 * @param fieldOrder - number of field elements, usually CURVE.n. Callers are expected to pass an
 *   order greater than 1.
 * @returns byte length of field
 * @throws If the field order is not a bigint. {@link Error}
 * @example
 * Read the fixed-width byte length of one field.
 *
 * ```ts
 * getFieldBytesLength(255n);
 * ```
 */
export function getFieldBytesLength(fieldOrder: bigint): number {
  if (typeof fieldOrder !== 'bigint') throw new Error('field order must be bigint');
  // Valid field elements are in 0..ORDER-1, so ORDER <= 1 would make the encoded range degenerate.
  if (fieldOrder <= _1n) throw new Error('field order must be greater than 1');
  // Valid field elements are < ORDER, so the maximal encoded element is ORDER - 1.
  const bitLength = bitLen(fieldOrder - _1n);
  return Math.ceil(bitLength / 8);
}

/**
 * Returns minimal amount of bytes that can be safely reduced
 * by field order.
 * Should be 2^-128 for 128-bit curve such as P256.
 * This is the reduction / modulo-bias lower bound; higher-level helpers may still impose a larger
 * absolute floor for policy reasons.
 * @param fieldOrder - number of field elements greater than 1, usually CURVE.n.
 * @returns byte length of target hash
 * @throws If the field order is invalid. {@link Error}
 * @example
 * Compute the minimum hash length needed for field reduction.
 *
 * ```ts
 * getMinHashLength(255n);
 * ```
 */
export function getMinHashLength(fieldOrder: bigint): number {
  const length = getFieldBytesLength(fieldOrder);
  return length + Math.ceil(length / 2);
}

/**
 * "Constant-time" private key generation utility.
 * Can take (n + n/2) or more bytes of uniform input e.g. from CSPRNG or KDF
 * and convert them into private scalar, with the modulo bias being negligible.
 * Needs at least 48 bytes of input for 32-byte private key. The implementation also keeps a hard
 * 16-byte minimum even when `getMinHashLength(...)` is smaller, so toy-small inputs do not look
 * accidentally acceptable for real scalar derivation.
 * See {@link https://research.kudelskisecurity.com/2020/07/28/the-definitive-guide-to-modulo-bias-and-how-to-avoid-it/ | Kudelski's modulo-bias guide},
 * {@link https://csrc.nist.gov/publications/detail/fips/186/5/final | FIPS 186-5 appendix A.2}, and
 * {@link https://www.rfc-editor.org/rfc/rfc9380#section-5 | RFC 9380 section 5}. Unlike RFC 9380
 * `hash_to_field`, this helper intentionally maps into the non-zero private-scalar range `1..n-1`.
 * @param key - Uniform input bytes.
 * @param fieldOrder - Size of subgroup.
 * @param isLE - interpret hash bytes as LE num
 * @returns valid private scalar
 * @throws If the hash length or field order is invalid for scalar reduction. {@link Error}
 * @example
 * Map hash output into a private scalar range.
 *
 * ```ts
 * mapHashToField(new Uint8Array(48).fill(1), 255n);
 * ```
 */
export function mapHashToField(
  key: TArg<Uint8Array>,
  fieldOrder: bigint,
  isLE = false
): TRet<Uint8Array> {
  abytes(key);
  const len = key.length;
  const fieldLen = getFieldBytesLength(fieldOrder);
  const minLen = Math.max(getMinHashLength(fieldOrder), 16);
  // No toy-small inputs: the helper is for real scalar derivation, not tiny test curves. No huge
  // inputs: easier to reason about JS timing / allocation behavior.
  if (len < minLen || len > 1024)
    throw new Error('expected ' + minLen + '-1024 bytes of input, got ' + len);
  const num = isLE ? bytesToNumberLE(key) : bytesToNumberBE(key);
  // `mod(x, 11)` can sometimes produce 0. `mod(x, 10) + 1` is the same, but no 0
  const reduced = mod(num, fieldOrder - _1n) + _1n;
  return isLE ? numberToBytesLE(reduced, fieldLen) : numberToBytesBE(reduced, fieldLen);
}
