/**
 * Utils for modular division and finite fields.
 * A finite field over 11 is integer number operations `mod 11`.
 * There is no division: it is replaced by modular multiplicative inverse.
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { anumber } from '@noble/hashes/utils';
import {
  bitMask,
  bytesToNumberBE,
  bytesToNumberLE,
  ensureBytes,
  numberToBytesBE,
  numberToBytesLE,
  validateObject,
} from './utils.ts';

// prettier-ignore
const _0n = BigInt(0), _1n = BigInt(1), _2n = /* @__PURE__ */ BigInt(2), _3n = /* @__PURE__ */ BigInt(3);
// prettier-ignore
const _4n = /* @__PURE__ */ BigInt(4), _5n = /* @__PURE__ */ BigInt(5), _8n = /* @__PURE__ */ BigInt(8);
// prettier-ignore
const _9n =/* @__PURE__ */ BigInt(9), _16n = /* @__PURE__ */ BigInt(16);

// Calculates a modulo b
export function mod(a: bigint, b: bigint): bigint {
  const result = a % b;
  return result >= _0n ? result : b + result;
}
/**
 * Efficiently raise num to power and do modular division.
 * Unsafe in some contexts: uses ladder, so can expose bigint bits.
 * TODO: remove.
 * @example
 * pow(2n, 6n, 11n) // 64n % 11n == 9n
 */
export function pow(num: bigint, power: bigint, modulo: bigint): bigint {
  if (power < _0n) throw new Error('invalid exponent, negatives unsupported');
  if (modulo <= _0n) throw new Error('invalid modulus');
  if (modulo === _1n) return _0n;
  let res = _1n;
  while (power > _0n) {
    if (power & _1n) res = (res * num) % modulo;
    num = (num * num) % modulo;
    power >>= _1n;
  }
  return res;
}

/** Does `x^(2^power)` mod p. `pow2(30, 4)` == `30^(2^4)` */
export function pow2(x: bigint, power: bigint, modulo: bigint): bigint {
  let res = x;
  while (power-- > _0n) {
    res *= res;
    res %= modulo;
  }
  return res;
}

/**
 * Inverses number over modulo.
 * Implemented using [Euclidean GCD](https://brilliant.org/wiki/extended-euclidean-algorithm/).
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

/**
 * Tonelli-Shanks square root search algorithm.
 * 1. https://eprint.iacr.org/2012/685.pdf (page 12)
 * 2. Square Roots from 1; 24, 51, 10 to Dan Shanks
 * @param P field order
 * @returns function that takes field Fp (created from P) and number n
 */
export function tonelliShanks(P: bigint): <T>(Fp: IField<T>, n: T) => T {
  // Do expensive precomputation step
  // Step 1: By factoring out powers of 2 from p - 1,
  // find q and s such that p-1 == q*(2^s) with q odd
  let Q = P - _1n;
  let S = 0;
  while (Q % _2n === _0n) {
    Q /= _2n;
    S++;
  }

  // Step 2: Select a non-square z such that (z | p) ≡ -1 and set c ≡ zq
  let Z = _2n;
  const _Fp = Field(P);
  while (Z < P && FpIsSquare(_Fp, Z)) {
    if (Z++ > 1000) throw new Error('Cannot find square root: probably non-prime P');
  }

  // Fast-path
  if (S === 1) {
    const p1div4 = (P + _1n) / _4n;
    return function tonelliFast<T>(Fp: IField<T>, n: T) {
      const root = Fp.pow(n, p1div4);
      if (!Fp.eql(Fp.sqr(root), n)) throw new Error('Cannot find square root');
      return root;
    };
  }
  // Slow-path
  const Q1div2 = (Q + _1n) / _2n;
  return function tonelliSlow<T>(Fp: IField<T>, n: T): T {
    // Step 0: Check that n is indeed a square: (n | p) should not be ≡ -1
    if (!FpIsSquare(Fp, n)) throw new Error('Cannot find square root');
    let r = S;
    // TODO: test on Fp2 and others
    let g = Fp.pow(Fp.mul(Fp.ONE, Z), Q); // will update both x and b
    let x = Fp.pow(n, Q1div2); // first guess at the square root
    let b = Fp.pow(n, Q); // first guess at the fudge factor

    while (!Fp.eql(b, Fp.ONE)) {
      // (4. If t = 0, return r = 0)
      // https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm
      if (Fp.eql(b, Fp.ZERO)) return Fp.ZERO;
      // Find m such b^(2^m)==1
      let m = 1;
      for (let t2 = Fp.sqr(b); m < r; m++) {
        if (Fp.eql(t2, Fp.ONE)) break;
        t2 = Fp.sqr(t2); // t2 *= t2
      }
      // NOTE: r-m-1 can be bigger than 32, need to convert to bigint before shift,
      // otherwise there will be overflow.
      const ge = Fp.pow(g, _1n << BigInt(r - m - 1)); // ge = 2^(r-m-1)
      g = Fp.sqr(ge); // g = ge * ge
      x = Fp.mul(x, ge); // x *= ge
      b = Fp.mul(b, g); // b *= g
      r = m;
    }
    return x;
  };
}

/**
 * Square root for a finite field. It will try to check if optimizations are applicable and fall back to 4:
 *
 * 1. P ≡ 3 (mod 4)
 * 2. P ≡ 5 (mod 8)
 * 3. P ≡ 9 (mod 16)
 * 4. Tonelli-Shanks algorithm
 *
 * Different algorithms can give different roots, it is up to user to decide which one they want.
 * For example there is FpSqrtOdd/FpSqrtEven to choice root based on oddness (used for hash-to-curve).
 */
export function FpSqrt(P: bigint): <T>(Fp: IField<T>, n: T) => T {
  // P ≡ 3 (mod 4)
  // √n = n^((P+1)/4)
  if (P % _4n === _3n) {
    // Not all roots possible!
    // const ORDER =
    //   0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn;
    // const NUM = 72057594037927816n;
    return function sqrt3mod4<T>(Fp: IField<T>, n: T) {
      const p1div4 = (P + _1n) / _4n;
      const root = Fp.pow(n, p1div4);
      // Throw if root**2 != n
      if (!Fp.eql(Fp.sqr(root), n)) throw new Error('Cannot find square root');
      return root;
    };
  }

  // Atkin algorithm for q ≡ 5 (mod 8), https://eprint.iacr.org/2012/685.pdf (page 10)
  if (P % _8n === _5n) {
    return function sqrt5mod8<T>(Fp: IField<T>, n: T) {
      const n2 = Fp.mul(n, _2n);
      const c1 = (P - _5n) / _8n;
      const v = Fp.pow(n2, c1);
      const nv = Fp.mul(n, v);
      const i = Fp.mul(Fp.mul(nv, _2n), v);
      const root = Fp.mul(nv, Fp.sub(i, Fp.ONE));
      if (!Fp.eql(Fp.sqr(root), n)) throw new Error('Cannot find square root');
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
export const isNegativeLE = (num: bigint, modulo: bigint): boolean =>
  (mod(num, modulo) & _1n) === _1n;

/** Field is not always over prime: for example, Fp2 has ORDER(q)=p^m. */
export interface IField<T> {
  ORDER: bigint;
  isLE: boolean;
  BYTES: number;
  BITS: number;
  MASK: bigint;
  ZERO: T;
  ONE: T;
  // 1-arg
  create: (num: T) => T;
  isValid: (num: T) => boolean;
  is0: (num: T) => boolean;
  neg(num: T): T;
  inv(num: T): T;
  sqrt(num: T): T;
  sqr(num: T): T;
  // 2-args
  eql(lhs: T, rhs: T): boolean;
  add(lhs: T, rhs: T): T;
  sub(lhs: T, rhs: T): T;
  mul(lhs: T, rhs: T | bigint): T;
  pow(lhs: T, power: bigint): T;
  div(lhs: T, rhs: T | bigint): T;
  // N for NonNormalized (for now)
  addN(lhs: T, rhs: T): T;
  subN(lhs: T, rhs: T): T;
  mulN(lhs: T, rhs: T | bigint): T;
  sqrN(num: T): T;

  // Optional
  // Should be same as sgn0 function in
  // [RFC9380](https://www.rfc-editor.org/rfc/rfc9380#section-4.1).
  // NOTE: sgn0 is 'negative in LE', which is same as odd. And negative in LE is kinda strange definition anyway.
  isOdd?(num: T): boolean; // Odd instead of even since we have it for Fp2
  // legendre?(num: T): T;
  pow(lhs: T, power: bigint): T;
  invertBatch: (lst: T[]) => T[];
  toBytes(num: T): Uint8Array;
  fromBytes(bytes: Uint8Array): T;
  // If c is False, CMOV returns a, otherwise it returns b.
  cmov(a: T, b: T, c: boolean): T;
}
// prettier-ignore
const FIELD_FIELDS = [
  'create', 'isValid', 'is0', 'neg', 'inv', 'sqrt', 'sqr',
  'eql', 'add', 'sub', 'mul', 'pow', 'div',
  'addN', 'subN', 'mulN', 'sqrN'
] as const;
export function validateField<T>(field: IField<T>): IField<T> {
  const initial = {
    ORDER: 'bigint',
    MASK: 'bigint',
    BYTES: 'isSafeInteger',
    BITS: 'isSafeInteger',
  } as Record<string, string>;
  const opts = FIELD_FIELDS.reduce((map, val: string) => {
    map[val] = 'function';
    return map;
  }, initial);
  return validateObject(field, opts);
}

// Generic field functions

/**
 * Same as `pow` but for Fp: non-constant-time.
 * Unsafe in some contexts: uses ladder, so can expose bigint bits.
 */
export function FpPow<T>(Fp: IField<T>, num: T, power: bigint): T {
  if (power < _0n) throw new Error('invalid exponent, negatives unsupported');
  if (power === _0n) return Fp.ONE;
  if (power === _1n) return num;
  // @ts-ignore
  let p = Fp.ONE;
  let d = num;
  while (power > _0n) {
    if (power & _1n) p = Fp.mul(p, d);
    d = Fp.sqr(d);
    power >>= _1n;
  }
  return p;
}

/**
 * Efficiently invert an array of Field elements.
 * Exception-free. Will return `undefined` for 0 elements.
 * @param passZero map 0 to 0 (instead of undefined)
 */
export function FpInvertBatch<T>(Fp: IField<T>, nums: T[], passZero = false): T[] {
  const inverted = new Array(nums.length).fill(passZero ? Fp.ZERO : undefined);
  // Walk from first to last, multiply them by each other MOD p
  const multipliedAcc = nums.reduce((acc, num, i) => {
    if (Fp.is0(num)) return acc;
    inverted[i] = acc;
    return Fp.mul(acc, num);
  }, Fp.ONE);
  // Invert last element
  const invertedAcc = Fp.inv(multipliedAcc);
  // Walk from last to first, multiply them by inverted each other MOD p
  nums.reduceRight((acc, num, i) => {
    if (Fp.is0(num)) return acc;
    inverted[i] = Fp.mul(acc, inverted[i]);
    return Fp.mul(acc, num);
  }, invertedAcc);
  return inverted;
}

// TODO: remove
export function FpDiv<T>(Fp: IField<T>, lhs: T, rhs: T | bigint): T {
  return Fp.mul(lhs, typeof rhs === 'bigint' ? invert(rhs, Fp.ORDER) : Fp.inv(rhs));
}

/**
 * Legendre symbol.
 * Legendre constant is used to calculate Legendre symbol (a | p)
 * which denotes the value of a^((p-1)/2) (mod p)..
 *
 * * (a | p) ≡ 1    if a is a square (mod p), quadratic residue
 * * (a | p) ≡ -1   if a is not a square (mod p), quadratic non residue
 * * (a | p) ≡ 0    if a ≡ 0 (mod p)
 */
export function FpLegendre<T>(Fp: IField<T>, n: T): number {
  const legc = (Fp.ORDER - _1n) / _2n;
  const powered = Fp.pow(n, legc);
  const yes = Fp.eql(powered, Fp.ONE);
  const zero = Fp.eql(powered, Fp.ZERO);
  const no = Fp.eql(powered, Fp.neg(Fp.ONE));
  if (!yes && !zero && !no) throw new Error('Cannot find square root: probably non-prime P');
  return yes ? 1 : zero ? 0 : -1;
}

// This function returns True whenever the value x is a square in the field F.
export function FpIsSquare<T>(Fp: IField<T>, n: T): boolean {
  const l = FpLegendre(Fp, n);
  return l === 0 || l === 1;
}

// CURVE.n lengths
export function nLength(
  n: bigint,
  nBitLength?: number
): {
  nBitLength: number;
  nByteLength: number;
} {
  // Bit size, byte size of CURVE.n
  if (nBitLength !== undefined) anumber(nBitLength);
  const _nBitLength = nBitLength !== undefined ? nBitLength : n.toString(2).length;
  const nByteLength = Math.ceil(_nBitLength / 8);
  return { nBitLength: _nBitLength, nByteLength };
}

type FpField = IField<bigint> & Required<Pick<IField<bigint>, 'isOdd'>>;
/**
 * Initializes a finite field over prime.
 * Major performance optimizations:
 * * a) denormalized operations like mulN instead of mul
 * * b) same object shape: never add or remove keys
 * * c) Object.freeze
 * Fragile: always run a benchmark on a change.
 * Security note: operations don't check 'isValid' for all elements for performance reasons,
 * it is caller responsibility to check this.
 * This is low-level code, please make sure you know what you're doing.
 * @param ORDER prime positive bigint
 * @param bitLen how many bits the field consumes
 * @param isLE (def: false) if encoding / decoding should be in little-endian
 * @param redef optional faster redefinitions of sqrt and other methods
 */
export function Field(
  ORDER: bigint,
  bitLen?: number,
  isLE = false,
  redef: Partial<IField<bigint>> = {}
): Readonly<FpField> {
  if (ORDER <= _0n) throw new Error('invalid field: expected ORDER > 0, got ' + ORDER);
  const { nBitLength: BITS, nByteLength: BYTES } = nLength(ORDER, bitLen);
  if (BYTES > 2048) throw new Error('invalid field: expected ORDER of <= 2048 bytes');
  let sqrtP: ReturnType<typeof FpSqrt>; // cached sqrtP
  const f: Readonly<FpField> = Object.freeze({
    ORDER,
    isLE,
    BITS,
    BYTES,
    MASK: bitMask(BITS),
    ZERO: _0n,
    ONE: _1n,
    create: (num) => mod(num, ORDER),
    isValid: (num) => {
      if (typeof num !== 'bigint')
        throw new Error('invalid field element: expected bigint, got ' + typeof num);
      return _0n <= num && num < ORDER; // 0 is valid element, but it's not invertible
    },
    is0: (num) => num === _0n,
    isOdd: (num) => (num & _1n) === _1n,
    neg: (num) => mod(-num, ORDER),
    eql: (lhs, rhs) => lhs === rhs,

    sqr: (num) => mod(num * num, ORDER),
    add: (lhs, rhs) => mod(lhs + rhs, ORDER),
    sub: (lhs, rhs) => mod(lhs - rhs, ORDER),
    mul: (lhs, rhs) => mod(lhs * rhs, ORDER),
    pow: (num, power) => FpPow(f, num, power),
    div: (lhs, rhs) => mod(lhs * invert(rhs, ORDER), ORDER),

    // Same as above, but doesn't normalize
    sqrN: (num) => num * num,
    addN: (lhs, rhs) => lhs + rhs,
    subN: (lhs, rhs) => lhs - rhs,
    mulN: (lhs, rhs) => lhs * rhs,

    inv: (num) => invert(num, ORDER),
    sqrt:
      redef.sqrt ||
      ((n) => {
        if (!sqrtP) sqrtP = FpSqrt(ORDER);
        return sqrtP(f, n);
      }),
    toBytes: (num) => (isLE ? numberToBytesLE(num, BYTES) : numberToBytesBE(num, BYTES)),
    fromBytes: (bytes) => {
      if (bytes.length !== BYTES)
        throw new Error('Field.fromBytes: expected ' + BYTES + ' bytes, got ' + bytes.length);
      return isLE ? bytesToNumberLE(bytes) : bytesToNumberBE(bytes);
    },
    // TODO: we don't need it here, move out to separate fn
    invertBatch: (lst) => FpInvertBatch(f, lst),
    // We can't move this out because Fp6, Fp12 implement it
    // and it's unclear what to return in there.
    cmov: (a, b, c) => (c ? b : a),
  } as FpField);
  return Object.freeze(f);
}

export function FpSqrtOdd<T>(Fp: IField<T>, elm: T): T {
  if (!Fp.isOdd) throw new Error("Field doesn't have isOdd");
  const root = Fp.sqrt(elm);
  return Fp.isOdd(root) ? root : Fp.neg(root);
}

export function FpSqrtEven<T>(Fp: IField<T>, elm: T): T {
  if (!Fp.isOdd) throw new Error("Field doesn't have isOdd");
  const root = Fp.sqrt(elm);
  return Fp.isOdd(root) ? Fp.neg(root) : root;
}

/**
 * "Constant-time" private key generation utility.
 * Same as mapKeyToField, but accepts less bytes (40 instead of 48 for 32-byte field).
 * Which makes it slightly more biased, less secure.
 * @deprecated use `mapKeyToField` instead
 */
export function hashToPrivateScalar(
  hash: string | Uint8Array,
  groupOrder: bigint,
  isLE = false
): bigint {
  hash = ensureBytes('privateHash', hash);
  const hashLen = hash.length;
  const minLen = nLength(groupOrder).nByteLength + 8;
  if (minLen < 24 || hashLen < minLen || hashLen > 1024)
    throw new Error(
      'hashToPrivateScalar: expected ' + minLen + '-1024 bytes of input, got ' + hashLen
    );
  const num = isLE ? bytesToNumberLE(hash) : bytesToNumberBE(hash);
  return mod(num, groupOrder - _1n) + _1n;
}

/**
 * Returns total number of bytes consumed by the field element.
 * For example, 32 bytes for usual 256-bit weierstrass curve.
 * @param fieldOrder number of field elements, usually CURVE.n
 * @returns byte length of field
 */
export function getFieldBytesLength(fieldOrder: bigint): number {
  if (typeof fieldOrder !== 'bigint') throw new Error('field order must be bigint');
  const bitLength = fieldOrder.toString(2).length;
  return Math.ceil(bitLength / 8);
}

/**
 * Returns minimal amount of bytes that can be safely reduced
 * by field order.
 * Should be 2^-128 for 128-bit curve such as P256.
 * @param fieldOrder number of field elements, usually CURVE.n
 * @returns byte length of target hash
 */
export function getMinHashLength(fieldOrder: bigint): number {
  const length = getFieldBytesLength(fieldOrder);
  return length + Math.ceil(length / 2);
}

/**
 * "Constant-time" private key generation utility.
 * Can take (n + n/2) or more bytes of uniform input e.g. from CSPRNG or KDF
 * and convert them into private scalar, with the modulo bias being negligible.
 * Needs at least 48 bytes of input for 32-byte private key.
 * https://research.kudelskisecurity.com/2020/07/28/the-definitive-guide-to-modulo-bias-and-how-to-avoid-it/
 * FIPS 186-5, A.2 https://csrc.nist.gov/publications/detail/fips/186/5/final
 * RFC 9380, https://www.rfc-editor.org/rfc/rfc9380#section-5
 * @param hash hash output from SHA3 or a similar function
 * @param groupOrder size of subgroup - (e.g. secp256k1.CURVE.n)
 * @param isLE interpret hash bytes as LE num
 * @returns valid private scalar
 */
export function mapHashToField(key: Uint8Array, fieldOrder: bigint, isLE = false): Uint8Array {
  const len = key.length;
  const fieldLen = getFieldBytesLength(fieldOrder);
  const minLen = getMinHashLength(fieldOrder);
  // No small numbers: need to understand bias story. No huge numbers: easier to detect JS timings.
  if (len < 16 || len < minLen || len > 1024)
    throw new Error('expected ' + minLen + '-1024 bytes of input, got ' + len);
  const num = isLE ? bytesToNumberLE(key) : bytesToNumberBE(key);
  // `mod(x, 11)` can sometimes produce 0. `mod(x, 10) + 1` is the same, but no 0
  const reduced = mod(num, fieldOrder - _1n) + _1n;
  return isLE ? numberToBytesLE(reduced, fieldLen) : numberToBytesBE(reduced, fieldLen);
}
