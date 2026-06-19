/**
 * SECG secp256k1. See [pdf](https://www.secg.org/sec2-v2.pdf).
 *
 * Belongs to Koblitz curves: it has efficiently-computable GLV endomorphism ψ,
 * check out {@link EndomorphismOpts}. Seems to be rigid (not backdoored).
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { createKeygen, type CurveLengths } from './abstract/curve.ts';
import {
  createFROST,
  type FROST,
  type FrostPublic,
  type FrostSecret,
  type Nonces,
} from './abstract/frost.ts';
import { FieldCt, FieldCtBigint, type CtField } from './abstract/field-ct.ts';
import { createHasher, type H2CHasher, isogenyMap } from './abstract/hash-to-curve.ts';
import { mapHashToField, type IField } from './abstract/modular.ts';
import {
  type ECDSA,
  ecdsa,
  type EndomorphismOpts,
  mapToCurveSimpleSWU,
  type WeierstrassPoint as PointType,
  weierstrass,
  type WeierstrassOpts,
  type WeierstrassPointCons,
} from './abstract/weierstrass.ts';
import {
  abool,
  abytes,
  asciiToBytes,
  bytesToNumberBE,
  concatBytes,
  numberToBytesBE,
  type TArg,
  type TRet,
} from './utils.ts';

// Seems like generator was produced from some seed:
// `Pointk1.BASE.multiply(Pointk1.Fn.inv(2n, N)).toAffine().x`
// // gives short x 0x3b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63n
const secp256k1_CURVE: WeierstrassOpts<bigint> = {
  p: BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f'),
  n: BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'),
  h: BigInt(1),
  a: BigInt(0),
  b: BigInt(7),
  Gx: BigInt('0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
  Gy: BigInt('0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'),
};

const secp256k1_ENDO: EndomorphismOpts = {
  beta: BigInt('0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee'),
  basises: [
    [BigInt('0x3086d221a7d46bcde86c90e49284eb15'), -BigInt('0xe4437ed6010e88286f547fa90abfe4c3')],
    [BigInt('0x114ca50f7a8e2f3f657c1108d9d44cfd8'), BigInt('0x3086d221a7d46bcde86c90e49284eb15')],
  ],
};

const _0n = /* @__PURE__ */ BigInt(0);
const _1n = /* @__PURE__ */ BigInt(1);
const _2n = /* @__PURE__ */ BigInt(2);

const K1_FIELD_BYTES = 32;
const K1_LIMBS = 11;
const K1_BASE = 0x1000000;
const K1_TOP_BASE = 0x10000;
const K1_FOLD = 977;
const K1_FOLD_SHIFT = 0x100;
const K1_P = secp256k1_CURVE.p;
const K1_P_LIMBS = /* @__PURE__ */ Uint32Array.from([
  0xfffc2f, 0xfffeff, 0xffffff, 0xffffff, 0xffffff, 0xffffff,
  0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffff,
]);
function k1Wide(): number[] {
  return [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  ];
}
function k1Narrow(): number[] {
  return [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
}
type K1Elem = Uint32Array;
type K1Input = K1Elem | bigint;
type K1Field = Omit<
  IField<K1Elem>,
  | 'create'
  | 'isValid'
  | 'is0'
  | 'isValidNot0'
  | 'neg'
  | 'inv'
  | 'sqrt'
  | 'sqr'
  | 'eql'
  | 'add'
  | 'sub'
  | 'mul'
  | 'pow'
  | 'div'
  | 'addN'
  | 'subN'
  | 'mulN'
  | 'sqrN'
  | 'toBytes'
  | 'isOdd'
> & {
  create(num: K1Input): K1Elem;
  isValid(num: K1Input): boolean;
  is0(num: K1Input): boolean;
  isValidNot0(num: K1Input): boolean;
  isOdd(num: K1Input): boolean;
  neg(num: K1Input): K1Elem;
  inv(num: K1Input): K1Elem;
  sqrt(num: K1Input): K1Elem;
  sqr(num: K1Input): K1Elem;
  eql(lhs: K1Input, rhs: K1Input): boolean;
  add(lhs: K1Input, rhs: K1Input): K1Elem;
  sub(lhs: K1Input, rhs: K1Input): K1Elem;
  mul(lhs: K1Input, rhs: K1Input): K1Elem;
  pow(lhs: K1Input, power: K1Input): K1Elem;
  div(lhs: K1Input, rhs: K1Input): K1Elem;
  addN(lhs: K1Input, rhs: K1Input): K1Elem;
  subN(lhs: K1Input, rhs: K1Input): K1Elem;
  mulN(lhs: K1Input, rhs: K1Input): K1Elem;
  sqrN(num: K1Input): K1Elem;
  toBytes(num: K1Input): Uint8Array;
  fromBigint(num: bigint): K1Elem;
  toBigint(num: K1Input): bigint;
};

function modK1(num: bigint): bigint {
  const out = num % K1_P;
  return out >= _0n ? out : out + K1_P;
}

function FieldSecp256k1(): Readonly<K1Field> {
  const cache = new Map<bigint, K1Elem>();
  const powCache = new Map<bigint, number[]>();
  const ZERO = new Uint32Array(K1_LIMBS);
  const ONE = packK1(Uint32Array.of(1));

  function copy(bytes: K1Elem): K1Elem {
    return new Uint32Array(bytes);
  }
  function assertElem(limbs: K1Elem): K1Elem {
    if (!(limbs instanceof Uint32Array) || limbs.length !== K1_LIMBS)
      throw new Error('invalid field element: expected secp256k1 limbs');
    return limbs;
  }
  function gteP(limbs: ArrayLike<number>): boolean {
    for (let i = K1_LIMBS - 1; i >= 0; i--) {
      const a = limbs[i] || 0;
      const b = K1_P_LIMBS[i];
      if (a > b) return true;
      if (a < b) return false;
    }
    return true;
  }
  function maybeSubP(limbs: Uint32Array): Uint32Array {
    let d0 = limbs[0] - 0xfffc2f;
    let borrow = Number(d0 < 0);
    d0 += borrow * K1_BASE;
    let d1 = limbs[1] - 0xfffeff - borrow;
    borrow = Number(d1 < 0);
    d1 += borrow * K1_BASE;
    let d2 = limbs[2] - 0xffffff - borrow;
    borrow = Number(d2 < 0);
    d2 += borrow * K1_BASE;
    let d3 = limbs[3] - 0xffffff - borrow;
    borrow = Number(d3 < 0);
    d3 += borrow * K1_BASE;
    let d4 = limbs[4] - 0xffffff - borrow;
    borrow = Number(d4 < 0);
    d4 += borrow * K1_BASE;
    let d5 = limbs[5] - 0xffffff - borrow;
    borrow = Number(d5 < 0);
    d5 += borrow * K1_BASE;
    let d6 = limbs[6] - 0xffffff - borrow;
    borrow = Number(d6 < 0);
    d6 += borrow * K1_BASE;
    let d7 = limbs[7] - 0xffffff - borrow;
    borrow = Number(d7 < 0);
    d7 += borrow * K1_BASE;
    let d8 = limbs[8] - 0xffffff - borrow;
    borrow = Number(d8 < 0);
    d8 += borrow * K1_BASE;
    let d9 = limbs[9] - 0xffffff - borrow;
    borrow = Number(d9 < 0);
    d9 += borrow * K1_BASE;
    let d10 = limbs[10] - 0xffff - borrow;
    borrow = Number(d10 < 0);
    d10 += borrow * K1_TOP_BASE;
    const mask = borrow - 1; // all ones if limbs >= p, zero otherwise
    limbs[0] = (limbs[0] & ~mask) | (d0 & mask);
    limbs[1] = (limbs[1] & ~mask) | (d1 & mask);
    limbs[2] = (limbs[2] & ~mask) | (d2 & mask);
    limbs[3] = (limbs[3] & ~mask) | (d3 & mask);
    limbs[4] = (limbs[4] & ~mask) | (d4 & mask);
    limbs[5] = (limbs[5] & ~mask) | (d5 & mask);
    limbs[6] = (limbs[6] & ~mask) | (d6 & mask);
    limbs[7] = (limbs[7] & ~mask) | (d7 & mask);
    limbs[8] = (limbs[8] & ~mask) | (d8 & mask);
    limbs[9] = (limbs[9] & ~mask) | (d9 & mask);
    limbs[10] = (limbs[10] & ~mask) | (d10 & mask);
    return limbs;
  }
  function foldTopOnce(limbs: Uint32Array): void {
    const high = Math.floor(limbs[10] / K1_TOP_BASE);
    limbs[10] -= high * K1_TOP_BASE;
    let v = limbs[0] + high * K1_FOLD;
    let carry = Math.floor(v / K1_BASE);
    limbs[0] = v - carry * K1_BASE;
    v = limbs[1] + high * K1_FOLD_SHIFT + carry;
    carry = Math.floor(v / K1_BASE);
    limbs[1] = v - carry * K1_BASE;
    for (let i = 2; i < K1_LIMBS - 1; i++) {
      v = limbs[i] + carry;
      carry = Math.floor(v / K1_BASE);
      limbs[i] = v - carry * K1_BASE;
    }
    limbs[10] += carry;
  }
  function packSigned(limbs: number[]): K1Elem {
    const out = new Uint32Array(K1_LIMBS);
    let carry = 0;
    for (let i = 0; i < K1_LIMBS - 1; i++) {
      const v = limbs[i] + carry;
      carry = Math.floor(v / K1_BASE);
      out[i] = v - carry * K1_BASE;
    }
    out[10] = limbs[10] + carry;
    maybeSubP(out);
    return out;
  }
  function carryBase(t: number[]): void {
    let carry = 0;
    for (let i = 0; i < t.length; i++) {
      const v = t[i] + carry;
      carry = Math.floor(v / K1_BASE);
      t[i] = v - carry * K1_BASE;
    }
  }
  function foldHigh(t: number[]): void {
    let prev = Math.floor(t[10] / K1_TOP_BASE);
    t[10] -= prev * K1_TOP_BASE;
    for (let pos = 11, k = 0; pos < t.length; pos++, k++) {
      const limb = t[pos];
      const low = limb - Math.floor(limb / K1_TOP_BASE) * K1_TOP_BASE;
      const h = prev + low * K1_FOLD_SHIFT;
      prev = Math.floor(limb / K1_TOP_BASE);
      t[pos] = 0;
      t[k] += h * K1_FOLD;
      t[k + 1] += h * K1_FOLD_SHIFT;
    }
  }
  function normalize(t: number[]): K1Elem {
    carryBase(t);
    foldHigh(t);
    carryBase(t);
    foldHigh(t);
    carryBase(t);
    const out = new Uint32Array(K1_LIMBS);
    for (let i = 0; i < K1_LIMBS; i++) out[i] = t[i];
    maybeSubP(out);
    maybeSubP(out);
    return out;
  }
  function fromBE(bytes: Uint8Array): Uint32Array {
    bytes = abytes(bytes, K1_FIELD_BYTES, 'Field.fromBytes');
    const out = new Uint32Array(K1_LIMBS);
    for (let i = 0; i < K1_LIMBS - 1; i++) {
      const pos = 31 - 3 * i;
      out[i] = bytes[pos] | (bytes[pos - 1] << 8) | (bytes[pos - 2] << 16);
    }
    out[10] = bytes[1] | (bytes[0] << 8);
    return out;
  }
  function toBE(bytes: K1Elem): Uint8Array {
    const limbs = assertElem(bytes);
    const out = new Uint8Array(K1_FIELD_BYTES);
    for (let i = 0; i < K1_LIMBS - 1; i++) {
      const l = limbs[i];
      const pos = 31 - 3 * i;
      out[pos] = l & 0xff;
      out[pos - 1] = (l >>> 8) & 0xff;
      out[pos - 2] = l >>> 16;
    }
    const top = limbs[10];
    out[1] = top & 0xff;
    out[0] = top >>> 8;
    return out;
  }
  function elem(num: K1Input): K1Elem {
    return typeof num === 'bigint' ? fromBigint(num) : assertElem(num);
  }
  function fromBigint(num: bigint): K1Elem {
    const reduced = modK1(num);
    let hit = cache.get(reduced);
    if (hit !== undefined) return copy(hit);
    hit = fromBytes(numberToBytesBE(reduced, K1_FIELD_BYTES), true);
    if (cache.size > 256) cache.clear();
    cache.set(reduced, copy(hit));
    return hit;
  }
  function fromBytes(bytes: TArg<Uint8Array>, skipValidation = false): K1Elem {
    const limbs = fromBE(bytes as Uint8Array);
    const outside = gteP(limbs);
    if (!skipValidation && outside) throw new Error('invalid field element: outside of range 0..ORDER');
    if (outside) maybeSubP(limbs);
    return limbs;
  }
  function add(lhs: K1Input, rhs: K1Input): K1Elem {
    const a = elem(lhs);
    const b = elem(rhs);
    const out = new Uint32Array(K1_LIMBS);
    let carry = 0;
    for (let i = 0; i < K1_LIMBS - 1; i++) {
      const sum = a[i] + b[i] + carry;
      carry = Math.floor(sum / K1_BASE);
      out[i] = sum - carry * K1_BASE;
    }
    out[10] = a[10] + b[10] + carry;
    foldTopOnce(out);
    foldTopOnce(out);
    maybeSubP(out);
    maybeSubP(out);
    return out;
  }
  function neg(num: K1Input): K1Elem {
    const a = elem(num);
    const out = new Uint32Array(K1_LIMBS);
    let borrow = 0;
    for (let i = 0; i < K1_LIMBS; i++) {
      let d = K1_P_LIMBS[i] - a[i] - borrow;
      borrow = d < 0 ? 1 : 0;
      if (borrow) d += i === K1_LIMBS - 1 ? K1_TOP_BASE : K1_BASE;
      out[i] = d;
    }
    maybeSubP(out);
    return out;
  }
  function sub(lhs: K1Input, rhs: K1Input): K1Elem {
    const a = elem(lhs);
    const b = elem(rhs);
    const out = k1Narrow();
    let borrow = 0;
    for (let i = 0; i < K1_LIMBS; i++) {
      const base = i === K1_LIMBS - 1 ? K1_TOP_BASE : K1_BASE;
      let diff = a[i] - b[i] - borrow;
      borrow = diff < 0 ? 1 : 0;
      if (borrow) diff += base;
      out[i] = diff;
    }
    out[0] -= borrow * K1_FOLD;
    out[1] -= borrow * K1_FOLD_SHIFT;
    return packSigned(out);
  }
  function mul(lhs: K1Input, rhs: K1Input): K1Elem {
    const a = elem(lhs);
    const b = elem(rhs);
    const a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4], a5 = a[5];
    const a6 = a[6], a7 = a[7], a8 = a[8], a9 = a[9], a10 = a[10];
    const b0 = b[0], b1 = b[1], b2 = b[2], b3 = b[3], b4 = b[4], b5 = b[5];
    const b6 = b[6], b7 = b[7], b8 = b[8], b9 = b[9], b10 = b[10];
    const t = k1Wide();
    t[0] = a0 * b0;
    t[1] = a0 * b1 + a1 * b0;
    t[2] = a0 * b2 + a1 * b1 + a2 * b0;
    t[3] = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
    t[4] = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
    t[5] = a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0;
    t[6] = a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0;
    t[7] =
      a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1 + a7 * b0;
    t[8] =
      a0 * b8 + a1 * b7 + a2 * b6 + a3 * b5 + a4 * b4 + a5 * b3 + a6 * b2 + a7 * b1 +
      a8 * b0;
    t[9] =
      a0 * b9 + a1 * b8 + a2 * b7 + a3 * b6 + a4 * b5 + a5 * b4 + a6 * b3 + a7 * b2 +
      a8 * b1 + a9 * b0;
    t[10] =
      a0 * b10 + a1 * b9 + a2 * b8 + a3 * b7 + a4 * b6 + a5 * b5 + a6 * b4 + a7 * b3 +
      a8 * b2 + a9 * b1 + a10 * b0;
    t[11] =
      a1 * b10 + a2 * b9 + a3 * b8 + a4 * b7 + a5 * b6 + a6 * b5 + a7 * b4 + a8 * b3 +
      a9 * b2 + a10 * b1;
    t[12] =
      a2 * b10 + a3 * b9 + a4 * b8 + a5 * b7 + a6 * b6 + a7 * b5 + a8 * b4 + a9 * b3 +
      a10 * b2;
    t[13] =
      a3 * b10 + a4 * b9 + a5 * b8 + a6 * b7 + a7 * b6 + a8 * b5 + a9 * b4 + a10 * b3;
    t[14] = a4 * b10 + a5 * b9 + a6 * b8 + a7 * b7 + a8 * b6 + a9 * b5 + a10 * b4;
    t[15] = a5 * b10 + a6 * b9 + a7 * b8 + a8 * b7 + a9 * b6 + a10 * b5;
    t[16] = a6 * b10 + a7 * b9 + a8 * b8 + a9 * b7 + a10 * b6;
    t[17] = a7 * b10 + a8 * b9 + a9 * b8 + a10 * b7;
    t[18] = a8 * b10 + a9 * b9 + a10 * b8;
    t[19] = a9 * b10 + a10 * b9;
    t[20] = a10 * b10;
    return normalize(t);
  }
  function sqr(num: K1Input): K1Elem {
    const a = elem(num);
    const a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4], a5 = a[5];
    const a6 = a[6], a7 = a[7], a8 = a[8], a9 = a[9], a10 = a[10];
    const t = k1Wide();
    t[0] = a0 * a0;
    t[1] = 2 * a0 * a1;
    t[2] = 2 * a0 * a2 + a1 * a1;
    t[3] = 2 * (a0 * a3 + a1 * a2);
    t[4] = 2 * (a0 * a4 + a1 * a3) + a2 * a2;
    t[5] = 2 * (a0 * a5 + a1 * a4 + a2 * a3);
    t[6] = 2 * (a0 * a6 + a1 * a5 + a2 * a4) + a3 * a3;
    t[7] = 2 * (a0 * a7 + a1 * a6 + a2 * a5 + a3 * a4);
    t[8] = 2 * (a0 * a8 + a1 * a7 + a2 * a6 + a3 * a5) + a4 * a4;
    t[9] = 2 * (a0 * a9 + a1 * a8 + a2 * a7 + a3 * a6 + a4 * a5);
    t[10] = 2 * (a0 * a10 + a1 * a9 + a2 * a8 + a3 * a7 + a4 * a6) + a5 * a5;
    t[11] = 2 * (a1 * a10 + a2 * a9 + a3 * a8 + a4 * a7 + a5 * a6);
    t[12] = 2 * (a2 * a10 + a3 * a9 + a4 * a8 + a5 * a7) + a6 * a6;
    t[13] = 2 * (a3 * a10 + a4 * a9 + a5 * a8 + a6 * a7);
    t[14] = 2 * (a4 * a10 + a5 * a9 + a6 * a8) + a7 * a7;
    t[15] = 2 * (a5 * a10 + a6 * a9 + a7 * a8);
    t[16] = 2 * (a6 * a10 + a7 * a9) + a8 * a8;
    t[17] = 2 * (a7 * a10 + a8 * a9);
    t[18] = 2 * a8 * a10 + a9 * a9;
    t[19] = 2 * a9 * a10;
    t[20] = a10 * a10;
    return normalize(t);
  }
  function pow(lhs: K1Input, power: K1Input): K1Elem {
    const p = typeof power === 'bigint' ? power : toBigint(power);
    if (p < _0n) throw new Error('invalid exponent, negatives unsupported');
    if (p === _0n) return copy(ONE);
    if (p === _1n) return copy(elem(lhs));
    let digits = powCache.get(p);
    if (digits === undefined) {
      const hex = p.toString(16);
      digits = new Array(hex.length);
      for (let i = 0; i < hex.length; i++) {
        const code = hex.charCodeAt(i);
        digits[i] = code < 58 ? code - 48 : code - 87;
      }
      powCache.set(p, digits);
    }
    const table = new Array<K1Elem>(16);
    table[0] = copy(ONE);
    table[1] = copy(elem(lhs));
    for (let i = 2; i < 16; i++) table[i] = mul(table[i - 1], table[1]);
    let out = copy(ONE);
    for (const idx of digits) {
      out = sqr(sqr(sqr(sqr(out))));
      if (idx !== 0) out = mul(out, table[idx]);
    }
    return out;
  }
  function sqrPow(num: K1Elem, power: number): K1Elem {
    let out = num;
    for (let i = 0; i < power; i++) out = sqr(out);
    return out;
  }
  function pow223(num: K1Input): {
    x1: K1Elem;
    x2: K1Elem;
    x3: K1Elem;
    x22: K1Elem;
    x223: K1Elem;
  } {
    const x1 = copy(elem(num));
    const x2 = mul(sqr(x1), x1); // x^(2^2 - 1)
    const x3 = mul(sqr(x2), x1); // x^(2^3 - 1)
    const x6 = mul(sqrPow(x3, 3), x3);
    const x9 = mul(sqrPow(x6, 3), x3);
    const x11 = mul(sqrPow(x9, 2), x2);
    const x22 = mul(sqrPow(x11, 11), x11);
    const x44 = mul(sqrPow(x22, 22), x22);
    const x88 = mul(sqrPow(x44, 44), x44);
    const x176 = mul(sqrPow(x88, 88), x88);
    const x220 = mul(sqrPow(x176, 44), x44);
    const x223 = mul(sqrPow(x220, 3), x3);
    return { x1, x2, x3, x22, x223 };
  }
  function sqrtChain(num: K1Input): K1Elem {
    const { x2, x22, x223 } = pow223(num);
    let t = mul(sqrPow(x223, 23), x22);
    t = mul(sqrPow(t, 6), x2);
    return sqrPow(t, 2);
  }
  function invChain(num: K1Input): K1Elem {
    const { x1, x2, x22, x223 } = pow223(num);
    let t = mul(sqrPow(x223, 23), x22);
    t = mul(sqrPow(t, 5), x1);
    t = sqr(t);
    t = mul(sqrPow(t, 2), x2);
    t = sqr(sqr(t));
    return mul(t, x1);
  }
  function eql(lhs: K1Input, rhs: K1Input): boolean {
    const a = elem(lhs);
    const b = elem(rhs);
    let diff = 0;
    for (let i = 0; i < K1_LIMBS; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }
  function is0(num: K1Input): boolean {
    if (typeof num === 'bigint') return modK1(num) === _0n;
    const a = assertElem(num);
    let acc = 0;
    for (let i = 0; i < K1_LIMBS; i++) acc |= a[i];
    return acc === 0;
  }
  function inv(num: K1Input): K1Elem {
    if (is0(num)) throw new Error('invert: expected non-zero number');
    return invChain(num);
  }
  function sqrt(num: K1Input): K1Elem {
    const root = sqrtChain(num);
    if (!eql(sqr(root), num)) throw new Error('Cannot find square root');
    return root;
  }
  function toBigint(num: K1Input): bigint {
    if (typeof num === 'bigint') return modK1(num);
    return bytesToNumberBE(toBE(num));
  }
  function invertBatch(lst: K1Elem[]): K1Elem[] {
    const inverted = new Array<K1Elem>(lst.length).fill(ZERO);
    const multiplied = new Array<K1Elem>(lst.length);
    let acc = copy(ONE);
    for (let i = 0; i < lst.length; i++) {
      const num = assertElem(lst[i]);
      if (is0(num)) continue;
      multiplied[i] = acc;
      acc = mul(acc, num);
    }
    acc = inv(acc);
    for (let i = lst.length - 1; i >= 0; i--) {
      const num = assertElem(lst[i]);
      if (is0(num)) continue;
      inverted[i] = mul(acc, multiplied[i]);
      acc = mul(acc, num);
    }
    return inverted;
  }
  const field: K1Field = {
    ORDER: K1_P,
    BITS: 256,
    BYTES: K1_FIELD_BYTES,
    isLE: false,
    get ZERO() {
      return copy(ZERO);
    },
    get ONE() {
      return copy(ONE);
    },
    create(num) {
      return typeof num === 'bigint' ? fromBigint(num) : copy(assertElem(num));
    },
    isValid(num) {
      if (typeof num === 'bigint') return _0n <= num && num < K1_P;
      const limbs = assertElem(num);
      for (let i = 0; i < K1_LIMBS - 1; i++) if (limbs[i] >= K1_BASE) return false;
      if (limbs[10] >= K1_TOP_BASE) return false;
      return !gteP(limbs);
    },
    is0,
    isValidNot0(num) {
      return !is0(num) && this.isValid(num);
    },
    isOdd(num) {
      if (typeof num === 'bigint') return (num & _1n) === _1n;
      return !!(assertElem(num)[0] & 1);
    },
    neg,
    inv,
    sqrt,
    sqr,
    eql,
    add,
    sub,
    mul,
    pow,
    div(lhs, rhs) {
      return mul(lhs, inv(rhs));
    },
    addN: add,
    subN: sub,
    mulN: mul,
    sqrN: sqr,
    invertBatch,
    toBytes(num) {
      return typeof num === 'bigint' ? numberToBytesBE(modK1(num), K1_FIELD_BYTES) : toBE(num);
    },
    fromBytes,
    cmov(a, b, condition) {
      abool(condition, 'condition');
      a = assertElem(a);
      b = assertElem(b);
      const out = new Uint32Array(K1_LIMBS);
      const mask = -Number(condition);
      for (let i = 0; i < K1_LIMBS; i++) out[i] = (a[i] & ~mask) | (b[i] & mask);
      return out;
    },
    fromBigint,
    toBigint,
  };
  Object.freeze(field);
  return field;
}

function packK1(limbs: ArrayLike<number>): K1Elem {
  const out = new Uint32Array(K1_LIMBS);
  for (let i = 0; i < K1_LIMBS; i++) out[i] = limbs[i] || 0;
  return out;
}

export const secp256k1_Fp: Readonly<K1Field> = /* @__PURE__ */ (() => FieldSecp256k1())();
export const secp256k1_Fn: Readonly<CtField> = /* @__PURE__ */ (() =>
  FieldCt(secp256k1_CURVE.n))();

const Fpk1 = secp256k1_Fp;
const Fnk1 = /* @__PURE__ */ (() => FieldCtBigint(secp256k1_CURVE.n))();
const secp256k1_CURVE_CT = /* @__PURE__ */ (() =>
  Object.freeze({
    ...secp256k1_CURVE,
    a: Fpk1.fromBigint(secp256k1_CURVE.a),
    b: Fpk1.fromBigint(secp256k1_CURVE.b),
    Gx: Fpk1.fromBigint(secp256k1_CURVE.Gx),
    Gy: Fpk1.fromBigint(secp256k1_CURVE.Gy),
  }))();
const Pointk1: WeierstrassPointCons<bigint> = /* @__PURE__ */ weierstrass(
  secp256k1_CURVE_CT as any,
  {
    Fp: Fpk1 as any,
    Fn: Fnk1,
    endo: secp256k1_ENDO,
  } as any
);

/**
 * secp256k1 curve: ECDSA and ECDH methods.
 *
 * Uses sha256 to hash messages. To use a different hash,
 * pass `{ prehash: false }` to sign / verify.
 *
 * @example
 * Generate one secp256k1 keypair, sign a message, and verify it.
 *
 * ```js
 * import { secp256k1 } from '@noble/curves/secp256k1.js';
 * const { secretKey, publicKey } = secp256k1.keygen();
 * // const publicKey = secp256k1.getPublicKey(secretKey);
 * const msg = new TextEncoder().encode('hello noble');
 * const sig = secp256k1.sign(msg, secretKey);
 * const isValid = secp256k1.verify(sig, msg, publicKey);
 * // const sigKeccak = secp256k1.sign(keccak256(msg), secretKey, { prehash: false });
 * ```
 */
export const secp256k1: ECDSA = /* @__PURE__ */ ecdsa(Pointk1, sha256);

// Schnorr signatures are superior to ECDSA from above. Below is Schnorr-specific BIP0340 code.
// https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
/** An object mapping tags to their tagged hash prefix of [SHA256(tag) | SHA256(tag)] */
const TAGGED_HASH_PREFIXES: { [tag: string]: Uint8Array } = {};
// BIP-340 phrases tags as UTF-8, but all current standardized names here are 7-bit ASCII.
function taggedHash(tag: string, ...messages: TArg<Uint8Array[]>): TRet<Uint8Array> {
  let tagP = TAGGED_HASH_PREFIXES[tag];
  if (tagP === undefined) {
    const tagH = sha256(asciiToBytes(tag));
    tagP = concatBytes(tagH, tagH);
    TAGGED_HASH_PREFIXES[tag] = tagP;
  }
  return sha256(concatBytes(tagP, ...messages)) as TRet<Uint8Array>;
}

// ECDSA compact points are 33-byte. Schnorr is 32: we strip first byte 0x02 or 0x03
const pointToBytes = (point: TArg<PointType<bigint>>): TRet<Uint8Array> =>
  point.toBytes(true).slice(1) as TRet<Uint8Array>;
const hasEven = (y: bigint) => y % _2n === _0n;

// Calculate point, scalar and bytes
function schnorrGetExtPubKey(priv: TArg<Uint8Array>) {
  const { Fn, BASE } = Pointk1;
  const d_ = Fn.fromBytes(abytes(priv, 32, 'secretKey'));
  const p = BASE.multiply(d_); // P = d'⋅G; 0 < d' < n check is done inside
  const scalar = hasEven(p.y) ? d_ : Fn.neg(d_);
  return { scalar, bytes: pointToBytes(p) };
}
/**
 * lift_x from BIP340. Convert 32-byte x coordinate to elliptic curve point.
 * @returns valid point checked for being on-curve
 */
function lift_x(x: bigint): PointType<bigint> {
  const Fp = Fpk1;
  if (!Fp.isValidNot0(x)) throw new Error('invalid x: Fail if x ≥ p');
  const fx = Fp.fromBigint(x);
  const c = Fp.add(Fp.mul(Fp.sqr(fx), fx), BigInt(7)); // Let c = x³ + 7 mod p.
  let y = Fp.toBigint(Fp.sqrt(c)); // Let y = c^(p+1)/4 mod p. Same as sqrt().
  // Return the unique point P such that x(P) = x and
  // y(P) = y if y mod 2 = 0 or y(P) = p-y otherwise.
  if (!hasEven(y)) y = Fp.toBigint(Fp.neg(y));
  const p = Pointk1.fromAffine({ x, y });
  p.assertValidity();
  return p;
}
// BIP-340 callers still need to supply canonical 32-byte inputs where required; this alias only
// parses big-endian bytes and does not enforce the fixed-width contract itself.
const num = bytesToNumberBE;
/** Create tagged hash, convert it to bigint, reduce modulo-n. */
function challenge(...args: TArg<Uint8Array[]>): bigint {
  return Pointk1.Fn.create(num(taggedHash('BIP0340/challenge', ...args)));
}

/** Schnorr public key is just `x` coordinate of Point as per BIP340. */
function schnorrGetPublicKey(secretKey: TArg<Uint8Array>): TRet<Uint8Array> {
  return schnorrGetExtPubKey(secretKey).bytes; // d'=int(sk). Fail if d'=0 or d'≥n. Ret bytes(d'⋅G)
}

/**
 * Creates Schnorr signature as per BIP340. Verifies itself before returning anything.
 * `auxRand` is optional and is not the sole source of `k` generation: bad CSPRNG output will not
 * be catastrophic, but BIP-340 still recommends fresh auxiliary randomness when available to harden
 * deterministic signing against side-channel and fault-injection attacks.
 */
function schnorrSign(
  message: TArg<Uint8Array>,
  secretKey: TArg<Uint8Array>,
  auxRand: TArg<Uint8Array> = randomBytes(32)
): TRet<Uint8Array> {
  const { Fn, BASE } = Pointk1;
  const m = abytes(message, undefined, 'message');
  const { bytes: px, scalar: d } = schnorrGetExtPubKey(secretKey); // checks for isWithinCurveOrder
  const a = abytes(auxRand, 32, 'auxRand'); // Auxiliary random data a: a 32-byte array
  // Let t be the byte-wise xor of bytes(d) and hash/aux(a).
  const t = Fn.toBytes(d ^ num(taggedHash('BIP0340/aux', a)));
  const rand = taggedHash('BIP0340/nonce', t, px, m); // Let rand = hash/nonce(t || bytes(P) || m)
  // BIP340 defines k' = int(rand) mod n. We can't reuse schnorrGetExtPubKey(rand)
  // here: that helper parses canonical secret keys and rejects rand >= n instead
  // of reducing the nonce hash modulo the group order.
  const k_ = Fn.create(num(rand));
  // BIP-340: "Let k' = int(rand) mod n. Fail if k' = 0. Let R = k'⋅G."
  if (k_ === _0n) throw new Error('sign failed: k is zero');
  const p = BASE.multiply(k_); // Rejects zero; only the raw nonce hash needs reduction.
  const k = hasEven(p.y) ? k_ : Fn.neg(k_);
  const rx = pointToBytes(p);
  const e = challenge(rx, px, m); // Let e = int(hash/challenge(bytes(R) || bytes(P) || m)) mod n.
  const sig = new Uint8Array(64); // Let sig = bytes(R) || bytes((k + ed) mod n).
  sig.set(rx, 0);
  sig.set(Fn.toBytes(Fn.create(k + e * d)), 32);
  // If Verify(bytes(P), m, sig) (see below) returns failure, abort
  if (!schnorrVerify(sig, m, px)) throw new Error('sign: Invalid signature produced');
  return sig as TRet<Uint8Array>;
}

/**
 * Verifies Schnorr signature.
 * Will swallow errors & return false except for initial type validation of arguments.
 */
function schnorrVerify(
  signature: TArg<Uint8Array>,
  message: TArg<Uint8Array>,
  publicKey: TArg<Uint8Array>
): boolean {
  const { Fp, Fn, BASE } = Pointk1;
  const sig = abytes(signature, 64, 'signature');
  const m = abytes(message, undefined, 'message');
  const pub = abytes(publicKey, 32, 'publicKey');
  try {
    const P = lift_x(num(pub)); // P = lift_x(int(pk)); fail if that fails
    const r = num(sig.subarray(0, 32)); // Let r = int(sig[0:32]); fail if r ≥ p.
    if (!Fp.isValidNot0(r)) return false;
    const s = num(sig.subarray(32, 64)); // Let s = int(sig[32:64]); fail if s ≥ n.
    // Stricter than BIP-340/libsecp256k1, which only reject s >= n. Honest signing reaches
    // s = 0 only with negligible probability (k + e*d ≡ 0 mod n), so treat zero-s inputs as
    // crafted edge cases and fail closed instead of carrying that extra verification surface.
    if (!Fn.isValidNot0(s)) return false;

    // int(challenge(bytes(r) || bytes(P) || m)) % n
    const e = challenge(Fn.toBytes(r), pointToBytes(P), m);
    // R = s⋅G - e⋅P, where -eP == (n-e)P
    const R = BASE.multiplyUnsafe(s).add(P.multiplyUnsafe(Fn.neg(e)));
    const { x, y } = R.toAffine();
    // Fail if is_infinite(R) / not has_even_y(R) / x(R) ≠ r.
    if (R.is0() || !hasEven(y) || x !== r) return false;
    return true;
  } catch (error) {
    return false;
  }
}

export const __TEST: { lift_x: typeof lift_x } = /* @__PURE__ */ Object.freeze({ lift_x });

/** Schnorr-specific secp256k1 API from BIP340. */
export type SecpSchnorr = {
  /**
   * Generate one Schnorr secret/public keypair.
   * @param seed - Optional seed for deterministic testing or custom randomness.
   * @returns Fresh secret/public keypair.
   */
  keygen: (seed?: TArg<Uint8Array>) => { secretKey: TRet<Uint8Array>; publicKey: TRet<Uint8Array> };
  /**
   * Derive the x-only public key from a secret key.
   * @param secretKey - Secret key bytes.
   * @returns X-only public key bytes.
   */
  getPublicKey: typeof schnorrGetPublicKey;
  /**
   * Create one BIP340 Schnorr signature.
   * @param message - Message bytes to sign.
   * @param secretKey - Secret key bytes.
   * @param auxRand - Optional auxiliary randomness.
   * @returns Compact Schnorr signature bytes.
   */
  sign: typeof schnorrSign;
  /**
   * Verify one BIP340 Schnorr signature.
   * @param signature - Compact signature bytes.
   * @param message - Signed message bytes.
   * @param publicKey - X-only public key bytes.
   * @returns `true` when the signature is valid.
   */
  verify: typeof schnorrVerify;
  /** Underlying secp256k1 point constructor. */
  Point: WeierstrassPointCons<bigint>;
  /** Helper utilities for Schnorr-specific key handling and tagged hashing. */
  utils: {
    /** Generate one Schnorr secret key. */
    randomSecretKey: (seed?: TArg<Uint8Array>) => TRet<Uint8Array>;
    /** Convert one point into its x-only BIP340 byte encoding. */
    pointToBytes: (point: TArg<PointType<bigint>>) => TRet<Uint8Array>;
    /** Lift one x coordinate into the unique even-Y point. */
    lift_x: typeof lift_x;
    /** Compute a BIP340 tagged hash. */
    taggedHash: typeof taggedHash;
  };
  /** Public byte lengths for keys, signatures, and seeds. */
  lengths: CurveLengths;
};
/**
 * Schnorr signatures over secp256k1.
 * See {@link https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki | BIP 340}.
 * @example
 * Generate one BIP340 Schnorr keypair, sign a message, and verify it.
 *
 * ```js
 * import { schnorr } from '@noble/curves/secp256k1.js';
 * const { secretKey, publicKey } = schnorr.keygen();
 * // const publicKey = schnorr.getPublicKey(secretKey);
 * const msg = new TextEncoder().encode('hello');
 * const sig = schnorr.sign(msg, secretKey);
 * const isValid = schnorr.verify(sig, msg, publicKey);
 * ```
 */
export const schnorr: SecpSchnorr = /* @__PURE__ */ (() => {
  const size = 32;
  const seedLength = 48;
  const randomSecretKey = (seed?: TArg<Uint8Array>): TRet<Uint8Array> => {
    seed = seed === undefined ? randomBytes(seedLength) : seed;
    return mapHashToField(abytes(seed, seedLength, 'seed'), secp256k1_CURVE.n);
  };
  return Object.freeze({
    keygen: createKeygen(randomSecretKey, schnorrGetPublicKey),
    getPublicKey: schnorrGetPublicKey,
    sign: schnorrSign,
    verify: schnorrVerify,
    Point: Pointk1,
    utils: Object.freeze({
      randomSecretKey,
      taggedHash,
      lift_x,
      pointToBytes,
    }),
    lengths: Object.freeze({
      secretKey: size,
      publicKey: size,
      publicKeyHasPrefix: false,
      signature: size * 2,
      seed: seedLength,
    }),
  });
})();

// RFC 9380 Appendix E.1 3-isogeny coefficients for secp256k1, stored in ascending degree order.
// The final `1` in each denominator array is the explicit monic leading term.
const isoMap = /* @__PURE__ */ (() =>
  isogenyMap(
    Fpk1 as any,
    [
      // xNum
      [
        '0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa8c7',
        '0x7d3d4c80bc321d5b9f315cea7fd44c5d595d2fc0bf63b92dfff1044f17c6581',
        '0x534c328d23f234e6e2a413deca25caece4506144037c40314ecbd0b53d9dd262',
        '0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa88c',
      ],
      // xDen
      [
        '0xd35771193d94918a9ca34ccbb7b640dd86cd409542f8487d9fe6b745781eb49b',
        '0xedadc6f64383dc1df7c4b2d51b54225406d36b641f5e41bbc52a56612a8c6d14',
        '0x0000000000000000000000000000000000000000000000000000000000000001', // LAST 1
      ],
      // yNum
      [
        '0x4bda12f684bda12f684bda12f684bda12f684bda12f684bda12f684b8e38e23c',
        '0xc75e0c32d5cb7c0fa9d0a54b12a0a6d5647ab046d686da6fdffc90fc201d71a3',
        '0x29a6194691f91a73715209ef6512e576722830a201be2018a765e85a9ecee931',
        '0x2f684bda12f684bda12f684bda12f684bda12f684bda12f684bda12f38e38d84',
      ],
      // yDen
      [
        '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffff93b',
        '0x7a06534bb8bdb49fd5e9e6632722c2989467c1bfc8e8d978dfb425d2685c2573',
        '0x6484aa716545ca2cf3a70c3fa8fe337e0a3d21162f0d6299a7bf8192bfd2a76f',
        '0x0000000000000000000000000000000000000000000000000000000000000001', // LAST 1
      ],
    ].map((i) => i.map((j) => Fpk1.fromBigint(BigInt(j)))) as [
      K1Elem[],
      K1Elem[],
      K1Elem[],
      K1Elem[],
    ]
  ) as (x: K1Elem, y: K1Elem) => { x: K1Elem; y: K1Elem })();
// RFC 9380 §8.7 secp256k1 E' parameters for the SWU-to-isogeny pipeline below.
let mapSWU: ((u: K1Elem) => { x: K1Elem; y: K1Elem }) | undefined;
const getMapSWU = () =>
  mapSWU ||
  (mapSWU = mapToCurveSimpleSWU(Fpk1 as any, {
    // Building the SWU sqrt-ratio helper eagerly adds noticeable `secp256k1.js` import cost, so
    // defer it to first use; after that the cached mapper is reused directly.
    A: Fpk1.fromBigint(
      BigInt('0x3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533')
    ),
    B: Fpk1.fromBigint(BigInt('1771')),
    Z: Fpk1.create(BigInt('-11')),
  }) as unknown as (u: K1Elem) => { x: K1Elem; y: K1Elem });

/**
 * Hashing / encoding to secp256k1 points / field. RFC 9380 methods.
 * @example
 * Hash one message onto secp256k1.
 *
 * ```ts
 * const point = secp256k1_hasher.hashToCurve(new TextEncoder().encode('hello noble'));
 * ```
 */
export const secp256k1_hasher: H2CHasher<WeierstrassPointCons<bigint>> = /* @__PURE__ */ (() =>
  createHasher(
    Pointk1,
    (scalars: bigint[]) => {
      const { x, y } = getMapSWU()(Fpk1.create(scalars[0]));
      const p = isoMap(x, y);
      return { x: Fpk1.toBigint(p.x), y: Fpk1.toBigint(p.y) };
    },
    {
      DST: 'secp256k1_XMD:SHA-256_SSWU_RO_',
      encodeDST: 'secp256k1_XMD:SHA-256_SSWU_NU_',
      p: Fpk1.ORDER,
      m: 1,
      k: 128,
      expand: 'xmd',
      hash: sha256,
    }
  ))();
/**
 * FROST threshold signatures over secp256k1. RFC 9591.
 * @example
 * Create one trusted-dealer package for 2-of-3 secp256k1 signing.
 *
 * ```ts
 * const alice = secp256k1_FROST.Identifier.derive('alice@example.com');
 * const bob = secp256k1_FROST.Identifier.derive('bob@example.com');
 * const carol = secp256k1_FROST.Identifier.derive('carol@example.com');
 * const deal = secp256k1_FROST.trustedDealer({ min: 2, max: 3 }, [alice, bob, carol]);
 * ```
 */
export const secp256k1_FROST: TRet<FROST> = /* @__PURE__ */ (() =>
  createFROST({
    name: 'FROST-secp256k1-SHA256-v1',
    Point: Pointk1,
    hashToScalar: secp256k1_hasher.hashToScalar,
    hash: sha256,
  }))();

// Taproot utils
// `undefined` means "disable TapTweak entirely"; callers that want the BIP-341/BIP-386 empty
// merkle root must pass `new Uint8Array(0)` explicitly.
function tweak(point: PointType<bigint>, merkleRoot?: TArg<Uint8Array>): bigint {
  if (merkleRoot === undefined) return _0n;
  const x = pointToBytes(point);
  const t = bytesToNumberBE(taggedHash('TapTweak', x, merkleRoot));
  // BIP-341 taproot_tweak_pubkey/taproot_tweak_seckey: "if t >= SECP256K1_ORDER:
  // raise ValueError". TapTweak must reject overflow instead of reducing modulo n.
  if (!Pointk1.Fn.isValid(t)) throw new Error('invalid TapTweak hash');
  return t;
}
function frostPubToEvenY(pub: TArg<FrostPublic>): TRet<FrostPublic> {
  const VK = Pointk1.fromBytes(pub.commitments[0]);
  // Keep aliasing on the already-even path so wrapper callers can skip unnecessary cloning.
  if (hasEven(VK.y)) return pub as TRet<FrostPublic>;
  return {
    signers: { min: pub.signers.min, max: pub.signers.max },
    commitments: pub.commitments.map((i) => Pointk1.fromBytes(i).negate().toBytes()),
    verifyingShares: Object.fromEntries(
      Object.entries(pub.verifyingShares).map(([k, v]) => [
        k,
        Pointk1.fromBytes(v).negate().toBytes(),
      ])
    ),
  } as TRet<FrostPublic>;
}
function frostSecretToEvenY(s: TArg<FrostSecret>, pub: TArg<FrostPublic>): TRet<FrostSecret> {
  const VK = Pointk1.fromBytes(pub.commitments[0]);
  // Keep aliasing on the already-even path so wrapper callers can preserve package identity.
  if (hasEven(VK.y)) return s as TRet<FrostSecret>;
  const Fn = Pointk1.Fn;
  return {
    ...s,
    signingShare: Fn.toBytes(Fn.neg(Fn.fromBytes(s.signingShare))),
  } as TRet<FrostSecret>;
}
function frostNoncesToEvenY(PK: PointType<bigint>, nonces: TArg<Nonces>): TRet<Nonces> {
  if (hasEven(PK.y)) return nonces as TRet<Nonces>;
  const Fn = Pointk1.Fn;
  return {
    binding: Fn.toBytes(Fn.neg(Fn.fromBytes(nonces.binding))),
    hiding: Fn.toBytes(Fn.neg(Fn.fromBytes(nonces.hiding))),
  } as TRet<Nonces>;
}

function frostTweakSecret(
  s: TArg<FrostSecret>,
  pub: TArg<FrostPublic>,
  merkleRoot?: TArg<Uint8Array>
): TRet<FrostSecret> {
  const Fn = Pointk1.Fn;
  const keyPackage = frostSecretToEvenY(s, pub);
  const evenPub = frostPubToEvenY(pub);
  const t = tweak(Pointk1.fromBytes(evenPub.commitments[0]), merkleRoot);
  const signingShare = Fn.toBytes(Fn.add(Fn.fromBytes(keyPackage.signingShare), t));
  return {
    identifier: keyPackage.identifier,
    signingShare,
  } as TRet<FrostSecret>;
}

function frostTweakPublic(
  pub: TArg<FrostPublic>,
  merkleRoot?: TArg<Uint8Array>
): TRet<FrostPublic> {
  const PKPackage = frostPubToEvenY(pub);
  const t = tweak(Pointk1.fromBytes(PKPackage.commitments[0]), merkleRoot);
  const tp = Pointk1.BASE.multiply(t);
  const commitments = PKPackage.commitments.map((c, i) =>
    (i === 0 ? Pointk1.fromBytes(c).add(tp) : Pointk1.fromBytes(c)).toBytes()
  );
  const verifyingShares: Record<string, Uint8Array> = {};
  for (const k in PKPackage.verifyingShares) {
    verifyingShares[k] = Pointk1.fromBytes(PKPackage.verifyingShares[k]).add(tp).toBytes();
  }
  return {
    signers: { min: PKPackage.signers.min, max: PKPackage.signers.max },
    commitments,
    verifyingShares,
  } as TRet<FrostPublic>;
}

/**
 * FROST threshold signatures over secp256k1-schnorr-taproot. RFC 9591.
 * DKG outputs are auto-tweaked with the empty Taproot merkle root for compatibility, while
 * `trustedDealer()` outputs stay untweaked unless callers apply the Taproot tweak themselves.
 * @example
 * Create one trusted-dealer package for Taproot-compatible FROST signing.
 *
 * ```ts
 * const alice = schnorr_FROST.Identifier.derive('alice@example.com');
 * const bob = schnorr_FROST.Identifier.derive('bob@example.com');
 * const carol = schnorr_FROST.Identifier.derive('carol@example.com');
 * const deal = schnorr_FROST.trustedDealer({ min: 2, max: 3 }, [alice, bob, carol]);
 * ```
 */
export const schnorr_FROST: TRet<FROST> = /* @__PURE__ */ (() =>
  createFROST({
    name: 'FROST-secp256k1-SHA256-TR-v1',
    Point: Pointk1,
    hashToScalar: secp256k1_hasher.hashToScalar,
    hash: sha256,
    // Taproot related hacks
    parsePublicKey(publicKey) {
      // External Taproot keys are x-only, but local key packages still use compressed points.
      if (publicKey.length === 32) return lift_x(bytesToNumberBE(publicKey));
      if (publicKey.length === 33) return Pointk1.fromBytes(publicKey);
      throw new Error(`expected x-only or compressed public key, got length=${publicKey.length}`);
    },
    adjustScalar(n: bigint) {
      const PK = Pointk1.BASE.multiply(n);
      return hasEven(PK.y) ? n : Pointk1.Fn.neg(n);
    },
    adjustPoint: (p) => (hasEven(p.y) ? p : p.negate()),
    challenge(R, PK, msg) {
      return challenge(pointToBytes(R), pointToBytes(PK), msg);
    },
    adjustNonces: frostNoncesToEvenY,
    adjustGroupCommitmentShare: (GC, GCShare) => (!hasEven(GC.y) ? GCShare.negate() : GCShare),
    adjustPublic: frostPubToEvenY,
    adjustSecret: frostSecretToEvenY,
    adjustTx: {
      // Compat with official implementation
      encode: (tx) => tx.subarray(1) as TRet<Uint8Array>,
      decode: (tx) => concatBytes(Uint8Array.of(0x02), tx) as TRet<Uint8Array>,
    },
    adjustDKG: (k) => {
      // Compatibility with frost-secp256k1-tr: DKG output is auto-tweaked with the
      // empty Taproot merkle root, while dealer-generated keys stay untweaked.
      const merkleRoot = new Uint8Array(0);
      return {
        public: frostTweakPublic(k.public, merkleRoot),
        secret: frostTweakSecret(k.secret, k.public, merkleRoot),
      };
    },
  }))();
