/**
 * Fixed-width byte-array field implementation.
 *
 * Elements are little-endian Montgomery residues internally. Public encodings follow the field's
 * `isLE` option, matching the generic bigint `Field` helper.
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import {
  abool,
  abytes,
  bytesToNumberBE,
  bytesToNumberLE,
  numberToBytesBE,
  numberToBytesLE,
  type TArg,
  type TRet,
} from '../utils.ts';
import { FpInvertBatch, FpSqrt, mod, nLength, type IField } from './modular.ts';

const LIMB_BITS = 24;
const BASE = 0x1000000;
const MASK = 0xffffff;
const _0n = /* @__PURE__ */ BigInt(0);
const _1n = /* @__PURE__ */ BigInt(1);
const _2n = /* @__PURE__ */ BigInt(2);
const BIGINT_CACHE_MAX = 8192;

type Limbs = Uint32Array;
type CtInput = Uint8Array | bigint;
type SubRes = { out: Limbs; borrow: number };

/** Options for {@link FieldCt}. Mirrors the common options accepted by the bigint field. */
export type CtFieldOpts = Partial<{
  /** Whether public byte encodings are little-endian. Internal Montgomery bytes are always LE. */
  isLE: boolean;
  /** Override encoded bit length. Useful for RFC 8032 Ed448's 456-bit container. */
  BITS: number;
  /** Additional input byte lengths accepted by fromBytes(), padded to BYTES. */
  allowedLengths: readonly number[];
  /** Reduce decoded bytes modulo ORDER instead of rejecting values outside the field. */
  modFromBytes: boolean;
}>;

/** Byte-array prime field with bigint conversion helpers for legacy boundaries. */
export type CtField = Omit<
  IField<Uint8Array>,
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
  create(num: CtInput): Uint8Array;
  isValid(num: CtInput): boolean;
  is0(num: CtInput): boolean;
  isValidNot0(num: CtInput): boolean;
  isOdd(num: CtInput): boolean;
  neg(num: CtInput): Uint8Array;
  inv(num: CtInput): Uint8Array;
  sqrt(num: CtInput): Uint8Array;
  sqr(num: CtInput): Uint8Array;
  eql(lhs: CtInput, rhs: CtInput): boolean;
  add(lhs: CtInput, rhs: CtInput): Uint8Array;
  sub(lhs: CtInput, rhs: CtInput): Uint8Array;
  mul(lhs: CtInput, rhs: CtInput): Uint8Array;
  pow(lhs: CtInput, power: CtInput): Uint8Array;
  div(lhs: CtInput, rhs: CtInput): Uint8Array;
  addN(lhs: CtInput, rhs: CtInput): Uint8Array;
  subN(lhs: CtInput, rhs: CtInput): Uint8Array;
  mulN(lhs: CtInput, rhs: CtInput): Uint8Array;
  sqrN(num: CtInput): Uint8Array;
  toBytes(num: CtInput): Uint8Array;
  /** Convert a bigint into an internal Montgomery field element. */
  fromBigint(num: bigint): Uint8Array;
  /** Convert an internal Montgomery field element into a bigint. */
  toBigint(num: CtInput): bigint;
  /** Additional accepted input lengths, when configured. */
  readonly _lengths?: readonly number[];
};

function copyBytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes);
}

function bytesLEToLimbsInto(bytes: Uint8Array, out: Limbs, byteLength: number): void {
  if (bytes.length !== byteLength)
    throw new Error(
      'invalid field element: expected ' + byteLength + ' bytes, got ' + bytes.length
    );
  for (let i = 0; i < out.length; i++) {
    const pos = 3 * i;
    out[i] = bytes[pos] | ((bytes[pos + 1] || 0) << 8) | ((bytes[pos + 2] || 0) << 16);
  }
}

function bytesLEToLimbs(bytes: Uint8Array, limbs: number, byteLength: number): Limbs {
  const out = new Uint32Array(limbs);
  bytesLEToLimbsInto(bytes, out, byteLength);
  return out;
}

function bytesBEToLimbs(bytes: Uint8Array, limbs: number, byteLength: number): Limbs {
  if (bytes.length !== byteLength)
    throw new Error(
      'invalid field element: expected ' + byteLength + ' bytes, got ' + bytes.length
    );
  const out = new Uint32Array(limbs);
  for (let i = 0; i < limbs; i++) {
    const pos = bytes.length - 1 - 3 * i;
    out[i] = (bytes[pos] || 0) | ((bytes[pos - 1] || 0) << 8) | ((bytes[pos - 2] || 0) << 16);
  }
  return out;
}

function limbsToBytesLE(limbs: Limbs, byteLength: number): Uint8Array {
  const out = new Uint8Array(byteLength);
  for (let i = 0; i < limbs.length; i++) {
    const pos = 3 * i;
    if (pos < byteLength) out[pos] = limbs[i] & 0xff;
    if (pos + 1 < byteLength) out[pos + 1] = (limbs[i] >>> 8) & 0xff;
    if (pos + 2 < byteLength) out[pos + 2] = limbs[i] >>> 16;
  }
  return out;
}

function limbsToBytesBE(limbs: Limbs, byteLength: number): Uint8Array {
  const out = new Uint8Array(byteLength);
  for (let i = 0; i < limbs.length; i++) {
    const pos = out.length - 1 - 3 * i;
    if (pos >= 0) out[pos] = limbs[i] & 0xff;
    if (pos - 1 >= 0) out[pos - 1] = (limbs[i] >>> 8) & 0xff;
    if (pos - 2 >= 0) out[pos - 2] = limbs[i] >>> 16;
  }
  return out;
}

function bigintToLimbs(num: bigint, limbs: number, byteLength: number): Limbs {
  return bytesBEToLimbs(numberToBytesBE(num, byteLength), limbs, byteLength);
}

function addLimbsInto(a: Limbs, b: Limbs, out: Limbs): number {
  let carry = 0;
  for (let i = 0; i < a.length; i++) {
    const sum = a[i] + b[i] + carry;
    out[i] = sum & MASK;
    carry = Math.floor(sum / BASE);
  }
  return carry;
}

function subLimbs(a: Limbs, b: Limbs): SubRes {
  const out = new Uint32Array(a.length);
  const borrow = subLimbsInto(a, b, out);
  return { out, borrow };
}

function subLimbsInto(a: Limbs, b: Limbs, out: Limbs): number {
  let borrow = 0;
  for (let i = 0; i < a.length; i++) {
    const diff = a[i] - b[i] - borrow;
    borrow = (diff >> 31) & 1;
    out[i] = diff + borrow * BASE;
  }
  return borrow;
}

function selectLimbs(a: Limbs, b: Limbs, bit: number): Limbs {
  const out = new Uint32Array(a.length);
  selectLimbsInto(a, b, bit, out);
  return out;
}

function selectLimbsInto(a: Limbs, b: Limbs, bit: number, out: Limbs): void {
  const mask = -bit;
  for (let i = 0; i < a.length; i++) out[i] = (a[i] & ~mask) | (b[i] & mask);
}

function invLimb(num: number): number {
  const mask = BigInt(MASK);
  const n = BigInt(num);
  let inv = _1n;
  for (let i = 0; i < 5; i++) inv = (inv * (_2n - n * inv)) & mask;
  return Number(inv);
}

function addCarry(t: Uint32Array, pos: number, carry: number): void {
  let sum = t[pos] + carry;
  t[pos] = sum & MASK;
  carry = Math.floor(sum / BASE);
  sum = t[pos + 1] + carry;
  t[pos + 1] = sum & MASK;
  t[pos + 2] += Math.floor(sum / BASE);
}

class _FieldCt implements CtField {
  readonly ORDER: bigint;
  readonly BYTES: number;
  readonly BITS: number;
  readonly isLE: boolean;
  readonly _lengths?: readonly number[];
  private readonly _limbs: number;
  private readonly _mod: Limbs;
  private readonly _one: Uint8Array;
  private readonly _r2: Limbs;
  private readonly _oneLimbs: Limbs;
  private readonly _oneMontLimbs: Limbs;
  private readonly _nInv: number;
  private readonly _sqrt: ReturnType<typeof FpSqrt>;
  private readonly _modFromBytes: boolean;
  private readonly _a: Limbs;
  private readonly _b: Limbs;
  private readonly _c: Limbs;
  private readonly _d: Limbs;
  private readonly _t: Uint32Array;
  private readonly _bigintCache = new Map<bigint, Uint8Array>();
  private readonly _powCache = new Map<bigint, number[]>();

  constructor(ORDER: bigint, opts: CtFieldOpts = {}) {
    if (ORDER <= _1n) throw new Error('invalid field: expected ORDER > 1, got ' + ORDER);
    if ((ORDER & _1n) === _0n) throw new Error('FieldCt: expected odd order');
    const { nBitLength, nByteLength } = nLength(ORDER, opts.BITS);
    if (nByteLength > 2048) throw new Error('invalid field: expected ORDER of <= 2048 bytes');
    this.ORDER = ORDER;
    this.BITS = nBitLength;
    this.BYTES = nByteLength;
    this.isLE = opts.isLE === true;
    this._limbs = Math.ceil((this.BYTES * 8) / LIMB_BITS);
    this._lengths = opts.allowedLengths && Object.freeze(opts.allowedLengths.slice());
    this._modFromBytes = opts.modFromBytes === true;
    this._mod = bigintToLimbs(ORDER, this._limbs, this.BYTES);
    this._oneLimbs = bigintToLimbs(_1n, this._limbs, this.BYTES);
    this._nInv = -invLimb(this._mod[0]) & MASK;
    this._r2 = bigintToLimbs(
      (_1n << BigInt(LIMB_BITS * this._limbs * 2)) % ORDER,
      this._limbs,
      this.BYTES
    );
    this._a = new Uint32Array(this._limbs);
    this._b = new Uint32Array(this._limbs);
    this._c = new Uint32Array(this._limbs);
    this._d = new Uint32Array(this._limbs);
    this._t = new Uint32Array(this._limbs * 2 + 2);
    this._one = this._limbsToBytesLE(this._montEncode(this._oneLimbs));
    this._oneMontLimbs = bytesLEToLimbs(this._one, this._limbs, this.BYTES);
    this._sqrt = FpSqrt(ORDER);
    for (const num of [_0n, _1n, _2n, BigInt(3), BigInt(4), BigInt(7), BigInt(8), BigInt(27)])
      this._bigintCache.set(num, this._limbsToBytesLE(this._fromBigintLimbs(num)));
    Object.freeze(this);
  }

  get ZERO(): Uint8Array {
    return new Uint8Array(this.BYTES);
  }

  get ONE(): Uint8Array {
    return copyBytes(this._one);
  }

  private _bytesToLimbs(bytes: Uint8Array): Limbs {
    return this.isLE
      ? bytesLEToLimbs(bytes, this._limbs, this.BYTES)
      : bytesBEToLimbs(bytes, this._limbs, this.BYTES);
  }

  private _limbsToBytesLE(limbs: Limbs): Uint8Array {
    return limbsToBytesLE(limbs, this.BYTES);
  }

  private _limbsToPublicBytes(limbs: Limbs): Uint8Array {
    return this.isLE ? limbsToBytesLE(limbs, this.BYTES) : limbsToBytesBE(limbs, this.BYTES);
  }

  private _condSubMod(limbs: Limbs, high = 0): Limbs {
    const { out: diff, borrow } = subLimbs(limbs, this._mod);
    const highBorrow = Number(high === 0) & borrow;
    return selectLimbs(limbs, diff, highBorrow ^ 1);
  }

  private _condSubModInto(limbs: Limbs, high: number, out: Limbs): void {
    const borrow = subLimbsInto(limbs, this._mod, this._d);
    const highBorrow = Number(high === 0) & borrow;
    selectLimbsInto(limbs, this._d, highBorrow ^ 1, out);
  }

  private _addModInto(a: Limbs, b: Limbs, out: Limbs): void {
    const carry = addLimbsInto(a, b, out);
    this._condSubModInto(out, carry, out);
  }

  private _subModInto(a: Limbs, b: Limbs, out: Limbs): void {
    const borrow = subLimbsInto(a, b, out);
    addLimbsInto(out, this._mod, this._d);
    selectLimbsInto(out, this._d, borrow, out);
  }

  private _montMul(a: Limbs, b: Limbs): Limbs {
    const t = new Uint32Array(this._limbs * 2 + 2);
    for (let i = 0; i < this._limbs; i++) {
      let carry = 0;
      for (let j = 0; j < this._limbs; j++) {
        const pos = i + j;
        const prod = t[pos] + a[i] * b[j] + carry;
        t[pos] = prod & MASK;
        carry = Math.floor(prod / BASE);
      }
      addCarry(t, i + this._limbs, carry);
    }
    for (let i = 0; i < this._limbs; i++) {
      const m = (t[i] * this._nInv) & MASK;
      let carry = 0;
      for (let j = 0; j < this._limbs; j++) {
        const pos = i + j;
        const prod = t[pos] + m * this._mod[j] + carry;
        t[pos] = prod & MASK;
        carry = Math.floor(prod / BASE);
      }
      addCarry(t, i + this._limbs, carry);
    }
    const out = new Uint32Array(this._limbs);
    for (let i = 0; i < this._limbs; i++) out[i] = t[i + this._limbs];
    return this._condSubMod(out, t[this._limbs * 2] + t[this._limbs * 2 + 1] * BASE);
  }

  private _montMulInto(a: Limbs, b: Limbs, out: Limbs): void {
    const t = this._t;
    t.fill(0);
    for (let i = 0; i < this._limbs; i++) {
      let carry = 0;
      for (let j = 0; j < this._limbs; j++) {
        const pos = i + j;
        const prod = t[pos] + a[i] * b[j] + carry;
        t[pos] = prod & MASK;
        carry = Math.floor(prod / BASE);
      }
      addCarry(t, i + this._limbs, carry);
    }
    for (let i = 0; i < this._limbs; i++) {
      const m = (t[i] * this._nInv) & MASK;
      let carry = 0;
      for (let j = 0; j < this._limbs; j++) {
        const pos = i + j;
        const prod = t[pos] + m * this._mod[j] + carry;
        t[pos] = prod & MASK;
        carry = Math.floor(prod / BASE);
      }
      addCarry(t, i + this._limbs, carry);
    }
    for (let i = 0; i < this._limbs; i++) out[i] = t[i + this._limbs];
    this._condSubModInto(out, t[this._limbs * 2] + t[this._limbs * 2 + 1] * BASE, out);
  }

  private _montEncode(limbs: Limbs): Limbs {
    return this._montMul(limbs, this._r2);
  }

  private _powLimbs(base: Limbs, power: bigint): Limbs {
    let digits = this._powCache.get(power);
    if (digits === undefined) {
      const hex = power.toString(16);
      digits = new Array(hex.length);
      for (let i = 0; i < hex.length; i++) {
        const code = hex.charCodeAt(i);
        digits[i] = code < 58 ? code - 48 : code - 87;
      }
      this._powCache.set(power, digits);
    }
    const table: Limbs[] = new Array(16);
    table[0] = this._oneMontLimbs;
    table[1] = base;
    for (let i = 2; i < 16; i++) table[i] = this._montMul(table[i - 1], base);
    let res = table[0].slice();
    let tmp = new Uint32Array(this._limbs);
    for (const idx of digits) {
      this._montMulInto(res, res, tmp);
      [res, tmp] = [tmp, res];
      this._montMulInto(res, res, tmp);
      [res, tmp] = [tmp, res];
      this._montMulInto(res, res, tmp);
      [res, tmp] = [tmp, res];
      this._montMulInto(res, res, tmp);
      [res, tmp] = [tmp, res];
      if (idx !== 0) {
        this._montMulInto(res, table[idx], tmp);
        [res, tmp] = [tmp, res];
      }
    }
    return res;
  }

  private _fromBigintLimbs(num: bigint): Limbs {
    return this._montEncode(bigintToLimbs(mod(num, this.ORDER), this._limbs, this.BYTES));
  }

  private _fromCanonicalBytes(bytes: Uint8Array, reduce: boolean): Limbs {
    if (reduce || this._modFromBytes) {
      const scalar = this.isLE ? bytesToNumberLE(bytes) : bytesToNumberBE(bytes);
      return this._fromBigintLimbs(mod(scalar, this.ORDER));
    }
    const limbs = this._bytesToLimbs(bytes);
    const { borrow } = subLimbs(limbs, this._mod);
    if (borrow === 0) throw new Error('invalid field element: outside of range 0..ORDER');
    return this._montEncode(limbs);
  }

  private _toLimbs(num: CtInput): Limbs {
    if (typeof num === 'bigint') {
      const cached = this._bigintCache.get(num);
      if (cached !== undefined) return bytesLEToLimbs(cached, this._limbs, this.BYTES);
      const limbs = this._fromBigintLimbs(num);
      this._rememberBigint(num, this._limbsToBytesLE(limbs));
      return limbs;
    }
    return bytesLEToLimbs(num, this._limbs, this.BYTES);
  }

  private _toLimbsInto(num: CtInput, out: Limbs): void {
    if (typeof num === 'bigint') {
      let cached = this._bigintCache.get(num);
      if (cached === undefined) {
        const limbs = this._fromBigintLimbs(num);
        this._rememberBigint(num, this._limbsToBytesLE(limbs));
        out.set(limbs);
        return;
      }
      bytesLEToLimbsInto(cached, out, this.BYTES);
    } else {
      bytesLEToLimbsInto(num, out, this.BYTES);
    }
  }

  private _toBytesLE(limbs: Limbs): Uint8Array {
    return this._limbsToBytesLE(this._condSubMod(limbs));
  }

  private _rememberBigint(num: bigint, bytesLE: Uint8Array): void {
    if (this._bigintCache.size >= BIGINT_CACHE_MAX) this._bigintCache.clear();
    this._bigintCache.set(num, copyBytes(bytesLE));
  }

  private _normalizeInputBytes(bytes: Uint8Array): Uint8Array {
    const { _lengths: allowedLengths, BYTES, isLE } = this;
    if (allowedLengths) {
      if (bytes.length < 1 || !allowedLengths.includes(bytes.length) || bytes.length > BYTES) {
        throw new Error(
          'Field.fromBytes: expected ' + allowedLengths + ' bytes, got ' + bytes.length
        );
      }
      const padded = new Uint8Array(BYTES);
      padded.set(bytes, isLE ? 0 : padded.length - bytes.length);
      return padded;
    }
    if (bytes.length !== BYTES)
      throw new Error('Field.fromBytes: expected ' + BYTES + ' bytes, got ' + bytes.length);
    return bytes;
  }

  create(num: CtInput): Uint8Array {
    if (typeof num === 'bigint') return this.fromBigint(num);
    return this.fromBytes(num, true);
  }

  isValid(num: CtInput): boolean {
    if (typeof num === 'bigint') return _0n <= num && num < this.ORDER;
    bytesLEToLimbs(num, this._limbs, this.BYTES);
    return true;
  }

  is0(num: CtInput): boolean {
    if (typeof num === 'bigint') return num === _0n;
    num = abytes(num, this.BYTES, 'field element');
    let acc = 0;
    for (let i = 0; i < this.BYTES; i++) acc |= num[i];
    return acc === 0;
  }

  isValidNot0(num: CtInput): boolean {
    return !this.is0(num) && this.isValid(num);
  }

  isOdd(num: CtInput): boolean {
    if (typeof num === 'bigint') return (num & _1n) === _1n;
    bytesLEToLimbsInto(num, this._a, this.BYTES);
    this._montMulInto(this._a, this._oneLimbs, this._c);
    return !!(this._c[0] & 1);
  }

  neg(num: CtInput): Uint8Array {
    this._toLimbsInto(num, this._a);
    this._subModInto(new Uint32Array(this._limbs), this._a, this._c);
    return this._limbsToBytesLE(this._c);
  }

  inv(num: CtInput): Uint8Array {
    if (this.is0(num)) throw new Error('invert: expected non-zero number');
    return this.pow(num, this.ORDER - _2n);
  }

  sqrt(num: CtInput): Uint8Array {
    return this._sqrt(this as IField<Uint8Array>, this._toBytesLE(this._toLimbs(num)));
  }

  sqr(num: CtInput): Uint8Array {
    this._toLimbsInto(num, this._a);
    this._montMulInto(this._a, this._a, this._c);
    return this._limbsToBytesLE(this._c);
  }

  eql(lhs: CtInput, rhs: CtInput): boolean {
    const a = this._toBytesLE(this._toLimbs(lhs));
    const b = this._toBytesLE(this._toLimbs(rhs));
    let diff = 0;
    for (let i = 0; i < this.BYTES; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  add(lhs: CtInput, rhs: CtInput): Uint8Array {
    this._toLimbsInto(lhs, this._a);
    this._toLimbsInto(rhs, this._b);
    this._addModInto(this._a, this._b, this._c);
    return this._limbsToBytesLE(this._c);
  }

  sub(lhs: CtInput, rhs: CtInput): Uint8Array {
    this._toLimbsInto(lhs, this._a);
    this._toLimbsInto(rhs, this._b);
    this._subModInto(this._a, this._b, this._c);
    return this._limbsToBytesLE(this._c);
  }

  mul(lhs: CtInput, rhs: CtInput): Uint8Array {
    this._toLimbsInto(lhs, this._a);
    this._toLimbsInto(rhs, this._b);
    this._montMulInto(this._a, this._b, this._c);
    return this._limbsToBytesLE(this._c);
  }

  pow(lhs: CtInput, power: CtInput): Uint8Array {
    power = typeof power === 'bigint' ? power : this.toBigint(power);
    if (power < _0n) throw new Error('invalid exponent, negatives unsupported');
    if (power === _0n) return this.ONE;
    if (power === _1n) return this._toBytesLE(this._toLimbs(lhs));
    return this._limbsToBytesLE(this._powLimbs(this._toLimbs(lhs), power));
  }

  div(lhs: CtInput, rhs: CtInput): Uint8Array {
    return this.mul(lhs, this.inv(rhs));
  }

  sqrN(num: CtInput): Uint8Array {
    return this.sqr(num);
  }

  addN(lhs: CtInput, rhs: CtInput): Uint8Array {
    return this.add(lhs, rhs);
  }

  subN(lhs: CtInput, rhs: CtInput): Uint8Array {
    return this.sub(lhs, rhs);
  }

  mulN(lhs: CtInput, rhs: CtInput): Uint8Array {
    return this.mul(lhs, rhs);
  }

  invertBatch(lst: Uint8Array[]): Uint8Array[] {
    return FpInvertBatch(this as IField<Uint8Array>, lst);
  }

  toBytes(num: CtInput): Uint8Array {
    if (typeof num === 'bigint') {
      const bytes = this.isLE
        ? numberToBytesLE(mod(num, this.ORDER), this.BYTES)
        : numberToBytesBE(mod(num, this.ORDER), this.BYTES);
      return bytes;
    }
    bytesLEToLimbsInto(num, this._a, this.BYTES);
    this._montMulInto(this._a, this._oneLimbs, this._c);
    return this._limbsToPublicBytes(this._c);
  }

  fromBytes(bytes: TArg<Uint8Array>, skipValidation = false): Uint8Array {
    bytes = this._normalizeInputBytes(abytes(bytes, undefined, 'Field.fromBytes'));
    return this._toBytesLE(this._fromCanonicalBytes(bytes, !!skipValidation));
  }

  cmov(a: Uint8Array, b: Uint8Array, condition: boolean): Uint8Array {
    abool(condition, 'condition');
    a = abytes(a, this.BYTES, 'field element');
    b = abytes(b, this.BYTES, 'field element');
    const out = new Uint8Array(this.BYTES);
    const mask = -Number(condition);
    for (let i = 0; i < this.BYTES; i++) out[i] = (a[i] & ~mask) | (b[i] & mask);
    return out;
  }

  fromBigint(num: bigint): Uint8Array {
    let cached = this._bigintCache.get(num);
    if (cached === undefined) {
      cached = this._toBytesLE(this._fromBigintLimbs(num));
      this._rememberBigint(num, cached);
    }
    return copyBytes(cached);
  }

  toBigint(num: CtInput): bigint {
    const bytes = this.toBytes(num);
    const out = this.isLE ? bytesToNumberLE(bytes) : bytesToNumberBE(bytes);
    if (typeof num !== 'bigint') this._rememberBigint(out, num);
    return out;
  }
}

Object.freeze(_FieldCt.prototype);

/**
 * Creates a fixed-width byte-array prime field for odd moduli.
 * Field elements are internal Montgomery byte arrays; use `toBytes()` for canonical encoding.
 */
export function FieldCt(ORDER: bigint, opts: CtFieldOpts = {}): TRet<Readonly<CtField>> {
  return new _FieldCt(ORDER, opts) as TRet<Readonly<CtField>>;
}

/** Bigint-compatible field facade backed by {@link FieldCt}. */
export type CtFieldBigint = IField<bigint> &
  Required<Pick<IField<bigint>, 'isOdd'>> & {
    readonly ct: Readonly<CtField>;
    readonly _lengths?: readonly number[];
  };

class _FieldCtBigint implements CtFieldBigint {
  readonly ct: Readonly<CtField>;
  readonly ORDER: bigint;
  readonly BYTES: number;
  readonly BITS: number;
  readonly isLE: boolean;
  readonly ZERO = _0n;
  readonly ONE = _1n;
  readonly _lengths?: readonly number[];

  constructor(ORDER: bigint, opts: CtFieldOpts = {}) {
    this.ct = FieldCt(ORDER, opts);
    this.ORDER = ORDER;
    this.BYTES = this.ct.BYTES;
    this.BITS = this.ct.BITS;
    this.isLE = this.ct.isLE;
    this._lengths = this.ct._lengths;
    Object.freeze(this);
  }

  private _isCt(num: unknown): num is Uint8Array {
    return num instanceof Uint8Array;
  }

  private _toCt(num: CtInput): Uint8Array {
    return this._isCt(num) ? num : this.ct.fromBigint(num);
  }

  private _fromCt(num: Uint8Array, asCt: boolean): any {
    return asCt ? num : this.ct.toBigint(num);
  }

  create(num: CtInput): bigint {
    if (this._isCt(num)) return num as unknown as bigint;
    return this.ct.toBigint(this.ct.fromBigint(num));
  }

  isValid(num: CtInput): boolean {
    if (this._isCt(num)) return this.ct.isValid(num);
    if (typeof num !== 'bigint')
      throw new TypeError('invalid field element: expected bigint, got ' + typeof num);
    return _0n <= num && num < this.ORDER;
  }

  is0(num: CtInput): boolean {
    if (this._isCt(num)) return this.ct.is0(num);
    return num === _0n;
  }

  isValidNot0(num: CtInput): boolean {
    return !this.is0(num) && this.isValid(num);
  }

  isOdd(num: CtInput): boolean {
    if (this._isCt(num)) return this.ct.isOdd(num);
    return (num & _1n) === _1n;
  }

  neg(num: CtInput): bigint {
    return this._fromCt(this.ct.neg(this._toCt(num)), this._isCt(num));
  }

  inv(num: CtInput): bigint {
    return this._fromCt(this.ct.inv(this._toCt(num)), this._isCt(num));
  }

  sqrt(num: CtInput): bigint {
    return this._fromCt(this.ct.sqrt(this._toCt(num)), this._isCt(num));
  }

  sqr(num: CtInput): bigint {
    return this._fromCt(this.ct.sqr(this._toCt(num)), this._isCt(num));
  }

  eql(lhs: CtInput, rhs: CtInput): boolean {
    if (this._isCt(lhs) || this._isCt(rhs)) return this.ct.eql(this._toCt(lhs), this._toCt(rhs));
    return lhs === rhs;
  }

  add(lhs: CtInput, rhs: CtInput): bigint {
    const asCt = this._isCt(lhs) || this._isCt(rhs);
    return this._fromCt(this.ct.add(this._toCt(lhs), this._toCt(rhs)), asCt);
  }

  sub(lhs: CtInput, rhs: CtInput): bigint {
    const asCt = this._isCt(lhs) || this._isCt(rhs);
    return this._fromCt(this.ct.sub(this._toCt(lhs), this._toCt(rhs)), asCt);
  }

  mul(lhs: CtInput, rhs: CtInput): bigint {
    const asCt = this._isCt(lhs) || this._isCt(rhs);
    return this._fromCt(this.ct.mul(this._toCt(lhs), this._toCt(rhs)), asCt);
  }

  pow(lhs: CtInput, power: CtInput): bigint {
    return this._fromCt(this.ct.pow(this._toCt(lhs), power), this._isCt(lhs));
  }

  div(lhs: CtInput, rhs: CtInput): bigint {
    const asCt = this._isCt(lhs) || this._isCt(rhs);
    return this._fromCt(this.ct.div(this._toCt(lhs), this._toCt(rhs)), asCt);
  }

  sqrN(num: CtInput): bigint {
    return this.sqr(num);
  }

  addN(lhs: CtInput, rhs: CtInput): bigint {
    return this.add(lhs, rhs);
  }

  subN(lhs: CtInput, rhs: CtInput): bigint {
    return this.sub(lhs, rhs);
  }

  mulN(lhs: CtInput, rhs: CtInput): bigint {
    return this.mul(lhs, rhs);
  }

  invertBatch(lst: CtInput[]): bigint[] {
    if (lst.some((i) => this._isCt(i)))
      return this.ct.invertBatch(lst.map((i) => this._toCt(i))) as unknown as bigint[];
    return FpInvertBatch(this as IField<bigint>, lst as bigint[]);
  }

  toBytes(num: CtInput): Uint8Array {
    if (this._isCt(num)) return this.ct.toBytes(num);
    // Match the bigint Field helper: this serializer is intentionally raw and does not reduce.
    // Some Edwards decoding paths keep non-canonical coordinates until validation is complete.
    return this.isLE ? numberToBytesLE(num, this.BYTES) : numberToBytesBE(num, this.BYTES);
  }

  fromBytes(bytes: TArg<Uint8Array>, skipValidation = false): bigint {
    return this.ct.toBigint(this.ct.fromBytes(bytes, skipValidation));
  }

  cmov(a: CtInput, b: CtInput, condition: boolean): bigint {
    const asCt = this._isCt(a) || this._isCt(b);
    return this._fromCt(this.ct.cmov(this._toCt(a), this._toCt(b), condition), asCt);
  }
}

Object.freeze(_FieldCtBigint.prototype);

/**
 * Creates a bigint-compatible field that performs arithmetic through the byte-array field backend.
 */
export function FieldCtBigint(
  ORDER: bigint,
  opts: CtFieldOpts = {}
): TRet<Readonly<CtFieldBigint>> {
  return new _FieldCtBigint(ORDER, opts) as TRet<Readonly<CtFieldBigint>>;
}
