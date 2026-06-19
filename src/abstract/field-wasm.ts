/**
 * Fixed-width byte-array field implementation backed by WebAssembly.
 *
 * Elements are little-endian Montgomery residues stored in a fixed internal limb width.
 * Public encodings use the field's configured byte length and endianness.
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
import createFieldWasm from './field-wasm-core.ts';

const WORD_BITS = 32;
const WORD_BYTES = 4;
const MAX_LIMBS = 17;
const MAX_BITS = MAX_LIMBS * WORD_BITS;
const _0n = /* @__PURE__ */ BigInt(0);
const _1n = /* @__PURE__ */ BigInt(1);
const _2n = /* @__PURE__ */ BigInt(2);
const U32_MOD = /* @__PURE__ */ _1n << BigInt(32);
const U32_MASK = /* @__PURE__ */ U32_MOD - _1n;

type WasmInput = Uint8Array | bigint;
type FieldWasmCore = {
  segments: {
    a: Uint8Array;
    b: Uint8Array;
    out: Uint8Array;
    exp: Uint8Array;
    one: Uint8Array;
    mod: Uint8Array;
  };
  add(limbs: number): void;
  sub(limbs: number): void;
  mul(limbs: number, nInv: number): void;
  pow(limbs: number, nInv: number, bits: number): void;
};

export type WasmFieldOpts = Partial<{
  isLE: boolean;
  BITS: number;
  allowedLengths: readonly number[];
  modFromBytes: boolean;
}>;

/** Byte-array prime field with bigint conversion helpers for legacy boundaries. */
export type WasmField = Omit<
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
  create(num: WasmInput): Uint8Array;
  isValid(num: WasmInput): boolean;
  is0(num: WasmInput): boolean;
  isValidNot0(num: WasmInput): boolean;
  isOdd(num: WasmInput): boolean;
  neg(num: WasmInput): Uint8Array;
  inv(num: WasmInput): Uint8Array;
  sqrt(num: WasmInput): Uint8Array;
  sqr(num: WasmInput): Uint8Array;
  eql(lhs: WasmInput, rhs: WasmInput): boolean;
  add(lhs: WasmInput, rhs: WasmInput): Uint8Array;
  sub(lhs: WasmInput, rhs: WasmInput): Uint8Array;
  mul(lhs: WasmInput, rhs: WasmInput): Uint8Array;
  pow(lhs: WasmInput, power: WasmInput): Uint8Array;
  div(lhs: WasmInput, rhs: WasmInput): Uint8Array;
  addN(lhs: WasmInput, rhs: WasmInput): Uint8Array;
  subN(lhs: WasmInput, rhs: WasmInput): Uint8Array;
  mulN(lhs: WasmInput, rhs: WasmInput): Uint8Array;
  sqrN(num: WasmInput): Uint8Array;
  toBytes(num: WasmInput): Uint8Array;
  /** Convert a bigint into an internal Montgomery field element. */
  fromBigint(num: bigint): Uint8Array;
  /** Convert an internal Montgomery field element into a bigint. */
  toBigint(num: WasmInput): bigint;
};

function copyBytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes);
}

function invert32(num: number): number {
  let t = _0n;
  let newT = _1n;
  let r = U32_MOD;
  let newR = BigInt(num >>> 0);
  while (newR !== _0n) {
    const q = r / newR;
    const nextT = t - q * newT;
    t = newT;
    newT = nextT;
    const nextR = r - q * newR;
    r = newR;
    newR = nextR;
  }
  return Number(t & U32_MASK);
}

function bigintToBytesLE(num: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    out[i] = Number(num & BigInt(0xff));
    num >>= BigInt(8);
  }
  return out;
}

function bytesLEToBigint(bytes: Uint8Array): bigint {
  let out = _0n;
  for (let i = bytes.length - 1; i >= 0; i--) out = (out << BigInt(8)) | BigInt(bytes[i]);
  return out;
}

const WASM_FIELD_SQRT = new WeakMap<object, ReturnType<typeof FpSqrt>>();

class _FieldWasm implements WasmField {
  readonly ORDER: bigint;
  readonly BYTES: number;
  readonly BITS: number;
  readonly isLE: boolean;
  private readonly _limbs: number;
  private readonly _widthBytes: number;
  private readonly _nInv: number;
  private readonly _lengths?: readonly number[];
  private readonly _modFromBytes: boolean;
  private readonly _wasm: FieldWasmCore = createFieldWasm(
    undefined as any,
    undefined as any
  ) as unknown as FieldWasmCore;
  private readonly _a: Uint8Array;
  private readonly _b: Uint8Array;
  private readonly _out: Uint8Array;
  private readonly _exp: Uint8Array;
  private readonly _modRaw: Uint8Array;
  private readonly _r2: Uint8Array;
  private readonly _oneRaw: Uint8Array;
  private readonly _one: Uint8Array;
  private readonly _bigintCache = new Map<bigint, Uint8Array>();

  constructor(ORDER: bigint, opts: WasmFieldOpts = {}) {
    if (ORDER <= _1n) throw new Error('invalid field: expected ORDER > 1, got ' + ORDER);
    if ((ORDER & _1n) === _0n) throw new Error('FieldWasm: expected odd order');
    const { nBitLength, nByteLength } = nLength(ORDER, opts.BITS);
    if (nBitLength > MAX_BITS)
      throw new Error('FieldWasm: expected ORDER of <= ' + MAX_BITS + ' bits');
    this.ORDER = ORDER;
    this.BITS = nBitLength;
    this.BYTES = nByteLength;
    this.isLE = opts.isLE === true;
    this._limbs = Math.ceil(nBitLength / WORD_BITS);
    this._widthBytes = this._limbs * WORD_BYTES;
    this._lengths = opts.allowedLengths ? Object.freeze(opts.allowedLengths.slice()) : undefined;
    this._modFromBytes = opts.modFromBytes === true;
    const segments = this._wasm.segments;
    this._a = segments.a;
    this._b = segments.b;
    this._out = segments.out;
    this._exp = segments.exp;
    this._modRaw = bigintToBytesLE(ORDER, this._widthBytes);
    segments.mod.set(this._modRaw);
    this._nInv = Number(-BigInt(invert32(Number(ORDER & U32_MASK))) & U32_MASK);
    const r2 = (_1n << BigInt(WORD_BITS * this._limbs * 2)) % ORDER;
    this._r2 = bigintToBytesLE(r2, this._widthBytes);
    this._oneRaw = bigintToBytesLE(_1n, this._widthBytes);
    this._one = this._toMont(this._oneRaw);
    segments.one.set(this._one);
    for (const num of [_0n, _1n, _2n, BigInt(3), BigInt(4), BigInt(7), BigInt(8), BigInt(27)])
      this._bigintCache.set(num, this._fromBigintNoCache(num));
    Object.freeze(this);
  }

  get ZERO(): Uint8Array {
    return new Uint8Array(this._widthBytes);
  }

  get ONE(): Uint8Array {
    return copyBytes(this._one);
  }

  private _copyOut(): Uint8Array {
    return new Uint8Array(this._out.subarray(0, this._widthBytes));
  }

  private _assertElement(bytes: Uint8Array, title = 'field element'): Uint8Array {
    return abytes(bytes, this._widthBytes, title);
  }

  private _setA(num: WasmInput): void {
    this._a.set(this._toElement(num));
  }

  private _setAB(lhs: WasmInput, rhs: WasmInput): void {
    const a = this._toElement(lhs);
    const b = this._toElement(rhs);
    this._a.set(a);
    this._b.set(b);
  }

  private _toElement(num: WasmInput): Uint8Array {
    if (typeof num === 'bigint') return this.fromBigint(num);
    return this._assertElement(num);
  }

  private _toMont(raw: Uint8Array): Uint8Array {
    this._a.set(raw);
    this._b.set(this._r2);
    this._wasm.mul(this._limbs, this._nInv);
    return this._copyOut();
  }

  private _fromMont(num: WasmInput): Uint8Array {
    this._setA(num);
    this._b.set(this._oneRaw);
    this._wasm.mul(this._limbs, this._nInv);
    return this._copyOut();
  }

  private _fromBigintNoCache(num: bigint): Uint8Array {
    return this._toMont(bigintToBytesLE(mod(num, this.ORDER), this._widthBytes));
  }

  private _fromBigintCached(num: bigint): Uint8Array {
    let cached = this._bigintCache.get(num);
    if (cached === undefined) {
      cached = this._fromBigintNoCache(num);
      if (this._bigintCache.size < 4096) this._bigintCache.set(num, cached);
    }
    return cached;
  }

  private _setBigintA(num: bigint): void {
    this._a.set(this._fromBigintCached(num));
  }

  private _setBigintAB(lhs: bigint, rhs: bigint): void {
    const a = this._fromBigintCached(lhs);
    const b = this._fromBigintCached(rhs);
    this._a.set(a);
    this._b.set(b);
  }

  private _outToBigint(): bigint {
    this._a.set(this._out.subarray(0, this._widthBytes));
    this._b.set(this._oneRaw);
    this._wasm.mul(this._limbs, this._nInv);
    return bytesLEToBigint(this._out.subarray(0, this._widthBytes));
  }

  private _rawToPublic(raw: Uint8Array): Uint8Array {
    const out = new Uint8Array(this.BYTES);
    if (this.isLE) {
      out.set(raw.subarray(0, this.BYTES));
    } else {
      for (let i = 0; i < this.BYTES; i++) out[this.BYTES - 1 - i] = raw[i];
    }
    return out;
  }

  private _publicToRaw(bytes: Uint8Array): Uint8Array {
    const out = new Uint8Array(this._widthBytes);
    if (this.isLE) {
      out.set(bytes);
    } else {
      for (let i = 0; i < this.BYTES; i++) out[i] = bytes[this.BYTES - 1 - i];
    }
    return out;
  }

  private _rawGteOrder(raw: Uint8Array): boolean {
    for (let i = this._widthBytes - 1; i >= 0; i--) {
      if (raw[i] > this._modRaw[i]) return true;
      if (raw[i] < this._modRaw[i]) return false;
    }
    return true;
  }

  private _publicToBigint(bytes: Uint8Array): bigint {
    return this.isLE ? bytesToNumberLE(bytes) : bytesToNumberBE(bytes);
  }

  create(num: WasmInput): Uint8Array {
    if (typeof num === 'bigint') return this.fromBigint(num);
    return this.fromBytes(num, true);
  }

  isValid(num: WasmInput): boolean {
    if (typeof num === 'bigint') return _0n <= num && num < this.ORDER;
    this._assertElement(num);
    return true;
  }

  is0(num: WasmInput): boolean {
    if (typeof num === 'bigint') return num === _0n;
    num = this._assertElement(num);
    let acc = 0;
    for (let i = 0; i < this._widthBytes; i++) acc |= num[i];
    return acc === 0;
  }

  isValidNot0(num: WasmInput): boolean {
    return !this.is0(num) && this.isValid(num);
  }

  isOdd(num: WasmInput): boolean {
    if (typeof num === 'bigint') return (num & _1n) === _1n;
    const raw = this._fromMont(num);
    return !!(raw[0] & 1);
  }

  neg(num: WasmInput): Uint8Array {
    const b = this._toElement(num);
    this._a.fill(0, 0, this._widthBytes);
    this._b.set(b);
    this._wasm.sub(this._limbs);
    return this._copyOut();
  }

  inv(num: WasmInput): Uint8Array {
    if (this.is0(num)) throw new Error('invert: expected non-zero number');
    return this.pow(num, this.ORDER - _2n);
  }

  sqrt(num: WasmInput): Uint8Array {
    let sqrt = WASM_FIELD_SQRT.get(this);
    if (!sqrt) WASM_FIELD_SQRT.set(this, (sqrt = FpSqrt(this.ORDER)));
    return sqrt(this as IField<Uint8Array>, this._toElement(num));
  }

  sqr(num: WasmInput): Uint8Array {
    this._setA(num);
    this._b.set(this._a.subarray(0, this._widthBytes));
    this._wasm.mul(this._limbs, this._nInv);
    return this._copyOut();
  }

  eql(lhs: WasmInput, rhs: WasmInput): boolean {
    const a = this._toElement(lhs);
    const b = this._toElement(rhs);
    let diff = 0;
    for (let i = 0; i < this._widthBytes; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  add(lhs: WasmInput, rhs: WasmInput): Uint8Array {
    this._setAB(lhs, rhs);
    this._wasm.add(this._limbs);
    return this._copyOut();
  }

  sub(lhs: WasmInput, rhs: WasmInput): Uint8Array {
    this._setAB(lhs, rhs);
    this._wasm.sub(this._limbs);
    return this._copyOut();
  }

  mul(lhs: WasmInput, rhs: WasmInput): Uint8Array {
    this._setAB(lhs, rhs);
    this._wasm.mul(this._limbs, this._nInv);
    return this._copyOut();
  }

  private _powJs(lhs: WasmInput, power: bigint): Uint8Array {
    const base = this._toElement(lhs);
    const table = [this.ONE, copyBytes(base)];
    for (let i = 2; i < 16; i++) table[i] = this.mul(table[i - 1], base);
    let res = this.ONE;
    for (const char of power.toString(16)) {
      res = this.sqr(this.sqr(this.sqr(this.sqr(res))));
      const idx = Number.parseInt(char, 16);
      if (idx !== 0) res = this.mul(res, table[idx]);
    }
    return res;
  }

  pow(lhs: WasmInput, power: WasmInput): Uint8Array {
    if (typeof power !== 'bigint') power = this.toBigint(power);
    if (power < _0n) throw new Error('invalid exponent, negatives unsupported');
    if (power === _0n) return this.ONE;
    const bits = power.toString(2).length;
    if (bits > this._limbs * WORD_BITS) return this._powJs(lhs, power);
    this._setA(lhs);
    this._exp.fill(0, 0, this._widthBytes);
    this._exp.set(bigintToBytesLE(power, this._widthBytes));
    this._wasm.pow(this._limbs, this._nInv, bits);
    return this._copyOut();
  }

  div(lhs: WasmInput, rhs: WasmInput): Uint8Array {
    return this.mul(lhs, this.inv(rhs));
  }

  sqrN(num: WasmInput): Uint8Array {
    return this.sqr(num);
  }

  addN(lhs: WasmInput, rhs: WasmInput): Uint8Array {
    return this.add(lhs, rhs);
  }

  subN(lhs: WasmInput, rhs: WasmInput): Uint8Array {
    return this.sub(lhs, rhs);
  }

  mulN(lhs: WasmInput, rhs: WasmInput): Uint8Array {
    return this.mul(lhs, rhs);
  }

  invertBatch(lst: Uint8Array[]): Uint8Array[] {
    return FpInvertBatch(this as IField<Uint8Array>, lst);
  }

  toBytes(num: WasmInput): Uint8Array {
    if (typeof num === 'bigint') {
      return this.isLE ? numberToBytesLE(num, this.BYTES) : numberToBytesBE(num, this.BYTES);
    }
    return this._rawToPublic(this._fromMont(num));
  }

  fromBytes(bytes: TArg<Uint8Array>, skipValidation = false): Uint8Array {
    bytes = abytes(bytes, undefined, 'Field.fromBytes');
    const { _lengths: allowedLengths, BYTES, isLE, ORDER } = this;
    if (allowedLengths) {
      if (bytes.length < 1 || !allowedLengths.includes(bytes.length) || bytes.length > BYTES) {
        throw new Error(
          'Field.fromBytes: expected ' + allowedLengths + ' bytes, got ' + bytes.length
        );
      }
      const padded = new Uint8Array(BYTES);
      padded.set(bytes, isLE ? 0 : padded.length - bytes.length);
      bytes = padded;
    }
    if (bytes.length !== BYTES)
      throw new Error('Field.fromBytes: expected ' + BYTES + ' bytes, got ' + bytes.length);
    if (this._modFromBytes || skipValidation) {
      let scalar = this._publicToBigint(bytes);
      scalar = mod(scalar, ORDER);
      return this.fromBigint(scalar);
    }
    const raw = this._publicToRaw(bytes);
    if (this._rawGteOrder(raw)) throw new Error('invalid field element: outside of range 0..ORDER');
    return this._toMont(raw);
  }

  cmov(a: Uint8Array, b: Uint8Array, condition: boolean): Uint8Array {
    abool(condition, 'condition');
    a = this._assertElement(a);
    b = this._assertElement(b);
    const out = new Uint8Array(this._widthBytes);
    const mask = -Number(condition);
    for (let i = 0; i < this._widthBytes; i++) out[i] = (a[i] & ~mask) | (b[i] & mask);
    return out;
  }

  fromBigint(num: bigint): Uint8Array {
    return copyBytes(this._fromBigintCached(num));
  }

  toBigint(num: WasmInput): bigint {
    if (typeof num === 'bigint') return mod(num, this.ORDER);
    return bytesLEToBigint(this._fromMont(num));
  }

  _bigintNeg(num: bigint): bigint {
    const b = this._fromBigintCached(num);
    this._a.fill(0, 0, this._widthBytes);
    this._b.set(b);
    this._wasm.sub(this._limbs);
    return this._outToBigint();
  }

  _bigintSqr(num: bigint): bigint {
    this._setBigintA(num);
    this._b.set(this._a.subarray(0, this._widthBytes));
    this._wasm.mul(this._limbs, this._nInv);
    return this._outToBigint();
  }

  _bigintAdd(lhs: bigint, rhs: bigint): bigint {
    this._setBigintAB(lhs, rhs);
    this._wasm.add(this._limbs);
    return this._outToBigint();
  }

  _bigintSub(lhs: bigint, rhs: bigint): bigint {
    this._setBigintAB(lhs, rhs);
    this._wasm.sub(this._limbs);
    return this._outToBigint();
  }

  _bigintMul(lhs: bigint, rhs: bigint): bigint {
    this._setBigintAB(lhs, rhs);
    this._wasm.mul(this._limbs, this._nInv);
    return this._outToBigint();
  }

  _bigintPow(lhs: bigint, power: bigint): bigint {
    if (power < _0n) throw new Error('invalid exponent, negatives unsupported');
    if (power === _0n) return _1n;
    const bits = power.toString(2).length;
    if (bits > this._limbs * WORD_BITS) return this.toBigint(this._powJs(lhs, power));
    this._setBigintA(lhs);
    this._exp.fill(0, 0, this._widthBytes);
    this._exp.set(bigintToBytesLE(power, this._widthBytes));
    this._wasm.pow(this._limbs, this._nInv, bits);
    return this._outToBigint();
  }

  _bigintInv(num: bigint): bigint {
    if (mod(num, this.ORDER) === _0n) throw new Error('invert: expected non-zero number');
    return this._bigintPow(num, this.ORDER - _2n);
  }

  _bigintDiv(lhs: bigint, rhs: bigint): bigint {
    return this._bigintMul(lhs, this._bigintInv(rhs));
  }
}

Object.freeze(_FieldWasm.prototype);

/**
 * Creates a fixed-width byte-array prime field for odd moduli up to 544 bits.
 * Field elements are internal Montgomery byte arrays; use `toBytes()` for canonical encoding.
 */
export function FieldWasm(ORDER: bigint, opts: WasmFieldOpts = {}): TRet<Readonly<WasmField>> {
  return new _FieldWasm(ORDER, opts) as TRet<Readonly<WasmField>>;
}

/** Bigint-compatible field facade backed by {@link FieldWasm}. */
export type WasmFieldBigint = IField<bigint> &
  Required<Pick<IField<bigint>, 'isOdd'>> & { readonly wasm: Readonly<WasmField> };

class _FieldWasmBigint implements WasmFieldBigint {
  readonly wasm: Readonly<WasmField>;
  private readonly _wasmi: any;
  private readonly _lengths?: readonly number[];
  readonly ORDER: bigint;
  readonly BYTES: number;
  readonly BITS: number;
  readonly isLE: boolean;
  readonly ZERO = _0n;
  readonly ONE = _1n;

  constructor(ORDER: bigint, opts: WasmFieldOpts = {}) {
    this.wasm = FieldWasm(ORDER, opts);
    this._wasmi = this.wasm as any;
    this._lengths = opts.allowedLengths ? Object.freeze(opts.allowedLengths.slice()) : undefined;
    this.ORDER = ORDER;
    this.BYTES = this.wasm.BYTES;
    this.BITS = this.wasm.BITS;
    this.isLE = this.wasm.isLE;
    Object.freeze(this);
  }

  create(num: bigint): bigint {
    return mod(num, this.ORDER);
  }

  isValid(num: bigint): boolean {
    if (typeof num !== 'bigint')
      throw new TypeError('invalid field element: expected bigint, got ' + typeof num);
    return _0n <= num && num < this.ORDER;
  }

  is0(num: bigint): boolean {
    return num === _0n;
  }

  isValidNot0(num: bigint): boolean {
    return !this.is0(num) && this.isValid(num);
  }

  isOdd(num: bigint): boolean {
    return (num & _1n) === _1n;
  }

  neg(num: bigint): bigint {
    return this._wasmi._bigintNeg(num);
  }

  inv(num: bigint): bigint {
    return this._wasmi._bigintInv(num);
  }

  sqrt(num: bigint): bigint {
    return this.wasm.toBigint(this.wasm.sqrt(num));
  }

  sqr(num: bigint): bigint {
    return this._wasmi._bigintSqr(num);
  }

  eql(lhs: bigint, rhs: bigint): boolean {
    return lhs === rhs;
  }

  add(lhs: bigint, rhs: bigint): bigint {
    return this._wasmi._bigintAdd(lhs, rhs);
  }

  sub(lhs: bigint, rhs: bigint): bigint {
    return this._wasmi._bigintSub(lhs, rhs);
  }

  mul(lhs: bigint, rhs: bigint): bigint {
    return this._wasmi._bigintMul(lhs, rhs);
  }

  pow(lhs: bigint, power: bigint): bigint {
    return this._wasmi._bigintPow(lhs, power);
  }

  div(lhs: bigint, rhs: bigint): bigint {
    return this._wasmi._bigintDiv(lhs, rhs);
  }

  sqrN(num: bigint): bigint {
    return num * num;
  }

  addN(lhs: bigint, rhs: bigint): bigint {
    return lhs + rhs;
  }

  subN(lhs: bigint, rhs: bigint): bigint {
    return lhs - rhs;
  }

  mulN(lhs: bigint, rhs: bigint): bigint {
    return lhs * rhs;
  }

  invertBatch(lst: bigint[]): bigint[] {
    return FpInvertBatch(this, lst);
  }

  toBytes(num: bigint): Uint8Array {
    return this.isLE ? numberToBytesLE(num, this.BYTES) : numberToBytesBE(num, this.BYTES);
  }

  fromBytes(bytes: TArg<Uint8Array>, skipValidation = false): bigint {
    if (skipValidation) {
      bytes = abytes(bytes, undefined, 'Field.fromBytes');
      const { _lengths: allowedLengths, BYTES, isLE } = this;
      if (allowedLengths) {
        if (bytes.length < 1 || !allowedLengths.includes(bytes.length) || bytes.length > BYTES) {
          throw new Error(
            'Field.fromBytes: expected ' + allowedLengths + ' bytes, got ' + bytes.length
          );
        }
        const padded = new Uint8Array(BYTES);
        padded.set(bytes, isLE ? 0 : padded.length - bytes.length);
        bytes = padded;
      }
      if (bytes.length !== BYTES)
        throw new Error('Field.fromBytes: expected ' + BYTES + ' bytes, got ' + bytes.length);
      return isLE ? bytesToNumberLE(bytes) : bytesToNumberBE(bytes);
    }
    return this.wasm.toBigint(this.wasm.fromBytes(bytes, skipValidation));
  }

  cmov(a: bigint, b: bigint, condition: boolean): bigint {
    return this.wasm.toBigint(
      this.wasm.cmov(this.wasm.fromBigint(a), this.wasm.fromBigint(b), condition)
    );
  }
}

Object.freeze(_FieldWasmBigint.prototype);

/**
 * Creates a bigint field facade backed by the WASM byte-array implementation.
 * Operations cross the bigint/byte boundary for compatibility with existing point engines.
 */
export function FieldWasmBigint(
  ORDER: bigint,
  opts: WasmFieldOpts = {}
): TRet<Readonly<WasmFieldBigint>> {
  return new _FieldWasmBigint(ORDER, opts) as TRet<Readonly<WasmFieldBigint>>;
}
