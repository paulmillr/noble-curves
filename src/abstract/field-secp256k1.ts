/**
 * secp256k1 prime-field implementation backed by WebAssembly.
 *
 * This uses the reduction shape from libsecp256k1: p = 2^256 - 2^32 - 977,
 * so high limbs are folded with 2^256 = 2^32 + 977 instead of using generic
 * Montgomery reduction.
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import {
  abool,
  abytes,
  bytesToNumberBE,
  numberToBytesBE,
  type TArg,
  type TRet,
} from '../utils.ts';
import { FpInvertBatch, FpSqrt, mod, type IField } from './modular.ts';
import createFieldWasm from './field-wasm-core.ts';
import type { WasmField } from './field-wasm.ts';

const ORDER = /* @__PURE__ */ BigInt(
  '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f'
);
const BYTES = 32;
const BITS = 256;
const _0n = /* @__PURE__ */ BigInt(0);
const _1n = /* @__PURE__ */ BigInt(1);
const _2n = /* @__PURE__ */ BigInt(2);
const P_RAW = /* @__PURE__ */ Uint8Array.of(
  0x2f,
  0xfc,
  0xff,
  0xff,
  0xfe,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff
);

type WasmInput = Uint8Array | bigint;
type K1Wasm = {
  segments: {
    a: Uint8Array;
    b: Uint8Array;
    out: Uint8Array;
    exp: Uint8Array;
    one: Uint8Array;
  };
  k1Add(): void;
  k1Sub(): void;
  k1Mul(): void;
  k1Sqr(): void;
  k1Pow(bits: number): void;
};

function copyBytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes);
}

function bigintToBytesLE(num: bigint): Uint8Array {
  const out = new Uint8Array(BYTES);
  for (let i = 0; i < BYTES; i++) {
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

function rawToPublic(raw: Uint8Array): Uint8Array {
  const out = new Uint8Array(BYTES);
  for (let i = 0; i < BYTES; i++) out[BYTES - 1 - i] = raw[i];
  return out;
}

function publicToRaw(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(BYTES);
  for (let i = 0; i < BYTES; i++) out[i] = bytes[BYTES - 1 - i];
  return out;
}

function rawGteOrder(raw: Uint8Array): boolean {
  for (let i = BYTES - 1; i >= 0; i--) {
    if (raw[i] > P_RAW[i]) return true;
    if (raw[i] < P_RAW[i]) return false;
  }
  return true;
}

class _FieldK1 implements WasmField {
  readonly ORDER = ORDER;
  readonly BYTES = BYTES;
  readonly BITS = BITS;
  readonly isLE = false;
  private readonly _wasm: K1Wasm = createFieldWasm(
    undefined as any,
    undefined as any
  ) as unknown as K1Wasm;
  private readonly _a: Uint8Array;
  private readonly _b: Uint8Array;
  private readonly _out: Uint8Array;
  private readonly _exp: Uint8Array;
  private readonly _bigintCache = new Map<bigint, Uint8Array>();
  readonly ZERO = new Uint8Array(BYTES);
  readonly ONE = bigintToBytesLE(_1n);

  constructor() {
    const segments = this._wasm.segments;
    this._a = segments.a;
    this._b = segments.b;
    this._out = segments.out;
    this._exp = segments.exp;
    segments.one.set(this.ONE);
    for (const num of [_0n, _1n, _2n, BigInt(3), BigInt(4), BigInt(7), BigInt(8), BigInt(27)])
      this._bigintCache.set(num, this._fromBigintNoCache(num));
    Object.freeze(this);
  }

  private _copyOut(): Uint8Array {
    return new Uint8Array(this._out.subarray(0, BYTES));
  }

  private _assertElement(bytes: Uint8Array, title = 'field element'): Uint8Array {
    return abytes(bytes, BYTES, title);
  }

  private _fromBigintNoCache(num: bigint): Uint8Array {
    return bigintToBytesLE(mod(num, ORDER));
  }

  private _fromBigintCached(num: bigint): Uint8Array {
    let cached = this._bigintCache.get(num);
    if (cached === undefined) {
      cached = this._fromBigintNoCache(num);
      if (this._bigintCache.size < 4096) this._bigintCache.set(num, cached);
    }
    return cached;
  }

  private _toElement(num: WasmInput): Uint8Array {
    if (typeof num === 'bigint') return this._fromBigintCached(num);
    return this._assertElement(num);
  }

  private _setA(num: WasmInput): void {
    this._a.set(this._toElement(num));
  }

  private _setAB(lhs: WasmInput, rhs: WasmInput): void {
    this._a.set(this._toElement(lhs));
    this._b.set(this._toElement(rhs));
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

  create(num: WasmInput): Uint8Array {
    if (typeof num === 'bigint') return this.fromBigint(num);
    return this.fromBytes(num, true);
  }

  isValid(num: WasmInput): boolean {
    if (typeof num === 'bigint') return _0n <= num && num < ORDER;
    this._assertElement(num);
    return true;
  }

  is0(num: WasmInput): boolean {
    if (typeof num === 'bigint') return num === _0n;
    num = this._assertElement(num);
    let acc = 0;
    for (let i = 0; i < BYTES; i++) acc |= num[i];
    return acc === 0;
  }

  isValidNot0(num: WasmInput): boolean {
    return !this.is0(num) && this.isValid(num);
  }

  isOdd(num: WasmInput): boolean {
    if (typeof num === 'bigint') return (num & _1n) === _1n;
    return !!(this._assertElement(num)[0] & 1);
  }

  neg(num: WasmInput): Uint8Array {
    this._a.fill(0, 0, BYTES);
    this._b.set(this._toElement(num));
    this._wasm.k1Sub();
    return this._copyOut();
  }

  inv(num: WasmInput): Uint8Array {
    if (this.is0(num)) throw new Error('invert: expected non-zero number');
    return this.pow(num, ORDER - _2n);
  }

  sqrt(num: WasmInput): Uint8Array {
    return FpSqrt(ORDER)(this as IField<Uint8Array>, this._toElement(num));
  }

  sqr(num: WasmInput): Uint8Array {
    this._setA(num);
    this._wasm.k1Sqr();
    return this._copyOut();
  }

  eql(lhs: WasmInput, rhs: WasmInput): boolean {
    const a = this._toElement(lhs);
    const b = this._toElement(rhs);
    let diff = 0;
    for (let i = 0; i < BYTES; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  add(lhs: WasmInput, rhs: WasmInput): Uint8Array {
    this._setAB(lhs, rhs);
    this._wasm.k1Add();
    return this._copyOut();
  }

  sub(lhs: WasmInput, rhs: WasmInput): Uint8Array {
    this._setAB(lhs, rhs);
    this._wasm.k1Sub();
    return this._copyOut();
  }

  mul(lhs: WasmInput, rhs: WasmInput): Uint8Array {
    this._setAB(lhs, rhs);
    this._wasm.k1Mul();
    return this._copyOut();
  }

  pow(lhs: WasmInput, power: WasmInput): Uint8Array {
    if (typeof power !== 'bigint') power = this.toBigint(power);
    if (power < _0n) throw new Error('invalid exponent, negatives unsupported');
    if (power === _0n) return this.ONE;
    const bits = power.toString(2).length;
    if (bits > BITS) return this._powJs(lhs, power);
    this._setA(lhs);
    this._exp.fill(0, 0, BYTES);
    this._exp.set(bigintToBytesLE(power));
    this._wasm.k1Pow(bits);
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
    if (typeof num === 'bigint') return numberToBytesBE(num, BYTES);
    return rawToPublic(this._assertElement(num));
  }

  fromBytes(bytes: TArg<Uint8Array>, skipValidation = false): Uint8Array {
    bytes = abytes(bytes, BYTES, 'Field.fromBytes');
    if (skipValidation) return this.fromBigint(bytesToNumberBE(bytes));
    const raw = publicToRaw(bytes);
    if (rawGteOrder(raw)) throw new Error('invalid field element: outside of range 0..ORDER');
    return raw;
  }

  cmov(a: Uint8Array, b: Uint8Array, condition: boolean): Uint8Array {
    abool(condition, 'condition');
    a = this._assertElement(a);
    b = this._assertElement(b);
    const out = new Uint8Array(BYTES);
    const mask = -Number(condition);
    for (let i = 0; i < BYTES; i++) out[i] = (a[i] & ~mask) | (b[i] & mask);
    return out;
  }

  fromBigint(num: bigint): Uint8Array {
    return copyBytes(this._fromBigintCached(num));
  }

  toBigint(num: WasmInput): bigint {
    if (typeof num === 'bigint') return mod(num, ORDER);
    return bytesLEToBigint(this._assertElement(num));
  }
}

Object.freeze(_FieldK1.prototype);

/**
 * Creates the secp256k1 base field backed by prime-shape WASM arithmetic.
 */
export function FieldSecp256k1(): TRet<Readonly<WasmField>> {
  return new _FieldK1() as TRet<Readonly<WasmField>>;
}
