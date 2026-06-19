import type {
  WeierstrassMultiply,
  WeierstrassPoint,
  WeierstrassPointCons,
} from '../abstract/weierstrass.ts';
import { SECP256K1_WASM_BASE64, SECP256K1_WASM_OFFSETS } from './secp256k1.wasm.ts';

const _0n = /* @__PURE__ */ BigInt(0);
const _1n = /* @__PURE__ */ BigInt(1);
const _2n = /* @__PURE__ */ BigInt(2);
const _64n = /* @__PURE__ */ BigInt(64);
const U64_MASK = /* @__PURE__ */ ((BigInt(1) << _64n) - BigInt(1));
const P = /* @__PURE__ */ BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f');
const N = /* @__PURE__ */ BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
const BETA = /* @__PURE__ */ BigInt('0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee');
const ENDO_BASIS = [
  [BigInt('0x3086d221a7d46bcde86c90e49284eb15'), -BigInt('0xe4437ed6010e88286f547fa90abfe4c3')],
  [BigInt('0x114ca50f7a8e2f3f657c1108d9d44cfd8'), BigInt('0x3086d221a7d46bcde86c90e49284eb15')],
] as const;
const ENDO_MAX = /* @__PURE__ */ (_1n << BigInt(128));

type WasmExports = {
  memory: WebAssembly.Memory;
  multiply: () => void;
};

let wasm: WasmExports | undefined | null;
let wasmBytes: Uint8Array | undefined;

function base64ToBytes(str: string): Uint8Array {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const pad = str.endsWith('==') ? 2 : str.endsWith('=') ? 1 : 0;
  const out = new Uint8Array((str.length * 3) / 4 - pad);
  let bits = 0;
  let buffer = 0;
  let pos = 0;
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    if (c === 61) break; // =
    const value = chars.indexOf(str[i]);
    if (value < 0) throw new Error('invalid base64');
    buffer = (buffer << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[pos++] = (buffer >> bits) & 0xff;
    }
  }
  return out;
}

function getWasmBytes(): Uint8Array {
  if (wasmBytes === undefined) wasmBytes = base64ToBytes(SECP256K1_WASM_BASE64);
  return wasmBytes;
}

function getWasm(): WasmExports | undefined {
  if (wasm !== undefined) return wasm || undefined;
  try {
    const mod = new WebAssembly.Module(getWasmBytes().buffer as ArrayBuffer);
    const instance = new WebAssembly.Instance(mod, {}) as WebAssembly.Instance & {
      exports: WasmExports;
    };
    wasm = instance.exports;
  } catch {
    wasm = null;
  }
  return wasm || undefined;
}

function writeBig(dataview: DataView, pos: number, value: bigint, words: number) {
  let v = value;
  for (let i = 0; i < words; i++) {
    dataview.setBigUint64(pos + i * 8, v & U64_MASK, true);
    v >>= _64n;
  }
}

function readBig(dataview: DataView, pos: number, words: number): bigint {
  let value = _0n;
  for (let i = words - 1; i >= 0; i--) value = (value << _64n) | dataview.getBigUint64(pos + i * 8, true);
  return value;
}

function modP(value: bigint): bigint {
  const res = value % P;
  return res >= _0n ? res : res + P;
}

function negY(value: bigint): bigint {
  return value === _0n ? _0n : P - value;
}

const divNearest = (num: bigint, den: bigint) => (num + (num >= _0n ? den : -den) / _2n) / den;

function splitEndoScalar(k: bigint) {
  const [[a1, b1], [a2, b2]] = ENDO_BASIS;
  const c1 = divNearest(b2 * k, N);
  const c2 = divNearest(-b1 * k, N);
  let k1 = k - c1 * a1 - c2 * a2;
  let k2 = -c1 * b1 - c2 * b2;
  const k1neg = k1 < _0n;
  const k2neg = k2 < _0n;
  if (k1neg) k1 = -k1;
  if (k2neg) k2 = -k2;
  if (k1 >= ENDO_MAX || k2 >= ENDO_MAX) throw new Error('splitScalar (endomorphism): failed for k');
  return { k1neg, k1, k2neg, k2 };
}

function writePointAt(dataview: DataView, pointOffset: number, x: bigint, y: bigint, z: bigint) {
  const { point: pointPos } = SECP256K1_WASM_OFFSETS;
  const pos = pointPos + pointOffset * 8;
  writeBig(dataview, pos, x, 4);
  writeBig(dataview, pos + 32, y, 4);
  writeBig(dataview, pos + 64, z, 4);
}

function writeSplit(dataview: DataView, point: WeierstrassPoint<bigint>, scalar: bigint) {
  const { k1neg, k1, k2neg, k2 } = splitEndoScalar(scalar);
  const x2 = modP(point.X * BETA);
  writePointAt(dataview, 0, point.X, k1neg ? negY(point.Y) : point.Y, point.Z);
  writePointAt(dataview, 12, x2, k2neg ? negY(point.Y) : point.Y, point.Z);
  writeBig(dataview, SECP256K1_WASM_OFFSETS.scalar, k1, 4);
  writeBig(dataview, SECP256K1_WASM_OFFSETS.scalar + 32, k2, 4);
}

function readPoint(dataview: DataView, Point: WeierstrassPointCons<bigint>) {
  const { out } = SECP256K1_WASM_OFFSETS;
  const X = readBig(dataview, out, 4);
  const Y = readBig(dataview, out + 32, 4);
  const Z = readBig(dataview, out + 64, 4);
  return new Point(X, Y, Z);
}

export const secp256k1WasmMultiply: WeierstrassMultiply<bigint> = (Point, point, scalar) => {
  if (point.X === _0n && point.Z === _0n) return new Point(_0n, _1n, _0n);
  const w = getWasm();
  if (!w) return;
  const dataview = new DataView(w.memory.buffer);
  writeSplit(dataview, point, scalar);
  w.multiply();
  return readPoint(dataview, Point);
};
