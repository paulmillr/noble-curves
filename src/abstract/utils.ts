/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import * as mod from './modular.js';
const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);

// We accept hex strings besides Uint8Array for simplicity
export type Hex = Uint8Array | string;
// Very few implementations accept numbers, we do it to ease learning curve
export type PrivKey = Hex | bigint;
export type CHash = {
  (message: Uint8Array | string): Uint8Array;
  blockLen: number;
  outputLen: number;
  create(opts?: { dkLen?: number }): any; // For shake
};

// NOTE: these are generic, even if curve is on some polynominal field (bls), it will still have P/n/h
// But generator can be different (Fp2/Fp6 for bls?)
export type BasicCurve<T> = {
  // Field over which we'll do calculations (Fp)
  Fp: mod.Field<T>;
  // Curve order, total count of valid points in the field
  n: bigint;
  // Bit/byte length of curve order
  nBitLength?: number;
  nByteLength?: number;
  // Cofactor
  // NOTE: we can assign default value of 1, but then users will just ignore it, without validating with spec
  // Has not use for now, but nice to have in API
  h: bigint;
  hEff?: bigint; // Number to multiply to clear cofactor
  // Base point (x, y) aka generator point
  Gx: T;
  Gy: T;
  // Wrap private key by curve order (% CURVE.n instead of throwing error)
  wrapPrivateKey?: boolean;
  // Point at infinity is perfectly valid point, but not valid public key.
  // Disabled by default because of compatibility reasons with @noble/secp256k1
  allowInfinityPoint?: boolean;
};

// Bans floats and integers above 2^53-1
export function isPositiveInt(num: any): num is number {
  return typeof num === 'number' && Number.isSafeInteger(num) && num > 0;
}

export function validateOpts<FP, T>(curve: BasicCurve<FP> & T) {
  mod.validateField(curve.Fp);
  for (const i of ['n', 'h'] as const) {
    const val = curve[i];
    if (typeof val !== 'bigint') throw new Error(`Invalid curve param ${i}=${val} (${typeof val})`);
  }
  if (!curve.Fp.isValid(curve.Gx)) throw new Error('Invalid generator X coordinate Fp element');
  if (!curve.Fp.isValid(curve.Gy)) throw new Error('Invalid generator Y coordinate Fp element');

  for (const i of ['nBitLength', 'nByteLength'] as const) {
    const val = curve[i];
    if (val === undefined) continue; // Optional
    if (!isPositiveInt(val)) throw new Error(`Invalid curve param ${i}=${val} (${typeof val})`);
  }
  // Set defaults
  return Object.freeze({ ...nLength(curve.n, curve.nBitLength), ...curve } as const);
}

const hexes = Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
export function bytesToHex(uint8a: Uint8Array): string {
  if (!(uint8a instanceof Uint8Array)) throw new Error('Expected Uint8Array');
  // pre-caching improves the speed 6x
  let hex = '';
  for (let i = 0; i < uint8a.length; i++) {
    hex += hexes[uint8a[i]];
  }
  return hex;
}

export function numberToHexUnpadded(num: number | bigint): string {
  const hex = num.toString(16);
  return hex.length & 1 ? `0${hex}` : hex;
}

export function hexToNumber(hex: string): bigint {
  if (typeof hex !== 'string') {
    throw new TypeError('hexToNumber: expected string, got ' + typeof hex);
  }
  // Big Endian
  return BigInt(`0x${hex}`);
}

// Caching slows it down 2-3x
export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string') {
    throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
  }
  if (hex.length % 2) throw new Error('hexToBytes: received invalid unpadded hex ' + hex.length);
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < array.length; i++) {
    const j = i * 2;
    const hexByte = hex.slice(j, j + 2);
    const byte = Number.parseInt(hexByte, 16);
    if (Number.isNaN(byte) || byte < 0) throw new Error('Invalid byte sequence');
    array[i] = byte;
  }
  return array;
}

// Big Endian
export function bytesToNumberBE(bytes: Uint8Array): bigint {
  return hexToNumber(bytesToHex(bytes));
}
export function bytesToNumberLE(uint8a: Uint8Array): bigint {
  if (!(uint8a instanceof Uint8Array)) throw new Error('Expected Uint8Array');
  return BigInt('0x' + bytesToHex(Uint8Array.from(uint8a).reverse()));
}

export const numberToBytesBE = (n: bigint, len: number) =>
  hexToBytes(n.toString(16).padStart(len * 2, '0'));
export const numberToBytesLE = (n: bigint, len: number) => numberToBytesBE(n, len).reverse();
// Returns variable number bytes (minimal bigint encoding?)
export const numberToVarBytesBE = (n: bigint) => {
  let hex = n.toString(16);
  if (hex.length & 1) hex = '0' + hex;
  return hexToBytes(hex);
};

export function ensureBytes(hex: Hex, expectedLength?: number): Uint8Array {
  // Uint8Array.from() instead of hash.slice() because node.js Buffer
  // is instance of Uint8Array, and its slice() creates **mutable** copy
  const bytes = hex instanceof Uint8Array ? Uint8Array.from(hex) : hexToBytes(hex);
  if (typeof expectedLength === 'number' && bytes.length !== expectedLength)
    throw new Error(`Expected ${expectedLength} bytes`);
  return bytes;
}

// Copies several Uint8Arrays into one.
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  if (!arrays.every((b) => b instanceof Uint8Array)) throw new Error('Uint8Array list expected');
  if (arrays.length === 1) return arrays[0];
  const length = arrays.reduce((a, arr) => a + arr.length, 0);
  const result = new Uint8Array(length);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const arr = arrays[i];
    result.set(arr, pad);
    pad += arr.length;
  }
  return result;
}

// CURVE.n lengths
export function nLength(n: bigint, nBitLength?: number) {
  // Bit size, byte size of CURVE.n
  const _nBitLength = nBitLength !== undefined ? nBitLength : n.toString(2).length;
  const nByteLength = Math.ceil(_nBitLength / 8);
  return { nBitLength: _nBitLength, nByteLength };
}

/**
 * FIPS 186 B.4.1-compliant "constant-time" private key generation utility.
 * Can take (n+8) or more bytes of uniform input e.g. from CSPRNG or KDF
 * and convert them into private scalar, with the modulo bias being neglible.
 * Needs at least 40 bytes of input for 32-byte private key.
 * https://research.kudelskisecurity.com/2020/07/28/the-definitive-guide-to-modulo-bias-and-how-to-avoid-it/
 * @param hash hash output from SHA3 or a similar function
 * @returns valid private scalar
 */
export function hashToPrivateScalar(hash: Hex, groupOrder: bigint, isLE = false): bigint {
  hash = ensureBytes(hash);
  const hashLen = hash.length;
  const minLen = nLength(groupOrder).nByteLength + 8;
  if (minLen < 24 || hashLen < minLen || hashLen > 1024)
    throw new Error(`hashToPrivateScalar: expected ${minLen}-1024 bytes of input, got ${hashLen}`);
  const num = isLE ? bytesToNumberLE(hash) : bytesToNumberBE(hash);
  return mod.mod(num, groupOrder - _1n) + _1n;
}

export function equalBytes(b1: Uint8Array, b2: Uint8Array) {
  // We don't care about timing attacks here
  if (b1.length !== b2.length) return false;
  for (let i = 0; i < b1.length; i++) if (b1[i] !== b2[i]) return false;
  return true;
}

// Bit operations

// Amount of bits inside bigint (Same as n.toString(2).length)
export function bitLen(n: bigint) {
  let len;
  for (len = 0; n > 0n; n >>= _1n, len += 1);
  return len;
}
// Gets single bit at position. NOTE: first bit position is 0 (same as arrays)
// Same as !!+Array.from(n.toString(2)).reverse()[pos]
export const bitGet = (n: bigint, pos: number) => (n >> BigInt(pos)) & 1n;
// Sets single bit at position
export const bitSet = (n: bigint, pos: number, value: boolean) =>
  n | ((value ? _1n : _0n) << BigInt(pos));
// Return mask for N bits (Same as BigInt(`0b${Array(i).fill('1').join('')}`))
// Not using ** operator with bigints for old engines.
export const bitMask = (n: number) => (_2n << BigInt(n - 1)) - _1n;
