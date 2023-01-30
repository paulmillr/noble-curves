/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);
const u8a = (a: any): a is Uint8Array => a instanceof Uint8Array;

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
export type FHash = (message: Uint8Array | string) => Uint8Array;

const hexes = Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
export function bytesToHex(bytes: Uint8Array): string {
  if (!u8a(bytes)) throw new Error('Uint8Array expected');
  // pre-caching improves the speed 6x
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += hexes[bytes[i]];
  }
  return hex;
}

export function numberToHexUnpadded(num: number | bigint): string {
  const hex = num.toString(16);
  return hex.length & 1 ? `0${hex}` : hex;
}

export function hexToNumber(hex: string): bigint {
  if (typeof hex !== 'string') throw new Error('string expected, got ' + typeof hex);
  // Big Endian
  return BigInt(hex === '' ? '0' : `0x${hex}`);
}

// Caching slows it down 2-3x
export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string') throw new Error('string expected, got ' + typeof hex);
  if (hex.length % 2) throw new Error('hex string is invalid: unpadded ' + hex.length);
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < array.length; i++) {
    const j = i * 2;
    const hexByte = hex.slice(j, j + 2);
    const byte = Number.parseInt(hexByte, 16);
    if (Number.isNaN(byte) || byte < 0) throw new Error('invalid byte sequence');
    array[i] = byte;
  }
  return array;
}

// Big Endian
export function bytesToNumberBE(bytes: Uint8Array): bigint {
  return hexToNumber(bytesToHex(bytes));
}
export function bytesToNumberLE(bytes: Uint8Array): bigint {
  if (!u8a(bytes)) throw new Error('Uint8Array expected');
  return hexToNumber(bytesToHex(Uint8Array.from(bytes).reverse()));
}

export const numberToBytesBE = (n: bigint, len: number) =>
  hexToBytes(n.toString(16).padStart(len * 2, '0'));
export const numberToBytesLE = (n: bigint, len: number) => numberToBytesBE(n, len).reverse();
// Returns variable number bytes (minimal bigint encoding?)
export const numberToVarBytesBE = (n: bigint) => hexToBytes(numberToHexUnpadded(n));

export function ensureBytes(hex: Hex, expectedLength?: number): Uint8Array {
  // Uint8Array.from() instead of hash.slice() because node.js Buffer
  // is instance of Uint8Array, and its slice() creates **mutable** copy
  const bytes = u8a(hex) ? Uint8Array.from(hex) : hexToBytes(hex);
  if (typeof expectedLength === 'number' && bytes.length !== expectedLength)
    throw new Error(`Expected ${expectedLength} bytes`);
  return bytes;
}

// Copies several Uint8Arrays into one.
export function concatBytes(...arrs: Uint8Array[]): Uint8Array {
  const r = new Uint8Array(arrs.reduce((sum, a) => sum + a.length, 0));
  let pad = 0; // walk through each item, ensure they have proper type
  arrs.forEach((a) => {
    if (!u8a(a)) throw new Error('Uint8Array expected');
    r.set(a, pad);
    pad += a.length;
  });
  return r;
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

const validatorFns = {
  bigint: (val: any) => typeof val === 'bigint',
  function: (val: any) => typeof val === 'function',
  boolean: (val: any) => typeof val === 'boolean',
  string: (val: any) => typeof val === 'string',
  isSafeInteger: (val: any) => Number.isSafeInteger(val),
  array: (val: any) => Array.isArray(val),
  field: (val: any, object: any) => (object as any).Fp.isValid(val),
  hash: (val: any) => typeof val === 'function' && Number.isSafeInteger(val.outputLen),
} as const;
type Validator = keyof typeof validatorFns;
type ValMap<T extends Record<string, any>> = { [K in keyof T]?: Validator };
// type Record<K extends string | number | symbol, T> = { [P in K]: T; }

export function validateObject<T extends Record<string, any>>(
  object: T,
  validators: ValMap<T>,
  optValidators: ValMap<T> = {}
) {
  const checkField = (fieldName: keyof T, type: Validator, isOptional: boolean) => {
    const checkVal = validatorFns[type];
    if (typeof checkVal !== 'function')
      throw new Error(`Invalid validator "${type}", expected function`);

    const val = object[fieldName as keyof typeof object];
    if (isOptional && val === undefined) return;
    if (!checkVal(val, object)) {
      throw new Error(
        `Invalid param ${String(fieldName)}=${val} (${typeof val}), expected ${type}`
      );
    }
  };
  for (const [fieldName, type] of Object.entries(validators)) checkField(fieldName, type!, false);
  for (const [fieldName, type] of Object.entries(optValidators)) checkField(fieldName, type!, true);
  return object;
}
// validate type tests
// const o: { a: number; b: number; c: number } = { a: 1, b: 5, c: 6 };
// const z0 = validateObject(o, { a: 'isSafeInteger' }, { c: 'bigint' }); // Ok!
// // Should fail type-check
// const z1 = validateObject(o, { a: 'tmp' }, { c: 'zz' });
// const z2 = validateObject(o, { a: 'isSafeInteger' }, { c: 'zz' });
// const z3 = validateObject(o, { test: 'boolean', z: 'bug' });
// const z4 = validateObject(o, { a: 'boolean', z: 'bug' });
