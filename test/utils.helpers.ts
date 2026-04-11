import { invert as _invert, mod as _mod } from '../src/abstract/modular.ts';
import { ed25519 } from '../src/ed25519.ts';
import { secp256k1 } from '../src/secp256k1.ts';
import {
  aInRange as _aInRange,
  abool as _abool,
  asafenumber as _asafenumber,
  abytes as _abytes,
  asciiToBytes as _asciiToBytes,
  bitLen as _bitLen,
  bitSet as _bitSet,
  bytesToHex as _bytesToHex,
  concatBytes as _concatBytes,
  copyBytes as _copyBytes,
  createHmacDrbg as _createHmacDrbg,
  equalBytes as _equalBytes,
  hexToNumber as _hexToNumber,
  hexToBytes as _hexToBytes,
  numberToBytesBE as _numberToBytesBE,
  numberToBytesLE as _numberToBytesLE,
  numberToHexUnpadded as _numberToHexUnpadded,
  numberToVarBytesBE as _numberToVarBytesBE,
  validateObject as _validateObject,
} from '../src/utils.ts';

type Etc = {
  bytesToHex: (value: Uint8Array) => string;
  concatBytes: (...values: Uint8Array[]) => Uint8Array;
  hexToBytes: (value: string) => Uint8Array;
  mod: (a: bigint, b: bigint) => bigint;
  invert: (value: bigint, modulo: bigint) => bigint;
  abytes?: (value: unknown, length?: number, title?: string) => Uint8Array;
  copyBytes?: (value: Uint8Array) => Uint8Array;
  equalBytes?: (a: Uint8Array, b: Uint8Array) => boolean;
  asciiToBytes?: (value: string) => Uint8Array;
  bitLen?: (value: bigint) => number;
  hexToNumber?: (value: string) => bigint;
  numberToHexUnpadded?: (value: number | bigint) => string;
  numberToBytesBE?: (value: number | bigint, length: number) => Uint8Array;
  numberToBytesLE?: (value: number | bigint, length: number) => Uint8Array;
  numberToVarBytesBE?: (value: number | bigint) => Uint8Array;
  aInRange?: (title: string, value: bigint, min: bigint, max: bigint) => void;
  abool?: (value: boolean) => boolean;
  asafenumber?: (value: number) => void;
  validateObject?: (value: unknown, validators: Record<string, string>) => void;
  bitSet?: (value: bigint, bit: number, enable: boolean) => bigint;
  createHmacDrbg?: (
    hashLen: number,
    qByteLen: number,
    hmacFn: (key: Uint8Array, msg: Uint8Array) => Uint8Array
  ) => (seed: Uint8Array, pred: () => bigint) => bigint;
};
type Ed = {
  Point: { BASE: { multiply: (value: bigint) => unknown } };
  utils: { randomSecretKey: (seed?: Uint8Array) => Uint8Array };
};
type Secp = {
  getPublicKey: (secretKey: Uint8Array, isCompressed?: boolean) => Uint8Array;
  utils: { randomSecretKey: (seed?: Uint8Array) => Uint8Array };
};

export const etc: Etc = {
  aInRange: _aInRange,
  abool: _abool,
  asafenumber: _asafenumber,
  abytes: _abytes,
  asciiToBytes: _asciiToBytes,
  bitLen: _bitLen,
  bitSet: _bitSet,
  bytesToHex: _bytesToHex,
  concatBytes: _concatBytes,
  copyBytes: _copyBytes,
  createHmacDrbg: _createHmacDrbg,
  equalBytes: _equalBytes,
  hexToNumber: _hexToNumber,
  hexToBytes: _hexToBytes,
  invert: _invert,
  mod: _mod,
  numberToBytesBE: _numberToBytesBE,
  numberToBytesLE: _numberToBytesLE,
  numberToHexUnpadded: _numberToHexUnpadded,
  numberToVarBytesBE: _numberToVarBytesBE,
  validateObject: _validateObject,
};
export const { bytesToHex, concatBytes, hexToBytes, mod, invert } = etc;
export const extra = etc;
export const ed: Ed | undefined = ed25519 as unknown as Ed;
export const secp: Secp | undefined = secp256k1 as unknown as Secp;
