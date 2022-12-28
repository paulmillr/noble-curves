/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { CHash, concatBytes } from './utils.js';
import * as mod from './modular.js';

export type htfOpts = {
  // DST: a domain separation tag
  // defined in section 2.2.5
  DST: string;
  // p: the characteristic of F
  //    where F is a finite field of characteristic p and order q = p^m
  p: bigint;
  // m: the extension degree of F, m >= 1
  //     where F is a finite field of characteristic p and order q = p^m
  m: number;
  // k: the target security level for the suite in bits
  // defined in section 5.1
  k: number;
  // option to use a message that has already been processed by
  // expand_message_xmd
  expand: boolean;
  // Hash functions for: expand_message_xmd is appropriate for use with a
  // wide range of hash functions, including SHA-2, SHA-3, BLAKE2, and others.
  // BBS+ uses blake2: https://github.com/hyperledger/aries-framework-go/issues/2247
  hash: CHash;
};

export function validateHTFOpts(opts: htfOpts) {
  if (typeof opts.DST !== 'string') throw new Error('Invalid htf/DST');
  if (typeof opts.p !== 'bigint') throw new Error('Invalid htf/p');
  if (typeof opts.m !== 'number') throw new Error('Invalid htf/m');
  if (typeof opts.k !== 'number') throw new Error('Invalid htf/k');
  if (typeof opts.expand !== 'boolean') throw new Error('Invalid htf/expand');
  if (typeof opts.hash !== 'function' || !Number.isSafeInteger(opts.hash.outputLen))
    throw new Error('Invalid htf/hash function');
}

// UTF8 to ui8a
// TODO: looks broken, ASCII only, why not TextEncoder/TextDecoder? it is in hashes anyway
export function stringToBytes(str: string) {
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
  return bytes;
}

// Octet Stream to Integer (bytesToNumberBE)
function os2ip(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result <<= 8n;
    result += BigInt(bytes[i]);
  }
  return result;
}

// Integer to Octet Stream
function i2osp(value: number, length: number): Uint8Array {
  if (value < 0 || value >= 1 << (8 * length)) {
    throw new Error(`bad I2OSP call: value=${value} length=${length}`);
  }
  const res = Array.from({ length }).fill(0) as number[];
  for (let i = length - 1; i >= 0; i--) {
    res[i] = value & 0xff;
    value >>>= 8;
  }
  return new Uint8Array(res);
}

function strxor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const arr = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    arr[i] = a[i] ^ b[i];
  }
  return arr;
}

// Produces a uniformly random byte string using a cryptographic hash function H that outputs b bits
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-5.4.1
export function expand_message_xmd(
  msg: Uint8Array,
  DST: Uint8Array,
  lenInBytes: number,
  H: CHash
): Uint8Array {
  // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#section-5.3.3
  if (DST.length > 255) DST = H(concatBytes(stringToBytes('H2C-OVERSIZE-DST-'), DST));
  const b_in_bytes = H.outputLen;
  const r_in_bytes = H.blockLen;
  const ell = Math.ceil(lenInBytes / b_in_bytes);
  if (ell > 255) throw new Error('Invalid xmd length');
  const DST_prime = concatBytes(DST, i2osp(DST.length, 1));
  const Z_pad = i2osp(0, r_in_bytes);
  const l_i_b_str = i2osp(lenInBytes, 2);
  const b = new Array<Uint8Array>(ell);
  const b_0 = H(concatBytes(Z_pad, msg, l_i_b_str, i2osp(0, 1), DST_prime));
  b[0] = H(concatBytes(b_0, i2osp(1, 1), DST_prime));
  for (let i = 1; i <= ell; i++) {
    const args = [strxor(b_0, b[i - 1]), i2osp(i + 1, 1), DST_prime];
    b[i] = H(concatBytes(...args));
  }
  const pseudo_random_bytes = concatBytes(...b);
  return pseudo_random_bytes.slice(0, lenInBytes);
}

// hashes arbitrary-length byte strings to a list of one or more elements of a finite field F
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-5.3
// Inputs:
// msg - a byte string containing the message to hash.
// count - the number of elements of F to output.
// Outputs:
// [u_0, ..., u_(count - 1)], a list of field elements.
export function hash_to_field(msg: Uint8Array, count: number, options: htfOpts): bigint[][] {
  // if options is provided but incomplete, fill any missing fields with the
  // value in hftDefaults (ie hash to G2).
  const log2p = options.p.toString(2).length;
  const L = Math.ceil((log2p + options.k) / 8); // section 5.1 of ietf draft link above
  const len_in_bytes = count * options.m * L;
  const DST = stringToBytes(options.DST);
  let pseudo_random_bytes = msg;
  if (options.expand) {
    pseudo_random_bytes = expand_message_xmd(msg, DST, len_in_bytes, options.hash);
  }
  const u = new Array(count);
  for (let i = 0; i < count; i++) {
    const e = new Array(options.m);
    for (let j = 0; j < options.m; j++) {
      const elm_offset = L * (j + i * options.m);
      const tv = pseudo_random_bytes.subarray(elm_offset, elm_offset + L);
      e[j] = mod.mod(os2ip(tv), options.p);
    }
    u[i] = e;
  }
  return u;
}

export function isogenyMap<T, F extends mod.Field<T>>(field: F, map: [T[], T[], T[], T[]]) {
  // Make same order as in spec
  const COEFF = map.map((i) => Array.from(i).reverse());
  return (x: T, y: T) => {
    const [xNum, xDen, yNum, yDen] = COEFF.map((val) =>
      val.reduce((acc, i) => field.add(field.mul(acc, x), i))
    );
    x = field.div(xNum, xDen); // xNum / xDen
    y = field.mul(y, field.div(yNum, yDen)); // y * (yNum / yDev)
    return { x, y };
  };
}
