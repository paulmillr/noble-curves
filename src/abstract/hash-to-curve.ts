/**
 * hash-to-curve from RFC 9380.
 * Hashes arbitrary-length byte strings to a list of one or more elements of a finite field F.
 * https://www.rfc-editor.org/rfc/rfc9380
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import type { CHash } from '../utils.ts';
import {
  abytes,
  asafenumber,
  asciiToBytes,
  bytesToNumberBE,
  concatBytes,
  isBytes,
  validateObject,
} from '../utils.ts';
import type { AffinePoint, PC_ANY, PC_F, PC_P } from './curve.ts';
import { FpInvertBatch, mod, type IField } from './modular.ts';

export type AsciiOrBytes = string | Uint8Array;

/**
 * * `DST` is a domain separation tag, defined in section 2.2.5
 * * `p` characteristic of F, where F is a finite field of characteristic p and order q = p^m
 * * `m` is extension degree (1 for prime fields)
 * * `k` is the target security target in bits (e.g. 128), from section 5.1
 * * `expand` is `xmd` (SHA2, SHA3, BLAKE) or `xof` (SHAKE, BLAKE-XOF)
 * * `hash` conforming to `utils.CHash` interface, with `outputLen` / `blockLen` props
 */
export type H2COpts = {
  DST: AsciiOrBytes;
  expand: 'xmd' | 'xof';
  hash: CHash;
  p: bigint;
  m: number;
  k: number;
};
export type H2CHashOpts = {
  expand: 'xmd' | 'xof';
  hash: CHash;
};
export type MapToCurve<T> = (scalar: bigint[]) => AffinePoint<T>;

// Separated from initialization opts, so users won't accidentally change per-curve parameters
// (changing DST is ok!)
export type H2CDSTOpts = { DST: AsciiOrBytes };
export type H2CHasherBase<PC extends PC_ANY> = {
  hashToCurve(msg: Uint8Array, options?: H2CDSTOpts): PC_P<PC>;
  hashToScalar(msg: Uint8Array, options?: H2CDSTOpts): bigint;
  deriveToCurve?(msg: Uint8Array, options?: H2CDSTOpts): PC_P<PC>;
  Point: PC;
};
/**
 * RFC 9380 methods, with cofactor clearing. See https://www.rfc-editor.org/rfc/rfc9380#section-3.
 *
 * * hashToCurve: `map(hash(input))`, encodes RANDOM bytes to curve (WITH hashing)
 * * encodeToCurve: `map(hash(input))`, encodes NON-UNIFORM bytes to curve (WITH hashing)
 * * mapToCurve: `map(scalars)`, encodes NON-UNIFORM scalars to curve (NO hashing)
 */
export type H2CHasher<PC extends PC_ANY> = H2CHasherBase<PC> & {
  encodeToCurve(msg: Uint8Array, options?: H2CDSTOpts): PC_P<PC>;
  mapToCurve: MapToCurve<PC_F<PC>>;
  defaults: H2COpts & { encodeDST?: AsciiOrBytes };
};

// Octet Stream to Integer. "spec" implementation of os2ip is 2.5x slower vs bytesToNumberBE.
const os2ip = bytesToNumberBE;

// Integer to Octet Stream (numberToBytesBE)
function i2osp(value: number, length: number): Uint8Array {
  asafenumber(value);
  asafenumber(length);
  if (value < 0 || value >= 1 << (8 * length)) throw new Error('invalid I2OSP input: ' + value);
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

// User can always use utf8 if they want, by passing Uint8Array.
// If string is passed, we treat it as ASCII: other formats are likely a mistake.
function normDST(DST: AsciiOrBytes): Uint8Array {
  if (!isBytes(DST) && typeof DST !== 'string')
    throw new Error('DST must be Uint8Array or ascii string');
  return typeof DST === 'string' ? asciiToBytes(DST) : DST;
}

/**
 * Produces a uniformly random byte string using a cryptographic hash function H that outputs b bits.
 * [RFC 9380 5.3.1](https://www.rfc-editor.org/rfc/rfc9380#section-5.3.1).
 */
export function expand_message_xmd(
  msg: Uint8Array,
  DST: AsciiOrBytes,
  lenInBytes: number,
  H: CHash
): Uint8Array {
  abytes(msg);
  asafenumber(lenInBytes);
  DST = normDST(DST);
  // https://www.rfc-editor.org/rfc/rfc9380#section-5.3.3
  if (DST.length > 255) DST = H(concatBytes(asciiToBytes('H2C-OVERSIZE-DST-'), DST));
  const { outputLen: b_in_bytes, blockLen: r_in_bytes } = H;
  const ell = Math.ceil(lenInBytes / b_in_bytes);
  if (lenInBytes > 65535 || ell > 255) throw new Error('expand_message_xmd: invalid lenInBytes');
  const DST_prime = concatBytes(DST, i2osp(DST.length, 1));
  const Z_pad = i2osp(0, r_in_bytes);
  const l_i_b_str = i2osp(lenInBytes, 2); // len_in_bytes_str
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

/**
 * Produces a uniformly random byte string using an extendable-output function (XOF) H.
 * 1. The collision resistance of H MUST be at least k bits.
 * 2. H MUST be an XOF that has been proved indifferentiable from
 *    a random oracle under a reasonable cryptographic assumption.
 * [RFC 9380 5.3.2](https://www.rfc-editor.org/rfc/rfc9380#section-5.3.2).
 */
export function expand_message_xof(
  msg: Uint8Array,
  DST: AsciiOrBytes,
  lenInBytes: number,
  k: number,
  H: CHash
): Uint8Array {
  abytes(msg);
  asafenumber(lenInBytes);
  DST = normDST(DST);
  // https://www.rfc-editor.org/rfc/rfc9380#section-5.3.3
  // DST = H('H2C-OVERSIZE-DST-' || a_very_long_DST, Math.ceil((lenInBytes * k) / 8));
  if (DST.length > 255) {
    const dkLen = Math.ceil((2 * k) / 8);
    DST = H.create({ dkLen }).update(asciiToBytes('H2C-OVERSIZE-DST-')).update(DST).digest();
  }
  if (lenInBytes > 65535 || DST.length > 255)
    throw new Error('expand_message_xof: invalid lenInBytes');
  return (
    H.create({ dkLen: lenInBytes })
      .update(msg)
      .update(i2osp(lenInBytes, 2))
      // 2. DST_prime = DST || I2OSP(len(DST), 1)
      .update(DST)
      .update(i2osp(DST.length, 1))
      .digest()
  );
}

/**
 * Hashes arbitrary-length byte strings to a list of one or more elements of a finite field F.
 * [RFC 9380 5.2](https://www.rfc-editor.org/rfc/rfc9380#section-5.2).
 * @param msg a byte string containing the message to hash
 * @param count the number of elements of F to output
 * @param options `{DST: string, p: bigint, m: number, k: number, expand: 'xmd' | 'xof', hash: H}`, see above
 * @returns [u_0, ..., u_(count - 1)], a list of field elements.
 */
export function hash_to_field(msg: Uint8Array, count: number, options: H2COpts): bigint[][] {
  validateObject(options, {
    p: 'bigint',
    m: 'number',
    k: 'number',
    hash: 'function',
  });
  const { p, k, m, hash, expand, DST } = options;
  asafenumber(hash.outputLen, 'valid hash');
  abytes(msg);
  asafenumber(count);
  const log2p = p.toString(2).length;
  const L = Math.ceil((log2p + k) / 8); // section 5.1 of ietf draft link above
  const len_in_bytes = count * m * L;
  let prb; // pseudo_random_bytes
  if (expand === 'xmd') {
    prb = expand_message_xmd(msg, DST, len_in_bytes, hash);
  } else if (expand === 'xof') {
    prb = expand_message_xof(msg, DST, len_in_bytes, k, hash);
  } else if (expand === '_internal_pass') {
    // for internal tests only
    prb = msg;
  } else {
    throw new Error('expand must be "xmd" or "xof"');
  }
  const u = new Array(count);
  for (let i = 0; i < count; i++) {
    const e = new Array(m);
    for (let j = 0; j < m; j++) {
      const elm_offset = L * (j + i * m);
      const tv = prb.subarray(elm_offset, elm_offset + L);
      e[j] = mod(os2ip(tv), p);
    }
    u[i] = e;
  }
  return u;
}

type XY<T> = (x: T, y: T) => { x: T; y: T };
type XYRatio<T> = [T[], T[], T[], T[]]; // xn/xd, yn/yd
export function isogenyMap<T, F extends IField<T>>(field: F, map: XYRatio<T>): XY<T> {
  // Make same order as in spec
  const coeff = map.map((i) => Array.from(i).reverse());
  return (x: T, y: T) => {
    const [xn, xd, yn, yd] = coeff.map((val) =>
      val.reduce((acc, i) => field.add(field.mul(acc, x), i))
    );
    // 6.6.3
    // Exceptional cases of iso_map are inputs that cause the denominator of
    // either rational function to evaluate to zero; such cases MUST return
    // the identity point on E.
    const [xd_inv, yd_inv] = FpInvertBatch(field, [xd, yd], true);
    x = field.mul(xn, xd_inv); // xNum / xDen
    y = field.mul(y, field.mul(yn, yd_inv)); // y * (yNum / yDev)
    return { x, y };
  };
}

export const _DST_scalar: Uint8Array = asciiToBytes('HashToScalar-');

/** Creates hash-to-curve methods from EC Point and mapToCurve function. See {@link H2CHasher}. */
export function createHasher<PC extends PC_ANY>(
  Point: PC,
  mapToCurve: MapToCurve<PC_F<PC>>,
  defaults: H2COpts & { encodeDST?: AsciiOrBytes }
): H2CHasher<PC> {
  if (typeof mapToCurve !== 'function') throw new Error('mapToCurve() must be defined');
  function map(num: bigint[]): PC_P<PC> {
    return Point.fromAffine(mapToCurve(num)) as PC_P<PC>;
  }
  function clear(initial: PC_P<PC>): PC_P<PC> {
    const P = initial.clearCofactor();
    if (P.equals(Point.ZERO)) return Point.ZERO as PC_P<PC>; // zero will throw in assert
    P.assertValidity();
    return P as PC_P<PC>;
  }

  return {
    defaults: Object.freeze(defaults),
    Point,

    hashToCurve(msg: Uint8Array, options?: H2CDSTOpts): PC_P<PC> {
      const opts = Object.assign({}, defaults, options);
      const u = hash_to_field(msg, 2, opts);
      const u0 = map(u[0]);
      const u1 = map(u[1]);
      return clear(u0.add(u1) as PC_P<PC>);
    },
    encodeToCurve(msg: Uint8Array, options?: H2CDSTOpts): PC_P<PC> {
      const optsDst = defaults.encodeDST ? { DST: defaults.encodeDST } : {};
      const opts = Object.assign({}, defaults, optsDst, options);
      const u = hash_to_field(msg, 1, opts);
      const u0 = map(u[0]);
      return clear(u0);
    },
    /** See {@link H2CHasher} */
    mapToCurve(scalars: bigint | bigint[]): PC_P<PC> {
      // Curves with m=1 accept only single scalar
      if (defaults.m === 1) {
        if (typeof scalars !== 'bigint') throw new Error('expected bigint (m=1)');
        return clear(map([scalars]));
      }
      if (!Array.isArray(scalars)) throw new Error('expected array of bigints');
      for (const i of scalars)
        if (typeof i !== 'bigint') throw new Error('expected array of bigints');
      return clear(map(scalars));
    },

    // hash_to_scalar can produce 0: https://www.rfc-editor.org/errata/eid8393
    // RFC 9380, draft-irtf-cfrg-bbs-signatures-08
    hashToScalar(msg: Uint8Array, options?: H2CDSTOpts): bigint {
      // @ts-ignore
      const N = Point.Fn.ORDER;
      const opts = Object.assign({}, defaults, { p: N, m: 1, DST: _DST_scalar }, options);
      return hash_to_field(msg, 1, opts)[0][0];
    },
  };
}
