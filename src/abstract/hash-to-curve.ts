/**
 * hash-to-curve from RFC 9380.
 * Hashes arbitrary-length byte strings to a list of one or more elements of a finite field F.
 * https://www.rfc-editor.org/rfc/rfc9380
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import type { CHash, TArg, TRet } from '../utils.ts';
import {
  abytes,
  asafenumber,
  asciiToBytes,
  bytesToNumberBE,
  copyBytes,
  concatBytes,
  isBytes,
  validateObject,
} from '../utils.ts';
import type { AffinePoint, PC_ANY, PC_F, PC_P } from './curve.ts';
import { FpInvertBatch, mod, type IField } from './modular.ts';

/** ASCII domain-separation tag or raw bytes. */
export type AsciiOrBytes = string | Uint8Array;
type H2CDefaults = {
  DST: AsciiOrBytes;
  expand: 'xmd' | 'xof';
  hash: CHash;
  p: bigint;
  m: number;
  k: number;
  encodeDST?: AsciiOrBytes;
};

/**
 * * `DST` is a domain separation tag, defined in section 2.2.5
 * * `p` characteristic of F, where F is a finite field of characteristic p and order q = p^m
 * * `m` is extension degree (1 for prime fields)
 * * `k` is the target security target in bits (e.g. 128), from section 5.1
 * * `expand` is `xmd` (SHA2, SHA3, BLAKE) or `xof` (SHAKE, BLAKE-XOF)
 * * `hash` conforming to `utils.CHash` interface, with `outputLen` / `blockLen` props
 */
export type H2COpts = {
  /** Domain separation tag. */
  DST: AsciiOrBytes;
  /** Expander family used by RFC 9380. */
  expand: 'xmd' | 'xof';
  /** Hash or XOF implementation used by the expander. */
  hash: CHash;
  /** Base-field characteristic. */
  p: bigint;
  /** Extension degree (`1` for prime fields). */
  m: number;
  /** Target security level in bits. */
  k: number;
};
/** Hash-only subset of RFC 9380 options used by per-call overrides. */
export type H2CHashOpts = {
  /** Expander family used by RFC 9380. */
  expand: 'xmd' | 'xof';
  /** Hash or XOF implementation used by the expander. */
  hash: CHash;
};
/**
 * Map one hash-to-field output tuple onto affine curve coordinates.
 * Implementations receive the validated scalar tuple by reference for performance and MUST treat it
 * as read-only. Callers that need scratch space should copy before mutating.
 * @param scalar - Field-element tuple produced by `hash_to_field`.
 * @returns Affine point before subgroup clearing.
 */
export type MapToCurve<T> = (scalar: bigint[]) => AffinePoint<T>;

// Separated from initialization opts, so users won't accidentally change per-curve parameters
// (changing DST is ok!)
/** Per-call override for the domain-separation tag. */
export type H2CDSTOpts = {
  /** Domain-separation tag override. */
  DST: AsciiOrBytes;
};
/** Base hash-to-curve helpers shared by `hashToCurve` and `encodeToCurve`. */
export type H2CHasherBase<PC extends PC_ANY> = {
  /**
   * Hash arbitrary bytes to one curve point.
   * @param msg - Input message bytes.
   * @param options - Optional domain-separation override. See {@link H2CDSTOpts}.
   * @returns Curve point after hash-to-curve.
   */
  hashToCurve(msg: TArg<Uint8Array>, options?: TArg<H2CDSTOpts>): PC_P<PC>;
  /**
   * Hash arbitrary bytes to one scalar.
   * @param msg - Input message bytes.
   * @param options - Optional domain-separation override. See {@link H2CDSTOpts}.
   * @returns Scalar reduced into the target field.
   */
  hashToScalar(msg: TArg<Uint8Array>, options?: TArg<H2CDSTOpts>): bigint;
  /**
   * Derive one curve point from non-uniform bytes without the random-oracle
   * guarantees of `hashToCurve`.
   * Accepts the same arguments as `hashToCurve`, but runs the encode-to-curve
   * path instead of the random-oracle construction.
   */
  deriveToCurve?(msg: TArg<Uint8Array>, options?: TArg<H2CDSTOpts>): PC_P<PC>;
  /** Point constructor for the target curve. */
  Point: PC;
};
/**
 * RFC 9380 methods, with cofactor clearing. See {@link https://www.rfc-editor.org/rfc/rfc9380#section-3 | RFC 9380 section 3}.
 *
 * * hashToCurve: `map(hash(input))`, encodes RANDOM bytes to curve (WITH hashing)
 * * encodeToCurve: `map(hash(input))`, encodes NON-UNIFORM bytes to curve (WITH hashing)
 * * mapToCurve: `map(scalars)`, encodes NON-UNIFORM scalars to curve (NO hashing)
 */
export type H2CHasher<PC extends PC_ANY> = H2CHasherBase<PC> & {
  /**
   * Encode non-uniform bytes to one curve point.
   * @param msg - Input message bytes.
   * @param options - Optional domain-separation override. See {@link H2CDSTOpts}.
   * @returns Curve point after encode-to-curve.
   */
  encodeToCurve(msg: TArg<Uint8Array>, options?: TArg<H2CDSTOpts>): PC_P<PC>;
  /** Deterministic map from `hash_to_field` tuples into affine coordinates. */
  mapToCurve: MapToCurve<PC_F<PC>>;
  /** Default RFC 9380 options captured by this hasher bundle. */
  defaults: H2CDefaults;
};

// Octet Stream to Integer. "spec" implementation of os2ip is 2.5x slower vs bytesToNumberBE.
const os2ip = bytesToNumberBE;

// Integer to Octet Stream (numberToBytesBE).
function i2osp(value: number, length: number): TRet<Uint8Array> {
  asafenumber(value);
  asafenumber(length);
  // This helper stays on the JS bitwise/u32 fast-path. Callers that need wider encodings should
  // use bigint + numberToBytesBE instead of routing large widths through this small helper.
  if (length < 0 || length > 4) throw new Error('invalid I2OSP length: ' + length);
  if (value < 0 || value > 2 ** (8 * length) - 1) throw new Error('invalid I2OSP input: ' + value);
  const res = Array.from({ length }).fill(0) as number[];
  for (let i = length - 1; i >= 0; i--) {
    res[i] = value & 0xff;
    value >>>= 8;
  }
  return new Uint8Array(res) as TRet<Uint8Array>;
}

// RFC 9380 only applies strxor() to equal-length strings; callers must preserve that invariant.
function strxor(a: TArg<Uint8Array>, b: TArg<Uint8Array>): TRet<Uint8Array> {
  const arr = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    arr[i] = a[i] ^ b[i];
  }
  return arr as TRet<Uint8Array>;
}

// User can always use utf8 if they want, by passing Uint8Array.
// If string is passed, we treat it as ASCII: other formats are likely a mistake.
function normDST(DST: TArg<AsciiOrBytes>): TRet<Uint8Array> {
  if (!isBytes(DST) && typeof DST !== 'string')
    throw new Error('DST must be Uint8Array or ascii string');
  const dst = typeof DST === 'string' ? asciiToBytes(DST) : DST;
  // RFC 9380 §3.1 requirement 2: tags "MUST have nonzero length".
  if (dst.length === 0) throw new Error('DST must be non-empty');
  return dst as TRet<Uint8Array>;
}

/**
 * Produces a uniformly random byte string using a cryptographic hash
 * function H that outputs b bits.
 * See {@link https://www.rfc-editor.org/rfc/rfc9380#section-5.3.1 | RFC 9380 section 5.3.1}.
 * @param msg - Input message.
 * @param DST - Domain separation tag. This helper normalizes DST, rejects empty DSTs, and
 *   oversize-hashes DST when needed.
 * @param lenInBytes - Output length.
 * @param H - Hash function.
 * @returns Uniform byte string.
 * @throws If the message, DST, hash, or output length is invalid. {@link Error}
 * @example
 * Expand one message into uniform bytes with the XMD construction.
 *
 * ```ts
 * import { expand_message_xmd } from '@noble/curves/abstract/hash-to-curve.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * const uniform = expand_message_xmd(new TextEncoder().encode('hello noble'), 'DST', 32, sha256);
 * ```
 */
export function expand_message_xmd(
  msg: TArg<Uint8Array>,
  DST: TArg<AsciiOrBytes>,
  lenInBytes: number,
  H: TArg<CHash>
): TRet<Uint8Array> {
  abytes(msg);
  asafenumber(lenInBytes);
  DST = normDST(DST);
  // https://www.rfc-editor.org/rfc/rfc9380#section-5.3.3
  if (DST.length > 255) DST = H(concatBytes(asciiToBytes('H2C-OVERSIZE-DST-'), DST));
  const { outputLen: b_in_bytes, blockLen: r_in_bytes } = H;
  const ell = Math.ceil(lenInBytes / b_in_bytes);
  if (lenInBytes > 65535 || ell > 255) throw new Error('expand_message_xmd: invalid lenInBytes');
  const DST_prime = concatBytes(DST, i2osp(DST.length, 1));
  const Z_pad = new Uint8Array(r_in_bytes); // RFC 9380: Z_pad = I2OSP(0, s_in_bytes)
  const l_i_b_str = i2osp(lenInBytes, 2); // len_in_bytes_str
  const b = new Array<Uint8Array>(ell);
  const b_0 = H(concatBytes(Z_pad, msg, l_i_b_str, i2osp(0, 1), DST_prime));
  b[0] = H(concatBytes(b_0, i2osp(1, 1), DST_prime));
  // `b[0]` already stores RFC `b_1`, so only derive `b_2..b_ell` here. The old `<= ell`
  // loop computed one extra tail block, which was usually sliced away but broke at max `ell=255`
  // by reaching `I2OSP(256, 1)`.
  for (let i = 1; i < ell; i++) {
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
 * See {@link https://www.rfc-editor.org/rfc/rfc9380#section-5.3.2 | RFC 9380 section 5.3.2}.
 * @param msg - Input message.
 * @param DST - Domain separation tag. This helper normalizes DST, rejects empty DSTs, and
 *   oversize-hashes DST when needed.
 * @param lenInBytes - Output length.
 * @param k - Target security level.
 * @param H - XOF hash function.
 * @returns Uniform byte string.
 * @throws If the message, DST, XOF, or output length is invalid. {@link Error}
 * @example
 * Expand one message into uniform bytes with the XOF construction.
 *
 * ```ts
 * import { expand_message_xof } from '@noble/curves/abstract/hash-to-curve.js';
 * import { shake256 } from '@noble/hashes/sha3.js';
 * const uniform = expand_message_xof(
 *   new TextEncoder().encode('hello noble'),
 *   'DST',
 *   32,
 *   128,
 *   shake256
 * );
 * ```
 */
export function expand_message_xof(
  msg: TArg<Uint8Array>,
  DST: TArg<AsciiOrBytes>,
  lenInBytes: number,
  k: number,
  H: TArg<CHash>
): TRet<Uint8Array> {
  abytes(msg);
  asafenumber(lenInBytes);
  DST = normDST(DST);
  // https://www.rfc-editor.org/rfc/rfc9380#section-5.3.3
  // RFC 9380 §5.3.3: DST = H("H2C-OVERSIZE-DST-" || a_very_long_DST, ceil(2 * k / 8)).
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
 * See {@link https://www.rfc-editor.org/rfc/rfc9380#section-5.2 | RFC 9380 section 5.2}.
 * @param msg - Input message bytes.
 * @param count - Number of field elements to derive. Must be `>= 1`.
 * @param options - RFC 9380 options. See {@link H2COpts}. `m` must be `>= 1`.
 * @returns `[u_0, ..., u_(count - 1)]`, a list of field elements.
 * @throws If the expander choice or RFC 9380 options are invalid. {@link Error}
 * @example
 * Hash one message into field elements before mapping it onto a curve.
 *
 * ```ts
 * import { hash_to_field } from '@noble/curves/abstract/hash-to-curve.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * const scalars = hash_to_field(new TextEncoder().encode('hello noble'), 2, {
 *   DST: 'DST',
 *   p: 17n,
 *   m: 1,
 *   k: 128,
 *   expand: 'xmd',
 *   hash: sha256,
 * });
 * ```
 */
export function hash_to_field(
  msg: TArg<Uint8Array>,
  count: number,
  options: TArg<H2COpts>
): bigint[][] {
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
  // RFC 9380 §5.2 defines hash_to_field over a list of one or more field elements and requires
  // extension degree `m >= 1`; rejecting here avoids degenerate `[]` / `[[]]` helper outputs.
  if (count < 1) throw new Error('hash_to_field: expected count >= 1');
  if (m < 1) throw new Error('hash_to_field: expected m >= 1');
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
/**
 * @param field - Field implementation.
 * @param map - Isogeny coefficients.
 * @returns Isogeny mapping helper.
 * @example
 * Build one rational isogeny map, then apply it to affine x/y coordinates.
 *
 * ```ts
 * import { isogenyMap } from '@noble/curves/abstract/hash-to-curve.js';
 * import { Field } from '@noble/curves/abstract/modular.js';
 * const Fp = Field(17n);
 * const iso = isogenyMap(Fp, [[0n, 1n], [1n], [1n], [1n]]);
 * const point = iso(3n, 5n);
 * ```
 */
export function isogenyMap<T, F extends IField<T>>(field: F, map: XYRatio<T>): XY<T> {
  // Make same order as in spec
  const coeff = map.map((i) => Array.from(i).reverse());
  return (x: T, y: T) => {
    const [xn, xd, yn, yd] = coeff.map((val) =>
      val.reduce((acc, i) => field.add(field.mul(acc, x), i))
    );
    // RFC 9380 §6.6.3 / Appendix E: denominator-zero exceptional cases must
    // return the identity on E.
    // Shipped Weierstrass consumers encode that affine identity as all-zero
    // coordinates, so `passZero=true` intentionally collapses zero
    // denominators to `{ x: 0, y: 0 }`.
    const [xd_inv, yd_inv] = FpInvertBatch(field, [xd, yd], true);
    x = field.mul(xn, xd_inv); // xNum / xDen
    y = field.mul(y, field.mul(yn, yd_inv)); // y * (yNum / yDev)
    return { x, y };
  };
}

// Keep the shared DST removable when the selected bundle never hashes to scalar.
// Callers that need protocol-specific scalar domain separation must override this generic default.
// RFC 9497 §§4.1-4.5 use this ASCII prefix before appending the ciphersuite context string.
// Export a string instead of mutable bytes so callers cannot poison default hash-to-scalar behavior
// by mutating a shared Uint8Array in place.
export const _DST_scalar = 'HashToScalar-' as const;

/**
 * Creates hash-to-curve methods from EC Point and mapToCurve function. See {@link H2CHasher}.
 * @param Point - Point constructor.
 * @param mapToCurve - Map-to-curve function.
 * @param defaults - Default hash-to-curve options. This object is frozen in place and reused as
 *   the shared defaults bundle for the returned helpers.
 * @returns Hash-to-curve helper namespace.
 * @throws If the map-to-curve callback or default hash-to-curve options are invalid. {@link Error}
 * @example
 * Bundle hash-to-curve, hash-to-scalar, and encode-to-curve helpers for one curve.
 *
 * ```ts
 * import { createHasher } from '@noble/curves/abstract/hash-to-curve.js';
 * import { p256 } from '@noble/curves/nist.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * const hasher = createHasher(p256.Point, () => p256.Point.BASE.toAffine(), {
 *   DST: 'P256_XMD:SHA-256_SSWU_RO_',
 *   encodeDST: 'P256_XMD:SHA-256_SSWU_NU_',
 *   p: p256.Point.Fp.ORDER,
 *   m: 1,
 *   k: 128,
 *   expand: 'xmd',
 *   hash: sha256,
 * });
 * const point = hasher.encodeToCurve(new TextEncoder().encode('hello noble'));
 * ```
 */
export function createHasher<PC extends PC_ANY>(
  Point: PC,
  mapToCurve: MapToCurve<PC_F<PC>>,
  defaults: TArg<H2COpts & { encodeDST?: AsciiOrBytes }>
): H2CHasher<PC> {
  if (typeof mapToCurve !== 'function') throw new Error('mapToCurve() must be defined');
  // `Point` is intentionally not shape-validated eagerly here: point constructors vary across
  // curve families, so this helper only checks the hooks it can validate cheaply. Misconfigured
  // suites fail later when hashing first touches Point.fromAffine / Point.ZERO / clearCofactor().
  const snapshot = (src: TArg<H2COpts & { encodeDST?: AsciiOrBytes }>): TRet<H2CDefaults> =>
    Object.freeze({
      ...src,
      DST: isBytes(src.DST) ? copyBytes(src.DST) : src.DST,
      ...(src.encodeDST === undefined
        ? {}
        : { encodeDST: isBytes(src.encodeDST) ? copyBytes(src.encodeDST) : src.encodeDST }),
    }) as TRet<H2CDefaults>;
  // Keep one private defaults snapshot for actual hashing and expose fresh
  // detached snapshots via the public getter.
  // Otherwise a caller could mutate `hasher.defaults.DST` in place and poison
  // the singleton hasher for every other consumer in the same process.
  const safeDefaults = snapshot(defaults);
  function map(num: bigint[]): PC_P<PC> {
    return Point.fromAffine(mapToCurve(num)) as PC_P<PC>;
  }
  function clear(initial: PC_P<PC>): PC_P<PC> {
    const P = initial.clearCofactor();
    // Keep ZERO as the algebraic cofactor-clearing result here; strict public point-validity
    // surfaces may still reject it later, but createHasher.clear() itself is not that boundary.
    if (P.equals(Point.ZERO)) return Point.ZERO as PC_P<PC>;
    P.assertValidity();
    return P as PC_P<PC>;
  }

  return Object.freeze({
    get defaults() {
      return snapshot(safeDefaults);
    },
    Point,

    hashToCurve(msg: TArg<Uint8Array>, options?: TArg<H2CDSTOpts>): PC_P<PC> {
      const opts = Object.assign({}, safeDefaults, options);
      const u = hash_to_field(msg, 2, opts);
      const u0 = map(u[0]);
      const u1 = map(u[1]);
      return clear(u0.add(u1) as PC_P<PC>);
    },
    encodeToCurve(msg: TArg<Uint8Array>, options?: TArg<H2CDSTOpts>): PC_P<PC> {
      const optsDst = safeDefaults.encodeDST ? { DST: safeDefaults.encodeDST } : {};
      const opts = Object.assign({}, safeDefaults, optsDst, options);
      const u = hash_to_field(msg, 1, opts);
      const u0 = map(u[0]);
      return clear(u0);
    },
    /** See {@link H2CHasher} */
    mapToCurve(scalars: bigint | bigint[]): PC_P<PC> {
      // Curves with m=1 accept only single scalar
      if (safeDefaults.m === 1) {
        if (typeof scalars !== 'bigint') throw new Error('expected bigint (m=1)');
        return clear(map([scalars]));
      }
      if (!Array.isArray(scalars)) throw new Error('expected array of bigints');
      for (const i of scalars)
        if (typeof i !== 'bigint') throw new Error('expected array of bigints');
      return clear(map(scalars));
    },

    // hash_to_scalar can produce 0: https://www.rfc-editor.org/errata/eid8393
    // RFC 9380, draft-irtf-cfrg-bbs-signatures-08. Default scalar DST is the shared generic
    // `HashToScalar-` prefix above unless the caller overrides it per invocation.
    hashToScalar(msg: TArg<Uint8Array>, options?: TArg<H2CDSTOpts>): bigint {
      // @ts-ignore
      const N = Point.Fn.ORDER;
      const opts = Object.assign({}, safeDefaults, { p: N, m: 1, DST: _DST_scalar }, options);
      return hash_to_field(msg, 1, opts)[0][0];
    },
  });
}
