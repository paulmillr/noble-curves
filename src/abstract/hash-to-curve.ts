/**
 * hash-to-curve from RFC 9380.
 * Hashes arbitrary-length byte strings to a list of one or more elements of a finite field F.
 * https://www.rfc-editor.org/rfc/rfc9380
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import type { CHash, TArg, TRet } from '../utils.ts';
import {
  aarray,
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
import { FpInvertBatch, FpIsSquare, mod, type IField, validateField } from './modular.ts';

// prettier-ignore
const _0n = /* @__PURE__ */ BigInt(0), _1n = /* @__PURE__ */ BigInt(1), _2n = /* @__PURE__ */ BigInt(2), _3n = /* @__PURE__ */ BigInt(3), _4n = /* @__PURE__ */ BigInt(4);

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
  if (typeof H !== 'function') throw new Error('expand_message_xmd: expected hash function');
  asafenumber(H.outputLen, 'hash.outputLen');
  asafenumber(H.blockLen, 'hash.blockLen');
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
  asafenumber(k, 'k');
  if (k < 0) throw new Error('expand_message_xof: invalid k');
  if (typeof H !== 'function') throw new Error('expand_message_xof: expected XOF function');
  if (typeof H.create !== 'function') throw new Error('expand_message_xof: expected XOF create');
  DST = normDST(DST);
  if (lenInBytes < 0 || lenInBytes > 65535)
    throw new Error('expand_message_xof: invalid lenInBytes');
  // https://www.rfc-editor.org/rfc/rfc9380#section-5.3.3
  // RFC 9380 §5.3.3: DST = H("H2C-OVERSIZE-DST-" || a_very_long_DST, ceil(2 * k / 8)).
  if (DST.length > 255) {
    const dkLen = Math.ceil((2 * k) / 8);
    DST = H.create({ dkLen }).update(asciiToBytes('H2C-OVERSIZE-DST-')).update(DST).digest();
  }
  // Oversize DSTs are compressed above; fail closed if a custom XOF still returns one
  // (possible when k > 1020 makes the compression dkLen itself exceed 255 bytes).
  if (DST.length > 255) throw new Error('expand_message_xof: invalid DST');
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
  asafenumber(m, 'm');
  asafenumber(k, 'k');
  // RFC 9380 §5.2 defines hash_to_field over a list of one or more field elements and an integer
  // extension degree `m >= 1`; rejecting here avoids degenerate `[]` / `[[]]` helper outputs.
  // The RFC also treats `p` as a finite-field characteristic; invalid values make log2/mod degenerate.
  if (p <= 1n) throw new Error('hash_to_field: expected valid field characteristic');
  if (count < 1) throw new Error('hash_to_field: expected count >= 1');
  if (m < 1) throw new Error('hash_to_field: expected m >= 1');
  if (k < 0) throw new Error('hash_to_field: invalid k');
  const log2p = p.toString(2).length;
  const L = Math.ceil((log2p + k) / 8); // section 5.1 of ietf draft link above
  const len_in_bytes = count * m * L;
  let prb; // pseudo_random_bytes
  if (expand === 'xmd') {
    prb = expand_message_xmd(msg, DST, len_in_bytes, hash);
  } else if (expand === 'xof') {
    prb = expand_message_xof(msg, DST, len_in_bytes, k, hash);
  } else if (expand === '_internal_pass') {
    // for internal tests only: msg is used as the uniform bytes directly. Short msg is allowed
    // on purpose (subarray() slices are short): zkcrypto map_scalar vectors feed empty okm.
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
  validateField(field);
  // Make same order as in spec
  aarray<T[]>(map, 'map');
  const coeff = map.map((i, row) => {
    aarray(i, 'map[' + row + ']');
    if (i.length < 1) throw new Error('isogenyMap: expected non-empty coefficients');
    return Array.from(i).reverse();
  });
  return (x: T, y: T) => {
    const [xn, xd, yn, yd] = coeff.map((val) =>
      val.reduce((acc, i) => field.add(field.mul(acc, x), i))
    );
    const isZero = field.is0(xd) || field.is0(yd);
    // Shipped Weierstrass consumers encode that affine identity as all-zero
    // coordinates, so `passZero=true` intentionally collapses zero
    // denominators to `{ x: 0, y: 0 }`.
    const [xd_inv, yd_inv] = FpInvertBatch(field, [xd, yd], true);
    x = field.mul(xn, xd_inv); // xNum / xDen
    y = field.mul(y, field.mul(yn, yd_inv)); // y * (yNum / yDev)
    // RFC 9380 §6.6.3: if the denominator of either isogeny rational function is
    // zero, the exceptional case must return the identity point on E.
    return isZero ? { x: field.ZERO, y: field.ZERO } : { x, y };
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
 * @param defaults - Default hash-to-curve options. A frozen detached snapshot is reused as the
 *   shared defaults bundle for the returned helpers.
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
  validateObject(defaults);
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
  // Per-call options are H2CDSTOpts: only DST may be overridden. Copying just that key keeps
  // off-type option objects from silently replacing suite parameters (p/m/k/hash/expand) at
  // runtime — same pinning hashToScalar always did for p/m.
  const dstOverride = (options?: TArg<H2CDSTOpts>) =>
    options && options.DST !== undefined ? { DST: options.DST } : undefined;
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
      const opts = Object.assign({}, safeDefaults, dstOverride(options));
      const u = hash_to_field(msg, 2, opts);
      const u0 = map(u[0]);
      const u1 = map(u[1]);
      return clear(u0.add(u1) as PC_P<PC>);
    },
    encodeToCurve(msg: TArg<Uint8Array>, options?: TArg<H2CDSTOpts>): PC_P<PC> {
      const optsDst = safeDefaults.encodeDST === undefined ? {} : { DST: safeDefaults.encodeDST };
      const opts = Object.assign({}, safeDefaults, optsDst, dstOverride(options));
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
      // RFC 9380 represents one GF(p^m) element as exactly m base-field scalars.
      if (scalars.length !== safeDefaults.m)
        throw new Error(`expected array of ${safeDefaults.m} bigints`);
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
      const opts = Object.assign({}, safeDefaults, { DST: _DST_scalar }, dstOverride(options), {
        p: N,
        m: 1,
      });
      return hash_to_field(msg, 1, opts)[0][0];
    },
  });
}

/**
 * Implementation of the Shallue and van de Woestijne method for any weierstrass curve.
 * TODO: check if there is a way to merge this with uvRatio in Edwards; move to modular.
 * b = True and y = sqrt(u / v) if (u / v) is square in F, and
 * b = False and y = sqrt(Z * (u / v)) otherwise.
 * RFC 9380 expects callers to provide `v != 0`; this helper does not enforce it.
 * @param Fp - Field implementation.
 * @param Z - Simplified SWU map parameter.
 * @returns Square-root ratio helper.
 * @example
 * Build the square-root ratio helper used by SWU map implementations.
 *
 * ```ts
 * import { SWUFpSqrtRatio } from '@noble/curves/abstract/hash-to-curve.js';
 * import { Field } from '@noble/curves/abstract/modular.js';
 * const Fp = Field(17n);
 * const sqrtRatio = SWUFpSqrtRatio(Fp, 3n);
 * const out = sqrtRatio(4n, 1n);
 * ```
 */
export function SWUFpSqrtRatio<T>(
  Fp: TArg<IField<T>>,
  Z: T
): (u: T, v: T) => { isValid: boolean; value: T } {
  // Fail with the usual field-shape error before touching pow/cmov on malformed field shims.
  const F = validateField(Fp as IField<T>) as IField<T>;
  // Generic implementation
  const q = F.ORDER;
  let l = _0n;
  for (let o = q - _1n; o % _2n === _0n; o /= _2n) l += _1n;
  const c1 = l; // 1. c1, the largest integer such that 2^c1 divides q - 1.
  // We need 2n ** c1 and 2n ** (c1-1). We can't use **; but we can use <<.
  // 2n ** c1 == 2n << (c1-1)
  const _2n_pow_c1_1 = _2n << (c1 - _1n - _1n);
  const _2n_pow_c1 = _2n_pow_c1_1 * _2n;
  const c2 = (q - _1n) / _2n_pow_c1; // 2. c2 = (q - 1) / (2^c1)  # Integer arithmetic
  const c3 = (c2 - _1n) / _2n; // 3. c3 = (c2 - 1) / 2            # Integer arithmetic
  const c4 = _2n_pow_c1 - _1n; // 4. c4 = 2^c1 - 1                # Integer arithmetic
  const c5 = _2n_pow_c1_1; // 5. c5 = 2^(c1 - 1)                  # Integer arithmetic
  const c6 = F.pow(Z, c2); // 6. c6 = Z^c2
  const c7 = F.pow(Z, (c2 + _1n) / _2n); // 7. c7 = Z^((c2 + 1) / 2)
  // RFC 9380 Appendix F.2.1.1 defines sqrt_ratio(u, v) only for v != 0.
  // We keep v=0 on the regular result path with isValid=false instead of
  // throwing so the helper stays closer to the RFC's fixed control flow.
  let sqrtRatio = (u: T, v: T): { isValid: boolean; value: T } => {
    let tv1 = c6; // 1. tv1 = c6
    let tv2 = F.pow(v, c4); // 2. tv2 = v^c4
    let tv3 = F.sqr(tv2); // 3. tv3 = tv2^2
    tv3 = F.mul(tv3, v); // 4. tv3 = tv3 * v
    let tv5 = F.mul(u, tv3); // 5. tv5 = u * tv3
    tv5 = F.pow(tv5, c3); // 6. tv5 = tv5^c3
    tv5 = F.mul(tv5, tv2); // 7. tv5 = tv5 * tv2
    tv2 = F.mul(tv5, v); // 8. tv2 = tv5 * v
    tv3 = F.mul(tv5, u); // 9. tv3 = tv5 * u
    let tv4 = F.mul(tv3, tv2); // 10. tv4 = tv3 * tv2
    tv5 = F.pow(tv4, c5); // 11. tv5 = tv4^c5
    let isQR = F.eql(tv5, F.ONE); // 12. isQR = tv5 == 1
    tv2 = F.mul(tv3, c7); // 13. tv2 = tv3 * c7
    tv5 = F.mul(tv4, tv1); // 14. tv5 = tv4 * tv1
    tv3 = F.cmov(tv2, tv3, isQR); // 15. tv3 = CMOV(tv2, tv3, isQR)
    tv4 = F.cmov(tv5, tv4, isQR); // 16. tv4 = CMOV(tv5, tv4, isQR)
    // 17. for i in (c1, c1 - 1, ..., 2):
    for (let i = c1; i > _1n; i--) {
      let tv5 = i - _2n; // 18.    tv5 = i - 2
      tv5 = _2n << (tv5 - _1n); // 19.    tv5 = 2^tv5
      let tvv5 = F.pow(tv4, tv5); // 20.    tv5 = tv4^tv5
      const e1 = F.eql(tvv5, F.ONE); // 21.    e1 = tv5 == 1
      tv2 = F.mul(tv3, tv1); // 22.    tv2 = tv3 * tv1
      tv1 = F.mul(tv1, tv1); // 23.    tv1 = tv1 * tv1
      tvv5 = F.mul(tv4, tv1); // 24.    tv5 = tv4 * tv1
      tv3 = F.cmov(tv2, tv3, e1); // 25.    tv3 = CMOV(tv2, tv3, e1)
      tv4 = F.cmov(tvv5, tv4, e1); // 26.    tv4 = CMOV(tv5, tv4, e1)
    }
    // RFC 9380 Appendix F.2.1.1 defines sqrt_ratio(u, v) for v != 0.
    // When u = 0 and v != 0, u / v = 0 is square and the computed root is
    // still 0, so widen only the final flag and keep the full control flow.
    return { isValid: !F.is0(v) && (isQR || F.is0(u)), value: tv3 };
  };
  if (F.ORDER % _4n === _3n) {
    // sqrt_ratio_3mod4(u, v)
    const c1 = (F.ORDER - _3n) / _4n; // 1. c1 = (q - 3) / 4     # Integer arithmetic
    const c2 = F.sqrt(F.neg(Z)); // 2. c2 = sqrt(-Z)
    sqrtRatio = (u: T, v: T) => {
      let tv1 = F.sqr(v); // 1. tv1 = v^2
      const tv2 = F.mul(u, v); // 2. tv2 = u * v
      tv1 = F.mul(tv1, tv2); // 3. tv1 = tv1 * tv2
      let y1 = F.pow(tv1, c1); // 4. y1 = tv1^c1
      y1 = F.mul(y1, tv2); // 5. y1 = y1 * tv2
      const y2 = F.mul(y1, c2); // 6. y2 = y1 * c2
      const tv3 = F.mul(F.sqr(y1), v); // 7. tv3 = y1^2; 8. tv3 = tv3 * v
      const isQR = F.eql(tv3, u); // 9. isQR = tv3 == u
      let y = F.cmov(y2, y1, isQR); // 10. y = CMOV(y2, y1, isQR)
      return { isValid: !F.is0(v) && isQR, value: y }; // 11. return (isQR, y) isQR ? y : y*c2
    };
  }
  // No curves uses that
  // if (Fp.ORDER % _8n === _5n) // sqrt_ratio_5mod8
  return sqrtRatio;
}
/**
 * Simplified Shallue-van de Woestijne-Ulas Method
 * See {@link https://www.rfc-editor.org/rfc/rfc9380#section-6.6.2 | RFC 9380 section 6.6.2}.
 * @param Fp - Field implementation.
 * @param opts - SWU parameters:
 *   - `A`: Curve parameter `A`.
 *   - `B`: Curve parameter `B`.
 *   - `Z`: Simplified SWU map parameter.
 * @returns Deterministic map-to-curve function.
 * @throws If the SWU parameters are invalid or the field lacks the required helpers. {@link Error}
 * @example
 * Map one field element to a Weierstrass curve point with the SWU recipe.
 *
 * ```ts
 * import { mapToCurveSimpleSWU } from '@noble/curves/abstract/hash-to-curve.js';
 * import { Field } from '@noble/curves/abstract/modular.js';
 * const Fp = Field(17n);
 * const map = mapToCurveSimpleSWU(Fp, { A: 1n, B: 2n, Z: 3n });
 * const point = map(5n);
 * ```
 */
export function mapToCurveSimpleSWU<T>(
  Fp: TArg<IField<T>>,
  opts: {
    A: T;
    B: T;
    Z: T;
  }
): (u: T) => { x: T; y: T } {
  const F = validateField(Fp as IField<T>) as IField<T>;
  validateObject(opts as any, {}, {}, 'opts');
  const { A, B, Z } = opts;
  if (!F.isValidNot0(A) || !F.isValidNot0(B) || !F.isValid(Z))
    throw new Error('mapToCurveSimpleSWU: invalid opts');
  // RFC 9380 §6.6.2 and Appendix H.2 require:
  // 1. Z is non-square in F
  // 2. Z != -1 in F
  // 3. g(x) - Z is irreducible over F
  // 4. g(B / (Z * A)) is square in F
  // We can enforce 1, 2, and 4 with the current field API.
  // Criterion 3 is not checked here because generic `IField<T>` does not expose
  // polynomial-ring / irreducibility operations, and this helper is used for
  // both prime and extension fields.
  if (F.eql(Z, F.neg(F.ONE)) || FpIsSquare(F, Z))
    throw new Error('mapToCurveSimpleSWU: invalid opts');
  // RFC 9380 Appendix H.2 criterion 4: g(B / (Z * A)) is square in F.
  // x = B / (Z * A)
  const x = F.mul(B, F.inv(F.mul(Z, A)));
  // g(x) = x^3 + A*x + B
  const gx = F.add(F.add(F.mul(F.sqr(x), x), F.mul(A, x)), B);
  if (!FpIsSquare(F, gx)) throw new Error('mapToCurveSimpleSWU: invalid opts');
  const sqrtRatio = SWUFpSqrtRatio(F, Z);
  if (!F.isOdd) throw new Error('Field does not have .isOdd()');
  // Input: u, an element of F.
  // Output: (x, y), a point on E.
  return (u: T): { x: T; y: T } => {
    // prettier-ignore
    let tv1, tv2, tv3, tv4, tv5, tv6, x, y;
    tv1 = F.sqr(u); // 1.  tv1 = u^2
    tv1 = F.mul(tv1, Z); // 2.  tv1 = Z * tv1
    tv2 = F.sqr(tv1); // 3.  tv2 = tv1^2
    tv2 = F.add(tv2, tv1); // 4.  tv2 = tv2 + tv1
    tv3 = F.add(tv2, F.ONE); // 5.  tv3 = tv2 + 1
    tv3 = F.mul(tv3, B); // 6.  tv3 = B * tv3
    tv4 = F.cmov(Z, F.neg(tv2), !F.eql(tv2, F.ZERO)); // 7.  tv4 = CMOV(Z, -tv2, tv2 != 0)
    tv4 = F.mul(tv4, A); // 8.  tv4 = A * tv4
    tv2 = F.sqr(tv3); // 9.  tv2 = tv3^2
    tv6 = F.sqr(tv4); // 10. tv6 = tv4^2
    tv5 = F.mul(tv6, A); // 11. tv5 = A * tv6
    tv2 = F.add(tv2, tv5); // 12. tv2 = tv2 + tv5
    tv2 = F.mul(tv2, tv3); // 13. tv2 = tv2 * tv3
    tv6 = F.mul(tv6, tv4); // 14. tv6 = tv6 * tv4
    tv5 = F.mul(tv6, B); // 15. tv5 = B * tv6
    tv2 = F.add(tv2, tv5); // 16. tv2 = tv2 + tv5
    x = F.mul(tv1, tv3); // 17.   x = tv1 * tv3
    const { isValid, value } = sqrtRatio(tv2, tv6); // 18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)
    y = F.mul(tv1, u); // 19.   y = tv1 * u  -> Z * u^3 * y1
    y = F.mul(y, value); // 20.   y = y * y1
    x = F.cmov(x, tv3, isValid); // 21.   x = CMOV(x, tv3, is_gx1_square)
    y = F.cmov(y, value, isValid); // 22.   y = CMOV(y, y1, is_gx1_square)
    const e1 = F.isOdd!(u) === F.isOdd!(y); // 23.  e1 = sgn0(u) == sgn0(y)
    y = F.cmov(F.neg(y), y, e1); // 24.   y = CMOV(-y, y, e1)
    const tv4_inv = FpInvertBatch(F, [tv4], true)[0];
    x = F.mul(x, tv4_inv); // 25.   x = x / tv4
    return { x, y };
  };
}
