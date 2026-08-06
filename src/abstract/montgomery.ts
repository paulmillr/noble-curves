/**
 * Montgomery curve methods. It's not really whole montgomery curve,
 * just bunch of very specific methods for X25519 / X448 from
 * [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import {
  abytes,
  aInRange,
  bytesToNumberLE,
  copyBytes,
  numberToBytesLE,
  randomBytes,
  validateObject,
  type CryptoKeys,
  type TArg,
  type TRet,
} from '../utils.ts';
import { createKeygen, type CurveLengths } from './curve.ts';
import { mod } from './modular.ts';

const _0n = /* @__PURE__ */ BigInt(0);
const _1n = /* @__PURE__ */ BigInt(1);
const _2n = /* @__PURE__ */ BigInt(2);

/** Curve-specific hooks required to build one X25519/X448 helper. */
export type MontgomeryOpts = {
  /** Prime field modulus. */
  P: bigint;
  /** RFC 7748 variant name. */
  type: 'x25519' | 'x448';
  /**
   * Clamp or otherwise normalize one scalar byte string before use.
   * @param bytes - Raw secret scalar bytes.
   * @returns Adjusted scalar bytes ready for Montgomery multiplication.
   */
  adjustScalarBytes: (bytes: TArg<Uint8Array>) => TRet<Uint8Array>;
  /**
   * Invert one field element with exponentiation by `p - 2`.
   * @param x - Field element to invert.
   * @returns Multiplicative inverse of `x`.
   */
  powPminus2: (x: bigint) => bigint;
  /**
   * Optional randomness source for `keygen()` and `utils.randomSecretKey()`.
   * @param bytesLength - Requested byte length.
   * @returns Random bytes.
   */
  randomBytes?: (bytesLength?: number) => TRet<Uint8Array>;
  /**
   * Optional fast fixed-base multiplication, replacing the Montgomery ladder in
   * `scalarMultBase()` / `getPublicKey()` only. Standard implementation computes `[k]B` on the
   * equivalent Edwards curve with cached base-point tables and maps the result back to a
   * Montgomery `u` coordinate (libsodium does the same for X25519); ~3x faster than the ladder.
   * @param k - Decoded, clamped scalar; guaranteed to be in the RFC 7748 clamped range.
   * @returns `u([k]G)` as an integer. Must return `0` when `[k]G` is the point at infinity
   *   (`k ≡ 0 mod n`) so the caller can reject it exactly like the ladder path does.
   */
  scalarMultBase?: (k: bigint) => bigint;
};

/** Public X25519/X448 ECDH API built on a Montgomery ladder. */
export type MontgomeryECDH = {
  /**
   * Multiply one scalar by one Montgomery `u` coordinate.
   * @param scalar - Secret scalar bytes.
   * @param u - Public Montgomery `u` coordinate.
   * @returns Shared point encoded as bytes.
   */
  scalarMult: (scalar: TArg<Uint8Array>, u: TArg<Uint8Array>) => TRet<Uint8Array>;
  /**
   * Multiply one scalar by the curve base point.
   * @param scalar - Secret scalar bytes.
   * @returns Public key bytes.
   */
  scalarMultBase: (scalar: TArg<Uint8Array>) => TRet<Uint8Array>;
  /**
   * Derive a shared secret from a local secret key and peer public key.
   * @param secretKeyA - Local secret key bytes.
   * @param publicKeyB - Peer public key bytes.
   * Rejects low-order public inputs instead of returning the all-zero shared secret.
   * @returns Shared secret bytes.
   */
  getSharedSecret: (secretKeyA: TArg<Uint8Array>, publicKeyB: TArg<Uint8Array>) => TRet<Uint8Array>;
  /**
   * Derive one public key from a secret key.
   * @param secretKey - Secret key bytes.
   * @returns Public key bytes.
   */
  getPublicKey: (secretKey: TArg<Uint8Array>) => TRet<Uint8Array>;
  /** Utility helpers for secret-key generation. */
  utils: {
    /** Generate one random secret key with the curve's expected byte length. */
    randomSecretKey: () => TRet<Uint8Array>;
  };
  /** Encoded Montgomery base point `u`. */
  GuBytes: TRet<Uint8Array>;
  /** Public lengths for keys and seeds. */
  lengths: CurveLengths;
  /**
   * Generate one random secret/public keypair.
   * @param seed - Optional seed bytes to use instead of random generation.
   * @returns Fresh secret/public keypair.
   */
  keygen: (seed?: TArg<Uint8Array>) => {
    secretKey: TRet<Uint8Array>;
    publicKey: TRet<Uint8Array>;
  };
};

// cswap from RFC7748 "example code", adapted to BigInt.
//
// RFC: "dummy = mask(swap) AND (x_2 XOR x_3), where mask(swap) is the all-1 or all-0 word of the
// same length as x_2 and x_3". On fixed-width machine words both cases cost the same. BigInt has
// no fixed width, so a {0n, 1n} selector does not: V8 short-circuits `0n * v` - and, identically,
// `0n & v`, `v + 0n`, `v - 0n` - to a no-op, while `1n * v` is a real multiply. The ladder calls
// this with swap = k_t XOR k_(t+1), which would make total running time a linear function of how
// often adjacent bits of the secret scalar differ: remotely measurable, and worth ~4 bits of a
// long-term key.
//
// So select with a full-width mask instead, and interpolate rather than mask off a dummy.

/**
 * Selector for cswap(): `P` to keep, `P + 1` to swap, chosen by the low bit of `swap`.
 * Higher bits are ignored, and `swap` is passed in whole rather than as a {0n, 1n} bit on
 * purpose: `P + (swap & _1n)` would short-circuit the addition whenever the bit is clear, which
 * is the very leak this construction avoids, one round-trip further down. Subtracting `swap`
 * with its low bit cleared keeps every operand full-width instead.
 * @param P - Field modulus.
 * @param swap - Value whose low bit selects; ignored above that bit.
 * @returns `P` when the low bit is clear, `P + 1` when it is set.
 */
function cmask(P: bigint, swap: bigint): bigint {
  return P + swap - ((swap >> _1n) << _1n);
}

/**
 * Swap two field elements when `mask` is `P + 1`, keep them when it is `P`:
 *
 *   d    = 6P + x_3 - x_2
 *   x_2' = d * mask + x_2   (mod P)      x_3' = (x_2 + x_3) - x_2'
 *
 * The extra `6P * mask` vanishes modulo P, so `mask === P` leaves x_2 and `mask === P + 1`
 * leaves x_3. Without the offset, the reduction dividend changes sign with input order and crosses
 * BigInt limb boundaries; those classes measured differently on the tested Node/V8 build. For
 * canonical inputs, the deliberately left-associative `offset + x_3 - x_2` is between 5P and 7P,
 * keeping the dividend positive and in one word-count band for both RFC fields and masks. Six is
 * the smallest coefficient `c` for which the shared offset `cP` has that property.
 *
 * This reduced the tested sign/size timing ratios, but JavaScript BigInt has no constant-time
 * contract and the contents of the multiply and remainder still vary. Valid ladder states can
 * contain genuine zero coordinates; this construction does not mask those value-shape effects.
 * Computing `x_3'` independently as `((6P + x_2 - x_3) * mask + x_3) % P` is more symmetric.
 * On the tested Node/V8 build, it reduced the timing difference between keeping `(0, v)` and
 * swapping `(v, 0)`—both return `(0, v)`—from about 10%/13% for X25519/X448 to about 3%.
 * Successful calls cannot reach that zero-in-the-first-output case. For the case they can reach,
 * swapping `(0, v)` and keeping `(v, 0)` both return `(v, 0)`; the difference instead grew from
 * about 0.7%/1.1% to 2.7%/2.8%. The extra multiply/remainder also made public
 * `getSharedSecret()` about 16% slower. The retained one-remainder form measured about 2.5%
 * slower than the prior helper for public X25519 `getSharedSecret()` in the same environment.
 * x_3' falls out of the sum, which a swap leaves invariant: no second multiply or reduction is
 * needed. Bind `6P` once per field so production and the timing regression exercise the same
 * configured helper without paying for the multiplication in every ladder round.
 *
 * The returned function is called twice per ladder round, so it validates nothing. Both elements
 * MUST already be reduced mod P; unreduced input silently corrupts the kept-side output.
 * @param P - Field modulus.
 * @returns A field-bound swap function taking mask, x_2, and x_3.
 */
function cswap(
  P: bigint
): (mask: bigint, x_2: bigint, x_3: bigint) => { x_2: bigint; x_3: bigint } {
  const offset = BigInt(6) * P;
  return (mask: bigint, x_2: bigint, x_3: bigint): { x_2: bigint; x_3: bigint } => {
    const sum = x_2 + x_3;
    const d = offset + x_3 - x_2;
    const a = (d * mask + x_2) % P;
    return { x_2: a, x_3: sum - a };
  };
}

/** Internal helpers, exported for tests only. Not part of the public API. */
export const __TEST: { cmask: typeof cmask; cswap: typeof cswap } = /* @__PURE__ */ Object.freeze({
  cmask,
  cswap,
});

function validateOpts(curve: TArg<MontgomeryOpts>) {
  // Validate constructor config eagerly, but do not call user-provided hooks here:
  // `randomBytes` may be transcript-backed or otherwise contextual. Runtime type checks are
  // enough to fail fast on malformed configs without consuming user state.
  validateObject(
    curve,
    {
      P: 'bigint',
      type: 'string',
      adjustScalarBytes: 'function',
      powPminus2: 'function',
    },
    {
      randomBytes: 'function',
      scalarMultBase: 'function',
    }
  );
  return Object.freeze({ ...curve } as const);
}

/**
 * @param curveDef - Montgomery curve definition.
 * @returns ECDH helper namespace.
 * @throws If the curve definition or derived shared point is invalid. {@link Error}
 * @example
 * Build an X25519 helper from curve parameters, then derive one public key.
 *
 * ```ts
 * import { montgomery } from '@noble/curves/abstract/montgomery.js';
 * const P = 2n ** 255n - 19n;
 * const mod = (num: bigint) => {
 *   const out = num % P;
 *   return out >= 0n ? out : out + P;
 * };
 * const pow = (num: bigint, power: bigint) => {
 *   let res = 1n;
 *   for (; power > 0n; power >>= 1n) {
 *     if (power & 1n) res = mod(res * num);
 *     num = mod(num * num);
 *   }
 *   return res;
 * };
 * const x25519 = montgomery({
 *   P,
 *   type: 'x25519',
 *   adjustScalarBytes(bytes: Uint8Array) {
 *     bytes[0] &= 248;
 *     bytes[31] &= 127;
 *     bytes[31] |= 64;
 *     return bytes;
 *   },
 *   powPminus2(x) {
 *     return pow(x, P - 2n);
 *   },
 * });
 * const publicKey = x25519.getPublicKey(new Uint8Array(32).fill(1));
 * ```
 */
export function montgomery(curveDef: TArg<MontgomeryOpts>): TRet<MontgomeryECDH> {
  const CURVE = validateOpts(curveDef);
  const { P, type, adjustScalarBytes, powPminus2, randomBytes: rand } = CURVE;
  const mulBaseHook = CURVE.scalarMultBase;
  const is25519 = type === 'x25519';
  if (!is25519 && type !== 'x448') throw new Error('invalid type');
  const randomBytes_ = rand === undefined ? randomBytes : rand;

  const montgomeryBits = is25519 ? 255 : 448;
  const swap = cswap(P);
  const fieldLen = is25519 ? 32 : 56;
  const Gu = is25519 ? BigInt(9) : BigInt(5);
  // RFC 7748 #5:
  // The constant a24 is (486662 - 2) / 4 = 121665 for curve25519/X25519 and
  // (156326 - 2) / 4 = 39081 for curve448/X448
  // const a = is25519 ? 486662n : 156326n;
  const a24 = is25519 ? BigInt(121665) : BigInt(39081);
  // RFC: x25519 "the resulting integer is of the form 2^254 plus
  // eight times a value between 0 and 2^251 - 1 (inclusive)"
  // x448: "2^447 plus four times a value between 0 and 2^445 - 1 (inclusive)"
  const minScalar = is25519 ? _2n ** BigInt(254) : _2n ** BigInt(447);
  const maxAdded = is25519
    ? BigInt(8) * (_2n ** BigInt(251) - _1n)
    : BigInt(4) * (_2n ** BigInt(445) - _1n);
  const maxScalar = minScalar + maxAdded + _1n; // (inclusive)
  const modP = (n: bigint) => mod(n, P);
  const GuBytes = encodeU(Gu);
  function encodeU(u: bigint): TRet<Uint8Array> {
    return numberToBytesLE(modP(u), fieldLen);
  }
  function decodeU(u: TArg<Uint8Array>): bigint {
    const _u = copyBytes(abytes(u, fieldLen, 'uCoordinate'));
    // RFC: When receiving such an array, implementations of X25519
    // (but not X448) MUST mask the most significant bit in the final byte.
    if (is25519) _u[31] &= 127; // 0b0111_1111
    // RFC: Implementations MUST accept non-canonical values and process them as
    // if they had been reduced modulo the field prime.  The non-canonical
    // values are 2^255 - 19 through 2^255 - 1 for X25519 and 2^448 - 2^224
    // - 1 through 2^448 - 1 for X448.
    return modP(bytesToNumberLE(_u));
  }
  function decodeScalar(scalar: TArg<Uint8Array>): bigint {
    return bytesToNumberLE(adjustScalarBytes(copyBytes(abytes(scalar, fieldLen, 'scalar'))));
  }
  /**
   * u coordinates whose order divides the cofactor, on the curve and on its quadratic twist -
   * the ladder sends every one of them to zero. Same blocklist libsodium and post-CVE-2017-0379
   * Libgcrypt carry. decodeU() reduces mod P first, so the non-canonical encodings P and P + 1
   * collapse onto 0 and 1, and `type` admits no curve beyond these two, so both lists are total.
   *
   * Complete by construction: x-only doubling sends u to (u^2 - 1)^2 / 4u(u^2 + a*u + 1). Order 4
   * therefore needs (u^2 - 1)^2 === 0, i.e. u = +-1; order 2 needs u(u^2 + a*u + 1) === 0, and
   * a^2 - 4 is a non-residue on both curves, leaving u = 0. curve448 stops there (cofactor 4);
   * curve25519 (cofactor 8) adds the two order-8 roots below. Cross-checked by clearing the
   * cofactor with those same doublings over 200k random u: no sixth value exists.
   */
  const lowOrderU = new Set(
    is25519
      ? [
          _0n,
          _1n,
          P - _1n,
          BigInt('325606250916557431795983626356110631294008115727848805560023387167927233504'),
          BigInt('39382357235489614581723060781553021112529911719440698176882885853963445705823'),
        ]
      : [_0n, _1n, P - _1n]
  );
  function scalarMult(scalar: TArg<Uint8Array>, u: TArg<Uint8Array>): TRet<Uint8Array> {
    // Some public keys are useless, of low-order. Curve author doesn't think
    // it needs to be validated, but we do it nonetheless.
    // https://cr.yp.to/ecdh.html#validate
    //
    // Reject them BEFORE the ladder. RFC 7748 #6.1 also permits detecting them from the
    // all-zero output, but that first runs all 255 rounds against the long-term secret,
    // handing an unauthenticated attacker a free timing oracle. Low-order inputs also drive
    // the ladder into a degenerate state (x_2 + z_2 === 0) whose extra zero-operand
    // multiplications amplify any residual key-dependent timing.
    const pointU = decodeU(u);
    if (lowOrderU.has(pointU)) throw new Error('invalid private or public key received');
    const pu = montgomeryLadder(pointU, decodeScalar(scalar));
    // Unreachable for RFC 7748 clamped scalars, which are cofactor multiples smaller than the
    // group order; kept because adjustScalarBytes is caller-supplied.
    if (pu === _0n) throw new Error('invalid private or public key received');
    return encodeU(pu);
  }
  // Computes public key from private. By doing scalar multiplication of base point.
  // With a curve-provided fixed-base hook (Edwards tables), the ladder is skipped, but the
  // contract — scalar validation, low-order rejection, encoding — stays identical.
  function scalarMultBase(scalar: TArg<Uint8Array>): TRet<Uint8Array> {
    if (mulBaseHook === undefined) return scalarMult(scalar, GuBytes);
    const k = decodeScalar(scalar);
    aInRange('scalar', k, minScalar, maxScalar);
    const pu = modP(mulBaseHook(k));
    if (pu === _0n) throw new Error('invalid private or public key received');
    return encodeU(pu);
  }
  const getPublicKey = scalarMultBase;
  const getSharedSecret = scalarMult;

  /**
   * Montgomery x-only multiplication ladder for the selected X25519/X448 curve.
   * @param pointU - decoded Montgomery u coordinate for the selected curve
   * @param scalar - decoded clamped scalar by which the point is multiplied
   * @returns resulting Montgomery u coordinate for the selected curve
   */
  function montgomeryLadder(u: bigint, scalar: bigint): bigint {
    aInRange('u', u, _0n, P);
    aInRange('scalar', scalar, minScalar, maxScalar);
    const k = scalar;
    const x_1 = u;
    let x_2 = _1n;
    let z_2 = _0n;
    let x_3 = u;
    let z_3 = _1n;
    // The RFC tracks `swap` across rounds to hold k_t XOR k_(t+1); the low bit of `kx >> t` is
    // the same value, without the carried state. aInRange above pins bit (montgomeryBits - 1)
    // of k set and everything above it clear, so `kx >> t` is never zero and its width is a
    // function of t alone - never of a secret bit.
    const kx = k ^ (k >> _1n);
    for (let t = BigInt(montgomeryBits - 1); t >= _0n; t--) {
      const mask = cmask(P, kx >> t);
      ({ x_2, x_3 } = swap(mask, x_2, x_3));
      ({ x_2: z_2, x_3: z_3 } = swap(mask, z_2, z_3));

      const A = x_2 + z_2;
      const AA = modP(A * A);
      const B = x_2 - z_2;
      const BB = modP(B * B);
      const E = AA - BB;
      const C = x_3 + z_3;
      const D = x_3 - z_3;
      const DA = modP(D * A);
      const CB = modP(C * B);
      const dacb = DA + CB;
      const da_cb = DA - CB;
      x_3 = modP(dacb * dacb);
      z_3 = modP(x_1 * modP(da_cb * da_cb));
      x_2 = modP(AA * BB);
      z_2 = modP(E * (AA + modP(a24 * E)));
    }
    // trailing cswap: the RFC's `swap` holds k_0 here, which is the low bit of k
    const mask = cmask(P, k);
    ({ x_2, x_3 } = swap(mask, x_2, x_3));
    ({ x_2: z_2, x_3: z_3 } = swap(mask, z_2, z_3));
    const z2 = powPminus2(z_2); // `Fp.pow(x, P - _2n)` is much slower equivalent
    return modP(x_2 * z2); // Return x_2 * (z_2^(p - 2))
  }
  const lengths = {
    secretKey: fieldLen,
    publicKey: fieldLen,
    seed: fieldLen,
  };
  const randomSecretKey = (seed?: TArg<Uint8Array>): TRet<Uint8Array> => {
    seed = seed === undefined ? randomBytes_(fieldLen) : seed;
    abytes(seed, lengths.seed, 'seed');
    // Reuse caller-supplied seed bytes verbatim; clamping is deferred until
    // decodeScalar(...) when the secret key is actually used.
    return seed as TRet<Uint8Array>;
  };
  const utils = { randomSecretKey };
  Object.freeze(lengths);
  Object.freeze(utils);

  return Object.freeze({
    keygen: createKeygen(randomSecretKey, getPublicKey),
    getSharedSecret,
    getPublicKey,
    scalarMult,
    scalarMultBase,
    utils,
    GuBytes: GuBytes.slice() as TRet<Uint8Array>,
    lengths,
  }) satisfies CryptoKeys;
}
