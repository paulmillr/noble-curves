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
  randomBytes,
  validateObject,
  type CryptoKeys,
  type TArg,
  type TRet,
} from '../utils.ts';
import { createKeygen, type CurveLengths } from './curve.ts';
import { FieldWasm, type WasmField } from './field-wasm.ts';

const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);

/** Curve-specific hooks required to build one X25519/X448 helper. */
export type MontgomeryOpts = {
  /** Prime field modulus. */
  P: bigint;
  /** Optional byte-array field override. */
  Fp?: Readonly<WasmField>;
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
      Fp: 'object',
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
 *   adjustScalarBytes(bytes) {
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
  const { P, type, adjustScalarBytes, randomBytes: rand } = CURVE;
  const is25519 = type === 'x25519';
  if (!is25519 && type !== 'x448') throw new Error('invalid type');
  const randomBytes_ = rand === undefined ? randomBytes : rand;

  const montgomeryBits = is25519 ? 255 : 448;
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
  const Fp: Readonly<WasmField> =
    CURVE.Fp === undefined ? FieldWasm(P, { isLE: true }) : (CURVE.Fp as Readonly<WasmField>);
  if (Fp.ORDER !== P || Fp.BYTES !== fieldLen || Fp.isLE !== true)
    throw new Error('invalid Montgomery field override');
  const a24F = Fp.fromBigint(a24);
  const GuBytes = encodeU(Fp.fromBigint(Gu));
  function encodeU(u: Uint8Array): TRet<Uint8Array> {
    return Fp.toBytes(u) as TRet<Uint8Array>;
  }
  function decodeU(u: TArg<Uint8Array>): Uint8Array {
    const _u = copyBytes(abytes(u, fieldLen, 'uCoordinate'));
    // RFC: When receiving such an array, implementations of X25519
    // (but not X448) MUST mask the most significant bit in the final byte.
    if (is25519) _u[31] &= 127; // 0b0111_1111
    // RFC: Implementations MUST accept non-canonical values and process them as
    // if they had been reduced modulo the field prime.  The non-canonical
    // values are 2^255 - 19 through 2^255 - 1 for X25519 and 2^448 - 2^224
    // - 1 through 2^448 - 1 for X448.
    return Fp.fromBigint(bytesToNumberLE(_u));
  }
  function decodeScalar(scalar: TArg<Uint8Array>): bigint {
    return bytesToNumberLE(adjustScalarBytes(copyBytes(abytes(scalar, fieldLen, 'scalar'))));
  }
  function scalarMult(scalar: TArg<Uint8Array>, u: TArg<Uint8Array>): TRet<Uint8Array> {
    const pu = montgomeryLadder(decodeU(u), decodeScalar(scalar));
    // Some public keys are useless, of low-order. Curve author doesn't think
    // it needs to be validated, but we do it nonetheless.
    // https://cr.yp.to/ecdh.html#validate
    if (Fp.is0(pu)) throw new Error('invalid private or public key received');
    return encodeU(pu);
  }
  // Computes public key from private. By doing scalar multiplication of base point.
  function scalarMultBase(scalar: TArg<Uint8Array>): TRet<Uint8Array> {
    return scalarMult(scalar, GuBytes);
  }
  const getPublicKey = scalarMultBase;
  const getSharedSecret = scalarMult;

  // cswap from RFC7748 "example code"
  function cswap(swap: bigint, x_2: Uint8Array, x_3: Uint8Array): void {
    const mask = -Number(swap === _1n);
    for (let i = 0; i < x_2.length; i++) {
      const t = mask & (x_2[i] ^ x_3[i]);
      x_2[i] ^= t;
      x_3[i] ^= t;
    }
  }

  /**
   * Montgomery x-only multiplication ladder for the selected X25519/X448 curve.
   * @param pointU - decoded Montgomery u coordinate for the selected curve
   * @param scalar - decoded clamped scalar by which the point is multiplied
   * @returns resulting Montgomery u coordinate for the selected curve
   */
  function montgomeryLadder(u: Uint8Array, scalar: bigint): Uint8Array {
    aInRange('scalar', scalar, minScalar, maxScalar);
    const k = scalar;
    const x_1 = u;
    let x_2 = Fp.ONE;
    let z_2 = Fp.ZERO;
    let x_3: Uint8Array = new Uint8Array(u);
    let z_3 = Fp.ONE;
    let swap = _0n;
    for (let t = BigInt(montgomeryBits - 1); t >= _0n; t--) {
      const k_t = (k >> t) & _1n;
      swap ^= k_t;
      cswap(swap, x_2, x_3);
      cswap(swap, z_2, z_3);
      swap = k_t;

      const A = Fp.add(x_2, z_2);
      const AA = Fp.sqr(A);
      const B = Fp.sub(x_2, z_2);
      const BB = Fp.sqr(B);
      const E = Fp.sub(AA, BB);
      const C = Fp.add(x_3, z_3);
      const D = Fp.sub(x_3, z_3);
      const DA = Fp.mul(D, A);
      const CB = Fp.mul(C, B);
      const dacb = Fp.add(DA, CB);
      const da_cb = Fp.sub(DA, CB);
      x_3 = Fp.sqr(dacb);
      z_3 = Fp.mul(x_1, Fp.sqr(da_cb));
      x_2 = Fp.mul(AA, BB);
      z_2 = Fp.mul(E, Fp.add(AA, Fp.mul(a24F, E)));
    }
    cswap(swap, x_2, x_3);
    cswap(swap, z_2, z_3);
    const isZero = Fp.is0(z_2);
    const zInv = Fp.inv(Fp.cmov(z_2, Fp.ONE, isZero));
    return Fp.cmov(Fp.mul(x_2, zInv), Fp.ZERO, isZero); // Return x_2 * (z_2^(p - 2))
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
