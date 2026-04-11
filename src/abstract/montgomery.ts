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

const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);

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
   * Receives the requested byte length and returns fresh random bytes.
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
    }
  );
  return Object.freeze({ ...curve } as const);
}

/**
 * @param curveDef - Montgomery curve definition.
 * @returns ECDH helper namespace.
 * @throws If the curve definition or derived shared point is invalid. {@link Error}
 * @example
 * Perform one X25519 key exchange through the generic Montgomery helper.
 *
 * ```ts
 * import { x25519 } from '@noble/curves/ed25519.js';
 * const alice = x25519.keygen();
 * const shared = x25519.getSharedSecret(alice.secretKey, alice.publicKey);
 * ```
 */
export function montgomery(curveDef: TArg<MontgomeryOpts>): TRet<MontgomeryECDH> {
  const CURVE = validateOpts(curveDef);
  const { P, type, adjustScalarBytes, powPminus2, randomBytes: rand } = CURVE;
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
    ? BigInt(8) * _2n ** BigInt(251) - _1n
    : BigInt(4) * _2n ** BigInt(445) - _1n;
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
  function scalarMult(scalar: TArg<Uint8Array>, u: TArg<Uint8Array>): TRet<Uint8Array> {
    const pu = montgomeryLadder(decodeU(u), decodeScalar(scalar));
    // Some public keys are useless, of low-order. Curve author doesn't think
    // it needs to be validated, but we do it nonetheless.
    // https://cr.yp.to/ecdh.html#validate
    if (pu === _0n) throw new Error('invalid private or public key received');
    return encodeU(pu);
  }
  // Computes public key from private. By doing scalar multiplication of base point.
  function scalarMultBase(scalar: TArg<Uint8Array>): TRet<Uint8Array> {
    return scalarMult(scalar, GuBytes);
  }
  const getPublicKey = scalarMultBase;
  const getSharedSecret = scalarMult;

  // cswap from RFC7748 "example code"
  function cswap(swap: bigint, x_2: bigint, x_3: bigint): { x_2: bigint; x_3: bigint } {
    // dummy = mask(swap) AND (x_2 XOR x_3)
    // Where mask(swap) is the all-1 or all-0 word of the same length as x_2
    // and x_3, computed, e.g., as mask(swap) = 0 - swap.
    const dummy = modP(swap * (x_2 - x_3));
    x_2 = modP(x_2 - dummy); // x_2 = x_2 XOR dummy
    x_3 = modP(x_3 + dummy); // x_3 = x_3 XOR dummy
    return { x_2, x_3 };
  }

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
    let swap = _0n;
    for (let t = BigInt(montgomeryBits - 1); t >= _0n; t--) {
      const k_t = (k >> t) & _1n;
      swap ^= k_t;
      ({ x_2, x_3 } = cswap(swap, x_2, x_3));
      ({ x_2: z_2, x_3: z_3 } = cswap(swap, z_2, z_3));
      swap = k_t;

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
    ({ x_2, x_3 } = cswap(swap, x_2, x_3));
    ({ x_2: z_2, x_3: z_3 } = cswap(swap, z_2, z_3));
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
