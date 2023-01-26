/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { mod, pow } from './modular.js';
import { ensureBytes, numberToBytesLE, bytesToNumberLE } from './utils.js';

const _0n = BigInt(0);
const _1n = BigInt(1);
type Hex = string | Uint8Array;

export type CurveType = {
  // Field over which we'll do calculations. Verify with:
  P: bigint;
  nByteLength: number;
  adjustScalarBytes?: (bytes: Uint8Array) => Uint8Array;
  domain?: (data: Uint8Array, ctx: Uint8Array, phflag: boolean) => Uint8Array;
  a24: bigint; // Related to d, but cannot be derived from it
  montgomeryBits: number;
  powPminus2?: (x: bigint) => bigint;
  xyToU?: (x: bigint, y: bigint) => bigint;
  Gu: string;
};
export type CurveFn = {
  scalarMult: (scalar: Hex, u: Hex) => Uint8Array;
  scalarMultBase: (scalar: Hex) => Uint8Array;
  getSharedSecret: (privateKeyA: Hex, publicKeyB: Hex) => Uint8Array;
  getPublicKey: (privateKey: Hex) => Uint8Array;
  Gu: string;
};

function validateOpts(curve: CurveType) {
  for (const i of ['a24'] as const) {
    if (typeof curve[i] !== 'bigint')
      throw new Error(`Invalid curve param ${i}=${curve[i]} (${typeof curve[i]})`);
  }
  for (const i of ['montgomeryBits', 'nByteLength'] as const) {
    if (curve[i] === undefined) continue; // Optional
    if (!Number.isSafeInteger(curve[i]))
      throw new Error(`Invalid curve param ${i}=${curve[i]} (${typeof curve[i]})`);
  }
  for (const fn of ['adjustScalarBytes', 'domain', 'powPminus2'] as const) {
    if (curve[fn] === undefined) continue; // Optional
    if (typeof curve[fn] !== 'function') throw new Error(`Invalid ${fn} function`);
  }
  for (const i of ['Gu'] as const) {
    if (curve[i] === undefined) continue; // Optional
    if (typeof curve[i] !== 'string')
      throw new Error(`Invalid curve param ${i}=${curve[i]} (${typeof curve[i]})`);
  }
  // Set defaults
  return Object.freeze({ ...curve } as const);
}

// NOTE: not really montgomery curve, just bunch of very specific methods for X25519/X448 (RFC 7748, https://www.rfc-editor.org/rfc/rfc7748)
// Uses only one coordinate instead of two
export function montgomery(curveDef: CurveType): CurveFn {
  const CURVE = validateOpts(curveDef);
  const { P } = CURVE;
  const modP = (a: bigint) => mod(a, P);
  const montgomeryBits = CURVE.montgomeryBits;
  const montgomeryBytes = Math.ceil(montgomeryBits / 8);
  const fieldLen = CURVE.nByteLength;
  const adjustScalarBytes = CURVE.adjustScalarBytes || ((bytes: Uint8Array) => bytes);
  const powPminus2 = CURVE.powPminus2 || ((x: bigint) => pow(x, P - BigInt(2), P));

  /**
   * Checks for num to be in range:
   * For strict == true:  `0 <  num < max`.
   * For strict == false: `0 <= num < max`.
   * Converts non-float safe numbers to bigints.
   */
  function normalizeScalar(num: bigint, max: bigint, strict = true): bigint {
    if (!max) throw new TypeError('Specify max value');
    if (typeof num === 'number' && Number.isSafeInteger(num)) num = BigInt(num);
    if (typeof num === 'bigint' && num < max) {
      if (strict) {
        if (_0n < num) return num;
      } else {
        if (_0n <= num) return num;
      }
    }
    throw new TypeError('Expected valid scalar: 0 < scalar < max');
  }

  // cswap from RFC7748
  // NOTE: cswap is not from RFC7748!
  /*
    cswap(swap, x_2, x_3):
         dummy = mask(swap) AND (x_2 XOR x_3)
         x_2 = x_2 XOR dummy
         x_3 = x_3 XOR dummy
         Return (x_2, x_3)
  Where mask(swap) is the all-1 or all-0 word of the same length as x_2
   and x_3, computed, e.g., as mask(swap) = 0 - swap.
  */
  function cswap(swap: bigint, x_2: bigint, x_3: bigint): [bigint, bigint] {
    const dummy = modP(swap * (x_2 - x_3));
    x_2 = modP(x_2 - dummy);
    x_3 = modP(x_3 + dummy);
    return [x_2, x_3];
  }

  // x25519 from 4
  /**
   *
   * @param pointU u coordinate (x) on Montgomery Curve 25519
   * @param scalar by which the point would be multiplied
   * @returns new Point on Montgomery curve
   */
  function montgomeryLadder(pointU: bigint, scalar: bigint): bigint {
    const { P } = CURVE;
    const u = normalizeScalar(pointU, P);
    // Section 5: Implementations MUST accept non-canonical values and process them as
    // if they had been reduced modulo the field prime.
    const k = normalizeScalar(scalar, P);
    // The constant a24 is (486662 - 2) / 4 = 121665 for curve25519/X25519
    const a24 = CURVE.a24;
    const x_1 = u;
    let x_2 = _1n;
    let z_2 = _0n;
    let x_3 = u;
    let z_3 = _1n;
    let swap = _0n;
    let sw: [bigint, bigint];
    for (let t = BigInt(montgomeryBits - 1); t >= _0n; t--) {
      const k_t = (k >> t) & _1n;
      swap ^= k_t;
      sw = cswap(swap, x_2, x_3);
      x_2 = sw[0];
      x_3 = sw[1];
      sw = cswap(swap, z_2, z_3);
      z_2 = sw[0];
      z_3 = sw[1];
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
    // (x_2, x_3) = cswap(swap, x_2, x_3)
    sw = cswap(swap, x_2, x_3);
    x_2 = sw[0];
    x_3 = sw[1];
    // (z_2, z_3) = cswap(swap, z_2, z_3)
    sw = cswap(swap, z_2, z_3);
    z_2 = sw[0];
    z_3 = sw[1];
    // z_2^(p - 2)
    const z2 = powPminus2(z_2);
    // Return x_2 * (z_2^(p - 2))
    return modP(x_2 * z2);
  }

  function encodeUCoordinate(u: bigint): Uint8Array {
    return numberToBytesLE(modP(u), montgomeryBytes);
  }

  function decodeUCoordinate(uEnc: Hex): bigint {
    const u = ensureBytes(uEnc, montgomeryBytes);
    // Section 5: When receiving such an array, implementations of X25519
    // MUST mask the most significant bit in the final byte.
    // This is very ugly way, but it works because fieldLen-1 is outside of bounds for X448, so this becomes NOOP
    // fieldLen - scalaryBytes = 1 for X448 and = 0 for X25519
    u[fieldLen - 1] &= 127; // 0b0111_1111
    return bytesToNumberLE(u);
  }

  function decodeScalar(n: Hex): bigint {
    const bytes = ensureBytes(n);
    if (bytes.length !== montgomeryBytes && bytes.length !== fieldLen)
      throw new Error(`Expected ${montgomeryBytes} or ${fieldLen} bytes, got ${bytes.length}`);
    return bytesToNumberLE(adjustScalarBytes(bytes));
  }
  /**
   * Computes shared secret between private key "scalar" and public key's "u" (x) coordinate.
   * We can get 'y' coordinate from 'u',
   * but Point.fromHex also wants 'x' coordinate oddity flag,
   * and we cannot get 'x' without knowing 'v'.
   * Need to add generic conversion between twisted edwards and complimentary curve for JubJub.
   */
  function scalarMult(scalar: Hex, u: Hex): Uint8Array {
    const pointU = decodeUCoordinate(u);
    const _scalar = decodeScalar(scalar);
    const pu = montgomeryLadder(pointU, _scalar);
    // The result was not contributory
    // https://cr.yp.to/ecdh.html#validate
    if (pu === _0n) throw new Error('Invalid private or public key received');
    return encodeUCoordinate(pu);
  }
  /**
   * Computes public key from private.
   * Executes scalar multiplication of curve's base point by scalar.
   * @param scalar private key
   * @returns new public key
   */
  function scalarMultBase(scalar: Hex): Uint8Array {
    return scalarMult(scalar, CURVE.Gu);
  }

  return {
    scalarMult,
    scalarMultBase,
    getSharedSecret: (privateKey: Hex, publicKey: Hex) => scalarMult(privateKey, publicKey),
    getPublicKey: (privateKey: Hex): Uint8Array => scalarMultBase(privateKey),
    Gu: CURVE.Gu,
  };
}
