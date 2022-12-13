/*! @noble/curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { createCurve } from './_shortw_utils.js';
import { sha256 } from '@noble/hashes/sha256';

// https://www.secg.org/sec2-v2.pdf
// https://neuromancer.sk/std/nist/P-256
export const P256 = createCurve(
  {
    // Params: a, b
    a: BigInt('0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc'),
    b: BigInt('0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b'),
    // Field over which we'll do calculations. Verify with:
    // 2n ** 224n * (2n ** 32n - 1n) + 2n ** 192n + 2n ** 96n - 1n,
    P: BigInt('0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff'),
    // Curve order, total count of valid points in the field. Verify with:
    n: BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'),
    // Base point (x, y) aka generator point
    Gx: BigInt('0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'),
    Gy: BigInt('0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'),
    h: BigInt(1),
    lowS: false,
  } as const,
  sha256
);
export const secp256r1 = P256;
