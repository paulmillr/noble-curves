/*! @noble/curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { createCurve } from './_shortw_utils.js';
import { sha256 } from '@noble/hashes/sha256';

// https://www.secg.org/sec2-v2.pdf
// https://neuromancer.sk/std/nist/P-224
export const P224 = createCurve(
  {
    // Params: a, b
    a: BigInt('0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe'),
    b: BigInt('0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4'),
    // Field over which we'll do calculations. Verify with:
    P: 2n ** 224n - 2n ** 96n + 1n,
    // Curve order, total count of valid points in the field. Verify with:
    n: BigInt('0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d'),
    // Base point (x, y) aka generator point
    Gx: BigInt('0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21'),
    Gy: BigInt('0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34'),
    h: BigInt(1),
    lowS: false,
  } as const,
  sha256 // TODO: replace with sha224 when new @noble/hashes released
);
export const secp224r1 = P224;
