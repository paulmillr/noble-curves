/*! @noble/curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { createCurve } from './_shortw_utils.js';
import { sha384 } from '@noble/hashes/sha512';

// https://www.secg.org/sec2-v2.pdf
// https://neuromancer.sk/std/nist/P-384
// prettier-ignore
export const P384 = createCurve({
  // Params: a, b
  a: BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc'),
  b: BigInt('0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef'),
  // Field over which we'll do calculations. Verify with:
  // 2n ** 384n - 2n ** 128n - 2n ** 96n + 2n ** 32n - 1n
  P: BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff'),
  // Curve order, total count of valid points in the field. Verify with:
  n: BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973'),
  // Base point (x, y) aka generator point
  Gx: BigInt('0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7'),
  Gy: BigInt('0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f'),
  h: BigInt(1),
  lowS: false,
} as const, sha384);
export const secp384r1 = P384;
