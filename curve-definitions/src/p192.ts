/*! @noble/curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { createCurve } from './_shortw_utils.js';
import { sha256 } from '@noble/hashes/sha256';
import { Fp } from '@noble/curves/modular';

// NIST secp192r1 aka P192
// https://www.secg.org/sec2-v2.pdf, https://neuromancer.sk/std/secg/secp192r1
export const P192 = createCurve(
  {
    // Params: a, b
    a: BigInt('0xfffffffffffffffffffffffffffffffefffffffffffffffc'),
    b: BigInt('0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1'),
    // Field over which we'll do calculations; 2n ** 192n - 2n ** 64n - 1n
    Fp: Fp(BigInt('0xfffffffffffffffffffffffffffffffeffffffffffffffff')),
    // Curve order, total count of valid points in the field.
    n: BigInt('0xffffffffffffffffffffffff99def836146bc9b1b4d22831'),
    // Base point (x, y) aka generator point
    Gx: BigInt('0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012'),
    Gy: BigInt('0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811'),
    h: BigInt(1),
    lowS: false,
  } as const,
  sha256
);
export const secp192r1 = P192;
