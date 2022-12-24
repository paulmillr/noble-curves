/*! @noble/curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { createCurve } from './_shortw_utils.js';
import { Fp } from '@noble/curves/modular';
import { sha512 } from '@noble/hashes/sha512';
import { bytesToHex, PrivKey } from '@noble/curves/utils';

// NIST secp521r1 aka P521
// Note that it's 521, which differs from 512 of its hash function.
// https://www.secg.org/sec2-v2.pdf, https://neuromancer.sk/std/nist/P-521
// prettier-ignore
export const P521 = createCurve({
  // Params: a, b
  a: BigInt('0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc'),
  b: BigInt('0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00'),
  // Field over which we'll do calculations; 2n**521n - 1n
  Fp: Fp(BigInt('0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')),
  // Curve order, total count of valid points in the field
  n: BigInt('0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409'),
  // Base point (x, y) aka generator point
  Gx: BigInt('0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66'),
  Gy: BigInt('0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650'),
  h: BigInt(1),
  lowS: false,
  normalizePrivateKey(key: PrivKey) {
    if (typeof key === 'bigint') return key;
    if (key instanceof Uint8Array) key = bytesToHex(key);
    if (typeof key !== 'string' || !([130, 131, 132].includes(key.length))) {
      throw new Error('Invalid key');
    }
    return key.padStart(66 * 2, '0');
  }
} as const, sha512);
export const secp521r1 = P521;
