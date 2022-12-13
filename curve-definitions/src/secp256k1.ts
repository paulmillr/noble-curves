/*! @noble/curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { sha256 } from '@noble/hashes/sha256';
import { mod, pow2 } from '@noble/curves/modular';
import { createCurve } from './_shortw_utils.js';

/**
 * secp256k1 definition with efficient square root and endomorphism.
 * Endomorphism works only for Koblitz curves with a == 0.
 * It improves efficiency:
 * Uses 2x less RAM, speeds up precomputation by 2x and ECDH / sign key recovery by 20%.
 * Should always be used for Jacobian's double-and-add multiplication.
 * For affines cached multiplication, it trades off 1/2 init time & 1/3 ram for 20% perf hit.
 * https://gist.github.com/paulmillr/eb670806793e84df628a7c434a873066
 */
const secp256k1P = BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f');
const secp256k1N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
const _1n = BigInt(1);
const _2n = BigInt(2);
const divNearest = (a: bigint, b: bigint) => (a + b / _2n) / b;
export const secp256k1 = createCurve(
  {
    a: 0n,
    b: 7n,
    // Field over which we'll do calculations. Verify with:
    // 2n ** 256n - 2n ** 32n - 2n ** 9n - 2n ** 8n - 2n ** 7n - 2n ** 6n - 2n ** 4n - 1n
    P: secp256k1P,
    // Curve order, total count of valid points in the field. Verify with:
    n: secp256k1N,
    // Base point (x, y) aka generator point
    Gx: BigInt('55066263022277343669578718895168534326250603453777594175500187360389116729240'),
    Gy: BigInt('32670510020758816978083085130507043184471273380659243275938904335757337482424'),
    h: BigInt(1),
    // noble-secp256k1 compat
    lowS: true,
    // Used to calculate y - the square root of y².
    // Exponentiates it to very big number (P+1)/4.
    // We are unwrapping the loop because it's 2x faster.
    // (P+1n/4n).toString(2) would produce bits [223x 1, 0, 22x 1, 4x 0, 11, 00]
    // We are multiplying it bit-by-bit
    sqrtMod: (x: bigint): bigint => {
      const P = secp256k1P;
      const _3n = BigInt(3);
      const _6n = BigInt(6);
      const _11n = BigInt(11);
      const _22n = BigInt(22);
      const _23n = BigInt(23);
      const _44n = BigInt(44);
      const _88n = BigInt(88);
      const b2 = (x * x * x) % P; // x^3, 11
      const b3 = (b2 * b2 * x) % P; // x^7
      const b6 = (pow2(b3, _3n, P) * b3) % P;
      const b9 = (pow2(b6, _3n, P) * b3) % P;
      const b11 = (pow2(b9, _2n, P) * b2) % P;
      const b22 = (pow2(b11, _11n, P) * b11) % P;
      const b44 = (pow2(b22, _22n, P) * b22) % P;
      const b88 = (pow2(b44, _44n, P) * b44) % P;
      const b176 = (pow2(b88, _88n, P) * b88) % P;
      const b220 = (pow2(b176, _44n, P) * b44) % P;
      const b223 = (pow2(b220, _3n, P) * b3) % P;
      const t1 = (pow2(b223, _23n, P) * b22) % P;
      const t2 = (pow2(t1, _6n, P) * b2) % P;
      return pow2(t2, _2n, P);
    },
    endo: {
      beta: BigInt('0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee'),
      splitScalar: (k: bigint) => {
        const n = secp256k1N;
        const a1 = BigInt('0x3086d221a7d46bcde86c90e49284eb15');
        const b1 = -_1n * BigInt('0xe4437ed6010e88286f547fa90abfe4c3');
        const a2 = BigInt('0x114ca50f7a8e2f3f657c1108d9d44cfd8');
        const b2 = a1;
        const POW_2_128 = BigInt('0x100000000000000000000000000000000');

        const c1 = divNearest(b2 * k, n);
        const c2 = divNearest(-b1 * k, n);
        let k1 = mod(k - c1 * a1 - c2 * a2, n);
        let k2 = mod(-c1 * b1 - c2 * b2, n);
        const k1neg = k1 > POW_2_128;
        const k2neg = k2 > POW_2_128;
        if (k1neg) k1 = n - k1;
        if (k2neg) k2 = n - k2;
        if (k1 > POW_2_128 || k2 > POW_2_128) {
          throw new Error('splitScalar: Endomorphism failed, k=' + k);
        }
        return { k1neg, k1, k2neg, k2 };
      },
    },
  },
  sha256
);
