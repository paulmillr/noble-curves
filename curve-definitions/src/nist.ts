/*! @noble/curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { sha384, sha512 } from '@noble/hashes/sha512';
import { concatBytes, randomBytes } from '@noble/hashes/utils';
import { weierstrass, CurveType, CHash } from '@noble/curves/shortw';
import { mod, pow2 } from '@noble/curves/modular';

// TODO: ability to provide API for different default hash.
// Wychenproof can help us here & test multiple hashes.

function getHash(hash: CHash) {
  return {
    hash,
    hmac: (key: Uint8Array, ...msgs: Uint8Array[]) => hmac(hash, key, concatBytes(...msgs)),
    randomBytes,
  };
}
// Same API as @noble/hashes, with ability to create curve with custom hash
type CurveDef = Readonly<Omit<CurveType, 'hash' | 'hmac' | 'randomBytes'>>;
function createCurve(curveDef: CurveDef, defHash: CHash) {
  const create = (hash: CHash) => weierstrass({ ...curveDef, ...getHash(hash) });
  return Object.freeze({ ...create(defHash), create });
}

// https://www.secg.org/sec2-v2.pdf
// https://neuromancer.sk/std/secg/secp192r1
export const P192 = createCurve(
  {
    // Params: a, b
    a: BigInt('0xfffffffffffffffffffffffffffffffefffffffffffffffc'),
    b: BigInt('0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1'),
    // Field over which we'll do calculations. Verify with: 2n ** 192n - 2n ** 64n - 1n
    P: BigInt('0xfffffffffffffffffffffffffffffffeffffffffffffffff'),
    // Curve order, total count of valid points in the field. Verify with:
    n: BigInt('0xffffffffffffffffffffffff99def836146bc9b1b4d22831'),
    // Base point (x, y) aka generator point
    Gx: BigInt('0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012'),
    Gy: BigInt('0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811'),
    lowS: false,
  } as const,
  sha256
);
export const secp192r1 = P192;
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
    lowS: false,
  } as const,
  sha256 // TODO: replace with sha224 when new @noble/hashes released
);
export const secp224r1 = P224;
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
    lowS: false,
  } as const,
  sha256
);
export const secp256r1 = P256;
// https://neuromancer.sk/std/nist/P-384
// prettier-ignore
export const P384 = createCurve(
  {
    // Params: a, b
    a: BigInt(
      '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc'
    ),
    b: BigInt(
      '0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef'
    ),
    // Field over which we'll do calculations. Verify with:
    // 2n ** 384n - 2n ** 128n - 2n ** 96n + 2n ** 32n - 1n
    P: BigInt(
      '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff'
    ),
    // Curve order, total count of valid points in the field. Verify with:
    n: BigInt(
      '0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973'
    ),
    // Base point (x, y) aka generator point
    Gx: BigInt(
      '0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7'
    ),
    Gy: BigInt(
      '0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f'
    ),
    lowS: false,
  } as const,
  sha384
);
export const secp384r1 = P384;
// https://neuromancer.sk/std/nist/P-521
// prettier-ignore
export const P521 = createCurve({
  // Params: a, b
  a: BigInt('0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc'),
  b: BigInt('0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00'),
  // Field over which we'll do calculations. Verify with:
  // 2n ** 521n - 1n,
  P: BigInt('0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'),
  // Curve order, total count of valid points in the field. Verify with:
  n: BigInt('0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409'),
  // Base point (x, y) aka generator point
  Gx: BigInt('0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66'),
  Gy: BigInt('0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650'),
  lowS: false,
} as const, sha512);
export const secp521r1 = P521;

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
