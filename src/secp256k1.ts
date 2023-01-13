/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { sha256 } from '@noble/hashes/sha256';
import { Fp as Field, mod, pow2 } from './abstract/modular.js';
import { createCurve } from './_shortw_utils.js';
import { PointType, mapToCurveSimpleSWU } from './abstract/weierstrass.js';
import {
  ensureBytes,
  concatBytes,
  Hex,
  hexToBytes,
  bytesToNumberBE,
  PrivKey,
} from './abstract/utils.js';
import { randomBytes } from '@noble/hashes/utils';
import { isogenyMap } from './abstract/hash-to-curve.js';

/**
 * secp256k1 belongs to Koblitz curves: it has efficiently computable endomorphism.
 * Endomorphism uses 2x less RAM, speeds up precomputation by 2x and ECDH / key recovery by 20%.
 * Should always be used for Projective's double-and-add multiplication.
 * For affines cached multiplication, it trades off 1/2 init time & 1/3 ram for 20% perf hit.
 * https://gist.github.com/paulmillr/eb670806793e84df628a7c434a873066
 */

const secp256k1P = BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f');
const secp256k1N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
const _1n = BigInt(1);
const _2n = BigInt(2);
const divNearest = (a: bigint, b: bigint) => (a + b / _2n) / b;

/**
 * Allows to compute square root √y 2x faster.
 * To calculate √y, we need to exponentiate it to a very big number:
 * `y² = x³ + ax + b; y = y² ^ (p+1)/4`
 * We are unwrapping the loop and multiplying it bit-by-bit.
 * (P+1n/4n).toString(2) would produce bits [223x 1, 0, 22x 1, 4x 0, 11, 00]
 */
function sqrtMod(y: bigint): bigint {
  const P = secp256k1P;
  // prettier-ignore
  const _3n = BigInt(3), _6n = BigInt(6), _11n = BigInt(11), _22n = BigInt(22);
  // prettier-ignore
  const _23n = BigInt(23), _44n = BigInt(44), _88n = BigInt(88);
  const b2 = (y * y * y) % P; // x^3, 11
  const b3 = (b2 * b2 * y) % P; // x^7
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
  const root = pow2(t2, _2n, P);
  if (!Fp.equals(Fp.square(root), y)) throw new Error('Cannot find square root');
  return root;
}

const Fp = Field(secp256k1P, undefined, undefined, { sqrt: sqrtMod });
type Fp = bigint;

const isoMap = isogenyMap(
  Fp,
  [
    // xNum
    [
      '0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa8c7',
      '0x7d3d4c80bc321d5b9f315cea7fd44c5d595d2fc0bf63b92dfff1044f17c6581',
      '0x534c328d23f234e6e2a413deca25caece4506144037c40314ecbd0b53d9dd262',
      '0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa88c',
    ],
    // xDen
    [
      '0xd35771193d94918a9ca34ccbb7b640dd86cd409542f8487d9fe6b745781eb49b',
      '0xedadc6f64383dc1df7c4b2d51b54225406d36b641f5e41bbc52a56612a8c6d14',
      '0x0000000000000000000000000000000000000000000000000000000000000001', // LAST 1
    ],
    // yNum
    [
      '0x4bda12f684bda12f684bda12f684bda12f684bda12f684bda12f684b8e38e23c',
      '0xc75e0c32d5cb7c0fa9d0a54b12a0a6d5647ab046d686da6fdffc90fc201d71a3',
      '0x29a6194691f91a73715209ef6512e576722830a201be2018a765e85a9ecee931',
      '0x2f684bda12f684bda12f684bda12f684bda12f684bda12f684bda12f38e38d84',
    ],
    // yDen
    [
      '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffff93b',
      '0x7a06534bb8bdb49fd5e9e6632722c2989467c1bfc8e8d978dfb425d2685c2573',
      '0x6484aa716545ca2cf3a70c3fa8fe337e0a3d21162f0d6299a7bf8192bfd2a76f',
      '0x0000000000000000000000000000000000000000000000000000000000000001', // LAST 1
    ],
  ].map((i) => i.map((j) => BigInt(j))) as [Fp[], Fp[], Fp[], Fp[]]
);

const mapSWU = mapToCurveSimpleSWU(Fp, {
  A: BigInt('0x3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533'),
  B: BigInt('1771'),
  Z: Fp.create(BigInt('-11')),
});

export const secp256k1 = createCurve(
  {
    // Params: a, b
    // Seem to be rigid https://bitcointalk.org/index.php?topic=289795.msg3183975#msg3183975
    a: BigInt(0),
    b: BigInt(7),
    // Field over which we'll do calculations;
    // 2n**256n - 2n**32n - 2n**9n - 2n**8n - 2n**7n - 2n**6n - 2n**4n - 1n
    Fp,
    // Curve order, total count of valid points in the field
    n: secp256k1N,
    // Base point (x, y) aka generator point
    Gx: BigInt('55066263022277343669578718895168534326250603453777594175500187360389116729240'),
    Gy: BigInt('32670510020758816978083085130507043184471273380659243275938904335757337482424'),
    h: BigInt(1),
    // Alllow only low-S signatures by default in sign() and verify()
    lowS: true,
    endo: {
      // Params taken from https://gist.github.com/paulmillr/eb670806793e84df628a7c434a873066
      beta: BigInt('0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee'),
      splitScalar: (k: bigint) => {
        const n = secp256k1N;
        const a1 = BigInt('0x3086d221a7d46bcde86c90e49284eb15');
        const b1 = -_1n * BigInt('0xe4437ed6010e88286f547fa90abfe4c3');
        const a2 = BigInt('0x114ca50f7a8e2f3f657c1108d9d44cfd8');
        const b2 = a1;
        const POW_2_128 = BigInt('0x100000000000000000000000000000000'); // (2n**128n).toString(16)

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
    mapToCurve: (scalars: bigint[]) => {
      const { x, y } = mapSWU(Fp.create(scalars[0]));
      return isoMap(x, y);
    },
    htfDefaults: {
      DST: 'secp256k1_XMD:SHA-256_SSWU_RO_',
      p: Fp.ORDER,
      m: 1,
      k: 128,
      expand: 'xmd',
      hash: sha256,
    },
  },
  sha256
);

// Schnorr
const _0n = BigInt(0);
const numTo32b = secp256k1.utils._bigintToBytes;
const numTo32bStr = secp256k1.utils._bigintToString;
const normalizePrivateKey = secp256k1.utils._normalizePrivateKey;

// TODO: export?
function normalizePublicKey(publicKey: Hex | PointType<bigint>): PointType<bigint> {
  if (publicKey instanceof secp256k1.Point) {
    publicKey.assertValidity();
    return publicKey;
  } else {
    const bytes = ensureBytes(publicKey);
    // Schnorr is 32 bytes
    if (bytes.length !== 32) throw new Error('Schnorr pubkeys must be 32 bytes');
    const x = bytesToNumberBE(bytes);
    if (!isValidFieldElement(x)) throw new Error('Point is not on curve');
    const y2 = secp256k1.utils._weierstrassEquation(x); // y² = x³ + ax + b
    let y = sqrtMod(y2); // y = y² ^ (p+1)/4
    const isYOdd = (y & _1n) === _1n;
    // Schnorr
    if (isYOdd) y = secp256k1.CURVE.Fp.negate(y);
    const point = new secp256k1.Point(x, y);
    point.assertValidity();
    return point;
  }
}

const isWithinCurveOrder = secp256k1.utils._isWithinCurveOrder;
const isValidFieldElement = secp256k1.utils._isValidFieldElement;

const TAGS = {
  challenge: 'BIP0340/challenge',
  aux: 'BIP0340/aux',
  nonce: 'BIP0340/nonce',
} as const;

/** An object mapping tags to their tagged hash prefix of [SHA256(tag) | SHA256(tag)] */
const TAGGED_HASH_PREFIXES: { [tag: string]: Uint8Array } = {};
export function taggedHash(tag: string, ...messages: Uint8Array[]): Uint8Array {
  let tagP = TAGGED_HASH_PREFIXES[tag];
  if (tagP === undefined) {
    const tagH = sha256(Uint8Array.from(tag, (c) => c.charCodeAt(0)));
    tagP = concatBytes(tagH, tagH);
    TAGGED_HASH_PREFIXES[tag] = tagP;
  }
  return sha256(concatBytes(tagP, ...messages));
}

const toRawX = (point: PointType<bigint>) => point.toRawBytes(true).slice(1);

// Schnorr signatures are superior to ECDSA from above.
// Below is Schnorr-specific code as per BIP0340.
function schnorrChallengeFinalize(ch: Uint8Array): bigint {
  return mod(bytesToNumberBE(ch), secp256k1.CURVE.n);
}
// Do we need this at all for Schnorr?
class SchnorrSignature {
  constructor(readonly r: bigint, readonly s: bigint) {
    this.assertValidity();
  }
  static fromHex(hex: Hex) {
    const bytes = ensureBytes(hex);
    const len = 32; // group length
    if (bytes.length !== 2 * len)
      throw new TypeError(
        `SchnorrSignature.fromHex: expected ${2 * len} bytes, not ${bytes.length}`
      );
    const r = bytesToNumberBE(bytes.subarray(0, len));
    const s = bytesToNumberBE(bytes.subarray(len, 2 * len));
    return new SchnorrSignature(r, s);
  }
  assertValidity() {
    const { r, s } = this;
    if (!isValidFieldElement(r) || !isWithinCurveOrder(s)) throw new Error('Invalid signature');
  }
  toHex(): string {
    return numTo32bStr(this.r) + numTo32bStr(this.s);
  }
  toRawBytes(): Uint8Array {
    return hexToBytes(this.toHex());
  }
}

function schnorrGetScalar(priv: bigint) {
  const point = secp256k1.Point.fromPrivateKey(priv);
  const scalar = point.hasEvenY() ? priv : secp256k1.CURVE.n - priv;
  return { point, scalar, x: toRawX(point) };
}
/**
 * Synchronously creates Schnorr signature. Improved security: verifies itself before
 * producing an output.
 * @param msg message (not message hash)
 * @param privateKey private key
 * @param auxRand random bytes that would be added to k. Bad RNG won't break it.
 */
function schnorrSign(
  message: Hex,
  privateKey: PrivKey,
  auxRand: Hex = randomBytes(32)
): Uint8Array {
  if (message == null) throw new TypeError(`sign: Expected valid message, not "${message}"`);
  const m = ensureBytes(message);
  // checks for isWithinCurveOrder
  const { x: px, scalar: d } = schnorrGetScalar(normalizePrivateKey(privateKey));
  const rand = ensureBytes(auxRand);
  if (rand.length !== 32) throw new TypeError('sign: Expected 32 bytes of aux randomness');
  const tag = taggedHash;
  const t0h = tag(TAGS.aux, rand);
  const t = numTo32b(d ^ bytesToNumberBE(t0h));
  const k0h = tag(TAGS.nonce, t, px, m);
  const k0 = mod(bytesToNumberBE(k0h), secp256k1.CURVE.n);
  if (k0 === _0n) throw new Error('sign: Creation of signature failed. k is zero');
  const { point: R, x: rx, scalar: k } = schnorrGetScalar(k0);
  const e = schnorrChallengeFinalize(tag(TAGS.challenge, rx, px, m));
  const sig = new SchnorrSignature(R.x, mod(k + e * d, secp256k1.CURVE.n)).toRawBytes();
  if (!schnorrVerify(sig, m, px)) throw new Error('sign: Invalid signature produced');
  return sig;
}

/**
 * Verifies Schnorr signature synchronously.
 */
function schnorrVerify(signature: Hex, message: Hex, publicKey: Hex): boolean {
  try {
    const raw = signature instanceof SchnorrSignature;
    const sig: SchnorrSignature = raw ? signature : SchnorrSignature.fromHex(signature);
    if (raw) sig.assertValidity(); // just in case

    const { r, s } = sig;
    const m = ensureBytes(message);
    const P = normalizePublicKey(publicKey);
    const e = schnorrChallengeFinalize(taggedHash(TAGS.challenge, numTo32b(r), toRawX(P), m));
    // Finalize
    // R = s⋅G - e⋅P
    // -eP == (n-e)P
    const R = secp256k1.Point.BASE.multiplyAndAddUnsafe(
      P,
      normalizePrivateKey(s),
      mod(-e, secp256k1.CURVE.n)
    );
    if (!R || !R.hasEvenY() || R.x !== r) return false;
    return true;
  } catch (error) {
    return false;
  }
}

export const schnorr = {
  Signature: SchnorrSignature,
  // Schnorr's pubkey is just `x` of Point (BIP340)
  getPublicKey: (privateKey: PrivKey): Uint8Array =>
    toRawX(secp256k1.Point.fromPrivateKey(privateKey)),
  sign: schnorrSign,
  verify: schnorrVerify,
};
