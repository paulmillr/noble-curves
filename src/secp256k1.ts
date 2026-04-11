/**
 * SECG secp256k1. See [pdf](https://www.secg.org/sec2-v2.pdf).
 *
 * Belongs to Koblitz curves: it has efficiently-computable GLV endomorphism ψ,
 * check out {@link EndomorphismOpts}. Seems to be rigid (not backdoored).
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { createKeygen, type CurveLengths } from './abstract/curve.ts';
import {
  createFROST,
  type FROST,
  type FrostPublic,
  type FrostSecret,
  type Nonces,
} from './abstract/frost.ts';
import { createHasher, type H2CHasher, isogenyMap } from './abstract/hash-to-curve.ts';
import { Field, mapHashToField, pow2 } from './abstract/modular.ts';
import {
  type ECDSA,
  ecdsa,
  type EndomorphismOpts,
  mapToCurveSimpleSWU,
  type WeierstrassPoint as PointType,
  weierstrass,
  type WeierstrassOpts,
  type WeierstrassPointCons,
} from './abstract/weierstrass.ts';
import {
  abytes,
  asciiToBytes,
  bytesToNumberBE,
  concatBytes,
  type TArg,
  type TRet,
} from './utils.ts';

// Seems like generator was produced from some seed:
// `Pointk1.BASE.multiply(Pointk1.Fn.inv(2n, N)).toAffine().x`
// // gives short x 0x3b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63n
const secp256k1_CURVE: WeierstrassOpts<bigint> = {
  p: BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f'),
  n: BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'),
  h: BigInt(1),
  a: BigInt(0),
  b: BigInt(7),
  Gx: BigInt('0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
  Gy: BigInt('0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'),
};

const secp256k1_ENDO: EndomorphismOpts = {
  beta: BigInt('0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee'),
  basises: [
    [BigInt('0x3086d221a7d46bcde86c90e49284eb15'), -BigInt('0xe4437ed6010e88286f547fa90abfe4c3')],
    [BigInt('0x114ca50f7a8e2f3f657c1108d9d44cfd8'), BigInt('0x3086d221a7d46bcde86c90e49284eb15')],
  ],
};

const _0n = /* @__PURE__ */ BigInt(0);
const _2n = /* @__PURE__ */ BigInt(2);

/**
 * √n = n^((p+1)/4) for fields p = 3 mod 4. We unwrap the loop and multiply bit-by-bit.
 * (P+1n/4n).toString(2) would produce bits [223x 1, 0, 22x 1, 4x 0, 11, 00]
 */
function sqrtMod(y: bigint): bigint {
  const P = secp256k1_CURVE.p;
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
  if (!Fpk1.eql(Fpk1.sqr(root), y)) throw new Error('Cannot find square root');
  return root;
}

const Fpk1 = Field(secp256k1_CURVE.p, { sqrt: sqrtMod });
const Pointk1 = /* @__PURE__ */ weierstrass(secp256k1_CURVE, {
  Fp: Fpk1,
  endo: secp256k1_ENDO,
});

/**
 * secp256k1 curve: ECDSA and ECDH methods.
 *
 * Uses sha256 to hash messages. To use a different hash,
 * pass `{ prehash: false }` to sign / verify.
 *
 * @example
 * Generate one secp256k1 keypair, sign a message, and verify it.
 *
 * ```js
 * import { secp256k1 } from '@noble/curves/secp256k1.js';
 * const { secretKey, publicKey } = secp256k1.keygen();
 * // const publicKey = secp256k1.getPublicKey(secretKey);
 * const msg = new TextEncoder().encode('hello noble');
 * const sig = secp256k1.sign(msg, secretKey);
 * const isValid = secp256k1.verify(sig, msg, publicKey);
 * // const sigKeccak = secp256k1.sign(keccak256(msg), secretKey, { prehash: false });
 * ```
 */
export const secp256k1: ECDSA = /* @__PURE__ */ ecdsa(Pointk1, sha256);

// Schnorr signatures are superior to ECDSA from above. Below is Schnorr-specific BIP0340 code.
// https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
/** An object mapping tags to their tagged hash prefix of [SHA256(tag) | SHA256(tag)] */
const TAGGED_HASH_PREFIXES: { [tag: string]: Uint8Array } = {};
// BIP-340 phrases tags as UTF-8, but all current standardized names here are 7-bit ASCII.
function taggedHash(tag: string, ...messages: TArg<Uint8Array[]>): TRet<Uint8Array> {
  let tagP = TAGGED_HASH_PREFIXES[tag];
  if (tagP === undefined) {
    const tagH = sha256(asciiToBytes(tag));
    tagP = concatBytes(tagH, tagH);
    TAGGED_HASH_PREFIXES[tag] = tagP;
  }
  return sha256(concatBytes(tagP, ...messages)) as TRet<Uint8Array>;
}

// ECDSA compact points are 33-byte. Schnorr is 32: we strip first byte 0x02 or 0x03
const pointToBytes = (point: TArg<PointType<bigint>>): TRet<Uint8Array> =>
  point.toBytes(true).slice(1) as TRet<Uint8Array>;
const hasEven = (y: bigint) => y % _2n === _0n;

// Calculate point, scalar and bytes
function schnorrGetExtPubKey(priv: TArg<Uint8Array>) {
  const { Fn, BASE } = Pointk1;
  const d_ = Fn.fromBytes(priv);
  const p = BASE.multiply(d_); // P = d'⋅G; 0 < d' < n check is done inside
  const scalar = hasEven(p.y) ? d_ : Fn.neg(d_);
  return { scalar, bytes: pointToBytes(p) };
}
/**
 * lift_x from BIP340. Convert 32-byte x coordinate to elliptic curve point.
 * @returns valid point checked for being on-curve
 */
function lift_x(x: bigint): PointType<bigint> {
  const Fp = Fpk1;
  if (!Fp.isValidNot0(x)) throw new Error('invalid x: Fail if x ≥ p');
  const xx = Fp.create(x * x);
  const c = Fp.create(xx * x + BigInt(7)); // Let c = x³ + 7 mod p.
  let y = Fp.sqrt(c); // Let y = c^(p+1)/4 mod p. Same as sqrt().
  // Return the unique point P such that x(P) = x and
  // y(P) = y if y mod 2 = 0 or y(P) = p-y otherwise.
  if (!hasEven(y)) y = Fp.neg(y);
  const p = Pointk1.fromAffine({ x, y });
  p.assertValidity();
  return p;
}
// BIP-340 callers still need to supply canonical 32-byte inputs where required; this alias only
// parses big-endian bytes and does not enforce the fixed-width contract itself.
const num = bytesToNumberBE;
/** Create tagged hash, convert it to bigint, reduce modulo-n. */
function challenge(...args: TArg<Uint8Array[]>): bigint {
  return Pointk1.Fn.create(num(taggedHash('BIP0340/challenge', ...args)));
}

/** Schnorr public key is just `x` coordinate of Point as per BIP340. */
function schnorrGetPublicKey(secretKey: TArg<Uint8Array>): TRet<Uint8Array> {
  return schnorrGetExtPubKey(secretKey).bytes; // d'=int(sk). Fail if d'=0 or d'≥n. Ret bytes(d'⋅G)
}

/**
 * Creates Schnorr signature as per BIP340. Verifies itself before returning anything.
 * `auxRand` is optional and is not the sole source of `k` generation: bad CSPRNG output will not
 * be catastrophic, but BIP-340 still recommends fresh auxiliary randomness when available to harden
 * deterministic signing against side-channel and fault-injection attacks.
 */
function schnorrSign(
  message: TArg<Uint8Array>,
  secretKey: TArg<Uint8Array>,
  auxRand: TArg<Uint8Array> = randomBytes(32)
): TRet<Uint8Array> {
  const { Fn, BASE } = Pointk1;
  const m = abytes(message, undefined, 'message');
  const { bytes: px, scalar: d } = schnorrGetExtPubKey(secretKey); // checks for isWithinCurveOrder
  const a = abytes(auxRand, 32, 'auxRand'); // Auxiliary random data a: a 32-byte array
  // Let t be the byte-wise xor of bytes(d) and hash/aux(a).
  const t = Fn.toBytes(d ^ num(taggedHash('BIP0340/aux', a)));
  const rand = taggedHash('BIP0340/nonce', t, px, m); // Let rand = hash/nonce(t || bytes(P) || m)
  // BIP340 defines k' = int(rand) mod n. We can't reuse schnorrGetExtPubKey(rand)
  // here: that helper parses canonical secret keys and rejects rand >= n instead
  // of reducing the nonce hash modulo the group order.
  const k_ = Fn.create(num(rand));
  // BIP-340: "Let k' = int(rand) mod n. Fail if k' = 0. Let R = k'⋅G."
  if (k_ === 0n) throw new Error('sign failed: k is zero');
  const p = BASE.multiply(k_); // Rejects zero; only the raw nonce hash needs reduction.
  const k = hasEven(p.y) ? k_ : Fn.neg(k_);
  const rx = pointToBytes(p);
  const e = challenge(rx, px, m); // Let e = int(hash/challenge(bytes(R) || bytes(P) || m)) mod n.
  const sig = new Uint8Array(64); // Let sig = bytes(R) || bytes((k + ed) mod n).
  sig.set(rx, 0);
  sig.set(Fn.toBytes(Fn.create(k + e * d)), 32);
  // If Verify(bytes(P), m, sig) (see below) returns failure, abort
  if (!schnorrVerify(sig, m, px)) throw new Error('sign: Invalid signature produced');
  return sig as TRet<Uint8Array>;
}

/**
 * Verifies Schnorr signature.
 * Will swallow errors & return false except for initial type validation of arguments.
 */
function schnorrVerify(
  signature: TArg<Uint8Array>,
  message: TArg<Uint8Array>,
  publicKey: TArg<Uint8Array>
): boolean {
  const { Fp, Fn, BASE } = Pointk1;
  const sig = abytes(signature, 64, 'signature');
  const m = abytes(message, undefined, 'message');
  const pub = abytes(publicKey, 32, 'publicKey');
  try {
    const P = lift_x(num(pub)); // P = lift_x(int(pk)); fail if that fails
    const r = num(sig.subarray(0, 32)); // Let r = int(sig[0:32]); fail if r ≥ p.
    if (!Fp.isValidNot0(r)) return false;
    const s = num(sig.subarray(32, 64)); // Let s = int(sig[32:64]); fail if s ≥ n.
    // Stricter than BIP-340/libsecp256k1, which only reject s >= n. Honest signing reaches
    // s = 0 only with negligible probability (k + e*d ≡ 0 mod n), so treat zero-s inputs as
    // crafted edge cases and fail closed instead of carrying that extra verification surface.
    if (!Fn.isValidNot0(s)) return false;

    // int(challenge(bytes(r) || bytes(P) || m)) % n
    const e = challenge(Fn.toBytes(r), pointToBytes(P), m);
    // R = s⋅G - e⋅P, where -eP == (n-e)P
    const R = BASE.multiplyUnsafe(s).add(P.multiplyUnsafe(Fn.neg(e)));
    const { x, y } = R.toAffine();
    // Fail if is_infinite(R) / not has_even_y(R) / x(R) ≠ r.
    if (R.is0() || !hasEven(y) || x !== r) return false;
    return true;
  } catch (error) {
    return false;
  }
}

export const __TEST: { lift_x: typeof lift_x } = /* @__PURE__ */ Object.freeze({ lift_x });

/** Schnorr-specific secp256k1 API from BIP340. */
export type SecpSchnorr = {
  /**
   * Generate one Schnorr secret/public keypair.
   * @param seed - Optional seed for deterministic testing or custom randomness.
   * @returns Fresh secret/public keypair.
   */
  keygen: (seed?: TArg<Uint8Array>) => { secretKey: TRet<Uint8Array>; publicKey: TRet<Uint8Array> };
  /**
   * Derive the x-only public key from a secret key.
   * @param secretKey - Secret key bytes.
   * @returns X-only public key bytes.
   */
  getPublicKey: typeof schnorrGetPublicKey;
  /**
   * Create one BIP340 Schnorr signature.
   * @param message - Message bytes to sign.
   * @param secretKey - Secret key bytes.
   * @param auxRand - Optional auxiliary randomness.
   * @returns Compact Schnorr signature bytes.
   */
  sign: typeof schnorrSign;
  /**
   * Verify one BIP340 Schnorr signature.
   * @param signature - Compact signature bytes.
   * @param message - Signed message bytes.
   * @param publicKey - X-only public key bytes.
   * @returns `true` when the signature is valid.
   */
  verify: typeof schnorrVerify;
  /** Underlying secp256k1 point constructor. */
  Point: WeierstrassPointCons<bigint>;
  /** Helper utilities for Schnorr-specific key handling and tagged hashing. */
  utils: {
    /** Generate one Schnorr secret key. */
    randomSecretKey: (seed?: TArg<Uint8Array>) => TRet<Uint8Array>;
    /** Convert one point into its x-only BIP340 byte encoding. */
    pointToBytes: (point: TArg<PointType<bigint>>) => TRet<Uint8Array>;
    /** Lift one x coordinate into the unique even-Y point. */
    lift_x: typeof lift_x;
    /** Compute a BIP340 tagged hash. */
    taggedHash: typeof taggedHash;
  };
  /** Public byte lengths for keys, signatures, and seeds. */
  lengths: CurveLengths;
};
/**
 * Schnorr signatures over secp256k1.
 * See {@link https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki | BIP 340}.
 * @example
 * Generate one BIP340 Schnorr keypair, sign a message, and verify it.
 *
 * ```js
 * import { schnorr } from '@noble/curves/secp256k1.js';
 * const { secretKey, publicKey } = schnorr.keygen();
 * // const publicKey = schnorr.getPublicKey(secretKey);
 * const msg = new TextEncoder().encode('hello');
 * const sig = schnorr.sign(msg, secretKey);
 * const isValid = schnorr.verify(sig, msg, publicKey);
 * ```
 */
export const schnorr: SecpSchnorr = /* @__PURE__ */ (() => {
  const size = 32;
  const seedLength = 48;
  const randomSecretKey = (seed?: TArg<Uint8Array>): TRet<Uint8Array> => {
    seed = seed === undefined ? randomBytes(seedLength) : seed;
    return mapHashToField(seed, secp256k1_CURVE.n);
  };
  return Object.freeze({
    keygen: createKeygen(randomSecretKey, schnorrGetPublicKey),
    getPublicKey: schnorrGetPublicKey,
    sign: schnorrSign,
    verify: schnorrVerify,
    Point: Pointk1,
    utils: Object.freeze({
      randomSecretKey,
      taggedHash,
      lift_x,
      pointToBytes,
    }),
    lengths: Object.freeze({
      secretKey: size,
      publicKey: size,
      publicKeyHasPrefix: false,
      signature: size * 2,
      seed: seedLength,
    }),
  });
})();

// RFC 9380 Appendix E.1 3-isogeny coefficients for secp256k1, stored in ascending degree order.
// The final `1` in each denominator array is the explicit monic leading term.
const isoMap = /* @__PURE__ */ (() =>
  isogenyMap(
    Fpk1,
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
    ].map((i) => i.map((j) => BigInt(j))) as [bigint[], bigint[], bigint[], bigint[]]
  ))();
// RFC 9380 §8.7 secp256k1 E' parameters for the SWU-to-isogeny pipeline below.
let mapSWU: ((u: bigint) => { x: bigint; y: bigint }) | undefined;
const getMapSWU = () =>
  mapSWU ||
  (mapSWU = mapToCurveSimpleSWU(Fpk1, {
    // Building the SWU sqrt-ratio helper eagerly adds noticeable `secp256k1.js` import cost, so
    // defer it to first use; after that the cached mapper is reused directly.
    A: BigInt('0x3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533'),
    B: BigInt('1771'),
    Z: Fpk1.create(BigInt('-11')),
  }));

/**
 * Hashing / encoding to secp256k1 points / field. RFC 9380 methods.
 * @example
 * Hash one message onto secp256k1.
 *
 * ```ts
 * const point = secp256k1_hasher.hashToCurve(new TextEncoder().encode('hello noble'));
 * ```
 */
export const secp256k1_hasher: H2CHasher<WeierstrassPointCons<bigint>> = /* @__PURE__ */ (() =>
  createHasher(
    Pointk1,
    (scalars: bigint[]) => {
      const { x, y } = getMapSWU()(Fpk1.create(scalars[0]));
      return isoMap(x, y);
    },
    {
      DST: 'secp256k1_XMD:SHA-256_SSWU_RO_',
      encodeDST: 'secp256k1_XMD:SHA-256_SSWU_NU_',
      p: Fpk1.ORDER,
      m: 1,
      k: 128,
      expand: 'xmd',
      hash: sha256,
    }
  ))();
/**
 * FROST threshold signatures over secp256k1. RFC 9591.
 * @example
 * Create one trusted-dealer package for 2-of-3 secp256k1 signing.
 *
 * ```ts
 * const alice = secp256k1_FROST.Identifier.derive('alice@example.com');
 * const bob = secp256k1_FROST.Identifier.derive('bob@example.com');
 * const carol = secp256k1_FROST.Identifier.derive('carol@example.com');
 * const deal = secp256k1_FROST.trustedDealer({ min: 2, max: 3 }, [alice, bob, carol]);
 * ```
 */
export const secp256k1_FROST: TRet<FROST> = /* @__PURE__ */ (() =>
  createFROST({
    name: 'FROST-secp256k1-SHA256-v1',
    Point: Pointk1,
    hashToScalar: secp256k1_hasher.hashToScalar,
    hash: sha256,
  }))();

// Taproot utils
// `undefined` means "disable TapTweak entirely"; callers that want the BIP-341/BIP-386 empty
// merkle root must pass `new Uint8Array(0)` explicitly.
function tweak(point: PointType<bigint>, merkleRoot?: TArg<Uint8Array>): bigint {
  if (merkleRoot === undefined) return _0n;
  const x = pointToBytes(point);
  const t = bytesToNumberBE(taggedHash('TapTweak', x, merkleRoot));
  // BIP-341 taproot_tweak_pubkey/taproot_tweak_seckey: "if t >= SECP256K1_ORDER:
  // raise ValueError". TapTweak must reject overflow instead of reducing modulo n.
  if (!Pointk1.Fn.isValid(t)) throw new Error('invalid TapTweak hash');
  return t;
}
function frostPubToEvenY(pub: TArg<FrostPublic>): TRet<FrostPublic> {
  const VK = Pointk1.fromBytes(pub.commitments[0]);
  // Keep aliasing on the already-even path so wrapper callers can skip unnecessary cloning.
  if (hasEven(VK.y)) return pub as TRet<FrostPublic>;
  return {
    signers: { min: pub.signers.min, max: pub.signers.max },
    commitments: pub.commitments.map((i) => Pointk1.fromBytes(i).negate().toBytes()),
    verifyingShares: Object.fromEntries(
      Object.entries(pub.verifyingShares).map(([k, v]) => [
        k,
        Pointk1.fromBytes(v).negate().toBytes(),
      ])
    ),
  } as TRet<FrostPublic>;
}
function frostSecretToEvenY(s: TArg<FrostSecret>, pub: TArg<FrostPublic>): TRet<FrostSecret> {
  const VK = Pointk1.fromBytes(pub.commitments[0]);
  // Keep aliasing on the already-even path so wrapper callers can preserve package identity.
  if (hasEven(VK.y)) return s as TRet<FrostSecret>;
  const Fn = Pointk1.Fn;
  return {
    ...s,
    signingShare: Fn.toBytes(Fn.neg(Fn.fromBytes(s.signingShare))),
  } as TRet<FrostSecret>;
}
function frostNoncesToEvenY(PK: PointType<bigint>, nonces: TArg<Nonces>): TRet<Nonces> {
  if (hasEven(PK.y)) return nonces as TRet<Nonces>;
  const Fn = Pointk1.Fn;
  return {
    binding: Fn.toBytes(Fn.neg(Fn.fromBytes(nonces.binding))),
    hiding: Fn.toBytes(Fn.neg(Fn.fromBytes(nonces.hiding))),
  } as TRet<Nonces>;
}

function frostTweakSecret(
  s: TArg<FrostSecret>,
  pub: TArg<FrostPublic>,
  merkleRoot?: TArg<Uint8Array>
): TRet<FrostSecret> {
  const Fn = Pointk1.Fn;
  const keyPackage = frostSecretToEvenY(s, pub);
  const evenPub = frostPubToEvenY(pub);
  const t = tweak(Pointk1.fromBytes(evenPub.commitments[0]), merkleRoot);
  const signingShare = Fn.toBytes(Fn.add(Fn.fromBytes(keyPackage.signingShare), t));
  return {
    identifier: keyPackage.identifier,
    signingShare,
  } as TRet<FrostSecret>;
}

function frostTweakPublic(
  pub: TArg<FrostPublic>,
  merkleRoot?: TArg<Uint8Array>
): TRet<FrostPublic> {
  const PKPackage = frostPubToEvenY(pub);
  const t = tweak(Pointk1.fromBytes(PKPackage.commitments[0]), merkleRoot);
  const tp = Pointk1.BASE.multiply(t);
  const commitments = PKPackage.commitments.map((c, i) =>
    (i === 0 ? Pointk1.fromBytes(c).add(tp) : Pointk1.fromBytes(c)).toBytes()
  );
  const verifyingShares: Record<string, Uint8Array> = {};
  for (const k in PKPackage.verifyingShares) {
    verifyingShares[k] = Pointk1.fromBytes(PKPackage.verifyingShares[k]).add(tp).toBytes();
  }
  return {
    signers: { min: PKPackage.signers.min, max: PKPackage.signers.max },
    commitments,
    verifyingShares,
  } as TRet<FrostPublic>;
}

/**
 * FROST threshold signatures over secp256k1-schnorr-taproot. RFC 9591.
 * DKG outputs are auto-tweaked with the empty Taproot merkle root for compatibility, while
 * `trustedDealer()` outputs stay untweaked unless callers apply the Taproot tweak themselves.
 * @example
 * Create one trusted-dealer package for Taproot-compatible FROST signing.
 *
 * ```ts
 * const alice = schnorr_FROST.Identifier.derive('alice@example.com');
 * const bob = schnorr_FROST.Identifier.derive('bob@example.com');
 * const carol = schnorr_FROST.Identifier.derive('carol@example.com');
 * const deal = schnorr_FROST.trustedDealer({ min: 2, max: 3 }, [alice, bob, carol]);
 * ```
 */
export const schnorr_FROST: TRet<FROST> = /* @__PURE__ */ (() =>
  createFROST({
    name: 'FROST-secp256k1-SHA256-TR-v1',
    Point: Pointk1,
    hashToScalar: secp256k1_hasher.hashToScalar,
    hash: sha256,
    // Taproot related hacks
    parsePublicKey(publicKey) {
      // External Taproot keys are x-only, but local key packages still use compressed points.
      if (publicKey.length === 32) return lift_x(bytesToNumberBE(publicKey));
      if (publicKey.length === 33) return Pointk1.fromBytes(publicKey);
      throw new Error(`expected x-only or compressed public key, got length=${publicKey.length}`);
    },
    adjustScalar(n: bigint) {
      const PK = Pointk1.BASE.multiply(n);
      return hasEven(PK.y) ? n : Pointk1.Fn.neg(n);
    },
    adjustPoint: (p) => (hasEven(p.y) ? p : p.negate()),
    challenge(R, PK, msg) {
      return challenge(pointToBytes(R), pointToBytes(PK), msg);
    },
    adjustNonces: frostNoncesToEvenY,
    adjustGroupCommitmentShare: (GC, GCShare) => (!hasEven(GC.y) ? GCShare.negate() : GCShare),
    adjustPublic: frostPubToEvenY,
    adjustSecret: frostSecretToEvenY,
    adjustTx: {
      // Compat with official implementation
      encode: (tx) => tx.subarray(1) as TRet<Uint8Array>,
      decode: (tx) => concatBytes(Uint8Array.of(0x02), tx) as TRet<Uint8Array>,
    },
    adjustDKG: (k) => {
      // Compatibility with frost-secp256k1-tr: DKG output is auto-tweaked with the
      // empty Taproot merkle root, while dealer-generated keys stay untweaked.
      const merkleRoot = new Uint8Array(0);
      return {
        public: frostTweakPublic(k.public, merkleRoot),
        secret: frostTweakSecret(k.secret, k.public, merkleRoot),
      };
    },
  }))();
