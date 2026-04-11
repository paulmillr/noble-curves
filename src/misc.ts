/**
 * Miscellaneous, rarely used curves.
 * jubjub, babyjubjub, pallas, vesta.
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { blake512 } from '@noble/hashes/blake1.js';
import { blake2s } from '@noble/hashes/blake2.js';
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import { abytes, concatBytes } from '@noble/hashes/utils.js';
import {
  eddsa,
  edwards,
  type EdDSA,
  type EdwardsOpts,
  type EdwardsPoint,
} from './abstract/edwards.ts';
import { ecdsa, weierstrass, type ECDSA, type WeierstrassOpts } from './abstract/weierstrass.ts';
import { asciiToBytes, type TArg } from './utils.ts';

// Jubjub curves have 𝔽p over scalar fields of other curves. They are friendly to ZK proofs.

// Zcash Protocol Specification "Jubjub" parameters:
// q = BLS12-381 Fr, r, h = 8, a = -1, d = -10240/10241.
// Gx/Gy keep the canonical Jubjub base point used by Zcash implementations.
const jubjub_CURVE: EdwardsOpts = /* @__PURE__ */ (() => ({
  p: BigInt('0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001'),
  n: BigInt('0xe7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7'),
  h: BigInt(8),
  a: BigInt('0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000'),
  d: BigInt('0x2a9318e74bfa2b48f5fd9207e6bd7fd4292d7f6d37579d2601065fd6d6343eb1'),
  Gx: BigInt('0x11dafe5d23e1218086a365b99fbf3d3be72f6afd7d1f72623e6b071492d1122b'),
  Gy: BigInt('0x1d523cf1ddab1a1793132e78c866c0c33e26ba5cc220fed7cc3f870e59d292aa'),
}))();
/**
 * Generic EdDSA-over-Jubjub convenience wrapper with `sha512`.
 * This is not the Zcash RedJubjub / Sapling signature scheme.
 * @example
 * Generate one Jubjub keypair, sign a message, and verify it.
 *
 * ```ts
 * const { secretKey, publicKey } = jubjub.keygen();
 * const msg = new TextEncoder().encode('hello noble');
 * const sig = jubjub.sign(msg, secretKey);
 * const isValid = jubjub.verify(sig, msg, publicKey);
 * ```
 */
export const jubjub: EdDSA = /* @__PURE__ */ (() => eddsa(edwards(jubjub_CURVE), sha512))();

// BabyJubJub over bn254 Fr. EIP-2494 explicitly defines both the full-group generator G and the
// prime-order subgroup base point B = 8*G.
// noble's Edwards abstraction expects Point.BASE / curve.n to describe the prime-order subgroup, so
// use the EIP base point B here.
// Historical noble incorrectly used the EIP generator G as Point.BASE, which mismatched the
// abstraction and leaked the wrong order into consumers.
// Historical noble used G instead:
//   Gx = 995203441582195749578291179787384436505546430278305826713579947235728471134
//   Gy = 5472060717959818805561601436314318772137091100104008585924551046643952123905
const babyjubjub_CURVE: EdwardsOpts = /* @__PURE__ */ (() => ({
  p: BigInt('0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001'),
  n: BigInt('0x060c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1'),
  h: BigInt(8),
  a: BigInt('168700'),
  d: BigInt('168696'),
  Gx: BigInt('0xbb77a6ad63e739b4eacb2e09d6277c12ab8d8010534e0b62893f3f6bb957051'),
  Gy: BigInt('0x25797203f7a0b24925572e1cd16bf9edfce0051fb9e133774b3c257a872d7d8b'),
}))();
/**
 * Curve over scalar field of bn254. babyjubjub Fp = bn254 n
 * This is a working generic EdDSA-over-BabyJubJub wrapper that uses `blake512` for the 64-byte
 * secret expansion required by the shared EdDSA helper.
 * It is not the BabyJubJub stack used by iden3/circomlib, `babyjubjub-rs`, or
 * `@zk-kit/eddsa-poseidon`: those pair the subgroup base B/B8 with Blake-style secret expansion
 * plus dedicated Poseidon / MiMC / Pedersen transcript hashing. This wrapper stays generic and is
 * not meant as an interoperability target for those BabyJubJub signing stacks.
 * @example
 * Access the BabyJubJub base point and round-trip it through the point codec.
 *
 * ```ts
 * import { babyjubjub } from '@noble/curves/misc.js';
 * const base = babyjubjub.Point.BASE;
 * const encoded = base.toBytes();
 * const decoded = babyjubjub.Point.fromBytes(encoded);
 * ```
 */
export const babyjubjub: EdDSA = /* @__PURE__ */ (() =>
  eddsa(edwards(babyjubjub_CURVE), blake512))();

// Sapling URS randomness beacon from the Zcash protocol. This stays as the 64-byte ASCII
// lowercase-hex string used for the first Blake2s block, not 32 raw bytes.
const jubjub_gh_first_block = /* @__PURE__ */ asciiToBytes(
  '096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0'
);

/**
 * @param tag - Hash input.
 * @param personalization - BLAKE2 personalization bytes.
 * @returns Prime-order Jubjub point.
 * @throws If the digest does not decode to a Jubjub point, or if the
 *   cofactor-cleared point has small order. {@link Error}
 * @example
 * Hash a tag into a prime-order Jubjub point.
 *
 * ```ts
 * import { jubjub_groupHash } from '@noble/curves/misc.js';
 * import { asciiToBytes } from '@noble/curves/utils.js';
 * const tag = Uint8Array.of(2);
 * const personalization = asciiToBytes('Zcash_G_');
 * const point = jubjub_groupHash(tag, personalization);
 * ```
 */
export function jubjub_groupHash(
  tag: TArg<Uint8Array>,
  personalization: TArg<Uint8Array>
): EdwardsPoint {
  const h = blake2s.create({ personalization, dkLen: 32 });
  h.update(jubjub_gh_first_block);
  h.update(tag);
  // NOTE: returns EdwardsPoint, in case it will be multiplied later
  let p = jubjub.Point.fromBytes(h.digest());
  // NOTE: cannot replace with isSmallOrder, returns Point*8
  p = p.multiply(jubjub_CURVE.h);
  if (p.equals(jubjub.Point.ZERO)) throw new Error('Point has small order');
  return p;
}

/**
 * No secret data is leaked here at all.
 * It operates over public data.
 * @param m - Message prefix.
 * @param personalization - 8-byte BLAKE2 personalization bytes.
 * @returns First non-zero group hash.
 * @throws If the personalization is invalid, or if no non-zero Jubjub group
 *   hash can be found. {@link Error}
 * @example
 * Derive the first non-zero Jubjub group hash for one personalization tag.
 *
 * ```ts
 * import { jubjub_findGroupHash } from '@noble/curves/misc.js';
 * import { asciiToBytes } from '@noble/curves/utils.js';
 * const msg = Uint8Array.of();
 * const personalization = asciiToBytes('Zcash_G_');
 * const point = jubjub_findGroupHash(msg, personalization);
 * ```
 */
export function jubjub_findGroupHash(
  m: TArg<Uint8Array>,
  personalization: TArg<Uint8Array>
): EdwardsPoint {
  // Validate BLAKE2s personalization once up front; otherwise the retry loop swallows the real
  // input error and turns it into a misleading "tag overflow".
  abytes(personalization, 8, 'personalization');
  const tag = concatBytes(m, Uint8Array.of(0));
  const hashes = [];
  for (let i = 0; i < 256; i++) {
    tag[tag.length - 1] = i;
    try {
      hashes.push(jubjub_groupHash(tag, personalization));
    } catch (e) {}
  }
  if (!hashes.length) throw new Error('findGroupHash tag overflow');
  return hashes[0];
}

const brainpoolP256r1_CURVE: WeierstrassOpts<bigint> = /* @__PURE__ */ (() => ({
  p: BigInt('0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377'),
  a: BigInt('0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9'),
  b: BigInt('0x26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6'),
  n: BigInt('0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7'),
  Gx: BigInt('0x8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262'),
  Gy: BigInt('0x547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997'),
  h: BigInt(1),
}))();
/**
 * Brainpool P256r1 with sha256, from RFC 5639.
 * @example
 * Generate one Brainpool P256r1 keypair, sign a message, and verify it.
 *
 * ```ts
 * const { secretKey, publicKey } = brainpoolP256r1.keygen();
 * const msg = new TextEncoder().encode('hello noble');
 * const sig = brainpoolP256r1.sign(msg, secretKey);
 * const isValid = brainpoolP256r1.verify(sig, msg, publicKey);
 * ```
 */
export const brainpoolP256r1: ECDSA = /* @__PURE__ */ (() =>
  ecdsa(weierstrass(brainpoolP256r1_CURVE), sha256))();

const brainpoolP384r1_CURVE: WeierstrassOpts<bigint> = /* @__PURE__ */ (() => ({
  p: BigInt(
    '0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53'
  ),
  a: BigInt(
    '0x7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826'
  ),
  b: BigInt(
    '0x04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11'
  ),
  n: BigInt(
    '0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565'
  ),
  Gx: BigInt(
    '0x1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e'
  ),
  Gy: BigInt(
    '0x8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315'
  ),
  h: BigInt(1),
}))();
/**
 * Brainpool P384r1 with sha384, from RFC 5639.
 * @example
 * Generate one Brainpool P384r1 keypair, sign a message, and verify it.
 *
 * ```ts
 * const { secretKey, publicKey } = brainpoolP384r1.keygen();
 * const msg = new TextEncoder().encode('hello noble');
 * const sig = brainpoolP384r1.sign(msg, secretKey);
 * const isValid = brainpoolP384r1.verify(sig, msg, publicKey);
 * ```
 */
export const brainpoolP384r1: ECDSA = /* @__PURE__ */ (() =>
  ecdsa(weierstrass(brainpoolP384r1_CURVE), sha384))();

const brainpoolP512r1_CURVE: WeierstrassOpts<bigint> = /* @__PURE__ */ (() => ({
  p: BigInt(
    '0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3'
  ),
  a: BigInt(
    '0x7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca'
  ),
  b: BigInt(
    '0x3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723'
  ),
  n: BigInt(
    '0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069'
  ),
  Gx: BigInt(
    '0x81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822'
  ),
  Gy: BigInt(
    '0x7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892'
  ),
  h: BigInt(1),
}))();
/**
 * Brainpool P512r1 with sha512, from RFC 5639.
 * @example
 * Generate one Brainpool P512r1 keypair, sign a message, and verify it.
 *
 * ```ts
 * const { secretKey, publicKey } = brainpoolP512r1.keygen();
 * const msg = new TextEncoder().encode('hello noble');
 * const sig = brainpoolP512r1.sign(msg, secretKey);
 * const isValid = brainpoolP512r1.verify(sig, msg, publicKey);
 * ```
 */
export const brainpoolP512r1: ECDSA = /* @__PURE__ */ (() =>
  ecdsa(weierstrass(brainpoolP512r1_CURVE), sha512))();
