/**
 * Miscellaneous, rarely used curves.
 * jubjub, babyjubjub, pallas, vesta.
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { blake256 } from '@noble/hashes/blake1.js';
import { blake2s } from '@noble/hashes/blake2.js';
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import { concatBytes } from '@noble/hashes/utils.js';
import {
  eddsa,
  edwards,
  type EdDSA,
  type EdwardsOpts,
  type EdwardsPoint,
} from './abstract/edwards.ts';
import { ecdsa, weierstrass, type ECDSA, type WeierstrassOpts } from './abstract/weierstrass.ts';
import { bls12_381_Fr } from './bls12-381.ts';
import { bn254_Fr } from './bn254.ts';
import { asciiToBytes } from './utils.ts';

// Jubjub curves have 𝔽p over scalar fields of other curves. They are friendly to ZK proofs.
// jubjub Fp = bls n. babyjubjub Fp = bn254 n.
// verify manually, check bls12-381.ts and bn254.ts.
const jubjub_CURVE: EdwardsOpts = {
  p: bls12_381_Fr.ORDER,
  n: BigInt('0xe7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7'),
  h: BigInt(8),
  a: BigInt('0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000'),
  d: BigInt('0x2a9318e74bfa2b48f5fd9207e6bd7fd4292d7f6d37579d2601065fd6d6343eb1'),
  Gx: BigInt('0x11dafe5d23e1218086a365b99fbf3d3be72f6afd7d1f72623e6b071492d1122b'),
  Gy: BigInt('0x1d523cf1ddab1a1793132e78c866c0c33e26ba5cc220fed7cc3f870e59d292aa'),
};
/** Curve over scalar field of bls12-381. jubjub Fp = bls n */
export const jubjub: EdDSA = /* @__PURE__ */ eddsa(edwards(jubjub_CURVE), sha512);

const babyjubjub_CURVE: EdwardsOpts = {
  p: bn254_Fr.ORDER,
  n: BigInt('0x30644e72e131a029b85045b68181585d59f76dc1c90770533b94bee1c9093788'),
  h: BigInt(8),
  a: BigInt('168700'),
  d: BigInt('168696'),
  Gx: BigInt('0x23343e3445b673d38bcba38f25645adb494b1255b1162bb40f41a59f4d4b45e'),
  Gy: BigInt('0xc19139cb84c680a6e14116da06056174a0cfa121e6e5c2450f87d64fc000001'),
};
/** Curve over scalar field of bn254. babyjubjub Fp = bn254 n */
export const babyjubjub: EdDSA = /* @__PURE__ */ eddsa(edwards(babyjubjub_CURVE), blake256);

const jubjub_gh_first_block = asciiToBytes(
  '096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0'
);

// Returns point at JubJub curve which is prime order and not zero
export function jubjub_groupHash(tag: Uint8Array, personalization: Uint8Array): EdwardsPoint {
  const h = blake2s.create({ personalization, dkLen: 32 });
  h.update(jubjub_gh_first_block);
  h.update(tag);
  // NOTE: returns ExtendedPoint, in case it will be multiplied later
  let p = jubjub.Point.fromBytes(h.digest());
  // NOTE: cannot replace with isSmallOrder, returns Point*8
  p = p.multiply(jubjub_CURVE.h);
  if (p.equals(jubjub.Point.ZERO)) throw new Error('Point has small order');
  return p;
}

// No secret data is leaked here at all.
// It operates over public data:
// const G_SPEND = jubjub.findGroupHash(Uint8Array.of(), utf8ToBytes('Item_G_'));
export function jubjub_findGroupHash(m: Uint8Array, personalization: Uint8Array): EdwardsPoint {
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

const brainpoolP256r1_CURVE: WeierstrassOpts<bigint> = {
  p: BigInt('0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377'),
  a: BigInt('0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9'),
  b: BigInt('0x26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6'),
  n: BigInt('0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7'),
  Gx: BigInt('0x8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262'),
  Gy: BigInt('0x547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997'),
  h: BigInt(1),
};
/** Brainpool P256r1 with sha256, from RFC 5639. */
export const brainpoolP256r1: ECDSA = ecdsa(weierstrass(brainpoolP256r1_CURVE), sha256);

const brainpoolP384r1_CURVE: WeierstrassOpts<bigint> = {
  p: BigInt(
    '0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53'
  ),
  a: BigInt(
    '0x7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826'
  ),
  b: BigInt(
    '0x04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11'
  ),
  n: BigInt(
    '0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565'
  ),
  Gx: BigInt(
    '0x1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E'
  ),
  Gy: BigInt(
    '0x8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315'
  ),
  h: BigInt(1),
};
/** Brainpool P384r1 with sha384, from RFC 5639. */
export const brainpoolP384r1: ECDSA = ecdsa(weierstrass(brainpoolP384r1_CURVE), sha384);

const brainpoolP512r1_CURVE: WeierstrassOpts<bigint> = {
  p: BigInt(
    '0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3'
  ),
  a: BigInt(
    '0x7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA'
  ),
  b: BigInt(
    '0x3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723'
  ),
  n: BigInt(
    '0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069'
  ),
  Gx: BigInt(
    '0x81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822'
  ),
  Gy: BigInt(
    '0x7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892'
  ),
  h: BigInt(1),
};
/** Brainpool P521r1 with sha512, from RFC 5639. */
export const brainpoolP512r1: ECDSA = ecdsa(weierstrass(brainpoolP512r1_CURVE), sha512);
