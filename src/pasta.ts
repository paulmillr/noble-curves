/**
 * Pasta curves. See [Spec](https://o1-labs.github.io/proof-systems/specs/pasta.html).
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { sha256 } from '@noble/hashes/sha256';
import { getHash } from './_shortw_utils.ts';
import { Field, mod } from './abstract/modular.ts';
import { type CurveFn, weierstrass } from './abstract/weierstrass.ts';

export const p: bigint = BigInt(
  '0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001'
);
export const q: bigint = BigInt(
  '0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001'
);

/** https://neuromancer.sk/std/other/Pallas */
export const pallas: CurveFn = weierstrass({
  a: BigInt(0),
  b: BigInt(5),
  Fp: Field(p),
  n: q,
  Gx: mod(BigInt(-1), p),
  Gy: BigInt(2),
  h: BigInt(1),
  ...getHash(sha256),
});
/** https://neuromancer.sk/std/other/Vesta */
export const vesta: CurveFn = weierstrass({
  a: BigInt(0),
  b: BigInt(5),
  Fp: Field(q),
  n: p,
  Gx: mod(BigInt(-1), q),
  Gy: BigInt(2),
  h: BigInt(1),
  ...getHash(sha256),
});
