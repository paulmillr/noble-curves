/*! @noble/curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { concatBytes, randomBytes } from '@noble/hashes/utils';
import { weierstrass, CHash } from '@noble/curves/shortw';

function getHash(hash: CHash) {
  return {
    hash,
    hmac: (key: Uint8Array, ...msgs: Uint8Array[]) => hmac(hash, key, concatBytes(...msgs)),
    randomBytes,
  };
}
const p = BigInt('0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001');
const q = BigInt('0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001');

export const pallas = weierstrass({
  a: BigInt(0),
  b: BigInt(5),
  P: p,
  n: q,
  Gx: BigInt(-1),
  Gy: BigInt(2),
  ...getHash(sha256),
});

export const vesta = weierstrass({
  a: BigInt(0),
  b: BigInt(5),
  P: q,
  n: p,
  Gx: BigInt(-1),
  Gy: BigInt(2),
  ...getHash(sha256),
});
