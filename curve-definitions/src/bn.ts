/*! @noble/curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { weierstrass, CHash } from '@noble/curves/weierstrass';
import { concatBytes, randomBytes } from '@noble/hashes/utils';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';

function getHash(hash: CHash) {
  return {
    hash,
    hmac: (key: Uint8Array, ...msgs: Uint8Array[]) => hmac(hash, key, concatBytes(...msgs)),
    randomBytes,
  };
}

// Was known as alt_bn128 when it had 128-bit security. Now that it's much lower, the naming
// has been changed to its prime bit count.
export const bn254 = weierstrass({
  a: 0n,
  b: 3n,
  P: 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47n,
  n: 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n,
  Gx: 1n,
  Gy: 2n,
  ...getHash(sha256),
});
