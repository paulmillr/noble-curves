import { hash_to_field } from '@noble/curves/abstract/hash-to-curve';
import { Field as Fp, hashToPrivateScalar } from '@noble/curves/abstract/modular';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@noble/hashes/utils';
import mark from 'micro-bmark';
import { title } from './_shared.js';

(async () => {
  title('modular over secp256k1 P field');
  const { Fp: secpFp } = secp256k1.CURVE;
  await mark('invert a', 300000, () => secpFp.inv(2n ** 232n - 5910n));
  await mark('invert b', 300000, () => secpFp.inv(2n ** 231n - 5910n));
  await mark('sqrt p = 3 mod 4', 15000, () => secpFp.sqrt(2n ** 231n - 5910n));
  const FpStark = Fp(BigInt('0x800000000000011000000000000000000000000000000000000000000000001'));
  await mark('sqrt tonneli-shanks', 500, () => FpStark.sqrt(2n ** 231n - 5909n));

  title('hashing to fields')
  const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const rand = randomBytes(40);
  await mark('hashToPrivateScalar', 1000000, () => hashToPrivateScalar(rand, N));
  // - p, the characteristic of F
  // - m, the extension degree of F, m >= 1
  // - L = ceil((ceil(log2(p)) + k) / 8), where k is the security of suite (e.g. 128)
  await mark('hash_to_field', 100000, () =>
    hash_to_field(rand, 1, { DST: 'secp256k1', hash: sha256, expand: 'xmd', p: N, m: 1, k: 128 })
  );
})();
