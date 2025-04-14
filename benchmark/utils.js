import { hash_to_field } from '@noble/curves/abstract/hash-to-curve';
import { Field as Fp, hashToPrivateScalar } from '@noble/curves/abstract/modular';
import { hexToBytes, utf8ToBytes } from '@noble/curves/abstract/utils';
import { ed25519, hash_to_ristretto255, RistrettoPoint } from '@noble/curves/ed25519';
import { DecafPoint, ed448, hash_to_decaf448 } from '@noble/curves/ed448';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { shake256 } from '@noble/hashes/sha3';
import { sha512 } from '@noble/hashes/sha512';
import { randomBytes } from '@noble/hashes/utils';
import mark from 'micro-bmark';
import { title } from './_shared.js';

(async () => {
  title('utils');
  const hex32 = '0123456789abcdef'.repeat(4);
  const hex256 = hex32.repeat(8);
  await mark('hexToBytes 32b', 5000000, () => hexToBytes(hex32));
  await mark('hexToBytes 256b', 500000, () => hexToBytes(hex256));

  title('modular over secp256k1 P field');
  const { Fp: secpFp } = secp256k1.CURVE;
  const NUMS = [2n ** 232n - 5910n, 2n ** 231n - 5910n, 2n ** 231n - 5909n];
  await mark('invert a', 300000, () => secpFp.inv(NUMS[0]));
  await mark('invert b', 300000, () => secpFp.inv(NUMS[1]));
  await mark('sqrt p = 3 mod 4', 15000, () => secpFp.sqrt(NUMS[1]));
  const FpStark = Fp(BigInt('0x800000000000011000000000000000000000000000000000000000000000001'));
  await mark('sqrt tonneli-shanks', 500, () => FpStark.sqrt(NUMS[2]));

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

  title('ristretto255');
  const priv = hashToPrivateScalar(sha512(ed25519.utils.randomPrivateKey()), ed25519.CURVE.n);
  const pub = RistrettoPoint.BASE.multiply(priv);
  const encoded = pub.toRawBytes();
  const msg = utf8ToBytes('message');

  await mark('add', 1000000, () => pub.add(RistrettoPoint.BASE));
  await mark('multiply', 10000, () => RistrettoPoint.BASE.multiply(priv));
  await mark('encode', 10000, () => RistrettoPoint.BASE.toRawBytes());
  await mark('decode', 10000, () => RistrettoPoint.fromHex(encoded));
  await mark('hash_to_ristretto255', 1000, () =>
    hash_to_ristretto255(msg, { DST: 'ristretto255_XMD:SHA-512_R255MAP_RO_' })
  );

  title('decaf448');
  const dpriv = hashToPrivateScalar(
    shake256(ed448.utils.randomPrivateKey(), { dkLen: 112 }),
    ed448.CURVE.n
  );
  const dpub = DecafPoint.BASE.multiply(priv);
  const dencoded = dpub.toRawBytes();
  await mark('add', 1000000, () => dpub.add(DecafPoint.BASE));
  await mark('multiply', 1000, () => DecafPoint.BASE.multiply(dpriv));
  await mark('encode', 10000, () => DecafPoint.BASE.toRawBytes());
  await mark('decode', 10000, () => DecafPoint.fromHex(dencoded));
  await mark('hash_to_decaf448', 1000, () =>
    hash_to_decaf448(msg, { DST: 'decaf448_XOF:SHAKE256_D448MAP_RO_' })
  );
})();

