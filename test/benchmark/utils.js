import { hash_to_field } from '@noble/curves/abstract/hash-to-curve';
import { Field as Fp, hashToPrivateScalar } from '@noble/curves/abstract/modular';
import { hexToBytes, utf8ToBytes } from '@noble/curves/abstract/utils';
import { ed25519, ristretto255, ristretto255_hasher } from '@noble/curves/ed25519';
import { decaf448, decaf448_hasher, ed448 } from '@noble/curves/ed448';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { shake256 } from '@noble/hashes/sha3';
import { randomBytes } from '@noble/hashes/utils';
import mark from 'micro-bmark';
import { title } from './_shared.js';

const RistrettoPoint = ristretto255.Point;
const DecafPoint = decaf448.Point;

(async () => {
  title('utils');
  const hex32 = '0123456789abcdef'.repeat(4);
  const hex256 = hex32.repeat(8);
  await mark('hexToBytes 32b', () => hexToBytes(hex32));
  await mark('hexToBytes 256b', () => hexToBytes(hex256));

  title('modular over secp256k1 P field');
  const { Fp: secpFp } = secp256k1.CURVE;
  const Fp25519 = Fp(2n ** 255n - 19n);
  const Fp383 = Fp(BigInt('2462625387274654950767440006258975862817483704404090416745738034557663054564649171262659326683244604346084081047321'));
  const FpStark = Fp(BigInt('0x800000000000011000000000000000000000000000000000000000000000001'));

  const NUM0 = 2n ** 232n - 5910n;
  const NUM1 = 2n ** 231n - 5910n;
  const NUM2 = 2n ** 231n - 5909n;
  const NUM3 = 16n;

  await mark('invert a', () => secpFp.inv(NUM0));
  await mark('invert b', () => secpFp.inv(NUM1));

  await mark('sqrt p = 3 mod 4', () => secpFp.sqrt(NUM1));
  await mark('sqrt p = 5 mod 8', () => Fp25519.sqrt(NUM3));
  await mark('sqrt p = 9 mod 16', () => Fp383.sqrt(NUM3));
  await mark('sqrt tonneli-shanks', () => FpStark.sqrt(NUM2));

  title('hashing to fields')
  const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const rand = randomBytes(40);
  await mark('hashToPrivateScalar', () => hashToPrivateScalar(rand, N));
  // - p, the characteristic of F
  // - m, the extension degree of F, m >= 1
  // - L = ceil((ceil(log2(p)) + k) / 8), where k is the security of suite (e.g. 128)
  await mark('hash_to_field', () =>
    hash_to_field(rand, 1, { DST: 'secp256k1', hash: sha256, expand: 'xmd', p: N, m: 1, k: 128 })
  );

  title('ristretto255');
  const priv = ristretto255_hasher.hashToScalar(sha512(ed25519.utils.randomSecretKey()));
  const pub = RistrettoPoint.BASE.multiply(priv);
  const encoded = pub.toBytes();
  const msg = utf8ToBytes('message');

  await mark('add', () => pub.add(RistrettoPoint.BASE));
  await mark('multiply', () => RistrettoPoint.BASE.multiply(priv));
  await mark('encode', () => RistrettoPoint.BASE.toBytes());
  await mark('decode', () => RistrettoPoint.fromHex(encoded));
  await mark('ristretto255_hasher', 1000, () =>
    ristretto255_hasher.hashToCurve(msg, { DST: 'ristretto255_XMD:SHA-512_R255MAP_RO_' })
  );

  title('decaf448');
  const dpriv = decaf448_hasher.hashToScalar(
    shake256(ed448.utils.randomSecretKey(), { dkLen: 112 })
  );
  const dpub = DecafPoint.BASE.multiply(priv);
  const dencoded = dpub.toBytes();
  await mark('add', () => dpub.add(DecafPoint.BASE));
  await mark('multiply', () => DecafPoint.BASE.multiply(dpriv));
  await mark('encode', () => DecafPoint.BASE.toBytes());
  await mark('decode', () => DecafPoint.fromHex(dencoded));
  await mark('decaf448_hasher', () =>
    decaf448_hasher.hashToCurve(msg, { DST: 'decaf448_XOF:SHAKE256_D448MAP_RO_' })
  );
})();

