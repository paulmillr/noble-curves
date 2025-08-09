import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { shake256 } from '@noble/hashes/sha3.js';
import { randomBytes } from '@noble/hashes/utils.js';
import mark from 'micro-bmark';
import { hash_to_field } from '../../src/abstract/hash-to-curve.ts';
import * as md from '../../src/abstract/modular.ts';
import { ed25519, ristretto255, ristretto255_hasher } from '../../src/ed25519.ts';
import { decaf448, decaf448_hasher, ed448 } from '../../src/ed448.ts';
import { secp256k1 } from '../../src/secp256k1.ts';
import { asciiToBytes, hexToBytes } from '../../src/utils.ts';
import { title } from './_shared.ts';

const { Field } = md;

const RistrettoPoint = ristretto255.Point;
const DecafPoint = decaf448.Point;

(async () => {
  title('utils');
  const hex32 = '0123456789abcdef'.repeat(4);
  const hex256 = hex32.repeat(8);
  await mark('hexToBytes 32b', () => hexToBytes(hex32));
  await mark('hexToBytes 256b', () => hexToBytes(hex256));

  title('modular over secp256k1 P field');
  const secpFp = secp256k1.Point.Fp;
  const Fp25519 = Field(2n ** 255n - 19n);
  const Fp383 = Field(BigInt('2462625387274654950767440006258975862817483704404090416745738034557663054564649171262659326683244604346084081047321'));
  const FpStark = Field(BigInt('0x800000000000011000000000000000000000000000000000000000000000001'));

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
  // await mark('hashToPrivateScalar', () => hashToPrivateScalar(rand, N));
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
  const msg = asciiToBytes('message');

  await mark('add', () => pub.add(RistrettoPoint.BASE));
  await mark('multiply', () => RistrettoPoint.BASE.multiply(priv));
  await mark('encode', () => RistrettoPoint.BASE.toBytes());
  await mark('decode', () => RistrettoPoint.fromBytes(encoded));
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
  await mark('decode', () => DecafPoint.fromBytes(dencoded));
  await mark('decaf448_hasher', () =>
    decaf448_hasher.hashToCurve(msg, { DST: 'decaf448_XOF:SHAKE256_D448MAP_RO_' })
  );
})();

