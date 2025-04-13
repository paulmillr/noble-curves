import * as mod from '@noble/curves/abstract/modular';
import { utf8ToBytes } from '@noble/curves/abstract/utils';
import { ed25519, hash_to_ristretto255, RistrettoPoint } from '@noble/curves/ed25519';
import { DecafPoint, ed448, hash_to_decaf448 } from '@noble/curves/ed448';
import { shake256 } from '@noble/hashes/sha3';
import { sha512 } from '@noble/hashes/sha512';
import mark from 'micro-bmark';
import { title } from './_shared.js';

(async () => {
  title('ristretto255');
  const priv = mod.hashToPrivateScalar(sha512(ed25519.utils.randomPrivateKey()), ed25519.CURVE.n);
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
  const dpriv = mod.hashToPrivateScalar(
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
