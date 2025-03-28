import * as mod from '@noble/curves/abstract/modular';
import { ed25519, RistrettoPoint } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import mark from 'micro-bmark';
import { title } from './_shared.js';

(async () => {
  title('ristretto255');
  const priv = mod.hashToPrivateScalar(sha512(ed25519.utils.randomPrivateKey()), ed25519.CURVE.n);
  const pub = RistrettoPoint.BASE.multiply(priv);
  const encoded = pub.toRawBytes();
  await mark('add', 1000000, () => pub.add(RistrettoPoint.BASE));
  await mark('multiply', 10000, () => RistrettoPoint.BASE.multiply(priv));
  await mark('encode', 10000, () => RistrettoPoint.BASE.toRawBytes());
  await mark('decode', 10000, () => RistrettoPoint.fromHex(encoded));
})();
