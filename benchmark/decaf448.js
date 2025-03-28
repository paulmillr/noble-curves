import * as mod from '@noble/curves/abstract/modular';
import { DecafPoint, ed448 } from '@noble/curves/ed448';
import { shake256 } from '@noble/hashes/sha3';
import mark from 'micro-bmark';
import { title } from './_shared.js';

(async () => {
  title('decaf448');
  const priv = mod.hashToPrivateScalar(
    shake256(ed448.utils.randomPrivateKey(), { dkLen: 112 }),
    ed448.CURVE.n
  );
  const pub = DecafPoint.BASE.multiply(priv);
  const encoded = pub.toRawBytes();
  await mark('add', 1000000, () => pub.add(DecafPoint.BASE));
  await mark('multiply', 1000, () => DecafPoint.BASE.multiply(priv));
  await mark('encode', 10000, () => DecafPoint.BASE.toRawBytes());
  await mark('decode', 10000, () => DecafPoint.fromHex(encoded));
})();
