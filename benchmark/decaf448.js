import { run, mark, utils } from 'micro-bmark';
import { shake256 } from '@noble/hashes/sha3';
import * as mod from '../abstract/modular.js';
import { ed448, DecafPoint } from '../ed448.js';

run(async () => {
  const RAM = false;
  if (RAM) utils.logMem();
  console.log(`\x1b[36mdecaf448\x1b[0m`);
  const priv = mod.hashToPrivateScalar(shake256(ed448.utils.randomPrivateKey(), { dkLen: 112 }), ed448.CURVE.n);
  const pub = DecafPoint.BASE.multiply(priv);
  const encoded = pub.toRawBytes();
  await mark('add', 1000000, () => pub.add(DecafPoint.BASE));
  await mark('multiply', 1000, () => DecafPoint.BASE.multiply(priv));
  await mark('encode', 10000, () => DecafPoint.BASE.toRawBytes());
  await mark('decode', 10000, () => DecafPoint.fromHex(encoded));
  if (RAM) utils.logMem();
});
