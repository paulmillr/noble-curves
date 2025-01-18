import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import mark from 'micro-bmark';
import { generateData } from './_shared.js';

(async () => {
  console.log(`\x1b[36msecp256k1\x1b[0m`);
  await mark('init', 1, () => secp256k1.utils.precompute(8));
  const d = generateData(secp256k1);
  await mark('getPublicKey', 10000, () => secp256k1.getPublicKey(d.priv));
  await mark('sign', 10000, () => secp256k1.sign(d.msg, d.priv));
  await mark('verify', 1000, () => secp256k1.verify(d.sig, d.msg, d.pub));
  const pub2 = secp256k1.getPublicKey(secp256k1.utils.randomPrivateKey());
  await mark('getSharedSecret', 1000, () => secp256k1.getSharedSecret(d.priv, pub2));
  await mark('recoverPublicKey', 1000, () => d.sig.recoverPublicKey(d.msg));
  const s = schnorr.sign(d.msg, d.priv);
  const spub = schnorr.getPublicKey(d.priv);
  await mark('schnorr.sign', 1000, () => schnorr.sign(d.msg, d.priv));
  await mark('schnorr.verify', 1000, () => schnorr.verify(s, d.msg, spub));
})();
