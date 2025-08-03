import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import mark from 'micro-bmark';
import { generateData, title } from './_shared.ts';

(async () => {
  title('secp256k1');
  await mark('init', 1, () => secp256k1.Point.BASE.precompute(8, false));
  const d = generateData(secp256k1);
  await mark('getPublicKey', () => secp256k1.getPublicKey(d.priv));
  await mark('sign', () => secp256k1.sign(d.msg, d.priv));
  await mark('verify', () => secp256k1.verify(d.sig, d.msg, d.pub));
  await mark('recoverPublicKey', () => secp256k1.Signature.fromBytes(d.sig).addRecoveryBit(1).recoverPublicKey(d.msg));
  const pub2 = secp256k1.getPublicKey(secp256k1.utils.randomSecretKey());
  await mark('getSharedSecret', () => secp256k1.getSharedSecret(d.priv, pub2));
  const s = schnorr.sign(d.msg, d.priv);
  const spub = schnorr.getPublicKey(d.priv);
  await mark('schnorr.sign', () => schnorr.sign(d.msg, d.priv));
  await mark('schnorr.verify', () => schnorr.verify(s, d.msg, spub));
})();
