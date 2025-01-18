import { x25519 } from '@noble/curves/ed25519';
import { x448 } from '@noble/curves/ed448';
import { p256 } from '@noble/curves/p256';
import { p384 } from '@noble/curves/p384';
import { p521 } from '@noble/curves/p521';
import { secp256k1 } from '@noble/curves/secp256k1';
// import { compare } from 'micro-bmark';

(async () => {
  const curves = { x25519, secp256k1, p256, p384, p521, x448 };
  const fns = {};
  for (let [k, c] of Object.entries(curves)) {
    const pubB = c.getPublicKey(c.utils.randomPrivateKey());
    const privA = c.utils.randomPrivateKey();
    fns[k] = () => c.getSharedSecret(privA, pubB);
  }
  // await compare('ecdh', 1000, fns);
})();
