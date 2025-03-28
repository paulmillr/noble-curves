import { x25519 } from '@noble/curves/ed25519';
import { x448 } from '@noble/curves/ed448';
import { p256 } from '@noble/curves/p256';
import { p384 } from '@noble/curves/p384';
import { p521 } from '@noble/curves/p521';
import { secp256k1 } from '@noble/curves/secp256k1';
import { title } from './_shared.js';
import mark from 'micro-bmark';

(async () => {
  const curves = { x25519, x448, secp256k1, p256, p384, p521 };
  title('ECDH');
  for (let [k, c] of Object.entries(curves)) {
    const pubB = c.getPublicKey(c.utils.randomPrivateKey());
    const privA = c.utils.randomPrivateKey();
    await mark(k, 500, () => c.getSharedSecret(privA, pubB));
  }
})();
