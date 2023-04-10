import { run, compare } from 'micro-bmark';
import { secp256k1 } from '../secp256k1.js';
import { p256 } from '../p256.js';
import { p384 } from '../p384.js';
import { p521 } from '../p521.js';
import { x25519 } from '../ed25519.js';
import { x448 } from '../ed448.js';

run(async () => {
  const curves = { x25519, secp256k1, p256, p384, p521, x448 };
  const fns = {};
  for (let [k, c] of Object.entries(curves)) {
    const pubB = c.getPublicKey(c.utils.randomPrivateKey());
    const privA = c.utils.randomPrivateKey();
    fns[k] = () => c.getSharedSecret(privA, pubB);
  }
  await compare('ecdh', 1000, fns);
});
