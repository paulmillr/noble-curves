import { run, mark, compare, utils } from 'micro-bmark';
import { generateData } from './_shared.js';
import { secp256k1 } from '../secp256k1.js';
import { P256 } from '../p256.js';
import { P384 } from '../p384.js';
import { P521 } from '../p521.js';
import { x25519 } from '../ed25519.js';
import { x448 } from '../ed448.js';

run(async () => {
  const curves = { x25519, secp256k1, P256, P384, P521, x448 };
  const fns = {};
  for (let [k, c] of Object.entries(curves)) {
    const pubB = c.getPublicKey(c.utils.randomPrivateKey());
    const privA = c.utils.randomPrivateKey();
    fns[k] = () => c.getSharedSecret(privA, pubB);
  }
  await compare('ecdh', 1000, fns);
});
