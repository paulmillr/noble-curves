import { ed25519 } from '@noble/curves/ed25519.js';
import { ed448 } from '@noble/curves/ed448.js';
import { p256, p384, p521 } from '@noble/curves/nist.js';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';

import { utf8ToBytes } from '@noble/curves/utils.js';

for (const curve of [secp256k1, schnorr, p256, p384, p521, ed25519, ed448]) {
  const { secretKey, publicKey } = curve.keygen();
  const msg = utf8ToBytes('hello noble');
  const sig = curve.sign(msg, secretKey);
  const isValid = curve.verify(sig, msg, publicKey);
  console.log(curve, secretKey, publicKey, sig);
}
