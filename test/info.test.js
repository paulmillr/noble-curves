import { isBytes } from '@noble/hashes/utils';
import { describe, should } from 'micro-should';
import { deepStrictEqual as eql } from 'node:assert';
import { randomBytes } from 'node:crypto';
import { ed25519, x25519 } from '../esm/ed25519.js';
import { ed448, x448 } from '../esm/ed448.js';
import { secp256r1, secp384r1, secp521r1 } from '../esm/nist.js';
import { schnorr, secp256k1 } from '../esm/secp256k1.js';

const CURVES = {
  secp256k1,
  secp256r1,
  secp384r1,
  secp521r1,
  ed25519,
  x25519,
  ed448,
  x448,
  schnorr,
};

describe('info', () => {
  for (const name in CURVES) {
    const curve = CURVES[name];
    describe(name, () => {
      should('keys', () => {
        const len = curve.info.lengths;
        const privateKey = curve.utils.randomPrivateKey();
        eql(privateKey.length, len.secret);
        const publicKey = curve.getPublicKey(privateKey);
        eql(publicKey.length, len.public);
        if (curve.getSharedSecret) {
          const shared = curve.getSharedSecret(privateKey, publicKey);
          eql(shared.length, len.public);
        }
        if (curve.sign) {
          const msg = new Uint8Array([1, 2, 3]);
          let sig = curve.sign(msg, privateKey);
          if (!isBytes(sig)) sig = sig.toBytes();
          // weierstrass uses compact signatures by default, so we know size
          eql(sig.length, len.signature);
          curve.verify(sig, msg, publicKey);
        }
        const seed = randomBytes(len.seed);
        eql(curve.utils.randomPrivateKey(seed), curve.utils.randomPrivateKey(seed));
        curve.getPublicKey(curve.utils.randomPrivateKey(seed)); // doesn't throw
      });
      should('keygen', () => {
        const seed = randomBytes(curve.info.lengths.seed);
        const keys = curve.keygen(seed);
        eql(keys.secretKey, curve.utils.randomPrivateKey(seed));
        eql(keys.publicKey, curve.getPublicKey(curve.utils.randomPrivateKey(seed)));
      });
    });
  }
});

should.runWhen(import.meta.url);
