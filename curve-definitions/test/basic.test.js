import { deepStrictEqual, throws } from 'assert';
import { should } from 'micro-should';
import * as nist from '../lib/nist.js';
import { hexToBytes } from '@noble/curves/utils';
import { default as ecdsa } from './fixtures/ecdsa_test.json' assert { type: 'json' };
import { default as ecdh } from './fixtures/ecdh_test.json' assert { type: 'json' };

// import { hexToBytes } from '@noble/curves';

should('Curve Fields', () => {
  const vectors = {
    secp192r1: 0xfffffffffffffffffffffffffffffffeffffffffffffffffn,
    secp224r1: 0xffffffffffffffffffffffffffffffff000000000000000000000001n,
    secp256r1: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
    secp256k1: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
    secp384r1:
      0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffffn,
    secp521r1:
      0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffn,
  };
  for (const n in vectors) deepStrictEqual(nist[n].CURVE.P, vectors[n]);
});

should('wychenproof ECDSA vectors', () => {
  for (const group of ecdsa.testGroups) {
    // Tested in secp256k1.test.js
    if (group.key.curve === 'secp256k1') continue;
    // We don't have SHA-224
    if (group.key.curve === 'secp224r1' && group.sha === 'SHA-224') continue;
    const CURVE = nist[group.key.curve];
    if (!CURVE) continue;
    const pubKey = CURVE.Point.fromHex(group.key.uncompressed);
    deepStrictEqual(pubKey.x, BigInt(`0x${group.key.wx}`));
    deepStrictEqual(pubKey.y, BigInt(`0x${group.key.wy}`));
    for (const test of group.tests) {
      if (['Hash weaker than DL-group'].includes(test.comment)) {
        continue;
      }
      const m = CURVE.CURVE.hash(hexToBytes(test.msg));
      if (test.result === 'valid' || test.result === 'acceptable') {
        try {
          CURVE.Signature.fromDER(test.sig);
        } catch (e) {
          // Some test has invalid signature which we don't accept
          if (e.message.includes('Invalid signature: incorrect length')) continue;
          throw e;
        }
        const verified = CURVE.verify(test.sig, m, pubKey);
        deepStrictEqual(verified, true, 'valid');
      } else if (test.result === 'invalid') {
        let failed = false;
        try {
          failed = !CURVE.verify(test.sig, m, pubKey);
        } catch (error) {
          failed = true;
        }
        deepStrictEqual(failed, true, 'invalid');
      } else throw new Error('unknown test result');
    }
  }
});

should('wychenproof ECDH vectors', () => {
  for (const group of ecdh.testGroups) {
    // // Tested in secp256k1.test.js
    // if (group.key.curve === 'secp256k1') continue;
    // We don't have SHA-224
    const CURVE = nist[group.curve];
    if (!CURVE) continue;
    for (const test of group.tests) {
      if (test.result === 'valid' || test.result === 'acceptable') {
        try {
          const pub = CURVE.Point.fromHex(test.public);
        } catch (e) {
          if (e.message.includes('Point.fromHex: received invalid point.')) continue;
          throw e;
        }
        const shared = CURVE.getSharedSecret(test.private, test.public);
        deepStrictEqual(shared, test.shared, 'valid');
      } else if (test.result === 'invalid') {
        let failed = false;
        try {
          CURVE.getSharedSecret(test.private, test.public);
        } catch (error) {
          failed = true;
        }
        deepStrictEqual(failed, true, 'invalid');
      } else throw new Error('unknown test result');
    }
  }
});

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
