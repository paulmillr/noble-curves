import { should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql } from 'node:assert';
import { randomBytes } from 'node:crypto';
import { bls12_381 } from '../src/bls12-381.ts';
import { ed25519, x25519 } from '../src/ed25519.ts';
import { p256 } from '../src/nist.ts';
import { bytesToHex } from '../src/utils.ts';

const CURVES = {
  p256,
  ed25519,
  bls12_381_shortSignatures: bls12_381.shortSignatures,
  bls12_381_longSignatures: bls12_381.longSignatures,
  x25519,
};

function getError(fn) {
  try {
    fn();
    throw new Error('NO ERROR!');
  } catch (e) {
    return e;
  }
}
const green = (s) => `\x1b[32m${s}\x1b[0m`;

should('Errors', () => {
  const res = {}; // Record<string, [string, string][]>
  const curveNameLength = Object.keys(CURVES)
    .map((i) => i.length)
    .reduce((acc, i) => Math.max(acc, i));
  for (const name in CURVES) {
    const C = CURVES[name];
    const CE = (s, fn) => {
      if (!res[s]) res[s] = [];
      res[s].push({ curveName: name, name: s, error: getError(fn) });
    };
    const CEG = (s, manglers, value, fn) => {
      for (const m in manglers) CE(s + m, () => fn(manglers[m](value)));
    };
    const BYTES10 = randomBytes(10);

    // NOTE: 'b.slice is not a function' is internal (we are trying to modify bls point)
    const U8 = {
      false: () => false,
      bytes10: () => BYTES10,
      empty: () => new Uint8Array(0),
      zero: (b) => new Uint8Array(b.length),
      slice1: (b) => b.slice(1),
      hex: (b) => bytesToHex(b),
      array: (b) => Array.from(b),
    };
    const B = {
      1: () => 1,
      0: () => 0,
      null: () => null,
      string: () => 'true',
    };
    console.log('a', C);
    if (C.keygen) {
      const seed = randomBytes(C.lengths.seed);
      CEG('keygen: wrong seed=', U8, seed, (s) => C.keygen(s));
      const keys = C.keygen();
      if (C.getPublicKey) {
        CEG('getPublicKey: wrong secretKey=', U8, keys.secretKey, (s) => C.getPublicKey(s));
      }
      if (C.sign && C.verify) {
        let msg = BYTES10;
        // TODO: prehash by default too?
        if (C.info.type.startsWith('bls')) msg = C.hash(msg);
        const sig = C.sign(msg, keys.secretKey);
        eql(C.verify(sig, msg, keys.publicKey), true);

        CEG('sign: wrong msg=', U8, msg, (s) => C.sign(s, keys.secretKey));
        CEG('sign: wrong secretKey=', U8, keys.secretKey, (s) => C.sign(msg, s));
        if (C.info.type === 'weierstrass') {
          CEG('sign: wrong prehash=', B, true, (s) => C.sign(msg, keys.secretKey, { prehash: s }));
          CEG('sign: wrong lowS=', B, true, (s) => C.sign(msg, keys.secretKey, { lowS: s }));
        }
        if (C.info.type === 'edwards') {
          CEG('sign: wrong context=', U8, BYTES10, (s) =>
            C.sign(msg, keys.secretKey, { context: s })
          );
        }
        const SIG = C.Signature ? { ...U8, sigObj: (s) => C.Signature.fromBytes(sig) } : U8;
        // Verify
        CEG('verify: wrong msg=', U8, msg, (s) => C.verify(sig, s, keys.publicKey));
        CEG('verify: wrong pk=', U8, keys.publicKey, (s) => C.verify(sig, msg, s));
        CEG('verify: wrong sig=', SIG, sig, (s) => C.verify(s, msg, keys.publicKey));
        if (C.info.type === 'weierstrass') {
          CEG('verify: wrong prehash=', B, true, (s) =>
            C.verify(sig, msg, keys.publicKey, { prehash: s })
          );
          CEG('verify: wrong lowS=', B, true, (s) =>
            C.verify(sig, msg, keys.publicKey, { lowS: s })
          );
        }
        if (C.info.type === 'edwards') {
          CEG('verify: wrong context=', U8, BYTES10, (s) =>
            C.verify(sig, msg, keys.publicKey, { context: s })
          );
          CEG('verify: wrong zip215=', B, true, (s) =>
            C.verify(sig, msg, keys.publicKey, { zip215: s })
          );
        }
      }
      if (C.getSharedSecret) {
        const shared = C.getSharedSecret(keys.secretKey, keys.publicKey);
        CEG('getSharedSecret: wrong secretKey=', U8, keys.secretKey, (s) =>
          C.getSharedSecret(s, keys.publicKey)
        );
        CEG('getSharedSecret: wrong publicKey=', U8, keys.publicKey, (s) =>
          C.getSharedSecret(keys.secretKey, s)
        );
      }
      if (C.utils) {
        if (C.utils.isValidSecretKey) {
          CEG('isValidSecretKey: wrong secretKey=', U8, keys.secretKey, (s) =>
            C.utils.isValidSecretKey(s)
          );
        }
        if (C.utils.isValidPublicKey) {
          CEG('isValidPublicKey: wrong publicKey=', U8, keys.publicKey, (s) =>
            C.utils.isValidPublicKey(s)
          );
        }
        if (C.utils.randomSecretKey) {
          CEG('randomSecretKey: wrong seed=', U8, seed, (s) => C.utils.randomSecretKey(s));
        }
      }
    }
  }

  for (const k in res) {
    console.log(green(k));
    for (const { curveName, error } of res[k])
      console.log(`- ${curveName.padEnd(curveNameLength, ' ')}: ${error.message}`);
  }
});

should.runWhen(import.meta.url);
