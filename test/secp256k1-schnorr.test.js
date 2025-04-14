import { bytesToHex as hex } from '@noble/hashes/utils.js';
import { describe, should } from 'micro-should';
import { deepStrictEqual } from 'node:assert';
import { readFileSync } from 'node:fs';
import { schnorr } from '../secp256k1.js';
const schCsv = readFileSync('./test/vectors/secp256k1/schnorr.csv', 'utf-8');

describe('schnorr.sign()', () => {
  // index,secret key,public key,aux_rand,message,signature,verification result,comment
  const vectors = schCsv
    .split('\n')
    .map((line) => line.split(','))
    .slice(1, -1);
  for (let vec of vectors) {
    const [index, sec, pub, rnd, msg, expSig, passes, comment] = vec;
    should(`${comment || 'vector ' + index}`, () => {
      if (sec) {
        deepStrictEqual(hex(schnorr.getPublicKey(sec)), pub.toLowerCase());
        const sig = schnorr.sign(msg, sec, rnd);
        deepStrictEqual(hex(sig), expSig.toLowerCase());
        deepStrictEqual(schnorr.verify(sig, msg, pub), true);
      } else {
        const passed = schnorr.verify(expSig, msg, pub);
        deepStrictEqual(passed, passes === 'TRUE');
      }
    });
  }
});

should.runWhen(import.meta.url);
