import {
  hexToBytes as bytes,
  concatBytes,
  bytesToHex as hex,
  randomBytes,
} from '@noble/hashes/utils.js';
import * as fc from 'fast-check';
import { describe, should } from 'micro-should';
import { deepStrictEqual as eql, strictEqual, throws } from 'node:assert';
import { ed25519 as ed, ED25519_TORSION_SUBGROUP, numberToBytesLE } from './ed25519.helpers.js';
import { getTypeTestsNonUi8a, json, txt } from './utils.js';

const VECTORS_rfc8032_ed25519 = json('./vectors/rfc8032-ed25519.json');
// Old vectors allow to test sign() because they include private key
const ed25519vectors_OLD = json('./vectors/ed25519/ed25519_test_OLD.json');
const ed25519vectors = json('./vectors/wycheproof/ed25519_test.json');
const zip215 = json('./vectors/ed25519/zip215.json');
const edgeCases = json('./vectors/ed25519/edge-cases.json');

// Any changes to the file will need to be aware of the fact
// the file is shared between noble-curves and noble-ed25519.

describe('ed25519', () => {
  const Point = ed.Point;

  function bytes32(numOrStr) {
    let hex2 = typeof numOrStr === 'string' ? numOrStr : numOrStr.toString(16);
    return bytes(hex2.padStart(64, '0'));
  }

  ed.utils.precompute(8);

  describe('getPublicKey()', () => {
    should('not accept >32byte private keys in Uint8Array format', () => {
      const invalidPriv = new Uint8Array(33).fill(1);
      throws(() => ed.getPublicKey(invalidPriv));
    });
    should('reject invalid inputs', () => {
      for (const item of getTypeTestsNonUi8a()) {
        // @ts-ignore
        throws(() => ed.getPublicKey(item));
      }
    });
  });

  describe('sign()', () => {
    should('creates random signature', () => {
      const priv = ed.utils.randomPrivateKey();
      const pub = ed.getPublicKey(priv);
      const msg = new TextEncoder().encode('hello');
      const sig = ed.sign(msg, priv);
      eql(ed.verify(sig, msg, pub), true);
    });

    should('pass 1024 vectors', () => {
      // https://ed25519.cr.yp.to/python/sign.py
      // https://ed25519.cr.yp.to/python/sign.input
      const vectorsCrYpTo = txt('vectors/ed25519/vectors.txt');
      for (let i = 0; i < vectorsCrYpTo.length; i++) {
        const vector = vectorsCrYpTo[i];
        // Extract.
        const priv = vector[0].slice(0, 64);
        const expectedPub = vector[1];
        const msg = vector[2];
        const expectedSignature = vector[3].slice(0, 128);

        // Calculate
        const pub = ed.getPublicKey(bytes32(priv));
        eql(hex(pub), expectedPub);
        eql(pub, Point.fromBytes(pub).toBytes());

        const signature = hex(ed.sign(msg, priv));
        // console.log('vector', i);
        // expect(pub).toBe(expectedPub);
        eql(signature, expectedSignature);
      }
    });

    should('pass rfc8032 vectors', () => {
      // https://tools.ietf.org/html/rfc8032#section-7
      for (const vec of VECTORS_rfc8032_ed25519) {
        const { priv, msg, pub, sig } = vec;
        const pubG = ed.getPublicKey(bytes(priv));
        const sigG = ed.sign(bytes(msg), bytes(priv));
        eql(hex(pubG), pub);
        eql(hex(sigG), sig);
      }
    });
  });

  describe('verify()', () => {
    should('correct static signatures', () => {
      const priv = bytes32('a665a45920422f9d417e4867ef');
      const priv2 = bytes32('a675a45920422f9d417e4867ef');
      const msg = bytes('874f9960c5d2b7a9b5fad383e1ba44719ebb743a');
      const msg2 = bytes('589d8c7f1da0a24bc07b7381ad48b1cfc211af1c');

      const pub = ed.getPublicKey(priv);
      const sig = ed.sign(msg, priv);

      eql(ed.verify(sig, msg, pub), true);

      const pub2 = ed.getPublicKey(priv2);
      const sig2 = ed.sign(msg, priv);
      eql(ed.verify(sig2, msg, pub2), false);

      eql(ed.verify(sig, msg2, pub), false);
    });

    function hexa() {
      const items = '0123456789abcdef';
      return fc.integer({ min: 0, max: 15 }).map((n) => items[n]);
    }
    function hexaString(constraints = {}) {
      return fc.string({ ...constraints, unit: hexa() });
    }

    should('random signature', () => {
      fc.assert(
        fc.property(
          hexaString({ minLength: 2, maxLength: 32 }),
          // @ts-ignore
          fc.bigInt(2n, ed.CURVE.n),
          (msgh, privnum) => {
            const priv = bytes32(privnum);
            const pub = ed.getPublicKey(priv);
            if (msgh.length % 2 !== 0) msgh = '0' + msgh;
            const msg = bytes(msgh);
            const sig = ed.sign(msg, priv);
            eql(pub.length, 32);
            eql(sig.length, 64);
            eql(ed.verify(sig, msg, pub), true);
          }
        ),
        { numRuns: 1000 }
      );
    });
    should('fail for wrong message', () => {
      fc.assert(
        fc.property(
          fc.array(fc.integer({ min: 0x00, max: 0xff })),
          // @ts-ignore
          fc.array(fc.integer({ min: 0x00, max: 0xff })),
          fc.bigInt(1n, ed.CURVE.n),
          (bytes, wrongBytes, privateKey) => {
            const privKey = bytes32(privateKey);
            const message = new Uint8Array(bytes);
            const wrongMessage = new Uint8Array(wrongBytes);
            const publicKey = ed.getPublicKey(privKey);
            const signature = ed.sign(message, privKey);
            eql(
              ed.verify(signature, wrongMessage, publicKey),
              bytes.toString() === wrongBytes.toString()
            );
          }
        ),
        { numRuns: 50 }
      );
    });

    should('not mutate inputs 1', () => {
      const privateKey = ed.utils.randomPrivateKey();
      const publicKey = ed.getPublicKey(privateKey);

      for (let i = 0; i < 100; i++) {
        let pay = randomBytes(100); // payload
        let sig = ed.sign(pay, privateKey);
        if (!ed.verify(sig, pay, publicKey)) throw new Error('Signature verification failed');
        if (typeof Buffer === 'undefined') {
          if (!ed.verify(sig.slice(), pay.slice(), publicKey))
            throw new Error('Signature verification failed');
        } else {
          const signatureCopy = Buffer.alloc(sig.byteLength);
          signatureCopy.set(sig, 0); // <-- breaks
          pay = pay.slice();
          sig = sig.slice();

          if (!ed.verify(signatureCopy, pay, publicKey))
            throw new Error('Copied signature verification failed');
        }
      }
    });

    should('not mutate inputs 2', () => {
      const message = new Uint8Array([12, 12, 12]);
      const signature = ed.sign(message, bytes32(1n));
      const publicKey = ed.getPublicKey(bytes32(1n)); // <- was 1n
      eql(ed.verify(signature, message, publicKey), true);
    });

    should('not verify when sig.s >= CURVE.n', () => {
      const privateKey = ed.utils.randomPrivateKey();
      const message = Uint8Array.from([0xab, 0xbc, 0xcd, 0xde]);
      const publicKey = ed.getPublicKey(privateKey);
      const signature = ed.sign(message, privateKey);

      const R = signature.slice(0, 32);
      let s_0 = signature.slice(32, 64);
      let s_1 = hex(s_0.slice().reverse());
      let s_2 = BigInt('0x' + s_1);
      s_2 = s_2 + ed.CURVE.n;
      let s_3 = numberToBytesLE(s_2, 32);

      const sig_invalid = concatBytes(R, s_3);
      eql(ed.verify(sig_invalid, message, publicKey), false);
    });

    should('have strict SUF-CMA and SBS properties', () => {
      // https://eprint.iacr.org/2020/1244
      const list = [0, 1, 6, 7, 8, 9, 10, 11].map((i) => edgeCases[i]);
      for (let v of list) {
        const result = ed.verify(v.signature, v.message, v.pub_key, { zip215: false });
        strictEqual(result, false, `zip215: false must not validate: ${v.signature}`);
      }
    });
  });

  describe('Point', () => {
    should('not create point without z, t', () => {
      const t = 81718630521762619991978402609047527194981150691135404693881672112315521837062n;
      const point = Point.fromAffine({ x: t, y: t });
      throws(() => point.assertValidity());
      // Otherwise (without assertValidity):
      // const point2 = point.double();
      // point2.toAffine(); // crash!
    });

    should('not accept point with z=0', () => {
      throws(() => new ed.Point(0n, 0n, 0n, 0n));
      throws(() => new ed.Point(1n, 1n, 0n, 1n));

      const zeros = ed.Point.fromAffine({ x: 0n, y: 0n });
      eql(zeros.equals(ed.Point.BASE.multiply(3n)), false);

      const key = ed.utils.randomPrivateKey();
      const A = ed.Point.fromBytes(ed.getPublicKey(key));
      const T = ed.Point.fromBytes(bytes(ED25519_TORSION_SUBGROUP[2]));
      const B = A.add(T).add(A);
      const C = ed.Point.fromBytes(ed.getPublicKey(ed.utils.randomPrivateKey()));
      eql(B.equals(C), false);

      const sig =
        '86d8373bf0797b5fee241605760ffebeae65d2d3395cd9afbf67b52f0198484344d9709abd414b2880485fa93a1bb98fb9af0f083c8c3b8141d71b9dfd448b0b';
      const msg = '48656c6c6f2c20576f726c6421';
      const pub = '34fe104df0a1348ef60699b3659b5a31b14a6f8488e14bfa55d2cc310959ae50';

      eql(ed.verify(bytes(sig), bytes(msg), bytes(pub)), false);
    });

    describe('#multiply()', () => {
      should('pass against addresstests vectors', () => {
        // https://xmr.llcoins.net/addresstests.html
        const xmrVectors = [
          [
            '090af56259a4b6bfbc4337980d5d75fbe3c074630368ff3804d33028e5dbfa77',
            '0f3b913371411b27e646b537e888f685bf929ea7aab93c950ed84433f064480d',
          ],
          [
            '00364e8711a60780382a5d57b061c126f039940f28a9e91fe039d4d3094d8b88',
            'ad545340b58610f0cd62f17d55af1ab11ecde9c084d5476865ddb4dbda015349',
          ],
          [
            '0b9bf90ff3abec042752cac3a07a62f0c16cfb9d32a3fc2305d676ec2d86e941',
            'e097c4415fe85724d522b2e449e8fd78dd40d20097bdc9ae36fe8ec6fe12cb8c',
          ],
          [
            '069d896f02d79524c9878e080308180e2859d07f9f54454e0800e8db0847a46e',
            'f12cb7c43b59971395926f278ce7c2eaded9444fbce62ca717564cb508a0db1d',
          ],
        ];
        for (const [scalarHex, pointHex] of xmrVectors) {
          const scalar = BigInt('0x' + scalarHex);
          eql(hex(Point.BASE.multiply(scalar).toBytes()), pointHex);
        }
      });

      should('throw Point#multiply on TEST 5', () => {
        for (const num of [0n, 0, -1n, -1, 1.1]) {
          // @ts-ignore
          throws(() => Point.BASE.multiply(num));
        }
      });
    });

    should('isTorsionFree()', () => {
      const { point } = ed.utils.getExtendedPublicKey(ed.utils.randomPrivateKey());
      for (const hex of ED25519_TORSION_SUBGROUP.slice(1)) {
        const dirty = point.add(Point.fromBytes(bytes(hex)));
        const cleared = dirty.clearCofactor();
        strictEqual(point.isTorsionFree(), true, `orig must be torsionFree: ${hex}`);
        strictEqual(dirty.isTorsionFree(), false, `dirty must not be torsionFree: ${hex}`);
        strictEqual(cleared.isTorsionFree(), true, `cleared must be torsionFree: ${hex}`);
      }
    });

    should('have roundtrip P.fromAffine(p.toAffine())', () => {
      const xy = { x: 0n, y: 1n };
      const p = Point.fromAffine(xy);
      eql(p, Point.ZERO);
      eql(p.toAffine(), xy);
    });
  });

  // https://zips.z.cash/zip-0215
  // Vectors from https://gist.github.com/hdevalence/93ed42d17ecab8e42138b213812c8cc7
  describe('ZIP215', () => {
    should('pass all compliance tests', () => {
      const str = new TextEncoder().encode('Zcash');
      for (let v of zip215) {
        let noble = false;
        try {
          noble = ed.verify(v.sig_bytes, str, v.vk_bytes);
        } catch (e) {
          noble = false;
        }
        eql(noble, v.valid_zip215, JSON.stringify(v));
      }
    });

    should('disallow sig.s >= CURVE.n', () => {
      // sig.R = BASE, sig.s = N+1
      const sig = bytes(
        '5866666666666666666666666666666666666666666666666666666666666666eed3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010'
      );
      const msg1 = bytes('deadbeef');
      const msg2 = bytes('be'.repeat(64));
      throws(() => {
        eql(ed.verify(sig, msg1, Point.BASE), false);
      });
      eql(ed.verify(sig, msg2, Point.BASE.toBytes()), false);
    });
  });

  should('wycheproof/ED25519 (OLD)', () => {
    for (let g = 0; g < ed25519vectors_OLD.testGroups.length; g++) {
      const group = ed25519vectors_OLD.testGroups[g];
      const key = group.key;
      eql(hex(ed.getPublicKey(key.sk)), key.pk, `(${g}, public)`);
      for (let i = 0; i < group.tests.length; i++) {
        const v = group.tests[i];
        const comment = `(${g}/${i}, ${v.result}): ${v.comment}`;
        if (v.result === 'valid' || v.result === 'acceptable') {
          eql(hex(ed.sign(v.msg, key.sk)), v.sig, comment);
          eql(ed.verify(v.sig, v.msg, key.pk), true, comment);
        } else if (v.result === 'invalid') {
          let failed = false;
          try {
            failed = !ed.verify(v.sig, v.msg, key.pk);
          } catch (error) {
            failed = true;
          }
          eql(failed, true, comment);
        } else throw new Error('unknown test result');
      }
    }
  });

  should('wycheproof/ED25519', () => {
    for (let g = 0; g < ed25519vectors.testGroups.length; g++) {
      const group = ed25519vectors.testGroups[g];
      const key = group.publicKey;
      for (let i = 0; i < group.tests.length; i++) {
        const v = group.tests[i];
        const comment = `(${g}/${i}, ${v.result}): ${v.comment}`;
        if (v.result === 'valid' || v.result === 'acceptable') {
          eql(ed.verify(v.sig, v.msg, key.pk), true, comment);
        } else if (v.result === 'invalid') {
          let failed = false;
          try {
            failed = !ed.verify(v.sig, v.msg, key.pk);
          } catch (error) {
            failed = true;
          }
          eql(failed, true, comment);
        } else throw new Error('unknown test result');
      }
    }
  });
});

should.runWhen(import.meta.url);
