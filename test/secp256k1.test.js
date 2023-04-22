import { hexToBytes, bytesToHex as hex } from '@noble/hashes/utils';
import { deepStrictEqual, throws } from 'assert';
import * as fc from 'fast-check';
import { readFileSync } from 'fs';
import { should, describe } from 'micro-should';
// prettier-ignore
import {
  secp, sigFromDER, sigToDER, selectHash, normVerifySig, mod, bytesToNumberBE, numberToBytesBE
} from './secp256k1.helpers.js';

import { default as ecdsa } from './vectors/secp256k1/ecdsa.json' assert { type: 'json' };
import { default as ecdh } from './wycheproof/ecdh_secp256k1_test.json' assert { type: 'json' };
import { default as privates } from './vectors/secp256k1/privates.json' assert { type: 'json' };
import { default as points } from './vectors/secp256k1/points.json' assert { type: 'json' };
import { default as wp } from './wycheproof/ecdsa_secp256k1_sha256_test.json' assert { type: 'json' };

// Any changes to the file will need to be aware of the fact
// the file is shared between noble-curves and noble-secp256k1.

const Point = secp.ProjectivePoint;
const privatesTxt = readFileSync('./test/vectors/secp256k1/privates-2.txt', 'utf-8');

const FC_BIGINT = fc.bigInt(1n + 1n, secp.CURVE.n - 1n);
// prettier-ignore
const INVALID_ITEMS = ['deadbeef', Math.pow(2, 53), [1], 'xyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxy', secp.CURVE.n + 2n];

const toBEHex = (n) => n.toString(16).padStart(64, '0');

function hexToNumber(hex) {
  if (typeof hex !== 'string') {
    throw new Error('hexToNumber: expected string, got ' + typeof hex);
  }
  // Big Endian
  return BigInt(`0x${hex}`);
}

describe('secp256k1', () => {
  should('getPublicKey()', () => {
    const data = privatesTxt
      .split('\n')
      .filter((line) => line)
      .map((line) => line.split(':'));
    for (let [priv, x, y] of data) {
      const point = Point.fromPrivateKey(BigInt(priv));
      deepStrictEqual(toBEHex(point.x), x);
      deepStrictEqual(toBEHex(point.y), y);

      const point2 = Point.fromHex(secp.getPublicKey(toBEHex(BigInt(priv))));
      deepStrictEqual(toBEHex(point2.x), x);
      deepStrictEqual(toBEHex(point2.y), y);

      const point3 = Point.fromHex(secp.getPublicKey(hexToBytes(toBEHex(BigInt(priv)))));
      deepStrictEqual(toBEHex(point3.x), x);
      deepStrictEqual(toBEHex(point3.y), y);
    }
  });
  should('getPublicKey() rejects invalid keys', () => {
    for (const item of INVALID_ITEMS) {
      throws(() => secp.getPublicKey(item));
    }
  });
  should('precompute', () => {
    secp.utils.precompute(4);
    const data = privatesTxt
      .split('\n')
      .filter((line) => line)
      .map((line) => line.split(':'));
    for (let [priv, x, y] of data) {
      const point = Point.fromPrivateKey(BigInt(priv));
      deepStrictEqual(toBEHex(point.x), x);
      deepStrictEqual(toBEHex(point.y), y);

      const point2 = Point.fromHex(secp.getPublicKey(toBEHex(BigInt(priv))));
      deepStrictEqual(toBEHex(point2.x), x);
      deepStrictEqual(toBEHex(point2.y), y);

      const point3 = Point.fromHex(secp.getPublicKey(hexToBytes(toBEHex(BigInt(priv)))));
      deepStrictEqual(toBEHex(point3.x), x);
      deepStrictEqual(toBEHex(point3.y), y);
    }
  });

  describe('Point', () => {
    should('fromHex() assertValidity', () => {
      for (const vector of points.valid.isPoint) {
        const { P, expected } = vector;
        if (expected) {
          Point.fromHex(P);
        } else {
          throws(() => Point.fromHex(P));
        }
      }
    });

    should('.fromPrivateKey()', () => {
      for (const vector of points.valid.pointFromScalar) {
        const { d, expected } = vector;
        let p = Point.fromPrivateKey(d);
        deepStrictEqual(p.toHex(true), expected);
      }
    });

    should('#toHex(compressed)', () => {
      for (const vector of points.valid.pointCompress) {
        const { P, compress, expected } = vector;
        let p = Point.fromHex(P);
        deepStrictEqual(p.toHex(compress), expected);
      }
    });

    should('#toHex() roundtrip (failed case)', () => {
      const point1 =
        Point.fromPrivateKey(
          88572218780422190464634044548753414301110513745532121983949500266768436236425n
        );
      // const hex = point1.toHex(true);
      // deepStrictEqual(Point.fromHex(hex).toHex(true), hex);
    });

    should('#toHex() roundtrip', () => {
      fc.assert(
        fc.property(FC_BIGINT, (x) => {
          const point1 = Point.fromPrivateKey(x);
          const hex = point1.toHex(true);
          deepStrictEqual(Point.fromHex(hex).toHex(true), hex);
        })
      );
    });

    should('#add(other)', () => {
      for (const vector of points.valid.pointAdd) {
        const { P, Q, expected } = vector;
        let p = Point.fromHex(P);
        let q = Point.fromHex(Q);
        if (expected) {
          deepStrictEqual(p.add(q).toHex(true), expected);
        } else {
          if (!p.equals(q.negate())) {
            throws(() => p.add(q).toHex(true));
          }
        }
      }
    });

    should('#multiply(privateKey)', () => {
      for (const vector of points.valid.pointMultiply) {
        const { P, d, expected } = vector;
        const p = Point.fromHex(P);
        if (expected) {
          deepStrictEqual(p.multiply(hexToNumber(d)).toHex(true), expected, P);
        } else {
          throws(() => {
            p.multiply(hexToNumber(d)).toHex(true);
          });
        }
      }

      for (const vector of points.invalid.pointMultiply) {
        const { P, d } = vector;
        if (hexToNumber(d) < secp.CURVE.n) {
          throws(() => {
            const p = Point.fromHex(P);
            p.multiply(hexToNumber(d)).toHex(true);
          });
        }
      }
      for (const num of [0n, 0, -1n, -1, 1.1]) {
        throws(() => Point.BASE.multiply(num));
      }
    });
  });

  // multiply() should equal multiplyUnsafe()
  // should('ProjectivePoint#multiplyUnsafe', () => {
  //   const p0 = new secp.ProjectivePoint(
  //     55066263022277343669578718895168534326250603453777594175500187360389116729240n,
  //     32670510020758816978083085130507043184471273380659243275938904335757337482424n,
  //     1n
  //   );
  //   const z = 106011723082030650010038151861333186846790370053628296836951575624442507889495n;
  //   console.log(p0.multiply(z));
  //   console.log(secp.ProjectivePoint.normalizeZ([p0.multiplyUnsafe(z)])[0])
  // });
  describe('Signature', () => {
    should('.fromCompactHex() roundtrip', () => {
      fc.assert(
        fc.property(FC_BIGINT, FC_BIGINT, (r, s) => {
          const sig = new secp.Signature(r, s);
          deepStrictEqual(secp.Signature.fromCompact(sig.toCompactHex()), sig);
        })
      );
    });

    should('.fromDERHex() roundtrip', () => {
      fc.assert(
        fc.property(FC_BIGINT, FC_BIGINT, (r, s) => {
          const sig = new secp.Signature(r, s);
          deepStrictEqual(sigFromDER(sigToDER(sig)), sig);
        })
      );
    });
  });

  describe('sign()', () => {
    should('create deterministic signatures with RFC 6979', () => {
      for (const vector of ecdsa.valid) {
        let usig = secp.sign(vector.m, vector.d);
        let sig = usig.toCompactHex();
        const vsig = vector.signature;
        deepStrictEqual(sig.slice(0, 64), vsig.slice(0, 64));
        deepStrictEqual(sig.slice(64, 128), vsig.slice(64, 128));
      }
    });

    should('not create invalid deterministic signatures with RFC 6979', () => {
      for (const vector of ecdsa.invalid.sign) {
        throws(() => secp.sign(vector.m, vector.d));
      }
    });

    should('edge cases', () => {
      throws(() => secp.sign());
      throws(() => secp.sign(''));
    });

    should('create correct DER encoding against libsecp256k1', () => {
      const CASES = [
        [
          'd1a9dc8ed4e46a6a3e5e594615ca351d7d7ef44df1e4c94c1802f3592183794b',
          '304402203de2559fccb00c148574997f660e4d6f40605acc71267ee38101abf15ff467af02200950abdf40628fd13f547792ba2fc544681a485f2fdafb5c3b909a4df7350e6b',
        ],
        [
          '5f97983254982546d3976d905c6165033976ee449d300d0e382099fa74deaf82',
          '3045022100c046d9ff0bd2845b9aa9dff9f997ecebb31e52349f80fe5a5a869747d31dcb88022011f72be2a6d48fe716b825e4117747b397783df26914a58139c3f4c5cbb0e66c',
        ],
        [
          '0d7017a96b97cd9be21cf28aada639827b2814a654a478c81945857196187808',
          '3045022100d18990bba7832bb283e3ecf8700b67beb39acc73f4200ed1c331247c46edccc602202e5c8bbfe47ae159512c583b30a3fa86575cddc62527a03de7756517ae4c6c73',
        ],
      ];
      const privKey = hexToBytes(
        '0101010101010101010101010101010101010101010101010101010101010101'
      );
      for (const [msg, exp] of CASES) {
        const res = secp.sign(msg, privKey, { extraEntropy: undefined });
        deepStrictEqual(sigToDER(res), exp);
        const rs = sigFromDER(sigToDER(res)).toCompactHex();
        deepStrictEqual(sigToDER(secp.Signature.fromCompact(rs)), exp);
      }
    });
    should('handle {extraData} option', () => {
      const ent1 = '0000000000000000000000000000000000000000000000000000000000000000';
      const ent2 = '0000000000000000000000000000000000000000000000000000000000000001';
      const ent3 = '6e723d3fd94ed5d2b6bdd4f123364b0f3ca52af829988a63f8afe91d29db1c33';
      const ent4 = 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141';
      const ent5 = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

      for (const e of ecdsa.extraEntropy) {
        const sign = (extraEntropy) => {
          const s = secp.sign(e.m, e.d, { extraEntropy }).toCompactHex();
          return s;
        };
        deepStrictEqual(sign(), e.signature);
        deepStrictEqual(sign(ent1), e.extraEntropy0);
        deepStrictEqual(sign(ent2), e.extraEntropy1);
        deepStrictEqual(sign(ent3), e.extraEntropyRand);
        deepStrictEqual(sign(ent4), e.extraEntropyN);
        deepStrictEqual(sign(ent5), e.extraEntropyMax);
      }
    });
  });

  describe('verify()', () => {
    should('verify signature', () => {
      const MSG = '01'.repeat(32);
      const PRIV_KEY = 0x2n;
      const signature = secp.sign(MSG, PRIV_KEY);
      const publicKey = secp.getPublicKey(PRIV_KEY);
      deepStrictEqual(publicKey.length, 33);
      deepStrictEqual(secp.verify(signature, MSG, publicKey), true);
    });
    should(' not verify signature with wrong public key', () => {
      const MSG = '01'.repeat(32);
      const PRIV_KEY = '01'.repeat(32);
      const WRONG_PRIV_KEY = '02'.repeat(32);
      const signature = secp.sign(MSG, PRIV_KEY);
      const publicKey = Point.fromPrivateKey(WRONG_PRIV_KEY).toHex();
      deepStrictEqual(publicKey.length, 66);
      deepStrictEqual(secp.verify(signature, MSG, publicKey), false);
    });
    should('not verify signature with wrong hash', () => {
      const MSG = '01'.repeat(32);
      const PRIV_KEY = 0x2n;
      const WRONG_MSG = '11'.repeat(32);
      const signature = secp.sign(MSG, PRIV_KEY);
      const publicKey = secp.getPublicKey(PRIV_KEY);
      deepStrictEqual(publicKey.length, 33);
      deepStrictEqual(secp.verify(signature, WRONG_MSG, publicKey), false);
    });
    should('verify random signatures', () =>
      fc.assert(
        fc.property(FC_BIGINT, fc.hexaString({ minLength: 64, maxLength: 64 }), (privKey, msg) => {
          const pub = secp.getPublicKey(privKey);
          const sig = secp.sign(msg, privKey);
          deepStrictEqual(secp.verify(sig, msg, pub), true);
        })
      )
    );
    should('not verify signature with invalid r/s', () => {
      const msg = new Uint8Array([
        0xbb, 0x5a, 0x52, 0xf4, 0x2f, 0x9c, 0x92, 0x61, 0xed, 0x43, 0x61, 0xf5, 0x94, 0x22, 0xa1,
        0xe3, 0x00, 0x36, 0xe7, 0xc3, 0x2b, 0x27, 0x0c, 0x88, 0x07, 0xa4, 0x19, 0xfe, 0xca, 0x60,
        0x50, 0x23,
      ]);
      const x = 100260381870027870612475458630405506840396644859280795015145920502443964769584n;
      const y = 41096923727651821103518389640356553930186852801619204169823347832429067794568n;
      const r = 1n;
      const s = 115792089237316195423570985008687907852837564279074904382605163141518162728904n;

      const pub = new Point(x, y, 1n).toRawBytes();
      const signature = new secp.Signature(2n, 2n);
      signature.r = r;
      signature.s = s;

      const verified = secp.verify(signature, msg, pub);
      // Verifies, but it shouldn't, because signature S > curve order
      deepStrictEqual(verified, false);
    });
    should('not verify msg = curve order', () => {
      const msg = 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141';
      const x = 55066263022277343669578718895168534326250603453777594175500187360389116729240n;
      const y = 32670510020758816978083085130507043184471273380659243275938904335757337482424n;
      const r = 104546003225722045112039007203142344920046999340768276760147352389092131869133n;
      const s = 96900796730960181123786672629079577025401317267213807243199432755332205217369n;
      const pub = new Point(x, y, 1n).toRawBytes();
      const sig = new secp.Signature(r, s);
      deepStrictEqual(secp.verify(sig, msg, pub), false);
    });
    should('verify non-strict msg bb5a...', () => {
      const msg = 'bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023';
      const x = 3252872872578928810725465493269682203671229454553002637820453004368632726370n;
      const y = 17482644437196207387910659778872952193236850502325156318830589868678978890912n;
      const r = 432420386565659656852420866390673177323n;
      const s = 115792089237316195423570985008687907852837564279074904382605163141518161494334n;
      const pub = new Point(x, y, 1n).toRawBytes();
      const sig = new secp.Signature(r, s);
      deepStrictEqual(secp.verify(sig, msg, pub, { lowS: false }), true);
    });
    should('not verify invalid deterministic signatures with RFC 6979', () => {
      for (const vector of ecdsa.invalid.verify) {
        const res = secp.verify(vector.signature, vector.m, vector.Q);
        deepStrictEqual(res, false);
      }
    });
  });
  describe('recoverPublicKey()', () => {
    should('recover public key from recovery bit', () => {
      const message = '00000000000000000000000000000000000000000000000000000000deadbeef';
      const privateKey = 123456789n;
      const publicKey = Point.fromHex(secp.getPublicKey(privateKey)).toHex(false);
      const sig = secp.sign(message, privateKey);
      const recoveredPubkey = sig.recoverPublicKey(message);
      // const recoveredPubkey = secp.recoverPublicKey(message, signature, recovery);
      deepStrictEqual(recoveredPubkey !== null, true);
      deepStrictEqual(recoveredPubkey.toHex(false), publicKey);
      deepStrictEqual(secp.verify(sig, message, publicKey), true);
    });
    should('not recover zero points', () => {
      const msgHash = '6b8d2c81b11b2d699528dde488dbdf2f94293d0d33c32e347f255fa4a6c1f0a9';
      const sig =
        '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817986b8d2c81b11b2d699528dde488dbdf2f94293d0d33c32e347f255fa4a6c1f0a9';
      const recovery = 0;
      throws(() => secp.recoverPublicKey(msgHash, sig, recovery));
    });
    should('handle all-zeros msghash', () => {
      const privKey = secp.utils.randomPrivateKey();
      const pub = secp.getPublicKey(privKey);
      const zeros = '0000000000000000000000000000000000000000000000000000000000000000';
      const sig = secp.sign(zeros, privKey);
      const recoveredKey = sig.recoverPublicKey(zeros);
      deepStrictEqual(recoveredKey.toRawBytes(), pub);
    });
    should('handle RFC 6979 vectors', () => {
      for (const vector of ecdsa.valid) {
        let usig = secp.sign(vector.m, vector.d);
        let sig = sigToDER(usig);
        const vpub = secp.getPublicKey(vector.d);
        const recovered = usig.recoverPublicKey(vector.m);
        deepStrictEqual(recovered.toHex(), hex(vpub));
      }
    });
  });

  describe('getSharedSecret()', () => {
    // TODO: Real implementation.
    function derToPub(der) {
      return der.slice(46);
    }
    should('produce correct results', () => {
      // TODO: Once der is there, run all tests.
      for (const vector of ecdh.testGroups[0].tests.slice(0, 230)) {
        if (vector.result === 'invalid' || vector.private.length !== 64) {
          throws(() => {
            secp.getSharedSecret(vector.private, derToPub(vector.public), true);
          });
        } else if (vector.result === 'valid') {
          const res = secp.getSharedSecret(vector.private, derToPub(vector.public), true);
          deepStrictEqual(hex(res.slice(1)), `${vector.shared}`);
        }
      }
    });
    should('priv/pub order matters', () => {
      for (const vector of ecdh.testGroups[0].tests.slice(0, 100)) {
        if (vector.result === 'valid') {
          let priv = vector.private;
          priv = priv.length === 66 ? priv.slice(2) : priv;
          throws(() => secp.getSharedSecret(derToPub(vector.public), priv, true));
        }
      }
    });
    should('reject invalid keys', () => {
      throws(() => secp.getSharedSecret('01', '02'));
    });
  });

  should('utils.isValidPrivateKey()', () => {
    for (const vector of privates.valid.isPrivate) {
      const { d, expected } = vector;
      deepStrictEqual(secp.utils.isValidPrivateKey(d), expected);
    }
  });
  should('have proper curve equation in assertValidity()', () => {
    throws(() => {
      const { Fp } = secp.CURVE;
      let point = new Point(Fp.create(-2n), Fp.create(-1n), Fp.create(1n));
      point.assertValidity();
    });
  });

  describe('tweak utilities (legacy)', () => {
    const normal = secp.utils.normPrivateKeyToScalar;
    const tweakUtils = {
      privateAdd: (privateKey, tweak) => {
        return numberToBytesBE(mod(normal(privateKey) + normal(tweak), secp.CURVE.n), 32);
      },

      privateNegate: (privateKey) => {
        return numberToBytesBE(mod(-normal(privateKey), secp.CURVE.n), 32);
      },

      pointAddScalar: (p, tweak, isCompressed) => {
        const tweaked = Point.fromHex(p).add(Point.fromPrivateKey(tweak));
        if (tweaked.equals(Point.ZERO)) throw new Error('Tweaked point at infinity');
        return tweaked.toRawBytes(isCompressed);
      },

      pointMultiply: (p, tweak, isCompressed) => {
        if (typeof tweak === 'string') tweak = hexToBytes(tweak);
        const t = bytesToNumberBE(tweak);
        return Point.fromHex(p).multiply(t).toRawBytes(isCompressed);
      },
    };

    should('privateAdd()', () => {
      for (const vector of privates.valid.add) {
        const { a, b, expected } = vector;
        deepStrictEqual(hex(tweakUtils.privateAdd(a, b)), expected);
      }
    });
    should('privateNegate()', () => {
      for (const vector of privates.valid.negate) {
        const { a, expected } = vector;
        deepStrictEqual(hex(tweakUtils.privateNegate(a)), expected);
      }
    });
    should('pointAddScalar()', () => {
      for (const vector of points.valid.pointAddScalar) {
        const { description, P, d, expected } = vector;
        const compressed = !!expected && expected.length === 66; // compressed === 33 bytes
        deepStrictEqual(hex(tweakUtils.pointAddScalar(P, d, compressed)), expected);
      }
    });
    should('pointAddScalar() invalid', () => {
      for (const vector of points.invalid.pointAddScalar) {
        const { P, d, exception } = vector;
        throws(() => tweakUtils.pointAddScalar(P, d));
      }
    });
    should('pointMultiply()', () => {
      for (const vector of points.valid.pointMultiply) {
        const { P, d, expected } = vector;
        deepStrictEqual(hex(tweakUtils.pointMultiply(P, d, true)), expected);
      }
    });
    should('pointMultiply() invalid', () => {
      for (const vector of points.invalid.pointMultiply) {
        const { P, d, exception } = vector;
        throws(() => tweakUtils.pointMultiply(P, d));
      }
    });
  });

  should('wycheproof vectors', () => {
    for (let group of wp.testGroups) {
      // const pubKey = Point.fromHex().toRawBytes();
      const key = group.publicKey;
      const pubKey = key.uncompressed;

      for (let test of group.tests) {
        const h = selectHash(secp);

        const m = h(hexToBytes(test.msg));
        if (test.result === 'valid' || test.result === 'acceptable') {
          let sig;
          try {
            sig = sigFromDER(test.sig);
          } catch (e) {
            // These old Wycheproof vectors which allows invalid behaviour of DER parser
            if (e.message === 'Invalid signature integer: negative') continue;
            throw e;
          }
          const verified = secp.verify(normVerifySig(test.sig), m, pubKey);
          if (sig.hasHighS()) {
            deepStrictEqual(verified, false);
          } else {
            deepStrictEqual(verified, true);
          }
        } else if (test.result === 'invalid') {
          let failed = false;
          try {
            const verified = secp.verify(test.sig, m, pubKey);
            if (!verified) failed = true;
          } catch (error) {
            failed = true;
          }
          deepStrictEqual(failed, true);
        } else {
          deepStrictEqual(false, true);
        }
      }
    }
  });
});

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
