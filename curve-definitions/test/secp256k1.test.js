import * as fc from 'fast-check';
import { secp256k1 } from '../lib/secp256k1.js';
import { readFileSync } from 'fs';
import { default as ecdsa } from './vectors/ecdsa.json' assert { type: 'json' };
import { default as ecdh } from './vectors/ecdh.json' assert { type: 'json' };
import { default as privates } from './vectors/privates.json' assert { type: 'json' };
import { default as points } from './vectors/points.json' assert { type: 'json' };
import { default as wp } from './vectors/wychenproof.json' assert { type: 'json' };
import { should } from 'micro-should';
import { deepStrictEqual, throws } from 'assert';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils';

const hex = bytesToHex;
const secp = secp256k1;
const privatesTxt = readFileSync('./test/vectors/privates-2.txt', 'utf-8');
const schCsv = readFileSync('./test/vectors/schnorr.csv', 'utf-8');

const FC_BIGINT = fc.bigInt(1n + 1n, secp.CURVE.n - 1n);
// prettier-ignore
const INVALID_ITEMS = ['deadbeef', Math.pow(2, 53), [1], 'xyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxy', secp.CURVE.n + 2n];

const toBEHex = (n) => n.toString(16).padStart(64, '0');

function hexToNumber(hex) {
  if (typeof hex !== 'string') {
    throw new TypeError('hexToNumber: expected string, got ' + typeof hex);
  }
  // Big Endian
  return BigInt(`0x${hex}`);
}

should('secp256k1.getPublicKey()', () => {
  const data = privatesTxt
    .split('\n')
    .filter((line) => line)
    .map((line) => line.split(':'));
  for (let [priv, x, y] of data) {
    const point = secp.Point.fromPrivateKey(BigInt(priv));
    deepStrictEqual(toBEHex(point.x), x);
    deepStrictEqual(toBEHex(point.y), y);

    const point2 = secp.Point.fromHex(secp.getPublicKey(toBEHex(BigInt(priv))));
    deepStrictEqual(toBEHex(point2.x), x);
    deepStrictEqual(toBEHex(point2.y), y);

    const point3 = secp.Point.fromHex(secp.getPublicKey(hexToBytes(toBEHex(BigInt(priv)))));
    deepStrictEqual(toBEHex(point3.x), x);
    deepStrictEqual(toBEHex(point3.y), y);
  }
});
should('secp256k1.getPublicKey() rejects invalid keys', () => {
  // for (const item of INVALID_ITEMS) {
  //   throws(() => secp.getPublicKey(item));
  // }
});
should('secp256k1.precompute', () => {
  secp.utils.precompute(4);
  const data = privatesTxt
    .split('\n')
    .filter((line) => line)
    .map((line) => line.split(':'));
  for (let [priv, x, y] of data) {
    const point = secp.Point.fromPrivateKey(BigInt(priv));
    deepStrictEqual(toBEHex(point.x), x);
    deepStrictEqual(toBEHex(point.y), y);

    const point2 = secp.Point.fromHex(secp.getPublicKey(toBEHex(BigInt(priv))));
    deepStrictEqual(toBEHex(point2.x), x);
    deepStrictEqual(toBEHex(point2.y), y);

    const point3 = secp.Point.fromHex(secp.getPublicKey(hexToBytes(toBEHex(BigInt(priv)))));
    deepStrictEqual(toBEHex(point3.x), x);
    deepStrictEqual(toBEHex(point3.y), y);
  }
});

should('secp256k1.Point.isValidPoint()', () => {
  for (const vector of points.valid.isPoint) {
    const { P, expected } = vector;
    if (expected) {
      secp.Point.fromHex(P);
    } else {
      throws(() => secp.Point.fromHex(P));
    }
  }
});

should('secp256k1.Point.fromPrivateKey()', () => {
  for (const vector of points.valid.pointFromScalar) {
    const { d, expected } = vector;
    let p = secp.Point.fromPrivateKey(d);
    deepStrictEqual(p.toHex(true), expected);
  }
});

should('secp256k1.Point#toHex(compressed)', () => {
  for (const vector of points.valid.pointCompress) {
    const { P, compress, expected } = vector;
    let p = secp.Point.fromHex(P);
    deepStrictEqual(p.toHex(compress), expected);
  }
});

should('secp256k1.Point#toHex() roundtrip (failed case)', () => {
  const point1 =
    secp.Point.fromPrivateKey(
      88572218780422190464634044548753414301110513745532121983949500266768436236425n
    );
  // const hex = point1.toHex(true);
  // deepStrictEqual(secp.Point.fromHex(hex).toHex(true), hex);
});

should('secp256k1.Point#toHex() roundtrip', () => {
  fc.assert(
    fc.property(FC_BIGINT, (x) => {
      const point1 = secp.Point.fromPrivateKey(x);
      const hex = point1.toHex(true);
      deepStrictEqual(secp.Point.fromHex(hex).toHex(true), hex);
    })
  );
});

should('secp256k1.Point#add(other)', () => {
  for (const vector of points.valid.pointAdd) {
    const { P, Q, expected } = vector;
    let p = secp.Point.fromHex(P);
    let q = secp.Point.fromHex(Q);
    if (expected) {
      deepStrictEqual(p.add(q).toHex(true), expected);
    } else {
      if (!p.equals(q.negate())) {
        throws(() => p.add(q).toHex(true));
      }
    }
  }
});

should('secp256k1.Point#multiply(privateKey)', () => {
  for (const vector of points.valid.pointMultiply) {
    const { P, d, expected } = vector;
    const p = secp.Point.fromHex(P);
    if (expected) {
      deepStrictEqual(p.multiply(hexToNumber(d)).toHex(true), expected);
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
        const p = secp.Point.fromHex(P);
        p.multiply(hexToNumber(d)).toHex(true);
      });
    }
  }
  for (const num of [0n, 0, -1n, -1, 1.1]) {
    throws(() => secp.Point.BASE.multiply(num));
  }
});

// multiply() should equal multiplyUnsafe()
// should('JacobianPoint#multiplyUnsafe', () => {
//   const p0 = new secp.JacobianPoint(
//     55066263022277343669578718895168534326250603453777594175500187360389116729240n,
//     32670510020758816978083085130507043184471273380659243275938904335757337482424n,
//     1n
//   );
//   const z = 106011723082030650010038151861333186846790370053628296836951575624442507889495n;
//   console.log(p0.multiply(z));
//   console.log(secp.JacobianPoint.normalizeZ([p0.multiplyUnsafe(z)])[0])
// });

should('secp256k1.Signature.fromCompactHex() roundtrip', () => {
  fc.assert(
    fc.property(FC_BIGINT, FC_BIGINT, (r, s) => {
      const sig = new secp.Signature(r, s);
      deepStrictEqual(secp.Signature.fromCompact(sig.toCompactHex()), sig);
    })
  );
});

should('secp256k1.Signature.fromDERHex() roundtrip', () => {
  fc.assert(
    fc.property(FC_BIGINT, FC_BIGINT, (r, s) => {
      const sig = new secp.Signature(r, s);
      deepStrictEqual(secp.Signature.fromDER(sig.toDERHex()), sig);
    })
  );
});

should('secp256k1.sign()/should create deterministic signatures with RFC 6979', () => {
  for (const vector of ecdsa.valid) {
    let usig = secp.sign(vector.m, vector.d);
    let sig = usig.toCompactHex();
    const vsig = vector.signature;
    deepStrictEqual(sig.slice(0, 64), vsig.slice(0, 64));
    deepStrictEqual(sig.slice(64, 128), vsig.slice(64, 128));
  }
});

should('secp256k1.sign()/should not create invalid deterministic signatures with RFC 6979', () => {
  for (const vector of ecdsa.invalid.sign) {
    throws(() => secp.sign(vector.m, vector.d));
  }
});

should('secp256k1.sign()/edge cases', () => {
  throws(() => secp.sign());
  throws(() => secp.sign(''));
});

should('secp256k1.sign()/should create correct DER encoding against libsecp256k1', () => {
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
  const privKey = hexToBytes('0101010101010101010101010101010101010101010101010101010101010101');
  for (const [msg, exp] of CASES) {
    const res = secp.sign(msg, privKey, { extraEntropy: undefined });
    deepStrictEqual(res.toDERHex(), exp);
    const rs = secp.Signature.fromDER(res.toDERHex()).toCompactHex();
    deepStrictEqual(secp.Signature.fromCompact(rs).toDERHex(), exp);
  }
});
should('secp256k1.sign()/sign ecdsa extraData', () => {
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

should('secp256k1.verify()/should verify signature', () => {
  const MSG = '01'.repeat(32);
  const PRIV_KEY = 0x2n;
  const signature = secp.sign(MSG, PRIV_KEY);
  const publicKey = secp.getPublicKey(PRIV_KEY);
  deepStrictEqual(publicKey.length, 65);
  deepStrictEqual(secp.verify(signature, MSG, publicKey), true);
});
should('secp256k1.verify()/should not verify signature with wrong public key', () => {
  const MSG = '01'.repeat(32);
  const PRIV_KEY = 0x2n;
  const WRONG_PRIV_KEY = 0x22n;
  const signature = secp.sign(MSG, PRIV_KEY);
  const publicKey = secp.Point.fromPrivateKey(WRONG_PRIV_KEY).toHex();
  deepStrictEqual(publicKey.length, 130);
  deepStrictEqual(secp.verify(signature, MSG, publicKey), false);
});
should('secp256k1.verify()/should not verify signature with wrong hash', () => {
  const MSG = '01'.repeat(32);
  const PRIV_KEY = 0x2n;
  const WRONG_MSG = '11'.repeat(32);
  const signature = secp.sign(MSG, PRIV_KEY);
  const publicKey = secp.getPublicKey(PRIV_KEY);
  deepStrictEqual(publicKey.length, 65);
  deepStrictEqual(secp.verify(signature, WRONG_MSG, publicKey), false);
});
should('secp256k1.verify()/should verify random signatures', () =>
  fc.assert(
    fc.property(FC_BIGINT, fc.hexaString({ minLength: 64, maxLength: 64 }), (privKey, msg) => {
      const pub = secp.getPublicKey(privKey);
      const sig = secp.sign(msg, privKey);
      deepStrictEqual(secp.verify(sig, msg, pub), true);
    })
  )
);
should('secp256k1.verify()/should not verify signature with invalid r/s', () => {
  const msg = new Uint8Array([
    0xbb, 0x5a, 0x52, 0xf4, 0x2f, 0x9c, 0x92, 0x61, 0xed, 0x43, 0x61, 0xf5, 0x94, 0x22, 0xa1, 0xe3,
    0x00, 0x36, 0xe7, 0xc3, 0x2b, 0x27, 0x0c, 0x88, 0x07, 0xa4, 0x19, 0xfe, 0xca, 0x60, 0x50, 0x23,
  ]);
  const x = 100260381870027870612475458630405506840396644859280795015145920502443964769584n;
  const y = 41096923727651821103518389640356553930186852801619204169823347832429067794568n;
  const r = 1n;
  const s = 115792089237316195423570985008687907852837564279074904382605163141518162728904n;

  const pub = new secp.Point(x, y);
  const signature = new secp.Signature(2n, 2n);
  signature.r = r;
  signature.s = s;

  const verified = secp.verify(signature, msg, pub);
  // Verifies, but it shouldn't, because signature S > curve order
  deepStrictEqual(verified, false);
});
should('secp256k1.verify()/should not verify msg = curve order', () => {
  const msg = 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141';
  const x = 55066263022277343669578718895168534326250603453777594175500187360389116729240n;
  const y = 32670510020758816978083085130507043184471273380659243275938904335757337482424n;
  const r = 104546003225722045112039007203142344920046999340768276760147352389092131869133n;
  const s = 96900796730960181123786672629079577025401317267213807243199432755332205217369n;
  const pub = new secp.Point(x, y);
  const sig = new secp.Signature(r, s);
  deepStrictEqual(secp.verify(sig, msg, pub), false);
});
should('secp256k1.verify()/should verify non-strict msg bb5a...', () => {
  const msg = 'bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023';
  const x = 3252872872578928810725465493269682203671229454553002637820453004368632726370n;
  const y = 17482644437196207387910659778872952193236850502325156318830589868678978890912n;
  const r = 432420386565659656852420866390673177323n;
  const s = 115792089237316195423570985008687907852837564279074904382605163141518161494334n;
  const pub = new secp.Point(x, y);
  const sig = new secp.Signature(r, s);
  deepStrictEqual(secp.verify(sig, msg, pub, { strict: false }), true);
});
should(
  'secp256k1.verify()/should not verify invalid deterministic signatures with RFC 6979',
  () => {
    for (const vector of ecdsa.invalid.verify) {
      const res = secp.verify(vector.signature, vector.m, vector.Q);
      deepStrictEqual(res, false);
    }
  }
);

// describe('schnorr', () => {
//   // index,secret key,public key,aux_rand,message,signature,verification result,comment
//   const vectors = schCsv
//     .split('\n')
//     .map((line: string) => line.split(','))
//     .slice(1, -1);
//   for (let vec of vectors) {
//     const [index, sec, pub, rnd, msg, expSig, passes, comment] = vec;
//     it(`should sign with Schnorr scheme vector ${index}`, async () => {
//       if (sec) {
//         expect(hex(secp.schnorr.getPublicKey(sec))).toBe(pub.toLowerCase());
//         const sig = await secp.schnorr.sign(msg, sec, rnd);
//         const sigS = secp.schnorr.signSync(msg, sec, rnd);
//         expect(hex(sig)).toBe(expSig.toLowerCase());
//         expect(hex(sigS)).toBe(expSig.toLowerCase());
//         expect(await secp.schnorr.verify(sigS, msg, pub)).toBe(true);
//         expect(secp.schnorr.verifySync(sig, msg, pub)).toBe(true);
//       } else {
//         const passed = await secp.schnorr.verify(expSig, msg, pub);
//         const passedS = secp.schnorr.verifySync(expSig, msg, pub);
//         if (passes === 'TRUE') {
//           expect(passed).toBeTruthy();
//           expect(passedS).toBeTruthy();
//         } else {
//           expect(passed).toBeFalsy();
//           expect(passedS).toBeFalsy();
//         }
//       }
//     });
//   }
// });

should('secp256k1.recoverPublicKey()/should recover public key from recovery bit', () => {
  const message = '00000000000000000000000000000000000000000000000000000000deadbeef';
  const privateKey = 123456789n;
  const publicKey = secp.Point.fromHex(secp.getPublicKey(privateKey)).toHex(false);
  const sig = secp.sign(message, privateKey);
  const recoveredPubkey = sig.recoverPublicKey(message);
  // const recoveredPubkey = secp.recoverPublicKey(message, signature, recovery);
  deepStrictEqual(recoveredPubkey !== null, true);
  deepStrictEqual(recoveredPubkey.toHex(), publicKey);
  deepStrictEqual(secp.verify(sig, message, publicKey), true);
});
should('secp256k1.recoverPublicKey()/should not recover zero points', () => {
  const msgHash = '6b8d2c81b11b2d699528dde488dbdf2f94293d0d33c32e347f255fa4a6c1f0a9';
  const sig =
    '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817986b8d2c81b11b2d699528dde488dbdf2f94293d0d33c32e347f255fa4a6c1f0a9';
  const recovery = 0;
  throws(() => secp.recoverPublicKey(msgHash, sig, recovery));
});
should('secp256k1.recoverPublicKey()/should handle all-zeros msghash', () => {
  const privKey = secp.utils.randomPrivateKey();
  const pub = secp.getPublicKey(privKey);
  const zeros = '0000000000000000000000000000000000000000000000000000000000000000';
  const sig = secp.sign(zeros, privKey, { recovered: true });
  const recoveredKey = sig.recoverPublicKey(zeros);
  deepStrictEqual(recoveredKey.toRawBytes(), pub);
});
should('secp256k1.recoverPublicKey()/should handle RFC 6979 vectors', () => {
  for (const vector of ecdsa.valid) {
    if (secp.utils.mod(hexToNumber(vector.m), secp.CURVE.n) === 0n) continue;
    let usig = secp.sign(vector.m, vector.d);
    let sig = usig.toDERHex();
    const vpub = secp.getPublicKey(vector.d);
    const recovered = usig.recoverPublicKey(vector.m);
    deepStrictEqual(recovered.toHex(), hex(vpub));
  }
});

// TODO: Real implementation.
function derToPub(der) {
  return der.slice(46);
}
should('secp256k1.getSharedSecret()/should produce correct results', () => {
  // TODO: Once der is there, run all tests.
  for (const vector of ecdh.testGroups[0].tests.slice(0, 230)) {
    if (vector.result === 'invalid' || vector.private.length !== 64) {
      // We support eth-like hexes
      if (vector.private.length < 64) continue;
      throws(() => {
        secp.getSharedSecret(vector.private, derToPub(vector.public), true);
      });
    } else if (vector.result === 'valid') {
      const res = secp.getSharedSecret(vector.private, derToPub(vector.public), true);
      deepStrictEqual(hex(res.slice(1)), `${vector.shared}`);
    }
  }
});
should('secp256k1.getSharedSecret()/priv/pub order matters', () => {
  for (const vector of ecdh.testGroups[0].tests.slice(0, 100)) {
    if (vector.result === 'valid') {
      let priv = vector.private;
      priv = priv.length === 66 ? priv.slice(2) : priv;
      throws(() => secp.getSharedSecret(derToPub(vector.public), priv, true));
    }
  }
});
should('secp256k1.getSharedSecret()/rejects invalid keys', () => {
  throws(() => secp.getSharedSecret('01', '02'));
});

should('secp256k1.utils.isValidPrivateKey()', () => {
  for (const vector of privates.valid.isPrivate) {
    const { d, expected } = vector;
    deepStrictEqual(secp.utils.isValidPrivateKey(d), expected);
  }
});
const normal = secp.utils._normalizePrivateKey;
const tweakUtils = {
  privateAdd: (privateKey, tweak) => {
    const p = normal(privateKey);
    const t = normal(tweak);
    return secp.utils._bigintToBytes(secp.utils.mod(p + t, secp.CURVE.n));
  },

  privateNegate: (privateKey) => {
    const p = normal(privateKey);
    return secp.utils._bigintToBytes(secp.CURVE.n - p);
  },

  pointAddScalar: (p, tweak, isCompressed) => {
    const P = secp.Point.fromHex(p);
    const t = normal(tweak);
    const Q = secp.Point.BASE.multiplyAndAddUnsafe(P, t, 1n);
    if (!Q) throw new Error('Tweaked point at infinity');
    return Q.toRawBytes(isCompressed);
  },

  pointMultiply: (p, tweak, isCompressed) => {
    const P = secp.Point.fromHex(p);
    const h = typeof tweak === 'string' ? tweak : bytesToHex(tweak);
    const t = BigInt(`0x${h}`);
    return P.multiply(t).toRawBytes(isCompressed);
  },
};

should('secp256k1.privateAdd()', () => {
  for (const vector of privates.valid.add) {
    const { a, b, expected } = vector;
    deepStrictEqual(bytesToHex(tweakUtils.privateAdd(a, b)), expected);
  }
});
should('secp256k1.privateNegate()', () => {
  for (const vector of privates.valid.negate) {
    const { a, expected } = vector;
    deepStrictEqual(bytesToHex(tweakUtils.privateNegate(a)), expected);
  }
});
should('secp256k1.pointAddScalar()', () => {
  for (const vector of points.valid.pointAddScalar) {
    const { description, P, d, expected } = vector;
    const compressed = !!expected && expected.length === 66; // compressed === 33 bytes
    deepStrictEqual(bytesToHex(tweakUtils.pointAddScalar(P, d, compressed)), expected);
  }
});
should('secp256k1.pointAddScalar() invalid', () => {
  for (const vector of points.invalid.pointAddScalar) {
    const { P, d, exception } = vector;
    throws(() => tweakUtils.pointAddScalar(P, d));
  }
});
should('secp256k1.pointMultiply()', () => {
  for (const vector of points.valid.pointMultiply) {
    const { P, d, expected } = vector;
    deepStrictEqual(bytesToHex(tweakUtils.pointMultiply(P, d, true)), expected);
  }
});
should('secp256k1.pointMultiply() invalid', () => {
  for (const vector of points.invalid.pointMultiply) {
    const { P, d, exception } = vector;
    throws(() => tweakUtils.pointMultiply(P, d));
  }
});

should('secp256k1.wychenproof vectors', () => {
  for (let group of wp.testGroups) {
    const pubKey = secp.Point.fromHex(group.key.uncompressed);
    for (let test of group.tests) {
      const m = secp.CURVE.hash(hexToBytes(test.msg));
      if (test.result === 'valid' || test.result === 'acceptable') {
        const verified = secp.verify(test.sig, m, pubKey);
        if (secp.Signature.fromDER(test.sig).hasHighS()) {
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

should.run();
