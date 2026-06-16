import { bytesToHex, hexToBytes, isBytes } from '@noble/hashes/utils.js';
import { describe, should } from '@paulmillr/jsbt/test.js';
import * as fc from 'fast-check';
import { deepStrictEqual as eql, rejects, throws } from 'node:assert';
import { deepHexToBytes, getTypeTestsNonUi8a, json, txt } from './utils.ts';
// prettier-ignore
import {
  bytesToNumberBE,
  mod,
  numberToBytesBE,
  schnorr,
  secp,
  selectHash,
  sigFromDER
} from './secp256k1.helpers.ts';

const loadEcdsaVectors = () => deepHexToBytes(json('./vectors/secp256k1/ecdsa.json'));
const loadEcdhVectors = () => deepHexToBytes(json('./vectors/wycheproof/ecdh_secp256k1_test.json'));
const loadPrivateVectors = () => {
  const vectors = json('./vectors/secp256k1/privates.json');
  return deepHexToBytes({
    valid: {
      isPrivate: vectors.valid.isPrivate,
      add: vectors.valid.add,
      negate: vectors.valid.negate,
    },
  });
};
const loadPointVectors = () => deepHexToBytes(json('./vectors/secp256k1/points.json'));
const loadWycheproofVectors = () =>
  deepHexToBytes(json('./vectors/wycheproof/ecdsa_secp256k1_sha256_test.json'));

export function pfrom(hex) {
  return Point.fromHex(hex);
}
export function phex(point) {
  return bytesToHex(point.toBytes());
}
// Any changes to the file will need to be aware of the fact
// the file is shared between noble-curves and noble-secp256k1.

const Point = secp.Point;
const isNobleCurves = !!Point.Fp;
const CURVE_N = secp.Point.CURVE().n;
const FC_BIGINT = fc.bigInt(1n + 1n, CURVE_N - 1n);
// TODO: Real implementation.
function derToPub(der) {
  return der.slice(46 / 2);
}
function hexToNumber(hex2) {
  if (typeof hex2 !== 'string') {
    throw new Error('hexToNumber: expected string, got ' + typeof hex2);
  }
  // Big Endian
  return BigInt(`0x${hex2}`);
}

function checkPrivatesTxt() {
  const data = txt('vectors/secp256k1/privates-2.txt').filter((l) => l[0]);
  const toBEHex = (n) => n.toString(16).padStart(64, '0');

  for (let [privNumStr, x, y] of data) {
    const privScalar = BigInt(privNumStr);
    const priv = numberToBytesBE(privScalar, 32);
    // bytes, getPublicKey
    const point = Point.fromBytes(secp.getPublicKey(priv));
    eql(toBEHex(point.x), x);
    eql(toBEHex(point.y), y);
  }
}

describe('secp256k1 static vectors', () => {
  should('getPublicKey()', () => {
    checkPrivatesTxt();
  });

  describe('Point', () => {
    should('static vector operations', () => {
      const VECTORS_points = loadPointVectors();
      for (const vector of VECTORS_points.valid.isPoint) {
        const { P, expected } = vector;
        if (expected) {
          Point.fromBytes(P);
        } else {
          throws(() => Point.fromBytes(P));
        }
      }

      for (const vector of VECTORS_points.valid.pointCompress) {
        const { P, compress, expected } = vector;
        let p = Point.fromBytes(P);
        eql(p.toBytes(compress), expected, '#toBytes(compressed)');
      }

      for (const vector of VECTORS_points.valid.pointAdd) {
        const { P, Q, expected } = vector;
        let p = Point.fromBytes(P);
        let q = Point.fromBytes(Q);
        if (expected) {
          eql(p.add(q).toBytes(true), expected, '#add(other)');
        } else {
          if (!p.equals(q.negate())) {
            throws(() => p.add(q).toBytes(true));
          }
        }
      }

      for (const vector of VECTORS_points.valid.pointMultiply) {
        const { P, d, expected } = vector;
        const p = Point.fromBytes(P);
        if (expected) {
          eql(p.multiply(bytesToNumberBE(d)).toBytes(true), expected, P);
        } else {
          throws(() => {
            p.multiply(bytesToNumberBE(d)).toBytes(true);
          });
        }
      }

      for (const vector of VECTORS_points.invalid.pointMultiply) {
        let { P, d } = vector;
        if (bytesToNumberBE(d) < CURVE_N) {
          throws(() => {
            const p = Point.fromBytes(P);
            p.multiply(bytesToNumberBE(d)).toBytes(true);
          });
        }
      }
      for (const num of [0n, 0, -1n, -1, 1.1]) {
        throws(() => Point.BASE.multiply(num));
      }
    });
  });

  should('sign() RFC 6979 and DER vectors', async () => {
    const VECTORS_ecdsa = loadEcdsaVectors();
    for (const vector of VECTORS_ecdsa.valid) {
      const { m, d, signature: vsig } = vector;
      const opts = { prehash: false };
      const sig = secp.sign(m, d, opts);
      eql(sig, vsig, 'valid RFC 6979');
      if (secp.signAsync) {
        const sig = await secp.signAsync(m, d, opts);
        eql(sig, vsig, 'valid RFC 6979 async');
      }
    }

    for (const vector of VECTORS_ecdsa.invalid.sign) {
      const { m, d } = vector;
      throws(() => secp.sign(m, d));
    }

    if (isNobleCurves) {
      const CASES = deepHexToBytes([
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
      ]);
      const privKey = hexToBytes(
        '0101010101010101010101010101010101010101010101010101010101010101'
      );
      for (const [msg, exp] of CASES) {
        const sig = secp.sign(msg, privKey, { prehash: false, format: 'der' });
        eql(sig, exp, 'format: der');
      }
    }
  });

  describe('sign() {extraEntropy} creates hedged signatures', () => {
    should('static vectors and accepted lengths', () => {
      const VECTORS_ecdsa = loadEcdsaVectors();
      const ent1 = '0000000000000000000000000000000000000000000000000000000000000000';
      const ent2 = '0000000000000000000000000000000000000000000000000000000000000001';
      const ent3 = '6e723d3fd94ed5d2b6bdd4f123364b0f3ca52af829988a63f8afe91d29db1c33';
      const ent4 = 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141';
      const ent5 = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

      for (const e of VECTORS_ecdsa.extraEntropy) {
        const sign = (enth) => {
          const extraEntropy = hexToBytes(enth);
          const { m, d } = e;
          return secp.sign(m, d, { extraEntropy, prehash: false });
        };
        eql(sign(''), e.signature);
        eql(sign(ent1), e.extraEntropy0);
        eql(sign(ent2), e.extraEntropy1);
        eql(sign(ent3), e.extraEntropyRand);
        eql(sign(ent4), e.extraEntropyN);
        eql(sign(ent5), e.extraEntropyMax);
      }

      const priv = hexToBytes('0101010101010101010101010101010101010101010101010101010101010101');
      const msg = hexToBytes('d1a9dc8ed4e46a6a3e5e594615ca351d7d7ef44df1e4c94c1802f3592183794b');
      const res = secp.sign(msg, priv, { extraEntropy: hexToBytes('01'), prehash: false });
      eql(
        bytesToHex(res),
        'a250ec23a54bfdecf0e924cbf484077c5044410f915cdba86731cb2e4e925aaa5b1e4e3553d88be2c48a9a0d8d849ce2cc5720d25b2f97473e02f2550abe9545',
        '1-byte extraEntropy'
      );

      const extraEntropy = hexToBytes(
        '000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000001'
      );
      const res48 = secp.sign(msg, priv, { extraEntropy, prehash: false });
      eql(
        bytesToHex(res48),
        '2bdf40f42ac0e42ee12750d03bb12b75306dae58eb3c961c5a80d78efae93e595295b66e8eb28f1eb046bb129a976340312159ec0c20b97342667572e4a8379a',
        '48-byte extraEntropy'
      );
    });
  });
  // TODO: do we even need that? nist.test.js does same
  should('verify() wycheproof vectors', () => {
    const VECTORS_wp = loadWycheproofVectors();
    for (let group of VECTORS_wp.testGroups) {
      const pubKey = group.publicKey.uncompressed;

      for (let test of group.tests) {
        const h = selectHash(secp);
        const m = h(test.msg);
        const sig = test.sig;
        if (test.result === 'valid' || test.result === 'acceptable') {
          let _sig;
          try {
            _sig = sigFromDER(sig);
          } catch (e) {
            // These old Wycheproof vectors which allows invalid behaviour of DER parser
            if (e.message === 'Invalid signature integer: negative') continue;
            throw e;
          }
          const verified = secp.verify(_sig.toBytes(), m, pubKey, {
            prehash: false,
          });
          if (_sig.hasHighS()) {
            eql(verified, false, 'sig should have high s');
          } else {
            eql(verified, true, 'sig should have low s');
          }
        } else if (test.result === 'invalid') {
          let failed = false;
          try {
            const verified = secp.verify(sig, m, pubKey, { prehash: false });
            if (!verified) failed = true;
          } catch (error) {
            failed = true;
          }
          eql(failed, true);
        } else {
          eql(false, true);
        }
      }
    }
  });

  should('verify() invalid RFC 6979 vectors', () => {
    const VECTORS_ecdsa = loadEcdsaVectors();
    for (const vector of VECTORS_ecdsa.invalid.verify) {
      const { signature: sig, m, Q } = vector;
      const res = secp.verify(sig, m, Q);
      eql(res, false);
    }
  });

  should('ECDH, secret-key validity, and public-key recovery vectors', () => {
    const VECTORS_ecdh = loadEcdhVectors();
    const VECTORS_privates = loadPrivateVectors();
    const VECTORS_ecdsa = loadEcdsaVectors();
    // TODO: Once der is there, run all tests.
    for (const vector of VECTORS_ecdh.testGroups[0].tests.slice(0, 230)) {
      const priv = vector.private;
      const pub = derToPub(vector.public);
      if (vector.result === 'invalid' || priv.length !== 32) {
        throws(() => {
          secp.getSharedSecret(priv, pub, true);
        });
      } else if (vector.result === 'valid') {
        const res = secp.getSharedSecret(priv, pub, true);
        eql(res.slice(1), vector.shared);
      }
    }
    for (const vector of VECTORS_ecdh.testGroups[0].tests.slice(0, 100)) {
      if (vector.result === 'valid') {
        let priv = vector.private;
        priv = priv.length === 33 ? priv.slice(1) : priv;
        throws(() => secp.getSharedSecret(derToPub(vector.public), priv, true));
      }
    }

    for (const vector of VECTORS_privates.valid.isPrivate) {
      const { d, expected } = vector;
      eql(secp.utils.isValidSecretKey(d), expected, 'utils.isValidSecretKey');
    }

    for (const vector of VECTORS_ecdsa.valid) {
      const { m, d } = vector;
      let sig = secp.sign(m, d, { prehash: false, format: 'recovered' });
      const vpub = secp.getPublicKey(d);
      const recovered = secp.recoverPublicKey(sig, m, { prehash: false });
      eql(recovered, vpub);
    }
  });

  describe('tweak utilities (legacy)', () => {
    const normPriv = (n) => {
      if (typeof n === 'bigint') return n;
      if (typeof n === 'string') return hexToNumber(n);
      if (isBytes(n)) return bytesToNumberBE(n);
      throw new Error('invalid priv type');
    };
    const normPub = (p) => {
      if (typeof p === 'string') return hexToBytes(p);
      if (isBytes(p)) return p;
      throw new Error('invalid pub type');
    };
    const tweakUtils = {
      privateAdd: (privateKey, tweak) => {
        return numberToBytesBE(mod(normPriv(privateKey) + normPriv(tweak), CURVE_N), 32);
      },

      privateNegate: (privateKey) => {
        return numberToBytesBE(mod(-normPriv(privateKey), CURVE_N), 32);
      },

      pointAddScalar: (p, tweak, isCompressed) => {
        p = normPub(p);
        tweak = normPub(tweak);
        const tweaked = Point.fromBytes(p).add(Point.BASE.multiply(bytesToNumberBE(tweak)));
        if (tweaked.is0()) throw new Error('Tweaked point at infinity');
        return tweaked.toBytes(isCompressed);
      },

      pointMultiply: (p, tweak, isCompressed) => {
        p = normPub(p);
        tweak = normPub(tweak);
        const t = bytesToNumberBE(tweak);
        return Point.fromBytes(p).multiply(t).toBytes(isCompressed);
      },
    };

    should('private and point tweak helpers', () => {
      const VECTORS_privates = loadPrivateVectors();
      const VECTORS_points = loadPointVectors();
      for (const vector of VECTORS_privates.valid.add) {
        const { a, b, expected } = vector;
        eql(tweakUtils.privateAdd(a, b), expected, 'privateAdd');
      }
      for (const vector of VECTORS_privates.valid.negate) {
        const { a, expected } = vector;
        eql(tweakUtils.privateNegate(a), expected, 'privateNegate');
      }
      for (const vector of VECTORS_points.valid.pointAddScalar) {
        const { description, P, d, expected } = vector;
        const compressed = !!expected && expected.length === 33; // compressed === 33 bytes
        eql(
          tweakUtils.pointAddScalar(P, d, compressed),
          expected,
          `pointAddScalar: ${description}`
        );
      }
      for (const vector of VECTORS_points.invalid.pointAddScalar) {
        const { P, d, exception } = vector;
        throws(() => tweakUtils.pointAddScalar(P, d), `pointAddScalar invalid: ${exception}`);
      }
      for (const vector of VECTORS_points.valid.pointMultiply) {
        const { P, d, expected } = vector;
        eql(tweakUtils.pointMultiply(P, d, true), expected, 'pointMultiply');
      }
      for (const vector of VECTORS_points.invalid.pointMultiply) {
        const { P, d, exception } = vector;
        throws(() => tweakUtils.pointMultiply(P, d), `pointMultiply invalid: ${exception}`);
      }
    });
  });
});

describe('secp256k1', () => {
  should('key and point edge cases', () => {
    for (const item of getTypeTestsNonUi8a()) {
      throws(() => secp.getPublicKey(item));
    }
    if (isNobleCurves) {
      secp.Point.BASE.precompute(4, false);
      checkPrivatesTxt();
    }

    // todo: fromPrivateScalar
    const p1 =
      Point.BASE.multiply(
        88572218780422190464634044548753414301110513745532121983949500266768436236425n
      );
    eql(Point.fromBytes(p1.toBytes(true)).equals(p1), true, '#toBytes() roundtrip failed case');

    fc.assert(
      fc.property(FC_BIGINT, (x) => {
        const p1 = Point.BASE.multiply(x);
        const b1 = p1.toBytes(true);
        eql(Point.fromBytes(b1).toBytes(true), b1, '#toBytes() roundtrip');
      })
    );

    const xy = { x: 0n, y: 0n };
    const p = Point.fromAffine(xy);
    eql(p.is0(), true, '.fromAffine is zero');
    eql(p.toAffine(), xy, '.fromAffine roundtrip');

    throws(() => secp.getSharedSecret(hexToBytes('01'), hexToBytes('02')));
  });
});

describe('Signature', () => {
  should('serialization roundtrips and recovery id validation', () => {
    fc.assert(
      fc.property(FC_BIGINT, FC_BIGINT, (r, s) => {
        const sig = new secp.Signature(r, s);
        eql(secp.Signature.fromBytes(sig.toBytes()), sig, 'compact roundtrip');
      })
    );

    const compact = new secp.Signature(1n, 1n).toBytes();
    for (const recovery of [4, 255]) {
      const recovered = new Uint8Array(compact.length + 1);
      recovered[0] = recovery;
      recovered.set(compact, 1);
      throws(() => new secp.Signature(1n, 1n, recovery), /invalid recovery id/);
      throws(
        () => secp.Signature.fromBytes(recovered as unknown as globalThis.Uint8Array, 'recovered'),
        /invalid recovery id/
      );
      throws(() => new secp.Signature(1n, 1n).addRecoveryBit(recovery), /invalid recovery id/);
    }

    if (isNobleCurves) {
      fc.assert(
        fc.property(FC_BIGINT, FC_BIGINT, (r, s) => {
          const sig = new secp.Signature(r, s).toBytes('der');
          eql(secp.Signature.fromBytes(sig, 'der').toBytes('der'), sig, 'DER roundtrip');
        })
      );
    }
  });

  should('.hasHighS()', () => {
    const priv = hexToBytes('c509ae2138ddca15f6b33062cd3bf76351c79f58c82ee2c2236d835bdea19d13');
    const msg = hexToBytes('b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9');

    const hi =
      'a6bf36d52da4eef85a513a88d81996a47804a2390c9910c0bd35488effca36bf8bf1f9232ab0efe4a93704ae871aa953b34d1000cef59c9d33fcc696f935108d';
    const lo =
      'a6bf36d52da4eef85a513a88d81996a47804a2390c9910c0bd35488effca36bf740e06dcd54f101b56c8fb5178e556ab0761cce5e053039e8bd597f5d70130b4';
    const hi_ = new secp.Signature(
      75421779095773161492578598757717572512754773103551662129966816753283695785663n,
      63299015578620006752099543153250095157058828301739590985992016204296254460045n,
      undefined
    );
    const lo_ = new secp.Signature(
      75421779095773161492578598757717572512754773103551662129966816753283695785663n,
      52493073658696188671471441855437812695778735977335313396613146937221907034292n,
      undefined
    );

    const pub = secp.getPublicKey(priv);
    const sigb = secp.sign(msg, priv, { prehash: false, lowS: false });
    const sig = secp.Signature.fromBytes(sigb);
    eql(sig.hasHighS(), true);
    eql(sig, hi_);
    eql(bytesToHex(sig.toBytes()), hi);

    const normalizeS = (sig) => {
      return new secp.Signature(sig.r, CURVE_N - sig.s);
    };
    const lowSig = normalizeS(sig);
    eql(lowSig.hasHighS(), false);
    eql(lowSig, lo_);
    eql(bytesToHex(lowSig.toBytes()), lo);

    eql(secp.verify(sig.toBytes(), msg, pub, { prehash: false, lowS: false }), true);
    eql(secp.verify(sig.toBytes(), msg, pub, { prehash: false, lowS: true }), false);
    for (let format of ['der', 'compact']) {
      if (format === 'der' && !isNobleCurves) continue;
      eql(
        secp.verify(sig.toBytes(format), msg, pub, { prehash: false, lowS: false, format }),
        true
      );
      eql(
        secp.verify(sig.toBytes(format), msg, pub, { prehash: false, lowS: true, format }),
        false
      );
      eql(
        secp.verify(lowSig.toBytes(format), msg, pub, { prehash: false, lowS: true, format }),
        true
      );
      eql(
        secp.verify(lowSig.toBytes(format), msg, pub, { prehash: false, lowS: false, format }),
        true
      );
    }
  });
});

describe('sign()', () => {
  should('edge cases', () => {
    let invalidInputs = ['', hexToBytes(''), new Uint8Array(0)];
    throws(() => secp.getPublicKey());
    throws(() => secp.sign());
    throws(() => secp.verify());
    const validMsg = new Uint8Array(32).fill(0x05);
    for (let l = 0; l < 32; l++) {
      let priv = new Uint8Array(l).fill(0x03);
      throws(() => secp.getPublicKey(priv));
      throws(() => secp.sign(validMsg, priv));
    }
  });
});

describe('verify()', () => {
  function hexa() {
    const items = '0123456789abcdef';
    return fc.integer({ min: 0, max: 15 }).map((n) => items[n]);
  }
  function hexaString(constraints = {}) {
    return fc.string({ ...constraints, unit: hexa() });
  }
  should('random signatures and fixed edge cases', async () => {
    await fc.assert(
      fc.asyncProperty(
        FC_BIGINT,
        // @ts-ignore
        hexaString({ minLength: 64, maxLength: 64 }),
        async (privKeyNum, msgh) => {
          const privKey = numberToBytesBE(privKeyNum, 32);
          const msg = hexToBytes(msgh);
          const pub = secp.getPublicKey(privKey);
          const sig = secp.sign(msg, privKey);
          eql(secp.verify(sig, msg, pub), true, 'verify random signatures');
          if ('signAsync' in secp) {
            const sig = await secp.signAsync(msg, privKey);
            eql(secp.verify(sig, msg, pub), true, 'verify random signatures async');
          }
        }
      )
    );

    {
      const msg = new Uint8Array([
        0xbb, 0x5a, 0x52, 0xf4, 0x2f, 0x9c, 0x92, 0x61, 0xed, 0x43, 0x61, 0xf5, 0x94, 0x22, 0xa1,
        0xe3, 0x00, 0x36, 0xe7, 0xc3, 0x2b, 0x27, 0x0c, 0x88, 0x07, 0xa4, 0x19, 0xfe, 0xca, 0x60,
        0x50, 0x23,
      ]);
      const x = 100260381870027870612475458630405506840396644859280795015145920502443964769584n;
      const y = 41096923727651821103518389640356553930186852801619204169823347832429067794568n;
      const r = 1n;
      const s = 115792089237316195423570985008687907852837564279074904382605163141518162728904n;

      const pub = new Point(x, y, 1n).toBytes();
      const sig = new secp.Signature(2n, 2n);
      throws(() => {
        sig.r = r;
        sig.s = s;
      });
      const sigHex = hexToBytes(
        '0000000000000000000000000000000000000000000000000000000000000001fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd04917c8'
      );

      const verified = secp.verify(sigHex, msg, pub);
      // Verifies, but it shouldn't, because signature S > curve order
      eql(verified, false, 'invalid r/s');
    }

    {
      const msg = hexToBytes('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
      const x = 55066263022277343669578718895168534326250603453777594175500187360389116729240n;
      const y = 32670510020758816978083085130507043184471273380659243275938904335757337482424n;
      const r = 104546003225722045112039007203142344920046999340768276760147352389092131869133n;
      const s = 96900796730960181123786672629079577025401317267213807243199432755332205217369n;
      const pub = new Point(x, y, 1n).toBytes();
      const sig = new secp.Signature(r, s).toBytes();
      eql(secp.verify(sig, msg, pub), false, 'msg = curve order');
    }

    {
      const msg = hexToBytes('bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023');
      const x = 3252872872578928810725465493269682203671229454553002637820453004368632726370n;
      const y = 17482644437196207387910659778872952193236850502325156318830589868678978890912n;
      const r = 432420386565659656852420866390673177323n;
      const s = 115792089237316195423570985008687907852837564279074904382605163141518161494334n;
      const pub = new Point(x, y, 1n).toBytes();
      const sig = new secp.Signature(r, s).toBytes();
      eql(secp.verify(sig, msg, pub, { prehash: false, lowS: false }), true, 'non-strict msg bb5a');
    }
  });

  describe('recoverPublicKey()', () => {
    should('recovery and curve-equation edge cases', () => {
      const message = hexToBytes(
        '00000000000000000000000000000000000000000000000000000000deadbeef'
      );
      const privateKey = numberToBytesBE(123456789n, 32);
      const publicKey = secp.getPublicKey(privateKey);
      const recoveredSig = secp.sign(message, privateKey, { prehash: false, format: 'recovered' });
      const recoveredPubkey = secp.recoverPublicKey(recoveredSig, message, { prehash: false });
      eql(recoveredPubkey, publicKey);
      eql(
        secp.verify(recoveredSig, message, publicKey, { prehash: false, format: 'recovered' }),
        true
      );

      const msgHash = hexToBytes(
        '6b8d2c81b11b2d699528dde488dbdf2f94293d0d33c32e347f255fa4a6c1f0a9'
      );
      const sigh = hexToBytes(
        '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817986b8d2c81b11b2d699528dde488dbdf2f94293d0d33c32e347f255fa4a6c1f0a9'
      );
      const recovery = 0;
      const zeroPointSig = secp.Signature.fromBytes(sigh, 'compact')
        .addRecoveryBit(recovery)
        .toBytes('recovered');
      throws(() => secp.recoverPublicKey(zeroPointSig, msgHash, { prehash: false }));

      const privKey = secp.utils.randomSecretKey();
      const pub = secp.getPublicKey(privKey);
      const zeros = hexToBytes('0000000000000000000000000000000000000000000000000000000000000000');
      const zeroMsgSig = secp.sign(zeros, privKey, { format: 'recovered' });
      const recoveredKey = secp.recoverPublicKey(zeroMsgSig, zeros);
      eql(recoveredKey, pub);

      throws(() => {
        const p = Point.CURVE().p;
        let point = new Point(p - 2n, p - 1n, p + 1n);
        point.assertValidity();
      });
    });
  });
});

describe('secp256k1 schnorr.sign()', () => {
  if (!schnorr) return;
  // index,secret key,public key,aux_rand,message,signature,verification result,comment
  should('BIP340 vectors', () => {
    const VECTORS_bip340 = txt('vectors/secp256k1/schnorr.csv', ',').slice(1, -1);
    for (let vec of VECTORS_bip340) {
      const index = vec[0];
      const [sec, pub, rnd, msg, expSig] = vec.slice(1, 6).map((item) => hexToBytes(item));
      const passes = vec[6];
      const comment = vec[7];
      const label = comment || 'vector ' + index;
      if (sec.length > 0) {
        eql(schnorr.getPublicKey(sec), pub, `${label}: public key`);
        const sig = schnorr.sign(msg, sec, rnd);
        eql(sig, expSig, `${label}: signature`);
        eql(schnorr.verify(sig, msg, pub), true, `${label}: verify generated`);
      } else {
        const passed = schnorr.verify(expSig, msg, pub);
        eql(passed, passes === 'TRUE', `${label}: verify vector`);
      }
    }
  });
});

describe('secp256k1 regressions', () => {
  describe('helpers', () => {
    should('curve params, BIP340 lift_x, and nonce extraction', () => {
      const curve = secp.Point.CURVE() as { p: bigint };
      const prev = secp.Point.CURVE().p;
      let changed = false;
      try {
        try {
          curve.p = 1n;
        } catch {}
        changed = secp.Point.CURVE().p !== prev;
        eql(secp.Point.CURVE().p, prev);
      } finally {
        if (changed) curve.p = prev;
      }

      const { x } = secp.Point.BASE.multiply(3n).toAffine();
      const p = secp.__TEST.lift_x(x);
      eql(p.x, x, 'BIP340 lift_x x-coordinate');
      eql((p.y & 1n) === 0n, true, 'BIP340 lift_x even y');

      if (isNobleCurves) return;
      const rand = numberToBytesBE(CURVE_N + 1n, 32);
      const { rx, k } = secp.__TEST.extractK(rand);
      eql(k, 1n, 'BIP340 nonce extraction k');
      eql(
        bytesToHex(rx),
        bytesToHex(secp.Point.BASE.toBytes(true).slice(1)),
        'BIP340 nonce extraction rx'
      );
    });
  });

  describe('typed arrays', () => {
    should(
      'APIs reject typed-array subclasses that only spoof the Uint8Array constructor name',
      async () => {
        {
          class Uint8Array extends Uint16Array {}
          const secretKey = globalThis.Uint8Array.of(...Array(31).fill(0), 1);
          const real = secp.getPublicKey(secretKey);
          const fake = new Uint8Array(real.length);
          for (let i = 0; i < real.length; i++) fake[i] = real[i];
          throws(
            () => secp.Point.fromBytes(fake as unknown as globalThis.Uint8Array),
            /expected Uint8Array/
          );
          eql(secp.utils.isValidPublicKey(fake as unknown as globalThis.Uint8Array), false);
          eql(secp.utils.isValidPublicKey(fake as unknown as globalThis.Uint8Array, true), false);
        }

        {
          class Uint8Array extends Uint16Array {}
          const fake = new Uint8Array(32);
          fake[31] = 1;
          eql(secp.utils.isValidSecretKey(fake as unknown as globalThis.Uint8Array), false);
          throws(
            () => secp.getPublicKey(fake as unknown as globalThis.Uint8Array),
            /expected Uint8Array|"secret key".*type=object/
          );
        }

        {
          class Uint8Array extends Uint16Array {}
          const secretKey = globalThis.Uint8Array.of(...Array(31).fill(0), 1);
          const message = globalThis.Uint8Array.of(1, 2, 3);
          const signature = secp.sign(message, secretKey);
          const publicKey = secp.getPublicKey(secretKey);
          const fake = new Uint8Array(signature.length);
          const verifyRejects = async (fn: () => boolean | Promise<boolean>) => {
            try {
              eql(await fn(), false);
            } catch (error) {
              eql(error instanceof Error && /Uint8Array/.test(error.message), true);
            }
          };
          for (let i = 0; i < signature.length; i++) fake[i] = signature[i];
          throws(
            () => secp.Signature.fromBytes(fake as unknown as globalThis.Uint8Array),
            /expected Uint8Array/
          );
          await verifyRejects(() =>
            secp.verify(fake as unknown as globalThis.Uint8Array, message, publicKey)
          );
          await verifyRejects(() =>
            secp.verifyAsync(fake as unknown as globalThis.Uint8Array, message, publicKey)
          );
        }

        {
          class Uint8Array extends Uint16Array {}
          const secretKey = globalThis.Uint8Array.of(...Array(31).fill(0), 1);
          const message = globalThis.Uint8Array.of(1, 2, 3);
          const signature = secp.sign(message, secretKey, { format: 'recovered' });
          const fake = new Uint8Array(signature.length);
          for (let i = 0; i < signature.length; i++) fake[i] = signature[i];
          throws(
            () => secp.recoverPublicKey(fake as unknown as globalThis.Uint8Array, message),
            /expected Uint8Array/
          );
          await rejects(
            () => secp.recoverPublicKeyAsync(fake as unknown as globalThis.Uint8Array, message),
            /expected Uint8Array/
          );
        }

        {
          class Uint8Array extends Uint16Array {}
          const alice = globalThis.Uint8Array.of(...Array(31).fill(0), 1);
          const bob = globalThis.Uint8Array.of(...Array(31).fill(0), 2);
          const publicKey = secp.getPublicKey(bob);
          const fakeSecretKey = new Uint8Array(alice.length);
          const fakePublicKey = new Uint8Array(publicKey.length);
          for (let i = 0; i < fakeSecretKey.length; i++) fakeSecretKey[i] = alice[i];
          for (let i = 0; i < fakePublicKey.length; i++) fakePublicKey[i] = publicKey[i];
          throws(
            () =>
              secp.getSharedSecret(
                fakeSecretKey as unknown as globalThis.Uint8Array,
                fakePublicKey as unknown as globalThis.Uint8Array
              ),
            /expected Uint8Array/
          );
        }

        {
          class Uint8Array extends Uint16Array {}
          const secretKey = globalThis.Uint8Array.of(...Array(31).fill(0), 1);
          const message = globalThis.Uint8Array.of(1, 2, 3);
          const auxRand = globalThis.Uint8Array.of(...Array(31).fill(0), 7);
          const signature = secp.schnorr.sign(message, secretKey, auxRand);
          const publicKey = secp.schnorr.getPublicKey(secretKey);
          const fakeSecretKey = new Uint8Array(secretKey.length);
          const fakeSignature = new Uint8Array(signature.length);
          const fakePublicKey = new Uint8Array(publicKey.length);
          for (let i = 0; i < fakeSecretKey.length; i++) fakeSecretKey[i] = secretKey[i];
          for (let i = 0; i < fakeSignature.length; i++) fakeSignature[i] = signature[i];
          for (let i = 0; i < fakePublicKey.length; i++) fakePublicKey[i] = publicKey[i];
          throws(
            () => secp.schnorr.getPublicKey(fakeSecretKey as unknown as globalThis.Uint8Array),
            /expected Uint8Array|"secret key".*type=object/
          );
          throws(
            () =>
              secp.schnorr.sign(
                message,
                fakeSecretKey as unknown as globalThis.Uint8Array,
                auxRand
              ),
            /expected Uint8Array|"secret key".*type=object/
          );
          await rejects(
            () =>
              secp.schnorr.signAsync(
                message,
                fakeSecretKey as unknown as globalThis.Uint8Array,
                auxRand
              ),
            /expected Uint8Array|"secret key".*type=object/
          );
          throws(
            () =>
              secp.schnorr.verify(
                fakeSignature as unknown as globalThis.Uint8Array,
                message,
                fakePublicKey as unknown as globalThis.Uint8Array
              ),
            /"signature".*type=object/
          );
          await rejects(
            () =>
              secp.schnorr.verifyAsync(
                fakeSignature as unknown as globalThis.Uint8Array,
                message,
                fakePublicKey as unknown as globalThis.Uint8Array
              ),
            /"signature".*type=object/
          );
        }
      }
    );
  });

  describe('signatures', () => {
    should('DER format support and long prehash handling', async () => {
      if (!isNobleCurves) {
        const secretKey = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
        const msg = Uint8Array.from({ length: 32 }, (_, i) => 255 - i);
        throws(
          () => new secp.Signature(1n, 2n).toBytes('der'),
          /Signature format "der" is not supported/
        );
        throws(
          () => secp.sign(msg, secretKey, { prehash: false, format: 'der' }),
          /Signature format "der" is not supported/
        );
        await rejects(
          () => secp.signAsync(msg, secretKey, { prehash: false, format: 'der' }),
          /Signature format "der" is not supported/
        );
      }

      const secretKey = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
      const leftmost32 = Uint8Array.from({ length: 32 }, (_, i) => 255 - i);
      const extended = new Uint8Array(161);
      extended.set(leftmost32);
      extended.fill(0xaa, 32);
      eql(
        secp.sign(extended, secretKey, { prehash: false }),
        secp.sign(leftmost32, secretKey, { prehash: false }),
        'RFC 6979 bits2int discards bits beyond qlen'
      );
    });
  });

  describe('recovery', () => {
    should(
      'recoverPublicKey()/recoverPublicKeyAsync() derive e from the same long prehashed message accepted by sign()/verify()',
      async () => {
        const secretKey = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
        const msg = Uint8Array.from({ length: 64 }, (_, i) => i);
        const publicKey = secp.getPublicKey(secretKey);
        const sig = secp.sign(msg, secretKey, { prehash: false, format: 'recovered' });
        eql(secp.verify(sig, msg, publicKey, { prehash: false, format: 'recovered' }), true);
        eql(secp.recoverPublicKey(sig, msg, { prehash: false }), publicKey);
        const sigA = await secp.signAsync(msg, secretKey, { prehash: false, format: 'recovered' });
        eql(
          await secp.verifyAsync(sigA, msg, publicKey, { prehash: false, format: 'recovered' }),
          true
        );
        eql(await secp.recoverPublicKeyAsync(sigA, msg, { prehash: false }), publicKey);
      }
    );
  });
});

should.runWhen(import.meta.url);
