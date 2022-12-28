import { deepStrictEqual, throws } from 'assert';
import { should } from 'micro-should';
import { secp192r1, P192 } from '../lib/esm/p192.js';
import { secp224r1, P224 } from '../lib/esm/p224.js';
import { secp256r1, P256 } from '../lib/esm/p256.js';
import { secp384r1, P384 } from '../lib/esm/p384.js';
import { secp521r1, P521 } from '../lib/esm/p521.js';
import { secp256k1 } from '../lib/esm/secp256k1.js';
import { hexToBytes, bytesToHex } from '../lib/esm/abstract/utils.js';
import { default as ecdsa } from './wycheproof/ecdsa_test.json' assert { type: 'json' };
import { default as ecdh } from './wycheproof/ecdh_test.json' assert { type: 'json' };
import { default as rfc6979 } from './fixtures/rfc6979.json' assert { type: 'json' };

const hex = bytesToHex;

// prettier-ignore
const NIST = {
  secp192r1, P192,
  secp224r1, P224,
  secp256r1, P256,
  secp384r1, P384,
  secp521r1, P521,
  secp256k1,
};

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
  for (const n in vectors) deepStrictEqual(NIST[n].CURVE.Fp.ORDER, vectors[n]);
});

should('wychenproof ECDSA vectors', () => {
  for (const group of ecdsa.testGroups) {
    // Tested in secp256k1.test.js
    if (group.key.curve === 'secp256k1') continue;
    let CURVE = NIST[group.key.curve];
    if (!CURVE) continue;
    if (group.key.curve === 'secp224r1' && group.sha !== 'SHA-224') {
      if (group.sha === 'SHA-256') CURVE = CURVE.create(sha256);
    }
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
    const CURVE = NIST[group.curve];
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

import { default as ecdh_secp224r1_test } from './wycheproof/ecdh_secp224r1_test.json' assert { type: 'json' };
import { default as ecdh_secp256r1_test } from './wycheproof/ecdh_secp256r1_test.json' assert { type: 'json' };
import { default as ecdh_secp256k1_test } from './wycheproof/ecdh_secp256k1_test.json' assert { type: 'json' };
import { default as ecdh_secp384r1_test } from './wycheproof/ecdh_secp384r1_test.json' assert { type: 'json' };
import { default as ecdh_secp521r1_test } from './wycheproof/ecdh_secp521r1_test.json' assert { type: 'json' };

// More per curve tests
const WYCHEPROOF_ECDH = {
  P224: {
    curve: P224,
    tests: [ecdh_secp224r1_test],
  },
  P256: {
    curve: P256,
    tests: [ecdh_secp256r1_test],
  },
  secp256k1: {
    curve: secp256k1,
    tests: [ecdh_secp256k1_test],
  },
  P384: {
    curve: P384,
    tests: [ecdh_secp384r1_test],
  },
  P521: {
    curve: P521,
    tests: [ecdh_secp521r1_test],
  },
};

for (const name in WYCHEPROOF_ECDH) {
  const { curve, tests } = WYCHEPROOF_ECDH[name];
  for (let i = 0; i < tests.length; i++) {
    const test = tests[i];
    for (let j = 0; j < test.testGroups.length; j++) {
      const group = test.testGroups[j];
      should(`Wycheproof/ECDH ${name} (${i}/${j})`, () => {
        for (const test of group.tests) {
          if (test.result === 'valid' || test.result === 'acceptable') {
            try {
              const pub = curve.Point.fromHex(test.public);
            } catch (e) {
              if (e.message.includes('Point.fromHex: received invalid point.')) continue;
              throw e;
            }
            const shared = curve.getSharedSecret(test.private, test.public);
            deepStrictEqual(hex(shared), test.shared, 'valid');
          } else if (test.result === 'invalid') {
            let failed = false;
            try {
              curve.getSharedSecret(test.private, test.public);
            } catch (error) {
              failed = true;
            }
            deepStrictEqual(failed, true, 'invalid');
          } else throw new Error('unknown test result');
        }
      });
    }
  }
}

// Tests with custom hashes
import { default as secp224r1_sha224_test } from './wycheproof/ecdsa_secp224r1_sha224_test.json' assert { type: 'json' };
import { default as secp224r1_sha256_test } from './wycheproof/ecdsa_secp224r1_sha256_test.json' assert { type: 'json' };
import { default as secp224r1_sha3_224_test } from './wycheproof/ecdsa_secp224r1_sha3_224_test.json' assert { type: 'json' };
import { default as secp224r1_sha3_256_test } from './wycheproof/ecdsa_secp224r1_sha3_256_test.json' assert { type: 'json' };
import { default as secp224r1_sha3_512_test } from './wycheproof/ecdsa_secp224r1_sha3_512_test.json' assert { type: 'json' };
import { default as secp224r1_sha512_test } from './wycheproof/ecdsa_secp224r1_sha512_test.json' assert { type: 'json' };

import { default as secp256k1_sha256_test } from './wycheproof/ecdsa_secp256k1_sha256_test.json' assert { type: 'json' };
import { default as secp256k1_sha3_256_test } from './wycheproof/ecdsa_secp256k1_sha3_256_test.json' assert { type: 'json' };
import { default as secp256k1_sha3_512_test } from './wycheproof/ecdsa_secp256k1_sha3_512_test.json' assert { type: 'json' };
import { default as secp256k1_sha512_test } from './wycheproof/ecdsa_secp256k1_sha512_test.json' assert { type: 'json' };

import { default as secp256r1_sha256_test } from './wycheproof/ecdsa_secp256r1_sha256_test.json' assert { type: 'json' };
import { default as secp256r1_sha3_256_test } from './wycheproof/ecdsa_secp256r1_sha3_256_test.json' assert { type: 'json' };
import { default as secp256r1_sha3_512_test } from './wycheproof/ecdsa_secp256r1_sha3_512_test.json' assert { type: 'json' };
import { default as secp256r1_sha512_test } from './wycheproof/ecdsa_secp256r1_sha512_test.json' assert { type: 'json' };

import { default as secp384r1_sha384_test } from './wycheproof/ecdsa_secp384r1_sha384_test.json' assert { type: 'json' };
import { default as secp384r1_sha3_384_test } from './wycheproof/ecdsa_secp384r1_sha3_384_test.json' assert { type: 'json' };
import { default as secp384r1_sha3_512_test } from './wycheproof/ecdsa_secp384r1_sha3_512_test.json' assert { type: 'json' };
import { default as secp384r1_sha512_test } from './wycheproof/ecdsa_secp384r1_sha512_test.json' assert { type: 'json' };

import { default as secp521r1_sha3_512_test } from './wycheproof/ecdsa_secp521r1_sha3_512_test.json' assert { type: 'json' };
import { default as secp521r1_sha512_test } from './wycheproof/ecdsa_secp521r1_sha512_test.json' assert { type: 'json' };

import { sha3_224, sha3_256, sha3_384, sha3_512 } from '@noble/hashes/sha3';
import { sha512, sha384 } from '@noble/hashes/sha512';
import { sha224, sha256 } from '@noble/hashes/sha256';

const WYCHEPROOF_ECDSA = {
  P224: {
    curve: P224,
    hashes: {
      sha224: {
        hash: sha224,
        tests: [secp224r1_sha224_test],
      },
      sha256: {
        hash: sha256,
        tests: [secp224r1_sha256_test],
      },
      sha3_224: {
        hash: sha3_224,
        tests: [secp224r1_sha3_224_test],
      },
      sha3_256: {
        hash: sha3_256,
        tests: [secp224r1_sha3_256_test],
      },
      sha3_512: {
        hash: sha3_512,
        tests: [secp224r1_sha3_512_test],
      },
      sha512: {
        hash: sha512,
        tests: [secp224r1_sha512_test],
      },
    },
  },
  secp256k1: {
    curve: secp256k1,
    hashes: {
      // TODO: debug why fails, can be bug
      sha256: {
        hash: sha256,
        tests: [secp256k1_sha256_test],
      },
      sha3_256: {
        hash: sha3_256,
        tests: [secp256k1_sha3_256_test],
      },
      sha3_512: {
        hash: sha3_512,
        tests: [secp256k1_sha3_512_test],
      },
      sha512: {
        hash: sha512,
        tests: [secp256k1_sha512_test],
      },
    },
  },
  P256: {
    curve: P256,
    hashes: {
      sha256: {
        hash: sha256,
        tests: [secp256r1_sha256_test],
      },
      sha3_256: {
        hash: sha3_256,
        tests: [secp256r1_sha3_256_test],
      },
      sha3_512: {
        hash: sha3_512,
        tests: [secp256r1_sha3_512_test],
      },
      sha512: {
        hash: sha512,
        tests: [secp256r1_sha512_test],
      },
    },
  },
  P384: {
    curve: P384,
    hashes: {
      sha384: {
        hash: sha384,
        tests: [secp384r1_sha384_test],
      },
      sha3_384: {
        hash: sha3_384,
        tests: [secp384r1_sha3_384_test],
      },
      sha3_512: {
        hash: sha3_512,
        tests: [secp384r1_sha3_512_test],
      },
      sha512: {
        hash: sha512,
        tests: [secp384r1_sha512_test],
      },
    },
  },
  P521: {
    curve: P521,
    hashes: {
      sha3_512: {
        hash: sha3_512,
        tests: [secp521r1_sha3_512_test],
      },
      sha512: {
        hash: sha512,
        tests: [secp521r1_sha512_test],
      },
    },
  },
};

function runWycheproof(name, CURVE, group, index) {
  const pubKey = CURVE.Point.fromHex(group.key.uncompressed);
  deepStrictEqual(pubKey.x, BigInt(`0x${group.key.wx}`));
  deepStrictEqual(pubKey.y, BigInt(`0x${group.key.wy}`));
  for (const test of group.tests) {
    const m = CURVE.CURVE.hash(hexToBytes(test.msg));

    if (test.result === 'valid' || test.result === 'acceptable') {
      try {
        CURVE.Signature.fromDER(test.sig);
      } catch (e) {
        // Some tests has invalid signature which we don't accept
        if (e.message.includes('Invalid signature: incorrect length')) continue;
        throw e;
      }
      const verified = CURVE.verify(test.sig, m, pubKey);
      if (name === 'secp256k1') {
        // lowS: true for secp256k1
        deepStrictEqual(verified, !CURVE.Signature.fromDER(test.sig).hasHighS(), `${index}: valid`);
      } else {
        deepStrictEqual(verified, true, `${index}: valid`);
      }
    } else if (test.result === 'invalid') {
      let failed = false;
      try {
        failed = !CURVE.verify(test.sig, m, pubKey);
      } catch (error) {
        failed = true;
      }
      deepStrictEqual(failed, true, `${index}: invalid`);
    } else throw new Error('unknown test result');
  }
}

for (const name in WYCHEPROOF_ECDSA) {
  const { curve, hashes } = WYCHEPROOF_ECDSA[name];
  for (const hName in hashes) {
    const { hash, tests } = hashes[hName];
    const CURVE = curve.create(hash);
    should(`Wycheproof/WYCHEPROOF_ECDSA ${name}/${hName}`, () => {
      for (let i = 0; i < tests.length; i++) {
        const groups = tests[i].testGroups;
        for (let j = 0; j < groups.length; j++) {
          const group = groups[j];
          runWycheproof(name, CURVE, group, `${i}/${j}`);
        }
      }
    });
  }
}

const hexToBigint = (hex) => BigInt(`0x${hex}`);
should('RFC6979', () => {
  for (const v of rfc6979) {
    const curve = NIST[v.curve];
    deepStrictEqual(curve.CURVE.n, hexToBigint(v.q));
    const pubKey = curve.getPublicKey(v.private);
    const pubPoint = curve.Point.fromHex(pubKey);
    deepStrictEqual(pubPoint.x, hexToBigint(v.Ux));
    deepStrictEqual(pubPoint.y, hexToBigint(v.Uy));
    for (const c of v.cases) {
      const h = curve.CURVE.hash(c.message);
      const sigObj = curve.sign(h, v.private);
      deepStrictEqual(sigObj.r, hexToBigint(c.r), 'R');
      deepStrictEqual(sigObj.s, hexToBigint(c.s), 'S');
      deepStrictEqual(curve.verify(sigObj.toDERRawBytes(), h, pubKey), true, 'verify(1)');
      deepStrictEqual(curve.verify(sigObj, h, pubKey), true, 'verify(2)');
    }
  }
});

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
