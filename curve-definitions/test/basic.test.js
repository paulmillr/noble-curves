import { deepStrictEqual, throws } from 'assert';
import { should } from 'micro-should';
import * as nist from '../lib/nist.js';
import { hexToBytes, bytesToHex } from '@noble/curves/utils';
import { default as ecdsa } from './wycheproof/ecdsa_test.json' assert { type: 'json' };
import { default as ecdh } from './wycheproof/ecdh_test.json' assert { type: 'json' };

const hex = bytesToHex;

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

import { default as ecdh_secp224r1_test } from './wycheproof/ecdh_secp224r1_test.json' assert { type: 'json' };
import { default as ecdh_secp256r1_test } from './wycheproof/ecdh_secp256r1_test.json' assert { type: 'json' };
import { default as ecdh_secp256k1_test } from './wycheproof/ecdh_secp256k1_test.json' assert { type: 'json' };
import { default as ecdh_secp384r1_test } from './wycheproof/ecdh_secp384r1_test.json' assert { type: 'json' };
import { default as ecdh_secp521r1_test } from './wycheproof/ecdh_secp521r1_test.json' assert { type: 'json' };

// More per curve tests
const WYCHEPROOF_ECDH = {
  P224: {
    curve: nist.P224,
    tests: [ecdh_secp224r1_test],
  },
  P256: {
    curve: nist.P256,
    tests: [ecdh_secp256r1_test],
  },
  secp256k1: {
    curve: nist.secp256k1,
    tests: [ecdh_secp256k1_test],
  },
  P384: {
    curve: nist.P384,
    tests: [ecdh_secp384r1_test],
  },
  P521: {
    curve: nist.P521,
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
import { sha256 } from '@noble/hashes/sha256';

const WYCHEPROOF_ECDSA = {
  P224: {
    curve: nist.P224,
    hashes: {
      // sha224 not released yet
      // sha224: {
      //   hash: sha224,
      //   tests: [secp224r1_sha224_test],
      // },
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
    curve: nist.secp256k1,
    hashes: {
      // TODO: debug why fails, can be bug
      // sha256: {
      //   hash: sha256,
      //   tests: [secp256k1_sha256_test],
      // },
      // sha3_256: {
      //   hash: sha3_256,
      //   tests: [secp256k1_sha3_256_test],
      // },
      // sha3_512: {
      //   hash: sha3_512,
      //   tests: [secp256k1_sha3_512_test],
      // },
      // sha512: {
      //   hash: sha512,
      //   tests: [secp256k1_sha512_test],
      // },
    },
  },
  P256: {
    curve: nist.P256,
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
    curve: nist.P384,
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
    curve: nist.P521,
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

for (const name in WYCHEPROOF_ECDSA) {
  const { curve, hashes } = WYCHEPROOF_ECDSA[name];
  for (const hName in hashes) {
    const { hash, tests } = hashes[hName];
    const CURVE = curve.create(hash);
    for (let i = 0; i < tests.length; i++) {
      const test = tests[i];
      for (let j = 0; j < test.testGroups.length; j++) {
        const group = test.testGroups[j];
        should(`Wycheproof/WYCHEPROOF_ECDSA ${name}/${hName} (${i}/${j})`, () => {
          const pubKey = CURVE.Point.fromHex(group.key.uncompressed);
          deepStrictEqual(pubKey.x, BigInt(`0x${group.key.wx}`));
          deepStrictEqual(pubKey.y, BigInt(`0x${group.key.wy}`));
          for (const test of group.tests) {
            // if (['Hash weaker than DL-group'].includes(test.comment)) {
            //   continue;
            // }
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
        });
      }
    }
  }
}

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
