import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual, throws } from 'node:assert';
import { ed25519, x25519 } from '../src/ed25519.ts';
import { ed448, x448 } from '../src/ed448.ts';
import { p256, p384, p521 } from '../src/nist.ts';
import * as webcrypto from '../src/webcrypto.ts';

// import {  base64urlnopad } from '@scure/base';

// function nobleJWK(curve, noble, key) {
//   if (curve === 'X25519' || curve === 'Ed25519' || curve === 'Ed448') {
//     const basic = {
//       key_ops: curve === 'X25519' ? ['deriveBits'] : ['sign'],
//       ext: true,
//       crv: curve,
//       x: base64urlnopad.encode(noble.getPublicKey(key)),
//       d: base64urlnopad.encode(key),
//       kty: 'OKP',
//     };
//     return basic;
//   }
//   const { x, y } = noble.Point.fromBytes(noble.getPublicKey(key)).toAffine();
//   const Fp = noble.Point.Fp;
//   return {
//     key_ops: ['sign', 'deriveBits'],
//     ext: true,
//     kty: 'EC',
//     crv: curve,
//     x: base64urlnopad.encode(Fp.toBytes(x)),
//     y: base64urlnopad.encode(Fp.toBytes(y)),
//     d: base64urlnopad.encode(key),
//   };
// }

const CURVES = {
  p256: { noble: p256, web: webcrypto.p256, canSign: true, canDerive: true },
  p384: { noble: p384, web: webcrypto.p384, canSign: true, canDerive: true },
  p521: { noble: p521, web: webcrypto.p521, canSign: true, canDerive: true },
  ed25519: { noble: ed25519, web: webcrypto.ed25519, canSign: true },
  ed448: { noble: ed448, web: webcrypto.ed448, canSign: true },
  x25519: { noble: x25519, web: webcrypto.x25519, canDerive: true },
  x448: { noble: x448, web: webcrypto.x448, canDerive: true },
};

const MSG = new Uint8Array([1, 2, 3]);
describe('webcrypto', () => {
  const isDeno = process?.versions?.deno;
  const isBun = process?.versions?.bun;
  for (const c in CURVES) {
    if (['ed25519', 'x25519', 'ed448', 'x448'].includes(c) && isBun) return;
    if (['ed448', 'x448', 'p521'].includes(c) && isDeno) return;
    describe(c, () => {
      const { noble, web, canDerive, canSign } = CURVES[c];
      for (const keyType of ['raw', 'pkcs8', 'spki', 'jwk']) {
        should(keyType, async () => {
          // Basic
          deepStrictEqual(await web.isSupported(), true);
          // Keygen
          const formatSec = keyType === 'spki' ? 'raw' : keyType;
          const formatPub = keyType === 'pkcs8' ? 'raw' : keyType;
          const randomWeb = await web.utils.randomSecretKey(formatSec);
          const randomNoble = noble.utils.randomSecretKey();
          const randomNobleConverted = await web.utils.convertSecretKey(
            randomNoble,
            'raw',
            formatSec
          );
          const randomNoblePub = await web.getPublicKey(randomNobleConverted, {
            formatSec: formatSec,
            formatPub: formatPub,
          });
          const publicWeb = await web.getPublicKey(randomWeb, {
            formatSec: formatSec,
            formatPub: formatPub,
          });
          const rawPrivWeb = await web.utils.convertSecretKey(randomWeb, formatSec, 'raw');
          const rawPubWeb = await web.utils.convertPublicKey(publicWeb, formatPub, 'raw');
          deepStrictEqual(rawPubWeb, noble.getPublicKey(rawPrivWeb, false));
          deepStrictEqual(
            await web.getPublicKey(randomNobleConverted, {
              formatSec: formatSec,
              formatPub: 'raw',
            }),
            noble.getPublicKey(randomNoble, false)
          );
          deepStrictEqual(
            await web.utils.convertPublicKey(randomNoblePub, formatPub, 'raw'),
            noble.getPublicKey(randomNoble, false)
          );
          // Sign
          if (canSign) {
            const sigWeb = await web.sign(MSG, randomWeb, { formatSec });
            const sigNoble = noble.sign(MSG, randomNoble);
            deepStrictEqual(await web.verify(sigWeb, MSG, publicWeb, { formatPub }), true);
            deepStrictEqual(await web.verify(sigNoble, MSG, randomNoblePub, { formatPub }), true);
            deepStrictEqual(noble.verify(sigWeb, MSG, rawPubWeb, { lowS: false }), true);
          }
          // Get shared secret
          if (canDerive && formatSec === formatPub) {
            const webShared = await web.getSharedSecret(randomWeb, randomNoblePub, {
              formatSec,
              formatPub,
            });
            const nobleShared = noble.getSharedSecret(rawPrivWeb, noble.getPublicKey(randomNoble));
            deepStrictEqual(
              c === 'x25519' || c === 'x448' ? nobleShared : nobleShared.slice(1),
              webShared
            );
          }
        });
      }
    });
  }

  should('wrapECDSA utils convert ECDH-flavored JWK secret keys', async () => {
    const secretKey = Uint8Array.from([
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
      27, 28, 29, 30, 31, 32,
    ]);
    const peerSecretKey = Uint8Array.from([
      32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9,
      8, 7, 6, 5, 4, 3, 2, 1,
    ]);
    const ecdhJwk = {
      ...(await webcrypto.p256.utils.convertSecretKey(secretKey, 'raw', 'jwk')),
      key_ops: ['deriveBits'],
    };
    const peerPkcs8 = await webcrypto.p256.utils.convertSecretKey(peerSecretKey, 'raw', 'pkcs8');
    const peerPublicKey = await webcrypto.p256.getPublicKey(peerPkcs8, {
      formatSec: 'pkcs8',
      formatPub: 'jwk',
    });
    const shared = await webcrypto.p256.getSharedSecret(ecdhJwk, peerPublicKey, {
      formatSec: 'jwk',
      formatPub: 'jwk',
    });
    deepStrictEqual(shared.length, 32);
    deepStrictEqual(await webcrypto.p256.utils.convertSecretKey(ecdhJwk, 'jwk', 'raw'), secretKey);
  });

  should('hexToBytesLocal rejects invalid hex digits', () => {
    deepStrictEqual(webcrypto.__TEST.hexToBytesLocal('aBcD'), Uint8Array.from([0xab, 0xcd]));
    throws(() => webcrypto.__TEST.hexToBytesLocal('gg'));
    throws(() => webcrypto.__TEST.hexToBytesLocal('0x'));
  });
});

should.runWhen(import.meta.url);
