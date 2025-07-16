import { describe, should } from 'micro-should';
import { deepStrictEqual } from 'node:assert';
import { ed25519, x25519 } from '../esm/ed25519.js';
import { ed448, x448 } from '../esm/ed448.js';
import { p256, p384, p521 } from '../esm/nist.js';
import * as webcrypto from '../esm/webcrypto.js';

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
          // if (!(await webcrypto.supportsWc(web))) {
          //   console.log(`skipping test, unsupported webcrypto ${c} ${keyType}`);
          //   return;
          // }
          // Basic
          deepStrictEqual(await web.isAvailable(), true);
          deepStrictEqual(await webcrypto.supportsWc(web), true);
          // Keygen
          const secFormat = keyType === 'spki' ? 'raw' : keyType;
          const pubFormat = keyType === 'pkcs8' ? 'raw' : keyType;
          const randomWeb = await web.utils.randomSecretKey(secFormat);
          const randomNoble = noble.utils.randomSecretKey();
          const randomNobleConverted = await web.utils.convertSecretKey(
            randomNoble,
            'raw',
            secFormat
          );
          const randomNoblePub = await web.getPublicKey(randomNobleConverted, {
            secFormat: secFormat,
            pubFormat,
          });
          const publicWeb = await web.getPublicKey(randomWeb, { secFormat: secFormat, pubFormat });
          const rawPrivWeb = await web.utils.convertSecretKey(randomWeb, secFormat, 'raw');
          const rawPubWeb = await web.utils.convertPublicKey(publicWeb, pubFormat, 'raw');
          deepStrictEqual(rawPubWeb, noble.getPublicKey(rawPrivWeb, false));
          deepStrictEqual(
            await web.getPublicKey(randomNobleConverted, {
              secFormat: secFormat,
              pubFormat: 'raw',
            }),
            noble.getPublicKey(randomNoble, false)
          );
          deepStrictEqual(
            await web.utils.convertPublicKey(randomNoblePub, pubFormat, 'raw'),
            noble.getPublicKey(randomNoble, false)
          );
          // Sign
          if (canSign) {
            const sigWeb = await web.sign(MSG, randomWeb, { format: secFormat });
            let sigNoble = noble.sign(MSG, randomNoble, { prehash: true });
            if (c !== 'ed25519' && c !== 'ed448') sigNoble = sigNoble.toBytes('compact');
            deepStrictEqual(await web.verify(sigWeb, MSG, publicWeb, { format: pubFormat }), true);
            deepStrictEqual(
              await web.verify(sigNoble, MSG, randomNoblePub, { format: pubFormat }),
              true
            );
            deepStrictEqual(noble.verify(sigWeb, MSG, rawPubWeb, { prehash: true }), true);
          }
          // Get shared secret
          if (canDerive && secFormat === pubFormat) {
            const webShared = await web.getSharedSecret(randomWeb, randomNoblePub, {
              format: secFormat,
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
});

should.runWhen(import.meta.url);
