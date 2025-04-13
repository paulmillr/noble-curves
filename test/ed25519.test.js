import { bytesToHex, concatBytes, hexToBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils';
import * as fc from 'fast-check';
import { describe, should } from 'micro-should';
import { deepStrictEqual, strictEqual, throws } from 'node:assert';
import { readFileSync } from 'node:fs';
import { ed25519 as ed, ED25519_TORSION_SUBGROUP, numberToBytesLE } from './ed25519.helpers.js';
import { json } from './utils.js';
// Old vectors allow to test sign() because they include private key
const ed25519vectors_OLD = json('./ed25519/ed25519_test_OLD.json');
const ed25519vectors = json('./wycheproof/ed25519_test.json');
const zip215 = json('./ed25519/zip215.json');
const edgeCases = json('./ed25519/edge-cases.json');

// Any changes to the file will need to be aware of the fact
// the file is shared between noble-curves and noble-ed25519.

describe('ed25519', () => {
  const hex = bytesToHex;
  const Point = ed.ExtendedPoint;

  function to32Bytes(numOrStr) {
    let hex = typeof numOrStr === 'string' ? numOrStr : numOrStr.toString(16);
    return hexToBytes(hex.padStart(64, '0'));
  }

  ed.utils.precompute(8);

  should('not accept >32byte private keys', () => {
    const invalidPriv =
      100000000000000000000000000000000000009000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000090000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800073278156000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n;
    throws(() => ed.getPublicKey(invalidPriv));
  });
  should('not accept >32byte private keys in Uint8Array format', () => {
    const invalidPriv = new Uint8Array(33).fill(1);
    throws(() => ed.getPublicKey(invalidPriv));
  });
  should('verify recent signature', () => {
    fc.assert(
      fc.property(
        fc.hexaString({ minLength: 2, maxLength: 32 }),
        fc.bigInt(2n, ed.CURVE.n),
        (message, privateKey) => {
          const publicKey = ed.getPublicKey(to32Bytes(privateKey));
          const signature = ed.sign(to32Bytes(message), to32Bytes(privateKey));
          deepStrictEqual(publicKey.length, 32);
          deepStrictEqual(signature.length, 64);
          deepStrictEqual(ed.verify(signature, to32Bytes(message), publicKey), true);
        }
      ),
      { numRuns: 5 }
    );
  });
  should('not verify signature with wrong message', () => {
    fc.assert(
      fc.property(
        fc.array(fc.integer({ min: 0x00, max: 0xff })),
        fc.array(fc.integer({ min: 0x00, max: 0xff })),
        fc.bigInt(1n, ed.CURVE.n),
        (bytes, wrongBytes, privateKey) => {
          const privKey = to32Bytes(privateKey);
          const message = new Uint8Array(bytes);
          const wrongMessage = new Uint8Array(wrongBytes);
          const publicKey = ed.getPublicKey(privKey);
          const signature = ed.sign(message, privKey);
          deepStrictEqual(
            ed.verify(signature, wrongMessage, publicKey),
            bytes.toString() === wrongBytes.toString()
          );
        }
      ),
      { numRuns: 5 }
    );
  });
  const privKey = to32Bytes('a665a45920422f9d417e4867ef');
  const wrongPriv = to32Bytes('a675a45920422f9d417e4867ef');
  const msg = hexToBytes('874f9960c5d2b7a9b5fad383e1ba44719ebb743a');
  const wrongMsg = hexToBytes('589d8c7f1da0a24bc07b7381ad48b1cfc211af1c');
  describe('basic methods', () => {
    should('sign and verify', () => {
      const publicKey = ed.getPublicKey(privKey);
      const signature = ed.sign(msg, privKey);
      deepStrictEqual(ed.verify(signature, msg, publicKey), true);
    });
  });
  describe('sync methods', () => {
    should('sign and verify', () => {
      const publicKey = ed.getPublicKey(privKey);
      const signature = ed.sign(msg, privKey);
      deepStrictEqual(ed.verify(signature, msg, publicKey), true);
    });
    should('not verify signature with wrong public key', () => {
      const publicKey = ed.getPublicKey(wrongPriv);
      const signature = ed.sign(msg, privKey);
      deepStrictEqual(ed.verify(signature, msg, publicKey), false);
    });
    should('not verify signature with wrong hash', () => {
      const publicKey = ed.getPublicKey(privKey);
      const signature = ed.sign(msg, privKey);
      deepStrictEqual(ed.verify(signature, wrongMsg, publicKey), false);
    });
  });
  describe('BASE_POINT.multiply()', () => {
    // https://xmr.llcoins.net/addresstests.html
    should('create right publicKey without SHA-512 hashing TEST 1', () => {
      const publicKey =
        Point.BASE.multiply(0x90af56259a4b6bfbc4337980d5d75fbe3c074630368ff3804d33028e5dbfa77n);
      deepStrictEqual(
        publicKey.toHex(),
        '0f3b913371411b27e646b537e888f685bf929ea7aab93c950ed84433f064480d'
      );
    });
    should('create right publicKey without SHA-512 hashing TEST 2', () => {
      const publicKey =
        Point.BASE.multiply(0x364e8711a60780382a5d57b061c126f039940f28a9e91fe039d4d3094d8b88n);
      deepStrictEqual(
        publicKey.toHex(),
        'ad545340b58610f0cd62f17d55af1ab11ecde9c084d5476865ddb4dbda015349'
      );
    });
    should('create right publicKey without SHA-512 hashing TEST 3', () => {
      const publicKey =
        Point.BASE.multiply(0xb9bf90ff3abec042752cac3a07a62f0c16cfb9d32a3fc2305d676ec2d86e941n);
      deepStrictEqual(
        publicKey.toHex(),
        'e097c4415fe85724d522b2e449e8fd78dd40d20097bdc9ae36fe8ec6fe12cb8c'
      );
    });
    should('create right publicKey without SHA-512 hashing TEST 4', () => {
      const publicKey =
        Point.BASE.multiply(0x69d896f02d79524c9878e080308180e2859d07f9f54454e0800e8db0847a46en);
      deepStrictEqual(
        publicKey.toHex(),
        'f12cb7c43b59971395926f278ce7c2eaded9444fbce62ca717564cb508a0db1d'
      );
    });
    should('throw Point#multiply on TEST 5', () => {
      for (const num of [0n, 0, -1n, -1, 1.1]) {
        throws(() => Point.BASE.multiply(num));
      }
    });
  });

  // https://ed25519.cr.yp.to/python/sign.py
  // https://ed25519.cr.yp.to/python/sign.input
  const data = readFileSync('./test/ed25519/vectors.txt', 'utf-8');
  const vectors = data
    .trim()
    .split('\n')
    .map((line) => line.split(':'));
  should('ed25519 official vectors/should match 1024 official vectors', () => {
    for (let i = 0; i < vectors.length; i++) {
      const vector = vectors[i];
      // Extract.
      const priv = vector[0].slice(0, 64);
      const expectedPub = vector[1];
      const msg = vector[2];
      const expectedSignature = vector[3].slice(0, 128);

      // Calculate
      const pub = ed.getPublicKey(to32Bytes(priv));
      deepStrictEqual(hex(pub), expectedPub);
      deepStrictEqual(pub, Point.fromHex(pub).toRawBytes());

      const signature = hex(ed.sign(msg, priv));
      // console.log('vector', i);
      // expect(pub).toBe(expectedPub);
      deepStrictEqual(signature, expectedSignature);
    }
  });

  // https://tools.ietf.org/html/rfc8032#section-7
  should('rfc8032 vectors/should create right signature for 0x9d and empty string', () => {
    const privateKey = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
    const publicKey = ed.getPublicKey(privateKey);
    const message = '';
    const signature = ed.sign(message, privateKey);
    deepStrictEqual(
      hex(publicKey),
      'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
    );
    deepStrictEqual(
      hex(signature),
      'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'
    );
  });
  should('rfc8032 vectors/should create right signature for 0x4c and 72', () => {
    const privateKey = '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb';
    const publicKey = ed.getPublicKey(privateKey);
    const message = '72';
    const signature = ed.sign(message, privateKey);
    deepStrictEqual(
      hex(publicKey),
      '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'
    );
    deepStrictEqual(
      hex(signature),
      '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'
    );
  });
  should('rfc8032 vectors/should create right signature for 0x00 and 5a', () => {
    const privateKey = '002fdd1f7641793ab064bb7aa848f762e7ec6e332ffc26eeacda141ae33b1783';
    const publicKey = ed.getPublicKey(privateKey);
    const message =
      '5ac1dfc324f43e6cb79a87ab0470fa857b51fb944982e19074ca44b1e40082c1d07b92efa7ea55ad42b7c027e0b9e33756d95a2c1796a7c2066811dc41858377d4b835c1688d638884cd2ad8970b74c1a54aadd27064163928a77988b24403aa85af82ceab6b728e554761af7175aeb99215b7421e4474c04d213e01ff03e3529b11077cdf28964b8c49c5649e3a46fa0a09dcd59dcad58b9b922a83210acd5e65065531400234f5e40cddcf9804968e3e9ac6f5c44af65001e158067fc3a660502d13fa8874fa93332138d9606bc41b4cee7edc39d753dae12a873941bb357f7e92a4498847d6605456cb8c0b425a47d7d3ca37e54e903a41e6450a35ebe5237c6f0c1bbbc1fd71fb7cd893d189850295c199b7d88af26bc8548975fda1099ffefee42a52f3428ddff35e0173d3339562507ac5d2c45bbd2c19cfe89b';
    const signature = ed.sign(message, privateKey);
    deepStrictEqual(
      hex(publicKey),
      '77d1d8ebacd13f4e2f8a40e28c4a63bc9ce3bfb69716334bcb28a33eb134086c'
    );
    deepStrictEqual(
      hex(signature),
      '0df3aa0d0999ad3dc580378f52d152700d5b3b057f56a66f92112e441e1cb9123c66f18712c87efe22d2573777296241216904d7cdd7d5ea433928bd2872fa0c'
    );
  });
  should('rfc8032 vectors/should create right signature for 0xf5 and long msg', () => {
    const privateKey = 'f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5';
    const publicKey = ed.getPublicKey(privateKey);
    const message =
      '08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0';
    const signature = ed.sign(message, privateKey);
    deepStrictEqual(
      hex(publicKey),
      '278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e'
    );
    deepStrictEqual(
      hex(signature),
      '0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03'
    );
  });

  should('input immutability: sign/verify are immutable', () => {
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

  // https://zips.z.cash/zip-0215
  // Vectors from https://gist.github.com/hdevalence/93ed42d17ecab8e42138b213812c8cc7
  describe('ZIP215', () => {
    should('pass all compliance tests', () => {
      const str = utf8ToBytes('Zcash');
      for (let v of zip215) {
        let noble = false;
        try {
          noble = ed.verify(v.sig_bytes, str, v.vk_bytes);
        } catch (e) {
          noble = false;
        }
        deepStrictEqual(noble, v.valid_zip215, JSON.stringify(v));
      }
    });
    should('disallow sig.s >= CURVE.n', () => {
      // sig.R = BASE, sig.s = N+1
      const sig =
        '5866666666666666666666666666666666666666666666666666666666666666eed3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010';
      throws(() => {
        deepStrictEqual(ed.verify(sig, 'deadbeef', Point.BASE), false);
      });
      deepStrictEqual(ed.verify(sig, 'be'.repeat(64), Point.BASE.toRawBytes()), false);
    });
  });

  // should('X25519/getSharedSecret() should be commutative', () => {
  //   for (let i = 0; i < 512; i++) {
  //     const asec = ed.utils.randomPrivateKey();
  //     const apub = ed.getPublicKey(asec);
  //     const bsec = ed.utils.randomPrivateKey();
  //     const bpub = ed.getPublicKey(bsec);
  //     try {
  //       deepStrictEqual(ed.getSharedSecret(asec, bpub), ed.getSharedSecret(bsec, apub));
  //     } catch (error) {
  //       console.error('not commutative', { asec, apub, bsec, bpub });
  //       throw error;
  //     }
  //   }
  // });

  // should('X25519: should convert base point to montgomery using fromPoint', () => {
  //   deepStrictEqual(
  //     hex(ed.montgomeryCurve.UfromPoint(Point.BASE)),
  //     ed.montgomeryCurve.BASE_POINT_U
  //   );
  // });

  should('wycheproof/ED25519 (OLD)', () => {
    for (let g = 0; g < ed25519vectors_OLD.testGroups.length; g++) {
      const group = ed25519vectors_OLD.testGroups[g];
      const key = group.key;
      deepStrictEqual(hex(ed.getPublicKey(key.sk)), key.pk, `(${g}, public)`);
      for (let i = 0; i < group.tests.length; i++) {
        const v = group.tests[i];
        const comment = `(${g}/${i}, ${v.result}): ${v.comment}`;
        if (v.result === 'valid' || v.result === 'acceptable') {
          deepStrictEqual(hex(ed.sign(v.msg, key.sk)), v.sig, comment);
          deepStrictEqual(ed.verify(v.sig, v.msg, key.pk), true, comment);
        } else if (v.result === 'invalid') {
          let failed = false;
          try {
            failed = !ed.verify(v.sig, v.msg, key.pk);
          } catch (error) {
            failed = true;
          }
          deepStrictEqual(failed, true, comment);
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
          deepStrictEqual(ed.verify(v.sig, v.msg, key.pk), true, comment);
        } else if (v.result === 'invalid') {
          let failed = false;
          try {
            failed = !ed.verify(v.sig, v.msg, key.pk);
          } catch (error) {
            failed = true;
          }
          deepStrictEqual(failed, true, comment);
        } else throw new Error('unknown test result');
      }
    }
  });

  should('not mutate inputs', () => {
    const message = new Uint8Array([12, 12, 12]);
    const signature = ed.sign(message, to32Bytes(1n));
    const publicKey = ed.getPublicKey(to32Bytes(1n)); // <- was 1n
    deepStrictEqual(ed.verify(signature, message, publicKey), true);
  });

  should('isTorsionFree()', () => {
    const { point } = ed.utils.getExtendedPublicKey(ed.utils.randomPrivateKey());
    for (const hex of ED25519_TORSION_SUBGROUP.slice(1)) {
      const dirty = point.add(Point.fromHex(hex));
      const cleared = dirty.clearCofactor();
      strictEqual(point.isTorsionFree(), true, `orig must be torsionFree: ${hex}`);
      strictEqual(dirty.isTorsionFree(), false, `dirty must not be torsionFree: ${hex}`);
      strictEqual(cleared.isTorsionFree(), true, `cleared must be torsionFree: ${hex}`);
    }
  });

  should('have strict SUF-CMA and SBS properties', () => {
    // https://eprint.iacr.org/2020/1244
    const list = [0, 1, 6, 7, 8, 9, 10, 11].map((i) => edgeCases[i]);
    for (let v of list) {
      const result = ed.verify(v.signature, v.message, v.pub_key, { zip215: false });
      strictEqual(result, false, `zip215: false must not validate: ${v.signature}`);
    }
  });

  should('not verify when sig.s >= CURVE.n', () => {
    const privateKey = ed.utils.randomPrivateKey();
    const message = Uint8Array.from([0xab, 0xbc, 0xcd, 0xde]);
    const publicKey = ed.getPublicKey(privateKey);
    const signature = ed.sign(message, privateKey);

    const R = signature.slice(0, 32);
    let s = signature.slice(32, 64);

    s = bytesToHex(s.slice().reverse());
    s = BigInt('0x' + s);
    s = s + ed.CURVE.n;
    s = numberToBytesLE(s, 32);

    const sig_invalid = concatBytes(R, s);
    deepStrictEqual(ed.verify(sig_invalid, message, publicKey), false);
  });

  should('not accept point without z, t', () => {
    const t = 81718630521762619991978402609047527194981150691135404693881672112315521837062n;
    const point = Point.fromAffine({ x: t, y: t });
    throws(() => point.assertValidity());
    // Otherwise (without assertValidity):
    // const point2 = point.double();
    // point2.toAffine(); // crash!
  });

  should('have roundtrip of ZERO Point from / to affine', () => {
    const xy = { x: 0n, y: 1n };
    const p = Point.fromAffine(xy);
    deepStrictEqual(p, Point.ZERO);
    deepStrictEqual(p.toAffine(), xy);
  });

  should('not accept point with z=0', () => {
    throws(() => new ed.ExtendedPoint(0n, 0n, 0n, 0n));

    const zeros = ed.ExtendedPoint.fromAffine({ x: 0n, y: 0n });
    deepStrictEqual(zeros.equals(ed.ExtendedPoint.BASE.multiply(3n)), false);

    const key = ed.utils.randomPrivateKey();
    const A = ed.ExtendedPoint.fromHex(ed.getPublicKey(key));
    const T = ed.ExtendedPoint.fromHex(ED25519_TORSION_SUBGROUP[2]);
    // console.log('A', A);
    // console.log('T', T);
    // console.log('add2', A.add(T).add(A));
    // console.log('add2 aff', A.add(T).add(A).toAffine());
    const B = A.add(T).add(A);
    const C = ed.ExtendedPoint.fromHex(ed.getPublicKey(ed.utils.randomPrivateKey()));
    deepStrictEqual(B.equals(C), false);

    deepStrictEqual(
      ed.verify(
        '86d8373bf0797b5fee241605760ffebeae65d2d3395cd9afbf67b52f0198484344d9709abd414b2880485fa93a1bb98fb9af0f083c8c3b8141d71b9dfd448b0b',
        '48656c6c6f2c20576f726c6421',
        '34fe104df0a1348ef60699b3659b5a31b14a6f8488e14bfa55d2cc310959ae50'
      ),
      false
    );
  });
});

should.runWhen(import.meta.url);
