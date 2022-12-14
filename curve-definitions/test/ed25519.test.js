import { deepStrictEqual, throws } from 'assert';
import { should } from 'micro-should';
import * as fc from 'fast-check';
import { ed25519, ed25519ctx, ed25519ph, x25519, RistrettoPoint } from '../lib/ed25519.js';
import { readFileSync } from 'fs';
import { default as zip215 } from './ed25519/zip215.json' assert { type: 'json' };
import { hexToBytes, bytesToHex, randomBytes } from '@noble/hashes/utils';
import { numberToBytesLE } from '@noble/curves/utils';
import { sha512 } from '@noble/hashes/sha512';
import { default as ed25519vectors } from './wycheproof/eddsa_test.json' assert { type: 'json' };
import { default as x25519vectors } from './wycheproof/x25519_test.json' assert { type: 'json' };

const ed = ed25519;
const hex = bytesToHex;

function to32Bytes(numOrStr) {
  let hex = typeof numOrStr === 'string' ? numOrStr : numOrStr.toString(16);
  return hexToBytes(hex.padStart(64, '0'));
}

function utf8ToBytes(str) {
  if (typeof str !== 'string') {
    throw new TypeError(`utf8ToBytes expected string, got ${typeof str}`);
  }
  return new TextEncoder().encode(str);
}

ed.utils.precompute(8);

should('ed25519/should not accept >32byte private keys', () => {
  const invalidPriv =
    100000000000000000000000000000000000009000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000090000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800073278156000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n;
  throws(() => ed.getPublicKey(invalidPriv));
});
should('ed25519/should verify recent signature', () => {
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
should('ed25519/should not verify signature with wrong message', () => {
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
const msg = hexToBytes('874f9960c5d2b7a9b5fad383e1ba44719ebb743a');
const wrongMsg = hexToBytes('589d8c7f1da0a24bc07b7381ad48b1cfc211af1c');
should('ed25519/basic methods/should sign and verify', () => {
  const publicKey = ed.getPublicKey(privKey);
  const signature = ed.sign(msg, privKey);
  deepStrictEqual(ed.verify(signature, msg, publicKey), true);
});
should('ed25519/basic methods/should not verify signature with wrong public key', () => {
  const publicKey = ed.getPublicKey(12);
  const signature = ed.sign(msg, privKey);
  deepStrictEqual(ed.verify(signature, msg, publicKey), false);
});
should('ed25519/basic methods/should not verify signature with wrong hash', () => {
  const publicKey = ed.getPublicKey(privKey);
  const signature = ed.sign(msg, privKey);
  deepStrictEqual(ed.verify(signature, wrongMsg, publicKey), false);
});

should('ed25519/sync methods/should sign and verify', () => {
  const publicKey = ed.getPublicKey(privKey);
  const signature = ed.sign(msg, privKey);
  deepStrictEqual(ed.verify(signature, msg, publicKey), true);
});
should('ed25519/sync methods/should not verify signature with wrong public key', () => {
  const publicKey = ed.getPublicKey(12);
  const signature = ed.sign(msg, privKey);
  deepStrictEqual(ed.verify(signature, msg, publicKey), false);
});
should('ed25519/sync methods/should not verify signature with wrong hash', () => {
  const publicKey = ed.getPublicKey(privKey);
  const signature = ed.sign(msg, privKey);
  deepStrictEqual(ed.verify(signature, wrongMsg, publicKey), false);
});

// https://xmr.llcoins.net/addresstests.html
should(
  'ed25519/BASE_POINT.multiply()/should create right publicKey without SHA-512 hashing TEST 1',
  () => {
    const publicKey =
      ed.Point.BASE.multiply(0x90af56259a4b6bfbc4337980d5d75fbe3c074630368ff3804d33028e5dbfa77n);
    deepStrictEqual(
      publicKey.toHex(),
      '0f3b913371411b27e646b537e888f685bf929ea7aab93c950ed84433f064480d'
    );
  }
);
should(
  'ed25519/BASE_POINT.multiply()/should create right publicKey without SHA-512 hashing TEST 2',
  () => {
    const publicKey =
      ed.Point.BASE.multiply(0x364e8711a60780382a5d57b061c126f039940f28a9e91fe039d4d3094d8b88n);
    deepStrictEqual(
      publicKey.toHex(),
      'ad545340b58610f0cd62f17d55af1ab11ecde9c084d5476865ddb4dbda015349'
    );
  }
);
should(
  'ed25519/BASE_POINT.multiply()/should create right publicKey without SHA-512 hashing TEST 3',
  () => {
    const publicKey =
      ed.Point.BASE.multiply(0xb9bf90ff3abec042752cac3a07a62f0c16cfb9d32a3fc2305d676ec2d86e941n);
    deepStrictEqual(
      publicKey.toHex(),
      'e097c4415fe85724d522b2e449e8fd78dd40d20097bdc9ae36fe8ec6fe12cb8c'
    );
  }
);
should(
  'ed25519/BASE_POINT.multiply()/should create right publicKey without SHA-512 hashing TEST 4',
  () => {
    const publicKey =
      ed.Point.BASE.multiply(0x69d896f02d79524c9878e080308180e2859d07f9f54454e0800e8db0847a46en);
    deepStrictEqual(
      publicKey.toHex(),
      'f12cb7c43b59971395926f278ce7c2eaded9444fbce62ca717564cb508a0db1d'
    );
  }
);
should('ed25519/BASE_POINT.multiply()/should throw Point#multiply on TEST 5', () => {
  for (const num of [0n, 0, -1n, -1, 1.1]) {
    throws(() => ed.Point.BASE.multiply(num));
  }
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
    deepStrictEqual(pub, ed.Point.fromHex(pub).toRawBytes());

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

// const PRIVATE_KEY = 0xa665a45920422f9d417e4867efn;
// const MESSAGE = ripemd160(new Uint8Array([97, 98, 99, 100, 101, 102, 103]));
// prettier-ignore
// const MESSAGE = new Uint8Array([
//   135, 79, 153, 96, 197, 210, 183, 169, 181, 250, 211, 131, 225, 186, 68, 113, 158, 187, 116, 58,
// ]);
// const WRONG_MESSAGE = ripemd160(new Uint8Array([98, 99, 100, 101, 102, 103]));
// prettier-ignore
// const WRONG_MESSAGE = new Uint8Array([
//   88, 157, 140, 127, 29, 160, 162, 75, 192, 123, 115, 129, 173, 72, 177, 207, 194, 17, 175, 28,
// ]);
// // it("should verify just signed message", async () => {
// //   await fc.assert(fc.asyncProperty(
// //     fc.hexa(),
// //     fc.bigInt(2n, ristretto25519.PRIME_ORDER),
// //     async (message, privateKey) => {
// //       const publicKey = await ristretto25519.getPublicKey(privateKey);
// //       const signature = await ristretto25519.sign(message, privateKey);
// //       expect(publicKey.length).toBe(32);
// //       expect(signature.length).toBe(64);
// //       expect(await ristretto25519.verify(signature, message, publicKey)).toBe(true);
// //     }),
// //    { numRuns: 1 }
// //   );
// // });
// // it("should not verify sign with wrong message", async () => {
// //   await fc.assert(fc.asyncProperty(
// //     fc.array(fc.integer(0x00, 0xff)),
// //     fc.array(fc.integer(0x00, 0xff)),
// //     fc.bigInt(2n, ristretto25519.PRIME_ORDER),
// //     async (bytes, wrongBytes, privateKey) => {
// //       const message = new Uint8Array(bytes);
// //       const wrongMessage = new Uint8Array(wrongBytes);
// //       const publicKey = await ristretto25519.getPublicKey(privateKey);
// //       const signature = await ristretto25519.sign(message, privateKey);
// //       expect(await ristretto25519.verify(signature, wrongMessage, publicKey)).toBe(
// //         bytes.toString() === wrongBytes.toString()
// //       );
// //     }),
// //    { numRuns: 1 }
// //   );
// // });
// // it("should sign and verify", async () => {
// //   const publicKey = await ristretto25519.getPublicKey(PRIVATE_KEY);
// //   const signature = await ristretto25519.sign(MESSAGE, PRIVATE_KEY);
// //   expect(await ristretto25519.verify(signature, MESSAGE, publicKey)).toBe(true);
// // });
// // it("should not verify signature with wrong public key", async () => {
// //   const publicKey = await ristretto25519.getPublicKey(12);
// //   const signature = await ristretto25519.sign(MESSAGE, PRIVATE_KEY);
// //   expect(await ristretto25519.verify(signature, MESSAGE, publicKey)).toBe(false);
// // });
// // it("should not verify signature with wrong hash", async () => {
// //   const publicKey = await ristretto25519.getPublicKey(PRIVATE_KEY);
// //   const signature = await ristretto25519.sign(MESSAGE, PRIVATE_KEY);
// //   expect(await ristretto25519.verify(signature, WRONG_MESSAGE, publicKey)).toBe(false);
// // });
should('ristretto255/should follow the byte encodings of small multiples', () => {
  const encodingsOfSmallMultiples = [
    // This is the identity point
    '0000000000000000000000000000000000000000000000000000000000000000',
    // This is the basepoint
    'e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76',
    // These are small multiples of the basepoint
    '6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919',
    '94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259',
    'da80862773358b466ffadfe0b3293ab3d9fd53c5ea6c955358f568322daf6a57',
    'e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e',
    'f64746d3c92b13050ed8d80236a7f0007c3b3f962f5ba793d19a601ebb1df403',
    '44f53520926ec81fbd5a387845beb7df85a96a24ece18738bdcfa6a7822a176d',
    '903293d8f2287ebe10e2374dc1a53e0bc887e592699f02d077d5263cdd55601c',
    '02622ace8f7303a31cafc63f8fc48fdc16e1c8c8d234b2f0d6685282a9076031',
    '20706fd788b2720a1ed2a5dad4952b01f413bcf0e7564de8cdc816689e2db95f',
    'bce83f8ba5dd2fa572864c24ba1810f9522bc6004afe95877ac73241cafdab42',
    'e4549ee16b9aa03099ca208c67adafcafa4c3f3e4e5303de6026e3ca8ff84460',
    'aa52e000df2e16f55fb1032fc33bc42742dad6bd5a8fc0be0167436c5948501f',
    '46376b80f409b29dc2b5f6f0c52591990896e5716f41477cd30085ab7f10301e',
    'e0c418f7c8d9c4cdd7395b93ea124f3ad99021bb681dfc3302a9d99a2e53e64e',
  ];
  let B = RistrettoPoint.BASE;
  let P = RistrettoPoint.ZERO;
  for (const encoded of encodingsOfSmallMultiples) {
    deepStrictEqual(P.toHex(), encoded);
    deepStrictEqual(RistrettoPoint.fromHex(encoded).toHex(), encoded);
    P = P.add(B);
  }
});
should('ristretto255/should not convert bad bytes encoding', () => {
  const badEncodings = [
    // These are all bad because they're non-canonical field encodings.
    '00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    'f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    // These are all bad because they're negative field elements.
    '0100000000000000000000000000000000000000000000000000000000000000',
    '01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    'ed57ffd8c914fb201471d1c3d245ce3c746fcbe63a3679d51b6a516ebebe0e20',
    'c34c4e1826e5d403b78e246e88aa051c36ccf0aafebffe137d148a2bf9104562',
    'c940e5a4404157cfb1628b108db051a8d439e1a421394ec4ebccb9ec92a8ac78',
    '47cfc5497c53dc8e61c91d17fd626ffb1c49e2bca94eed052281b510b1117a24',
    'f1c6165d33367351b0da8f6e4511010c68174a03b6581212c71c0e1d026c3c72',
    '87260f7a2f12495118360f02c26a470f450dadf34a413d21042b43b9d93e1309',
    // These are all bad because they give a nonsquare x^2.
    '26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371',
    '4eac077a713c57b4f4397629a4145982c661f48044dd3f96427d40b147d9742f',
    'de6a7b00deadc788eb6b6c8d20c0ae96c2f2019078fa604fee5b87d6e989ad7b',
    'bcab477be20861e01e4a0e295284146a510150d9817763caf1a6f4b422d67042',
    '2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08',
    'f4a9e534fc0d216c44b218fa0c42d99635a0127ee2e53c712f70609649fdff22',
    '8268436f8c4126196cf64b3c7ddbda90746a378625f9813dd9b8457077256731',
    '2810e5cbc2cc4d4eece54f61c6f69758e289aa7ab440b3cbeaa21995c2f4232b',
    // These are all bad because they give a negative xy value.
    '3eb858e78f5a7254d8c9731174a94f76755fd3941c0ac93735c07ba14579630e',
    'a45fdc55c76448c049a1ab33f17023edfb2be3581e9c7aade8a6125215e04220',
    'd483fe813c6ba647ebbfd3ec41adca1c6130c2beeee9d9bf065c8d151c5f396e',
    '8a2e1d30050198c65a54483123960ccc38aef6848e1ec8f5f780e8523769ba32',
    '32888462f8b486c68ad7dd9610be5192bbeaf3b443951ac1a8118419d9fa097b',
    '227142501b9d4355ccba290404bde41575b037693cef1f438c47f8fbf35d1165',
    '5c37cc491da847cfeb9281d407efc41e15144c876e0170b499a96a22ed31e01e',
    '445425117cb8c90edcbc7c1cc0e74f747f2c1efa5630a967c64f287792a48a4b',
    // This is s = -1, which causes y = 0.
    'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  ];
  for (const badBytes of badEncodings) {
    const b = hexToBytes(badBytes);
    throws(() => RistrettoPoint.fromHex(b), badBytes);
  }
});
should('ristretto255/should create right points from uniform hash', async () => {
  const labels = [
    'Ristretto is traditionally a short shot of espresso coffee',
    'made with the normal amount of ground coffee but extracted with',
    'about half the amount of water in the same amount of time',
    'by using a finer grind.',
    'This produces a concentrated shot of coffee per volume.',
    'Just pulling a normal shot short will produce a weaker shot',
    'and is not a Ristretto as some believe.',
  ];
  const encodedHashToPoints = [
    '3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46',
    'f26e5b6f7d362d2d2a94c5d0e7602cb4773c95a2e5c31a64f133189fa76ed61b',
    '006ccd2a9e6867e6a2c5cea83d3302cc9de128dd2a9a57dd8ee7b9d7ffe02826',
    'f8f0c87cf237953c5890aec3998169005dae3eca1fbb04548c635953c817f92a',
    'ae81e7dedf20a497e10c304a765c1767a42d6e06029758d2d7e8ef7cc4c41179',
    'e2705652ff9f5e44d3e841bf1c251cf7dddb77d140870d1ab2ed64f1a9ce8628',
    '80bd07262511cdde4863f8a7434cef696750681cb9510eea557088f76d9e5065',
  ];

  for (let i = 0; i < labels.length; i++) {
    const hash = sha512(utf8ToBytes(labels[i]));
    const point = RistrettoPoint.hashToCurve(hash);
    deepStrictEqual(point.toHex(), encodedHashToPoints[i]);
  }
});

should('input immutability: sign/verify are immutable', () => {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = ed.getPublicKey(privateKey);

  for (let i = 0; i < 100; i++) {
    let payload = randomBytes(100);
    let signature = ed.sign(payload, privateKey);
    if (!ed.verify(signature, payload, publicKey)) {
      throw new Error('Signature verification failed');
    }
    const signatureCopy = Buffer.alloc(signature.byteLength);
    signatureCopy.set(signature, 0); // <-- breaks
    payload = payload.slice();
    signature = signature.slice();

    if (!ed.verify(signatureCopy, payload, publicKey))
      throw new Error('Copied signature verification failed');
  }
});

// https://zips.z.cash/zip-0215
// Vectors from https://gist.github.com/hdevalence/93ed42d17ecab8e42138b213812c8cc7
should('ZIP-215 compliance tests/should pass all of them', () => {
  const str = utf8ToBytes('Zcash');
  for (let v of zip215) {
    let noble = false;
    try {
      noble = ed.verify(v.sig_bytes, str, v.vk_bytes);
    } catch (e) {
      noble = false;
    }
    deepStrictEqual(noble, v.valid_zip215);
  }
});
should('ZIP-215 compliance tests/disallows sig.s >= CURVE.n', () => {
  const sig = new ed.Signature(ed.Point.BASE, 1n);
  sig.s = ed.CURVE.n + 1n;
  throws(() => ed.verify(sig, 'deadbeef', ed.Point.BASE));
});

const rfc7748Mul = [
  {
    scalar: 'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4',
    u: 'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c',
    outputU: 'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552',
  },
  {
    scalar: '4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d',
    u: 'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493',
    outputU: '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957',
  },
];
for (let i = 0; i < rfc7748Mul.length; i++) {
  const v = rfc7748Mul[i];
  should(`RFC7748: scalarMult (${i})`, () => {
    deepStrictEqual(hex(x25519.scalarMult(v.u, v.scalar)), v.outputU);
  });
}

const rfc7748Iter = [
  { scalar: '422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079', iters: 1 },
  { scalar: '684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51', iters: 1000 },
  // { scalar: '7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424', iters: 1000000 },
];
for (let i = 0; i < rfc7748Iter.length; i++) {
  const { scalar, iters } = rfc7748Iter[i];
  should(`RFC7748: scalarMult iteration (${i})`, () => {
    let k = x25519.Gu;
    for (let i = 0, u = k; i < iters; i++) [k, u] = [x25519.scalarMult(u, k), k];
    deepStrictEqual(hex(k), scalar);
  });
}

should('RFC7748 getSharedKey', () => {
  const alicePrivate = '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a';
  const alicePublic = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a';
  const bobPrivate = '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb';
  const bobPublic = 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f';
  const shared = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742';
  deepStrictEqual(alicePublic, hex(x25519.getPublicKey(alicePrivate)));
  deepStrictEqual(bobPublic, hex(x25519.getPublicKey(bobPrivate)));
  deepStrictEqual(hex(x25519.scalarMult(bobPublic, alicePrivate)), shared);
  deepStrictEqual(hex(x25519.scalarMult(alicePublic, bobPrivate)), shared);
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
//     hex(ed.montgomeryCurve.UfromPoint(ed.Point.BASE)),
//     ed.montgomeryCurve.BASE_POINT_U
//   );
// });

{
  const group = x25519vectors.testGroups[0];
  should(`Wycheproof/X25519`, () => {
    for (let i = 0; i < group.tests.length; i++) {
      const v = group.tests[i];
      const comment = `(${i}, ${v.result}) ${v.comment}`;
      if (v.result === 'valid' || v.result === 'acceptable') {
        try {
          const shared = hex(x25519.scalarMult(v.public, v.private));
          deepStrictEqual(shared, v.shared, comment);
        } catch (e) {
          // We are more strict
          if (e.message.includes('Expected valid scalar')) return;
          if (e.message.includes('Invalid private or public key received')) return;
          throw e;
        }
      } else if (v.result === 'invalid') {
        let failed = false;
        try {
          x25519.scalarMult(v.public, v.private);
        } catch (error) {
          failed = true;
        }
        deepStrictEqual(failed, true, comment);
      } else throw new Error('unknown test result');
    }
  });
}

should(`Wycheproof/ED25519`, () => {
  for (let g = 0; g < ed25519vectors.testGroups.length; g++) {
    const group = ed25519vectors.testGroups[g];
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

should('Property test issue #1', () => {
  const message = new Uint8Array([12, 12, 12]);
  const signature = ed.sign(message, to32Bytes(1n));
  const publicKey = ed.getPublicKey(to32Bytes(1n)); // <- was 1n
  deepStrictEqual(ed.verify(signature, message, publicKey), true);
});

const VECTORS_RFC8032_CTX = [
  {
    secretKey: '0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6',
    publicKey: 'dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292',
    message: 'f726936d19c800494e3fdaff20b276a8',
    context: '666f6f',
    signature:
      '55a4cc2f70a54e04288c5f4cd1e45a7b' +
      'b520b36292911876cada7323198dd87a' +
      '8b36950b95130022907a7fb7c4e9b2d5' +
      'f6cca685a587b4b21f4b888e4e7edb0d',
  },
  {
    secretKey: '0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6',
    publicKey: 'dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292',
    message: 'f726936d19c800494e3fdaff20b276a8',
    context: '626172',
    signature:
      'fc60d5872fc46b3aa69f8b5b4351d580' +
      '8f92bcc044606db097abab6dbcb1aee3' +
      '216c48e8b3b66431b5b186d1d28f8ee1' +
      '5a5ca2df6668346291c2043d4eb3e90d',
  },
  {
    secretKey: '0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6',
    publicKey: 'dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292',
    message: '508e9e6882b979fea900f62adceaca35',
    context: '666f6f',
    signature:
      '8b70c1cc8310e1de20ac53ce28ae6e72' +
      '07f33c3295e03bb5c0732a1d20dc6490' +
      '8922a8b052cf99b7c4fe107a5abb5b2c' +
      '4085ae75890d02df26269d8945f84b0b',
  },
  {
    secretKey: 'ab9c2853ce297ddab85c993b3ae14bcad39b2c682beabc27d6d4eb20711d6560',
    publicKey: '0f1d1274943b91415889152e893d80e93275a1fc0b65fd71b4b0dda10ad7d772',
    message: 'f726936d19c800494e3fdaff20b276a8',
    context: '666f6f',
    signature:
      '21655b5f1aa965996b3f97b3c849eafb' +
      'a922a0a62992f73b3d1b73106a84ad85' +
      'e9b86a7b6005ea868337ff2d20a7f5fb' +
      'd4cd10b0be49a68da2b2e0dc0ad8960f',
  },
];

for (let i = 0; i < VECTORS_RFC8032_CTX.length; i++) {
  const v = VECTORS_RFC8032_CTX[i];
  should(`RFC8032ctx/${i}`, () => {
    deepStrictEqual(hex(ed25519ctx.getPublicKey(v.secretKey)), v.publicKey);
    deepStrictEqual(hex(ed25519ctx.sign(v.message, v.secretKey, v.context)), v.signature);
    deepStrictEqual(ed25519ctx.verify(v.signature, v.message, v.publicKey, v.context), true);
  });
}

const VECTORS_RFC8032_PH = [
  {
    secretKey: '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42',
    publicKey: 'ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf',
    message: '616263',
    signature:
      '98a70222f0b8121aa9d30f813d683f80' +
      '9e462b469c7ff87639499bb94e6dae41' +
      '31f85042463c2a355a2003d062adf5aa' +
      'a10b8c61e636062aaad11c2a26083406',
  },
];

for (let i = 0; i < VECTORS_RFC8032_PH.length; i++) {
  const v = VECTORS_RFC8032_PH[i];
  should(`RFC8032ph/${i}`, () => {
    deepStrictEqual(hex(ed25519ph.getPublicKey(v.secretKey)), v.publicKey);
    deepStrictEqual(hex(ed25519ph.sign(v.message, v.secretKey)), v.signature);
    deepStrictEqual(ed25519ph.verify(v.signature, v.message, v.publicKey), true);
  });
}

should('X25519 base point', () => {
  const { y } = ed25519.Point.BASE;
  const u = ed25519.utils.mod((y + 1n) * ed25519.utils.invert(1n - y, ed25519.CURVE.P));
  deepStrictEqual(hex(numberToBytesLE(u, 32)), x25519.Gu);
});

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
