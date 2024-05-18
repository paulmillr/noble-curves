import { sha512 } from '@noble/hashes/sha512';
import { bytesToHex as hex, hexToBytes } from '@noble/hashes/utils';
import { deepStrictEqual, throws } from 'node:assert';
import { describe, should } from 'micro-should';
import { bytesToNumberLE, numberToBytesLE } from '../esm/abstract/utils.js';
import { default as x25519vectors } from './wycheproof/x25519_test.json' with { type: 'json' };
import {
  ed25519,
  ed25519ctx,
  ed25519ph,
  edwardsToMontgomeryPub,
  edwardsToMontgomeryPriv,
  RistrettoPoint,
  x25519,
} from '../esm/ed25519.js';

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

describe('RFC8032ctx', () => {
  for (let i = 0; i < VECTORS_RFC8032_CTX.length; i++) {
    const v = VECTORS_RFC8032_CTX[i];
    should(`${i}`, () => {
      deepStrictEqual(hex(ed25519ctx.getPublicKey(v.secretKey)), v.publicKey);
      deepStrictEqual(
        hex(ed25519ctx.sign(v.message, v.secretKey, { context: v.context })),
        v.signature
      );
      deepStrictEqual(
        ed25519ctx.verify(v.signature, v.message, v.publicKey, { context: v.context }),
        true
      );
    });
  }
});

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

describe('RFC8032ph', () => {
  for (let i = 0; i < VECTORS_RFC8032_PH.length; i++) {
    const v = VECTORS_RFC8032_PH[i];
    should(`${i}`, () => {
      deepStrictEqual(hex(ed25519ph.getPublicKey(v.secretKey)), v.publicKey);
      deepStrictEqual(hex(ed25519ph.sign(v.message, v.secretKey)), v.signature);
      deepStrictEqual(ed25519ph.verify(v.signature, v.message, v.publicKey), true);
    });
  }
});

// x25519
describe('RFC7748 X25519 ECDH', () => {
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
    should(`scalarMult (${i})`, () => {
      deepStrictEqual(hex(x25519.scalarMult(v.scalar, v.u)), v.outputU);
    });
  }

  const rfc7748Iter = [
    { scalar: '422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079', iters: 1 },
    { scalar: '684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51', iters: 1000 },
    // { scalar: '7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424', iters: 1000000 },
  ];
  for (let i = 0; i < rfc7748Iter.length; i++) {
    const { scalar, iters } = rfc7748Iter[i];
    should(`scalarMult iteration x${iters}`, () => {
      let k = x25519.GuBytes;
      for (let i = 0, u = k; i < iters; i++) [k, u] = [x25519.scalarMult(k, u), k];
      deepStrictEqual(hex(k), scalar);
    });
  }

  should('getSharedKey', () => {
    const alicePrivate = '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a';
    const alicePublic = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a';
    const bobPrivate = '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb';
    const bobPublic = 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f';
    const shared = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742';
    deepStrictEqual(alicePublic, hex(x25519.getPublicKey(alicePrivate)));
    deepStrictEqual(bobPublic, hex(x25519.getPublicKey(bobPrivate)));
    deepStrictEqual(hex(x25519.scalarMult(alicePrivate, bobPublic)), shared);
    deepStrictEqual(hex(x25519.scalarMult(bobPrivate, alicePublic)), shared);
  });

  should('X25519/getSharedSecret() should be commutative', () => {
    for (let i = 0; i < 512; i++) {
      const asec = x25519.utils.randomPrivateKey();
      const apub = x25519.getPublicKey(asec);
      const bsec = x25519.utils.randomPrivateKey();
      const bpub = x25519.getPublicKey(bsec);
      try {
        deepStrictEqual(x25519.getSharedSecret(asec, bpub), x25519.getSharedSecret(bsec, apub));
      } catch (error) {
        console.error('not commutative', { asec, apub, bsec, bpub });
        throw error;
      }
    }
  });

  should('edwardsToMontgomery should produce correct output', () => {
    const edSecret = hexToBytes('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
    const edPublic = ed25519.getPublicKey(edSecret);
    const xPrivate = edwardsToMontgomeryPriv(edSecret);
    deepStrictEqual(
      hex(xPrivate),
      'a8cd44eb8e93319c0570bc11005c0e0189d34ff02f6c17773411ad191293c94f'
    );
    const xPublic = edwardsToMontgomeryPub(edPublic);
    deepStrictEqual(
      hex(xPublic),
      'ed7749b4d989f6957f3bfde6c56767e988e21c9f8784d91d610011cd553f9b06'
    );
  });

  should('edwardsToMontgomery should produce correct keyPair', () => {
    const edSecret = ed25519.utils.randomPrivateKey();
    const edPublic = ed25519.getPublicKey(edSecret);
    const xSecret = edwardsToMontgomeryPriv(edSecret);
    const expectedXPublic = x25519.getPublicKey(xSecret);
    const xPublic = edwardsToMontgomeryPub(edPublic);
    deepStrictEqual(xPublic, expectedXPublic);
  });

  should('ECDH through edwardsToMontgomery should be commutative', () => {
    const edSecret1 = ed25519.utils.randomPrivateKey();
    const edPublic1 = ed25519.getPublicKey(edSecret1);
    const edSecret2 = ed25519.utils.randomPrivateKey();
    const edPublic2 = ed25519.getPublicKey(edSecret2);
    deepStrictEqual(
      x25519.getSharedSecret(edwardsToMontgomeryPriv(edSecret1), edwardsToMontgomeryPub(edPublic2)),
      x25519.getSharedSecret(edwardsToMontgomeryPriv(edSecret2), edwardsToMontgomeryPub(edPublic1))
    );
  });

  should('base point', () => {
    const { y } = ed25519ph.ExtendedPoint.BASE;
    const { Fp } = ed25519ph.CURVE;
    const u = Fp.create((y + 1n) * Fp.inv(1n - y));
    deepStrictEqual(numberToBytesLE(u, 32), x25519.GuBytes);
  });

  const group = x25519vectors.testGroups[0];
  should('wycheproof', () => {
    for (let i = 0; i < group.tests.length; i++) {
      const v = group.tests[i];
      const comment = `(${i}, ${v.result}) ${v.comment}`;
      if (v.result === 'valid' || v.result === 'acceptable') {
        try {
          const shared = hex(x25519.scalarMult(v.private, v.public));
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
          x25519.scalarMult(v.private, v.public);
        } catch (error) {
          failed = true;
        }
        deepStrictEqual(failed, true, comment);
      } else throw new Error('unknown test result');
    }
  });
});

function utf8ToBytes(str) {
  if (typeof str !== 'string') {
    throw new Error(`utf8ToBytes expected string, got ${typeof str}`);
  }
  return new TextEncoder().encode(str);
}

describe('ristretto255', () => {
  should('follow the byte encodings of small multiples', () => {
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
  should('not convert bad bytes encoding', () => {
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
      // These are all bad because they give a nonsquare x².
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
  should('create right points from uniform hash', () => {
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
  should('have proper equality testing', () => {
    const MAX_255B = BigInt('0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
    const bytes255ToNumberLE = (bytes) =>
      ed25519ctx.CURVE.Fp.create(bytesToNumberLE(bytes) & MAX_255B);

    const priv = new Uint8Array([
      198, 101, 65, 165, 93, 120, 37, 238, 16, 133, 10, 35, 253, 243, 161, 246, 229, 135, 12, 137,
      202, 114, 222, 139, 146, 123, 4, 125, 152, 173, 1, 7,
    ]);
    const pub = RistrettoPoint.BASE.multiply(bytes255ToNumberLE(priv));
    deepStrictEqual(pub.equals(RistrettoPoint.ZERO), false);
  });
});

// ESM is broken.
import url from 'node:url';

if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
