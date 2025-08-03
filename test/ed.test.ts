import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { describe, should } from 'micro-should';
import { deepStrictEqual as eql } from 'node:assert';
import { ed25519, ed25519ctx, ed25519ph, x25519 } from '../src/ed25519.ts';
import { ed448 } from '../src/ed448.ts';
import { numberToBytesLE } from '../src/utils.ts';
import { deepHexToBytes, json } from './utils.ts';

const x25519vectors = json('./vectors/wycheproof/x25519_test.json');

const VECTORS_RFC8032 = deepHexToBytes([
  {
    fn: ed25519ctx,
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
    fn: ed25519ctx,
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
    fn: ed25519ctx,
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
    fn: ed25519ctx,
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
  {
    fn: ed25519ph,
    secretKey: '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42',
    publicKey: 'ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf',
    message: '616263',
    signature:
      '98a70222f0b8121aa9d30f813d683f80' +
      '9e462b469c7ff87639499bb94e6dae41' +
      '31f85042463c2a355a2003d062adf5aa' +
      'a10b8c61e636062aaad11c2a26083406',
  },
]);

describe('RFC8032', () => {
  for (let i = 0; i < VECTORS_RFC8032.length; i++) {
    const v = VECTORS_RFC8032[i];
    should(`${i}`, () => {
      const { context } = v;
      eql(v.fn.getPublicKey(v.secretKey), v.publicKey);
      eql(v.fn.sign(v.message, v.secretKey, { context }), v.signature);
      eql(v.fn.verify(v.signature, v.message, v.publicKey, { context }), true);
    });
  }
});

// x25519
describe('X25519 RFC7748 ECDH', () => {
  const rfc7748Mul = deepHexToBytes([
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
  ]);
  for (let i = 0; i < rfc7748Mul.length; i++) {
    const v = rfc7748Mul[i];
    should(`scalarMult (${i})`, () => {
      eql(x25519.scalarMult(v.scalar, v.u), v.outputU);
    });
  }

  const rfc7748Iter = [
    { scalar: '422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079', iters: 1 },
    { scalar: '684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51', iters: 1000 },
    // last ran: 2025-04, ~10 min
    // { scalar: '7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424', iters: 1000000 },
  ];
  for (let i = 0; i < rfc7748Iter.length; i++) {
    const { scalar, iters } = rfc7748Iter[i];
    should(`scalarMult iteration x${iters}`, () => {
      let k = x25519.GuBytes;
      for (let i = 0, u = k; i < iters; i++) [k, u] = [x25519.scalarMult(k, u), k];
      eql(bytesToHex(k), scalar);
    });
  }

  should('getSharedKey', () => {
    const { alicePrivate, alicePublic, bobPrivate, bobPublic, shared } = deepHexToBytes({
      alicePrivate: '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
      alicePublic: '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
      bobPrivate: '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
      bobPublic: 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
      shared: '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742',
    });
    eql(alicePublic, x25519.getPublicKey(alicePrivate));
    eql(bobPublic, x25519.getPublicKey(bobPrivate));
    eql(x25519.scalarMult(alicePrivate, bobPublic), shared);
    eql(x25519.scalarMult(bobPrivate, alicePublic), shared);
  });

  should('X25519/getSharedSecret() should be commutative', () => {
    for (let i = 0; i < 512; i++) {
      const asec = x25519.utils.randomSecretKey();
      const apub = x25519.getPublicKey(asec);
      const bsec = x25519.utils.randomSecretKey();
      const bpub = x25519.getPublicKey(bsec);
      try {
        eql(x25519.getSharedSecret(asec, bpub), x25519.getSharedSecret(bsec, apub));
      } catch (error) {
        console.error('not commutative', { asec, apub, bsec, bpub });
        throw error;
      }
    }
  });

  describe('toMontgomery()', () => {
    should('edwardsToMontgomery should produce correct output', () => {
      const edSecret = hexToBytes(
        '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'
      );
      const edPublic = ed25519.getPublicKey(edSecret);
      const xPrivate = ed25519.utils.toMontgomeryPriv(edSecret);
      eql(bytesToHex(xPrivate), 'a8cd44eb8e93319c0570bc11005c0e0189d34ff02f6c17773411ad191293c94f');
      const xPublic = ed25519.utils.toMontgomery(edPublic);
      eql(bytesToHex(xPublic), 'ed7749b4d989f6957f3bfde6c56767e988e21c9f8784d91d610011cd553f9b06');
    });

    should('edwardsToMontgomery should produce correct keyPair', () => {
      const edSecret = ed25519.utils.randomSecretKey();
      const edPublic = ed25519.getPublicKey(edSecret);
      const xSecret = ed25519.utils.toMontgomeryPriv(edSecret);
      const expectedXPublic = x25519.getPublicKey(xSecret);
      const xPublic = ed25519.utils.toMontgomery(edPublic);
      eql(xPublic, expectedXPublic);
    });

    should('ECDH through edwardsToMontgomery should be commutative', () => {
      const edSecret1 = ed25519.utils.randomSecretKey();
      const edPublic1 = ed25519.getPublicKey(edSecret1);
      const edSecret2 = ed25519.utils.randomSecretKey();
      const edPublic2 = ed25519.getPublicKey(edSecret2);
      eql(
        x25519.getSharedSecret(
          ed25519.utils.toMontgomeryPriv(edSecret1),
          ed25519.utils.toMontgomery(edPublic2)
        ),
        x25519.getSharedSecret(
          ed25519.utils.toMontgomeryPriv(edSecret2),
          ed25519.utils.toMontgomery(edPublic1)
        )
      );
    });

    should('edwardsToMontgomery should produce correct output', () => {
      const edSecret = hexToBytes(
        '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab1'
      );
      const edPublic = ed448.getPublicKey(edSecret);
      const xPublic = ed448.utils.toMontgomery(edPublic);
      eql(
        bytesToHex(xPublic),
        'f0301c19656bce1d1cd0a474c952d196041811b63617fc8fdaacee533644e2b2d49273426c8dbb5a76033ea84fb5215b84f9ebf22bde0b0700'
      );
    });
  });

  should('base point', () => {
    const { y } = ed25519ph.Point.BASE;
    const { Fp } = ed25519ph.Point;
    const u = Fp.create((y + 1n) * Fp.inv(1n - y));
    eql(numberToBytesLE(u, 32), x25519.GuBytes);
  });

  const group = deepHexToBytes(x25519vectors.testGroups[0]);
  should('wycheproof', () => {
    group.tests.forEach((v, i) => {
      const comment = `(${i}, ${v.result}) ${v.comment}`;
      if (v.result === 'valid' || v.result === 'acceptable') {
        try {
          const shared = x25519.scalarMult(v.private, v.public);
          eql(shared, v.shared, comment);
        } catch (e) {
          // We are more strict
          if (e.message.includes('invalid private or public key received')) return;
          throw e;
        }
      } else if (v.result === 'invalid') {
        let failed = false;
        try {
          x25519.scalarMult(v.private, v.public);
        } catch (error) {
          failed = true;
        }
        eql(failed, true, comment);
      } else throw new Error('unknown test result');
    });
  });
});

should.runWhen(import.meta.url);
