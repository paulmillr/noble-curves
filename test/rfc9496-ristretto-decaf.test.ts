import { sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { describe, should } from 'micro-should';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { ed25519ctx, ristretto255, ristretto255_hasher } from '../src/ed25519.ts';
import { decaf448, decaf448_hasher, ed448 } from '../src/ed448.ts';
import { asciiToBytes, bytesToNumberLE } from '../src/utils.ts';

const RistrettoPoint = ristretto255.Point;
const DecafPoint = decaf448.Point;

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
      const enc = hexToBytes(encoded);
      eql(P.toBytes(), enc);
      eql(RistrettoPoint.fromBytes(enc).toBytes(), enc);
      eql(RistrettoPoint.fromAffine(RistrettoPoint.fromBytes(enc).ep.toAffine()).toBytes(), enc);
      eql(RistrettoPoint.fromBytes(enc).toBytes(), enc);
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
      throws(() => RistrettoPoint.fromBytes(b), badBytes);
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
      const hash = sha512(asciiToBytes(labels[i]));
      const point = ristretto255_hasher.deriveToCurve(hash);
      eql(bytesToHex(point.toBytes()), encodedHashToPoints[i]);
    }
  });
  should('uniform byte string (from RFC)', () => {
    const VECTORS = [
      {
        I:
          '5d1be09e3d0c82fc538112490e35701979d99e06ca3e2b5b54bffe8b4dc772c1' +
          '4d98b696a1bbfb5ca32c436cc61c16563790306c79eaca7705668b47dffe5bb6',
        O: '3066f82a 1a747d45 120d1740 f1435853 1a8f04bb ffe6a819 f86dfe50 f44a0a46',
      },
      {
        I:
          'f116b34b8f17ceb56e8732a60d913dd10cce47a6d53bee9204be8b44f6678b27' +
          '0102a56902e2488c46120e9276cfe54638286b9e4b3cdb470b542d46c2068d38',
        O: 'f26e5b6f 7d362d2d 2a94c5d0 e7602cb4 773c95a2 e5c31a64 f133189f a76ed61b',
      },
      {
        I:
          '8422e1bbdaab52938b81fd602effb6f89110e1e57208ad12d9ad767e2e25510c' +
          '27140775f9337088b982d83d7fcf0b2fa1edffe51952cbe7365e95c86eaf325c',
        O: '006ccd2a 9e6867e6 a2c5cea8 3d3302cc 9de128dd 2a9a57dd 8ee7b9d7 ffe02826',
      },
      {
        I:
          'ac22415129b61427bf464e17baee8db65940c233b98afce8d17c57beeb7876c2' +
          '150d15af1cb1fb824bbd14955f2b57d08d388aab431a391cfc33d5bafb5dbbaf',
        O: 'f8f0c87c f237953c 5890aec3 99816900 5dae3eca 1fbb0454 8c635953 c817f92a',
      },
      {
        I:
          '165d697a1ef3d5cf3c38565beefcf88c0f282b8e7dbd28544c483432f1cec767' +
          '5debea8ebb4e5fe7d6f6e5db15f15587ac4d4d4a1de7191e0c1ca6664abcc413',
        O: 'ae81e7de df20a497 e10c304a 765c1767 a42d6e06 029758d2 d7e8ef7c c4c41179',
      },
      {
        I:
          'a836e6c9a9ca9f1e8d486273ad56a78c70cf18f0ce10abb1c7172ddd605d7fd2' +
          '979854f47ae1ccf204a33102095b4200e5befc0465accc263175485f0e17ea5c',
        O: 'e2705652 ff9f5e44 d3e841bf 1c251cf7 dddb77d1 40870d1a b2ed64f1 a9ce8628',
      },
      {
        I:
          '2cdc11eaeb95daf01189417cdddbf95952993aa9cb9c640eb5058d09702c7462' +
          '2c9965a697a3b345ec24ee56335b556e677b30e6f90ac77d781064f866a3c982',
        O: '80bd0726 2511cdde 4863f8a7 434cef69 6750681c b9510eea 557088f7 6d9e5065',
      },
      {
        I:
          'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' +
          '1200000000000000000000000000000000000000000000000000000000000000',
        O: '30428279 1023b731 28d277bd cb5c7746 ef2eac08 dde9f298 3379cb8e 5ef0517f',
      },
      {
        I:
          'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f' +
          'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        O: '30428279 1023b731 28d277bd cb5c7746 ef2eac08 dde9f298 3379cb8e 5ef0517f',
      },
      {
        I:
          '0000000000000000000000000000000000000000000000000000000000000080' +
          'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
        O: '30428279 1023b731 28d277bd cb5c7746 ef2eac08 dde9f298 3379cb8e 5ef0517f',
      },
      {
        I:
          '0000000000000000000000000000000000000000000000000000000000000000' +
          '1200000000000000000000000000000000000000000000000000000000000080',
        O: '30428279 1023b731 28d277bd cb5c7746 ef2eac08 dde9f298 3379cb8e 5ef0517f',
      },
    ];
    for (const { I, O } of VECTORS) {
      const point = ristretto255_hasher.deriveToCurve(hexToBytes(I));
      eql(point.toHex(), O.replaceAll(' ', ''));
    }
  });
  should('have proper equality testing', () => {
    const MAX_255B = BigInt('0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
    const bytes255ToNumberLE = (bytes) =>
      ed25519ctx.Point.Fp.create(bytesToNumberLE(bytes) & MAX_255B);

    const priv = new Uint8Array([
      198, 101, 65, 165, 93, 120, 37, 238, 16, 133, 10, 35, 253, 243, 161, 246, 229, 135, 12, 137,
      202, 114, 222, 139, 146, 123, 4, 125, 152, 173, 1, 7,
    ]);
    const pub = RistrettoPoint.BASE.multiply(bytes255ToNumberLE(priv));
    eql(pub.equals(RistrettoPoint.ZERO), false);

    const pub2 = RistrettoPoint.BASE.multiplyUnsafe(bytes255ToNumberLE(priv));
    eql(pub2.equals(RistrettoPoint.ZERO), false);
    eql(pub.toBytes(), pub2.toBytes());
  });

  should('ristretto255_hasher', () => {
    const res = ristretto255_hasher.hashToCurve(new Uint8Array(10).fill(5), {
      DST: 'ristretto255_XMD:SHA-512_R255MAP_RO_',
    });
    eql(
      bytesToHex(res.toBytes()),
      'be2194e53cc014665821003f8ecf49e99b7cd16f5326e53f234ecd21c448ee6c'
    );
  });
});

describe('decaf448', () => {
  should('follow the byte encodings of small multiples', () => {
    const encodingsOfSmallMultiples = [
      // This is the identity point
      '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
      // This is the basepoint
      '6666666666666666666666666666666666666666666666666666666633333333333333333333333333333333333333333333333333333333',
      // These are small multiples of the basepoint
      'c898eb4f87f97c564c6fd61fc7e49689314a1f818ec85eeb3bd5514ac816d38778f69ef347a89fca817e66defdedce178c7cc709b2116e75',
      'a0c09bf2ba7208fda0f4bfe3d0f5b29a543012306d43831b5adc6fe7f8596fa308763db15468323b11cf6e4aeb8c18fe44678f44545a69bc',
      'b46f1836aa287c0a5a5653f0ec5ef9e903f436e21c1570c29ad9e5f596da97eeaf17150ae30bcb3174d04bc2d712c8c7789d7cb4fda138f4',
      '1c5bbecf4741dfaae79db72dface00eaaac502c2060934b6eaaeca6a20bd3da9e0be8777f7d02033d1b15884232281a41fc7f80eed04af5e',
      '86ff0182d40f7f9edb7862515821bd67bfd6165a3c44de95d7df79b8779ccf6460e3c68b70c16aaa280f2d7b3f22d745b97a89906cfc476c',
      '502bcb6842eb06f0e49032bae87c554c031d6d4d2d7694efbf9c468d48220c50f8ca28843364d70cee92d6fe246e61448f9db9808b3b2408',
      '0c9810f1e2ebd389caa789374d78007974ef4d17227316f40e578b336827da3f6b482a4794eb6a3975b971b5e1388f52e91ea2f1bcb0f912',
      '20d41d85a18d5657a29640321563bbd04c2ffbd0a37a7ba43a4f7d263ce26faf4e1f74f9f4b590c69229ae571fe37fa639b5b8eb48bd9a55',
      'e6b4b8f408c7010d0601e7eda0c309a1a42720d6d06b5759fdc4e1efe22d076d6c44d42f508d67be462914d28b8edce32e7094305164af17',
      'be88bbb86c59c13d8e9d09ab98105f69c2d1dd134dbcd3b0863658f53159db64c0e139d180f3c89b8296d0ae324419c06fa87fc7daaf34c1',
      'a456f9369769e8f08902124a0314c7a06537a06e32411f4f93415950a17badfa7442b6217434a3a05ef45be5f10bd7b2ef8ea00c431edec5',
      '186e452c4466aa4383b4c00210d52e7922dbf9771e8b47e229a9b7b73c8d10fd7ef0b6e41530f91f24a3ed9ab71fa38b98b2fe4746d51d68',
      '4ae7fdcae9453f195a8ead5cbe1a7b9699673b52c40ab27927464887be53237f7f3a21b938d40d0ec9e15b1d5130b13ffed81373a53e2b43',
      '841981c3bfeec3f60cfeca75d9d8dc17f46cf0106f2422b59aec580a58f342272e3a5e575a055ddb051390c54c24c6ecb1e0aceb075f6056',
    ];
    let B = DecafPoint.BASE;
    let P = DecafPoint.ZERO;
    for (const encoded of encodingsOfSmallMultiples) {
      const enc = hexToBytes(encoded);
      eql(P.toBytes(), enc);
      eql(bytesToHex(DecafPoint.fromBytes(enc).toBytes()), encoded);
      P = P.add(B);
    }
  });
  should('not convert bad bytes encoding', () => {
    const badEncodings = [
      // These are all bad because they're non-canonical field encodings.
      '8e24f838059ee9fef1e209126defe53dcd74ef9b6304601c6966099effffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      '86fcc7212bd4a0b980928666dc28c444a605ef38e09fb569e28d4443ffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      '866d54bd4c4ff41a55d4eefdbeca73cbd653c7bd3135b383708ec0bdffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      '4a380ccdab9c86364a89e77a464d64f9157538cfdfa686adc0d5ece4ffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      'f22d9d4c945dd44d11e0b1d3d3d358d959b4844d83b08c44e659d79fffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      '8cdffc681aa99e9c818c8ef4c3808b58e86acdef1ab68c8477af185bffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      '0e1c12ac7b5920effbd044e897c57634e2d05b5c27f8fa3df8a086a1ffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      // These are all bad because they're negative field elements.
      '15141bd2121837ef71a0016bd11be757507221c26542244f23806f3fd3496b7d4c36826276f3bf5deea2c60c4fa4cec69946876da497e795',
      '455d380238434ab740a56267f4f46b7d2eb2dd8ee905e51d7b0ae8a6cb2bae501e67df34ab21fa45946068c9f233939b1d9521a998b7cb93',
      '810b1d8e8bf3a9c023294bbfd3d905a97531709bdc0f42390feedd7010f77e98686d400c9c86ed250ceecd9de0a18888ffecda0f4ea1c60d',
      'd3af9cc41be0e5de83c0c6273bedcb9351970110044a9a41c7b9b2267cdb9d7bf4dc9c2fdb8bed32878184604f1d9944305a8df4274ce301',
      '9312bcab09009e4330ff89c4bc1e9e000d863efc3c863d3b6c507a40fd2cdefde1bf0892b4b5ed9780b91ed1398fb4a7344c605aa5efda74',
      '53d11bce9e62a29d63ed82ae93761bdd76e38c21e2822d6ebee5eb1c5b8a03eaf9df749e2490eda9d8ac27d1f71150de93668074d18d1c3a',
      '697c1aed3cd8858515d4be8ac158b229fe184d79cb2b06e49210a6f3a7cd537bcd9bd390d96c4ab6a4406da5d93640726285370cfa95df80',
      // These are all bad because they give a nonsquare x².
      '58ad48715c9a102569b68b88362a4b0645781f5a19eb7e59c6a4686fd0f0750ff42e3d7af1ab38c29d69b670f31258919c9fdbf6093d06c0',
      '8ca37ee2b15693f06e910cf43c4e32f1d5551dda8b1e48cb6ddd55e440dbc7b296b601919a4e4069f59239ca247ff693f7daa42f086122b1',
      '982c0ec7f43d9f97c0a74b36db0abd9ca6bfb98123a90782787242c8a523cdc76df14a910d54471127e7662a1059201f902940cd39d57af5',
      'baa9ab82d07ca282b968a911a6c3728d74bf2fe258901925787f03ee4be7e3cb6684fd1bcfe5071a9a974ad249a4aaa8ca81264216c68574',
      '2ed9ffe2ded67a372b181ac524996402c42970629db03f5e8636cbaf6074b523d154a7a8c4472c4c353ab88cd6fec7da7780834cc5bd5242',
      'f063769e4241e76d815800e4933a3a144327a30ec40758ad3723a788388399f7b3f5d45b6351eb8eddefda7d5bff4ee920d338a8b89d8b63',
      '5a0104f1f55d152ceb68bc138182499891d90ee8f09b40038ccc1e07cb621fd462f781d045732a4f0bda73f0b2acf94355424ff0388d4b9c',
    ];
    for (const badBytes of badEncodings) {
      const b = hexToBytes(badBytes);
      throws(() => DecafPoint.fromBytes(b), badBytes);
    }
  });
  should('create right points from uniform hash', () => {
    const hashes = [
      'cbb8c991fd2f0b7e1913462d6463e4fd2ce4ccdd28274dc2ca1f4165d5ee6cdccea57be3416e166fd06718a31af45a2f8e987e301be59ae6673e963001dbbda80df47014a21a26d6c7eb4ebe0312aa6fffb8d1b26bc62ca40ed51f8057a635a02c2b8c83f48fa6a2d70f58a1185902c0',
      'b6d8da654b13c3101d6634a231569e6b85961c3f4b460a08ac4a5857069576b64428676584baa45b97701be6d0b0ba18ac28d443403b45699ea0fbd1164f5893d39ad8f29e48e399aec5902508ea95e33bc1e9e4620489d684eb5c26bc1ad1e09aba61fabc2cdfee0b6b6862ffc8e55a',
      '36a69976c3e5d74e4904776993cbac27d10f25f5626dd45c51d15dcf7b3e6a5446a6649ec912a56895d6baa9dc395ce9e34b868d9fb2c1fc72eb6495702ea4f446c9b7a188a4e0826b1506b0747a6709f37988ff1aeb5e3788d5076ccbb01a4bc6623c92ff147a1e21b29cc3fdd0e0f4',
      'd5938acbba432ecd5617c555a6a777734494f176259bff9dab844c81aadcf8f7abd1a9001d89c7008c1957272c1786a4293bb0ee7cb37cf3988e2513b14e1b75249a5343643d3c5e5545a0c1a2a4d3c685927c38bc5e5879d68745464e2589e000b31301f1dfb7471a4f1300d6fd0f99',
      '4dec58199a35f531a5f0a9f71a53376d7b4bdd6bbd2904234a8ea65bbacbce2a542291378157a8f4be7b6a092672a34d85e473b26ccfbd4cdc6739783dc3f4f6ee3537b7aed81df898c7ea0ae89a15b5559596c2a5eeacf8b2b362f3db2940e3798b63203cae77c4683ebaed71533e51',
      'df2aa1536abb4acab26efa538ce07fd7bca921b13e17bc5ebcba7d1b6b733deda1d04c220f6b5ab35c61b6bcb15808251cab909a01465b8ae3fc770850c66246d5a9eae9e2877e0826e2b8dc1bc08009590bc6778a84e919fbd28e02a0f9c49b48dc689eb5d5d922dc01469968ee81b5',
      'e9fb440282e07145f1f7f5ecf3c273212cd3d26b836b41b02f108431488e5e84bd15f2418b3d92a3380dd66a374645c2a995976a015632d36a6c2189f202fc766e1c82f50ad9189be190a1f0e8f9b9e69c9c18cc98fdd885608f68bf0fdedd7b894081a63f70016a8abf04953affbefa',
    ];
    const encodedHashToPoints = [
      '0c709c9607dbb01c94513358745b7c23953d03b33e39c7234e268d1d6e24f34014ccbc2216b965dd231d5327e591dc3c0e8844ccfd568848',
      '76ab794e28ff1224c727fa1016bf7f1d329260b7218a39aea2fdb17d8bd9119017b093d641cedf74328c327184dc6f2a64bd90eddccfcdab',
      'c8d7ac384143500e50890a1c25d643343accce584caf2544f9249b2bf4a6921082be0e7f3669bb5ec24535e6c45621e1f6dec676edd8b664',
      '62beffc6b8ee11ccd79dbaac8f0252c750eb052b192f41eeecb12f2979713b563caf7d22588eca5e80995241ef963e7ad7cb7962f343a973',
      'f4ccb31d263731ab88bed634304956d2603174c66da38742053fa37dd902346c3862155d68db63be87439e3d68758ad7268e239d39c4fd3b',
      '7e79b00e8e0a76a67c0040f62713b8b8c6d6f05e9c6d02592e8a22ea896f5deacc7c7df5ed42beae6fedb9000285b482aa504e279fd49c32',
      '20b171cb16be977f15e013b9752cf86c54c631c4fc8cbf7c03c4d3ac9b8e8640e7b0e9300b987fe0ab5044669314f6ed1650ae037db853f1',
    ];

    for (let i = 0; i < hashes.length; i++) {
      const hash = hexToBytes(hashes[i]);
      const point = decaf448_hasher.deriveToCurve(hash);
      eql(point.toBytes(), hexToBytes(encodedHashToPoints[i]));
    }
  });
  should('uniform byte string (from RFC)', () => {
    const VECTORS = [
      {
        I:
          'cbb8c991fd2f0b7e1913462d6463e4fd2ce4ccdd28274dc2ca1f4165' +
          'd5ee6cdccea57be3416e166fd06718a31af45a2f8e987e301be59ae6' +
          '673e963001dbbda80df47014a21a26d6c7eb4ebe0312aa6fffb8d1b2' +
          '6bc62ca40ed51f8057a635a02c2b8c83f48fa6a2d70f58a1185902c0',
        O:
          '0c709c96 07dbb01c 94513358 745b7c23 953d03b3 3e39c723 4e268d1d' +
          '6e24f340 14ccbc22 16b965dd 231d5327 e591dc3c 0e8844cc fd568848',
      },
      {
        I:
          'b6d8da654b13c3101d6634a231569e6b85961c3f4b460a08ac4a5857' +
          '069576b64428676584baa45b97701be6d0b0ba18ac28d443403b4569' +
          '9ea0fbd1164f5893d39ad8f29e48e399aec5902508ea95e33bc1e9e4' +
          '620489d684eb5c26bc1ad1e09aba61fabc2cdfee0b6b6862ffc8e55a',
        O:
          '76ab794e 28ff1224 c727fa10 16bf7f1d 329260b7 218a39ae a2fdb17d' +
          '8bd91190 17b093d6 41cedf74 328c3271 84dc6f2a 64bd90ed dccfcdab',
      },
      {
        I:
          '36a69976c3e5d74e4904776993cbac27d10f25f5626dd45c51d15dcf' +
          '7b3e6a5446a6649ec912a56895d6baa9dc395ce9e34b868d9fb2c1fc' +
          '72eb6495702ea4f446c9b7a188a4e0826b1506b0747a6709f37988ff' +
          '1aeb5e3788d5076ccbb01a4bc6623c92ff147a1e21b29cc3fdd0e0f4',
        O:
          'c8d7ac38 4143500e 50890a1c 25d64334 3accce58 4caf2544 f9249b2b' +
          'f4a69210 82be0e7f 3669bb5e c24535e6 c45621e1 f6dec676 edd8b664',
      },
      {
        I:
          'd5938acbba432ecd5617c555a6a777734494f176259bff9dab844c81' +
          'aadcf8f7abd1a9001d89c7008c1957272c1786a4293bb0ee7cb37cf3' +
          '988e2513b14e1b75249a5343643d3c5e5545a0c1a2a4d3c685927c38' +
          'bc5e5879d68745464e2589e000b31301f1dfb7471a4f1300d6fd0f99',
        O:
          '62beffc6 b8ee11cc d79dbaac 8f0252c7 50eb052b 192f41ee ecb12f29' +
          '79713b56 3caf7d22 588eca5e 80995241 ef963e7a d7cb7962 f343a973',
      },
      {
        I:
          '4dec58199a35f531a5f0a9f71a53376d7b4bdd6bbd2904234a8ea65b' +
          'bacbce2a542291378157a8f4be7b6a092672a34d85e473b26ccfbd4c' +
          'dc6739783dc3f4f6ee3537b7aed81df898c7ea0ae89a15b5559596c2' +
          'a5eeacf8b2b362f3db2940e3798b63203cae77c4683ebaed71533e51',
        O:
          'f4ccb31d 263731ab 88bed634 304956d2 603174c6 6da38742 053fa37d' +
          'd902346c 3862155d 68db63be 87439e3d 68758ad7 268e239d 39c4fd3b',
      },
      {
        I:
          'df2aa1536abb4acab26efa538ce07fd7bca921b13e17bc5ebcba7d1b' +
          '6b733deda1d04c220f6b5ab35c61b6bcb15808251cab909a01465b8a' +
          'e3fc770850c66246d5a9eae9e2877e0826e2b8dc1bc08009590bc677' +
          '8a84e919fbd28e02a0f9c49b48dc689eb5d5d922dc01469968ee81b5',
        O:
          '7e79b00e 8e0a76a6 7c0040f6 2713b8b8 c6d6f05e 9c6d0259 2e8a22ea' +
          '896f5dea cc7c7df5 ed42beae 6fedb900 0285b482 aa504e27 9fd49c32',
      },
      {
        I:
          'e9fb440282e07145f1f7f5ecf3c273212cd3d26b836b41b02f108431' +
          '488e5e84bd15f2418b3d92a3380dd66a374645c2a995976a015632d3' +
          '6a6c2189f202fc766e1c82f50ad9189be190a1f0e8f9b9e69c9c18cc' +
          '98fdd885608f68bf0fdedd7b894081a63f70016a8abf04953affbefa',
        O:
          '20b171cb 16be977f 15e013b9 752cf86c 54c631c4 fc8cbf7c 03c4d3ac' +
          '9b8e8640 e7b0e930 0b987fe0 ab504466 9314f6ed 1650ae03 7db853f1',
      },
    ];
    for (const { I, O } of VECTORS) {
      const point = decaf448_hasher.deriveToCurve(hexToBytes(I));
      eql(point.toHex(), O.replaceAll(' ', ''));
    }
  });
  should('have proper equality testing', () => {
    const MAX_448B = BigInt(
      '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    );
    const bytes448ToNumberLE = (bytes) => ed448.Point.Fp.create(bytesToNumberLE(bytes) & MAX_448B);

    const priv = new Uint8Array([
      23, 211, 149, 179, 209, 108, 78, 37, 229, 45, 122, 220, 85, 38, 192, 182, 96, 40, 168, 63,
      175, 194, 73, 202, 14, 175, 78, 15, 117, 175, 40, 32, 218, 221, 151, 58, 158, 91, 250, 141,
      18, 175, 191, 119, 152, 124, 223, 101, 54, 218, 76, 158, 43, 112, 151, 32,
    ]);
    const pub = DecafPoint.BASE.multiply(bytes448ToNumberLE(priv));
    eql(pub.equals(DecafPoint.ZERO), false);
  });

  should('decaf448_hasher', () => {
    eql(
      bytesToHex(
        decaf448_hasher
          .hashToCurve(new Uint8Array(10).fill(5), {
            DST: 'decaf448_XOF:SHAKE256_D448MAP_RO_',
          })
          .toBytes()
      ),
      '1287dea7519af966cf537a58f614e8b39b93a7c0b989bcdb4f94af8f2573ab59589accb0d2a2097b5f30c1d721619470f21e78613bbfc4b6'
    );
  });
});

should.runWhen(import.meta.url);
