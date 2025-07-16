import * as fc from 'fast-check';
import { describe, should } from 'micro-should';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { wNAF } from '../esm/abstract/curve.js';
import { hash_to_field } from '../esm/abstract/hash-to-curve.js';
import {
  bytesToHex,
  bytesToNumberBE,
  concatBytes,
  hexToBytes,
  utf8ToBytes,
} from '../esm/abstract/utils.js';
import { bls12_381 as bls, bls12_381 } from '../esm/bls12-381.js';
import { json, txt } from './utils.js';

import * as utils from '../esm/abstract/utils.js';

const eip2537 = json('./vectors/bls12-381/eip2537.json');
const zkVectors = json('./vectors/bls12-381/zkcrypto/converted.json');
const pairingVectors = json('./vectors/bls12-381/go_pairing_vectors/pairing.json');
const G1_VECTORS = txt('vectors/bls12-381/bls12-381-g1-test-vectors.txt');
const G2_VECTORS = txt('vectors/bls12-381/bls12-381-g2-test-vectors.txt');
// Vectors come from
// https://github.com/zkcrypto/bls12-381/blob/e501265cd36849a4981fe55e10dc87c38ee2213d/src/hash_to_curve/map_scalar.rs#L20
const SCALAR_VECTORS = txt('vectors/bls12-381/bls12-381-scalar-test-vectors.txt');
const SCALAR_XMD_SHA256_VECTORS = txt(
  'vectors/bls12-381/bls12-381-scalar-xmd-sha256-test-vectors.txt'
);
const H2C_KILLIC_G1 = [
  {
    msg: utf8ToBytes(''),
    expected:
      '0576730ab036cbac1d95b38dca905586f28d0a59048db4e8778782d89bff856ddef89277ead5a21e2975c4a6e3d8c79e' +
      '1273e568bebf1864393c517f999b87c1eaa1b8432f95aea8160cd981b5b05d8cd4a7cf00103b6ef87f728e4b547dd7ae',
  },
  {
    msg: utf8ToBytes('abc'),
    expected:
      '061daf0cc00d8912dac1d4cf5a7c32fca97f8b3bf3f805121888e5eb89f77f9a9f406569027ac6d0e61b1229f42c43d6' +
      '0de1601e5ba02cb637c1d35266f5700acee9850796dc88e860d022d7b9e7e3dce5950952e97861e5bb16d215c87f030d',
  },
  {
    msg: utf8ToBytes('abcdef0123456789'),
    expected:
      '0fb3455436843e76079c7cf3dfef75e5a104dfe257a29a850c145568d500ad31ccfe79be9ae0ea31a722548070cf98cd' +
      '177989f7e2c751658df1b26943ee829d3ebcf131d8f805571712f3a7527ee5334ecff8a97fc2a50cea86f5e6212e9a57',
  },
  {
    msg: utf8ToBytes(
      'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    ),
    expected:
      '0514af2137c1ae1d78d5cb97ee606ea142824c199f0f25ac463a0c78200de57640d34686521d3e9cf6b3721834f8a038' +
      '047a85d6898416a0899e26219bca7c4f0fa682717199de196b02b95eaf9fb55456ac3b810e78571a1b7f5692b7c58ab6',
  },
];
const BLS_H2C_VEC_ENCODE_G1 = [
  {
    msg: utf8ToBytes(''),
    expected:
      '1223effdbb2d38152495a864d78eee14cb0992d89a241707abb03819a91a6d2fd65854ab9a69e9aacb0cbebfd490732c' +
      '0f925d61e0b235ecd945cbf0309291878df0d06e5d80d6b84aa4ff3e00633b26f9a7cb3523ef737d90e6d71e8b98b2d5',
  },
  {
    msg: utf8ToBytes('abc'),
    expected:
      '179d3fd0b4fb1da43aad06cea1fb3f828806ddb1b1fa9424b1e3944dfdbab6e763c42636404017da03099af0dcca0fd6' +
      '0d037cb1c6d495c0f5f22b061d23f1be3d7fe64d3c6820cfcd99b6b36fa69f7b4c1f4addba2ae7aa46fb25901ab483e4',
  },
  {
    msg: utf8ToBytes('abcdef0123456789'),
    expected:
      '15aa66c77eded1209db694e8b1ba49daf8b686733afaa7b68c683d0b01788dfb0617a2e2d04c0856db4981921d3004af' +
      '0952bb2f61739dd1d201dd0a79d74cda3285403d47655ee886afe860593a8a4e51c5b77a22d2133e3a4280eaaaa8b788',
  },
  {
    msg: utf8ToBytes(
      'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    ),
    expected:
      '06328ce5106e837935e8da84bd9af473422e62492930aa5f460369baad9545defa468d9399854c23a75495d2a80487ee' +
      '094bfdfe3e552447433b5a00967498a3f1314b86ce7a7164c8a8f4131f99333b30a574607e301d5f774172c627fd0bca',
  },
];
const BLS_H2C_VEC_HASH_G2 = [
  {
    msg: utf8ToBytes(''),
    expected:
      '0fbdae26f9f9586a46d4b0b70390d09064ef2afe5c99348438a3c7d9756471e015cb534204c1b6824617a85024c772dc' +
      '0a650bd36ae7455cb3fe5d8bb1310594551456f5c6593aec9ee0c03d2f6cb693bd2c5e99d4e23cbaec767609314f51d3' +
      '02e5cf8f9b7348428cc9e66b9a9b36fe45ba0b0a146290c3a68d92895b1af0e1f2d9f889fb412670ae8478d8abd4c5aa' +
      '0d8d49e7737d8f9fc5cef7c4b8817633103faf2613016cb86a1f3fc29968fe2413e232d9208d2d74a89bf7a48ac36f83',
  },
  {
    msg: utf8ToBytes('abc'),
    expected:
      '03578447618463deb106b60e609c6f7cc446dc6035f84a72801ba17c94cd800583b493b948eff0033f09086fdd7f6175' +
      '1953ce6d4267939c7360756d9cca8eb34aac4633ef35369a7dc249445069888e7d1b3f9d2e75fbd468fbcbba7110ea02' +
      '0184d26779ae9d4670aca9b267dbd4d3b30443ad05b8546d36a195686e1ccc3a59194aea05ed5bce7c3144a29ec047c4' +
      '0882ab045b8fe4d7d557ebb59a63a35ac9f3d312581b509af0f8eaa2960cbc5e1e36bb969b6e22980b5cbdd0787fcf4e',
  },
  {
    msg: utf8ToBytes('abcdef0123456789'),
    expected:
      '195fad48982e186ce3c5c82133aefc9b26d55979b6f530992a8849d4263ec5d57f7a181553c8799bcc83da44847bdc8d' +
      '17b461fc3b96a30c2408958cbfa5f5927b6063a8ad199d5ebf2d7cdeffa9c20c85487204804fab53f950b2f87db365aa' +
      '005cdf3d984e3391e7e969276fb4bc02323c5924a4449af167030d855acc2600cf3d4fab025432c6d868c79571a95bef' +
      '174a3473a3af2d0302b9065e895ca4adba4ece6ce0b41148ba597001abb152f852dd9a96fb45c9de0a43d944746f833e',
  },
  {
    msg: utf8ToBytes(
      'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    ),
    expected:
      '123b6bd9feeba26dd4ad00f8bfda2718c9700dc093ea5287d7711844644eb981848316d3f3f57d5d3a652c6cdc816aca' +
      '0a162306f3b0f2bb326f0c4fb0e1fea020019c3af796dcd1d7264f50ddae94cacf3cade74603834d44b9ab3d5d0a6c98' +
      '05483f3b96d9252dd4fc0868344dfaf3c9d145e3387db23fa8e449304fab6a7b6ec9c15f05c0a1ea66ff0efcc03e001a' +
      '15c1d4f1a685bb63ee67ca1fd96155e3d091e852a684b78d085fd34f6091e5249ddddbdcf2e7ec82ce6c04c63647eeb7',
  },
];
const BLS_H2C_VEC_ENCODE_G2 = [
  {
    msg: utf8ToBytes(''),
    expected:
      '0d4333b77becbf9f9dfa3ca928002233d1ecc854b1447e5a71f751c9042d000f42db91c1d6649a5e0ad22bd7bf7398b8' +
      '027e4bfada0b47f9f07e04aec463c7371e68f2fd0c738cd517932ea3801a35acf09db018deda57387b0f270f7a219e4d' +
      '0cc76dc777ea0d447e02a41004f37a0a7b1fafb6746884e8d9fc276716ccf47e4e0899548a2ec71c2bdf1a2a50e876db' +
      '053674cba9ef516ddc218fedb37324e6c47de27f88ab7ef123b006127d738293c0277187f7e2f80a299a24d84ed03da7',
  },
  {
    msg: utf8ToBytes('abc'),
    expected:
      '18f0f87b40af67c056915dbaf48534c592524e82c1c2b50c3734d02c0172c80df780a60b5683759298a3303c5d942778' +
      '09349f1cb5b2e55489dcd45a38545343451cc30a1681c57acd4fb0a6db125f8352c09f4a67eb7d1d8242cb7d3405f97b' +
      '10a2ba341bc689ab947b7941ce6ef39be17acaab067bd32bd652b471ab0792c53a2bd03bdac47f96aaafe96e441f63c0' +
      '02f2d9deb2c7742512f5b8230bf0fd83ea42279d7d39779543c1a43b61c885982b611f6a7a24b514995e8a098496b811',
  },
  {
    msg: utf8ToBytes('abcdef0123456789'),
    expected:
      '19808ec5930a53c7cf5912ccce1cc33f1b3dcff24a53ce1cc4cba41fd6996dbed4843ccdd2eaf6a0cd801e562718d163' +
      '149fe43777d34f0d25430dea463889bd9393bdfb4932946db23671727081c629ebb98a89604f3433fba1c67d356a4af7' +
      '04783e391c30c83f805ca271e353582fdf19d159f6a4c39b73acbb637a9b8ac820cfbe2738d683368a7c07ad020e3e33' +
      '04c0d6793a766233b2982087b5f4a254f261003ccb3262ea7c50903eecef3e871d1502c293f9e063d7d293f6384f4551',
  },
  {
    msg: utf8ToBytes(
      'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    ),
    expected:
      '0b8e0094c886487870372eb6264613a6a087c7eb9804fab789be4e47a57b29eb19b1983a51165a1b5eb025865e9fc63a' +
      '0804152cbf8474669ad7d1796ab92d7ca21f32d8bed70898a748ed4e4e0ec557069003732fc86866d938538a2ae95552' +
      '14c80f068ece15a3936bb00c3c883966f75b4e8d9ddde809c11f781ab92d23a2d1d103ad48f6f3bb158bf3e3a4063449' +
      '09e5c8242dd7281ad32c03fe4af3f19167770016255fb25ad9b67ec51d62fade31a1af101e8f6172ec2ee8857662be3a',
  },
];

// @ts-ignore
const NUM_RUNS = Number(globalThis.process?.env?.RUNS_COUNT || 10); // reduce to 1 to shorten test time
fc.configureGlobal({ numRuns: NUM_RUNS });

const G1Point = bls.G1.Point;
const G2Point = bls.G2.Point;
const G1Aff = (x, y) => G1Point.fromAffine({ x, y });
const CURVE_ORDER = bls.params.r;

function hexa() {
  const items = '0123456789abcdef';
  return fc.integer({ min: 0, max: 15 }).map((n) => items[n]);
}
function hexaString(constraints = {}) {
  return fc.string({ ...constraints, unit: hexa() });
}

const FC_MSG = hexaString({ minLength: 64, maxLength: 64 });
const FC_MSG_5 = fc.array(FC_MSG, { minLength: 5, maxLength: 5 });
const FC_BIGINT = fc.bigInt(1n, CURVE_ORDER - 1n);
const FC_BIGINT_5 = fc.array(FC_BIGINT, { minLength: 5, maxLength: 5 });
const B_192_40 = '40'.padEnd(192, '0');
const B_384_40 = '40'.padEnd(384, '0'); // [0x40, 0, 0...]

const getPubKey = (priv) => blsl.getPublicKey(priv);
/**
 *
 * @param {string} item
 * @returns string
 */
function replaceZeroPoint(item) {
  const zeros = '0000000000000000000000000000000000000000000000000000000000000000';
  const ones = '1000000000000000000000000000000000000000000000000000000000000001';
  return item === zeros ? ones : item;
}

function equal(a, b, comment) {
  eql(a.equals(b), true, `eq(${comment})`);
}
const { Fp, Fp2 } = bls.fields;
const blss = bls.shortSignatures;
const blsl = bls.longSignatures;

// Fp
describe('bls12-381 Fields', () => {
  describe('bls12-381 Fp', () => {
    const FC_BIGINT = fc.bigInt(1n, Fp.ORDER - 1n);

    should('multiply/sqrt', () => {
      let sqr1 = Fp.sqrt(Fp.create(300855555557n));
      eql(
        sqr1 && sqr1.toString(),
        '364533921369419647282142659217537440628656909375169620464770009670699095647614890229414882377952296797827799113624'
      );
      throws(() => Fp.sqrt(Fp.create(72057594037927816n)));
    });
  });

  // Fp2
  describe('bls12-381 Fp2', () => {
    const { Fp, Fp2 } = bls.fields;
    const FC_BIGINT = fc.bigInt(1n, Fp.ORDER - 1n);
    const FC_BIGINT_2 = fc.array(FC_BIGINT, { minLength: 2, maxLength: 2 });

    should('non-equality', () => {
      fc.assert(
        // @ts-ignore
        fc.property(FC_BIGINT_2, FC_BIGINT_2, (num1, num2) => {
          const a = Fp2.fromBigTuple([num1[0], num1[1]]);
          const b = Fp2.fromBigTuple([num2[0], num2[1]]);
          eql(Fp2.eql(a, b), num1[0] === num2[0] && num1[1] === num2[1]);
          eql(Fp2.eql(b, a), num1[0] === num2[0] && num1[1] === num2[1]);
        })
      );
    });
    should('sqrt: correct root', () => {
      const sqr = Fp2.fromBigTuple([
        3341065098200961989598748404381324054605449840948293400785922068969583005812936621662354076014412578129291257715488n,
        2133050398774337206222816300118221327418763981033055222570091459262312519047975404484651902003138703421962555090222n,
      ]);
      const sqrt0 = Fp2.fromBigTuple([
        2017258952934375457849735304558732518256013841723352154472679471057686924117014146018818524865681679396399932211882n,
        3074855889729334937670587859959866275799142626485414915307030157330054773488162299461738339401058098462460928340205n,
      ]);
      const sqrt1 = Fp2.fromBigTuple([
        1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905n,
        927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582n,
      ]);
      eql(Fp2.sqr(sqrt0), sqr, 'sqrt0');
      eql(Fp2.sqr(sqrt1), sqr, 'sqrt1');
      eql(Fp2.sqrt(sqr), sqrt0);
    });

    should('div/x/1=x', () => {
      fc.assert(
        fc.property(FC_BIGINT_2, (num) => {
          const a = Fp2.fromBigTuple([num[0], num[1]]);
          eql(Fp2.div(a, Fp2.fromBigTuple([1n, 0n])), a);
          eql(Fp2.div(a, Fp2.ONE), a);
          eql(Fp2.div(a, a), Fp2.ONE);
        })
      );
    });

    should('frobenius', () => {
      // expect(Fp2.FROBENIUS_COEFFICIENTS[0].equals(Fp.ONE)).toBe(true);
      // expect(
      //   Fp2.FROBENIUS_COEFFICIENTS[1].equals(
      //     Fp.ONE.negate().pow(
      //       0x0f81ae6945026025546c75a2a5240311d8ab75fac730cbcacd117de46c663f3fdebb76c445078281bf953ed363fa069bn
      //     )
      //   )
      // ).toBe(true);
      let a = Fp2.fromBigTuple([
        0x00f8d295b2ded9dcccc649c4b9532bf3b966ce3bc2108b138b1a52e0a90f59ed11e59ea221a3b6d22d0078036923ffc7n,
        0x012d1137b8a6a8374e464dea5bcfd41eb3f8afc0ee248cadbe203411c66fb3a5946ae52d684fa7ed977df6efcdaee0dbn,
      ]);
      a = Fp2.frobeniusMap(a, 0);
      eql(
        Fp2.eql(
          a,
          Fp2.fromBigTuple([
            0x00f8d295b2ded9dcccc649c4b9532bf3b966ce3bc2108b138b1a52e0a90f59ed11e59ea221a3b6d22d0078036923ffc7n,
            0x012d1137b8a6a8374e464dea5bcfd41eb3f8afc0ee248cadbe203411c66fb3a5946ae52d684fa7ed977df6efcdaee0dbn,
          ])
        ),
        true
      );
      a = Fp2.frobeniusMap(a, 1);
      eql(
        Fp2.eql(
          a,
          Fp2.fromBigTuple([
            0x00f8d295b2ded9dcccc649c4b9532bf3b966ce3bc2108b138b1a52e0a90f59ed11e59ea221a3b6d22d0078036923ffc7n,
            0x18d400b280d93e62fcd559cbe77bd8b8b07e9bc405608611a9109e8f3041427e8a411ad149045812228109103250c9d0n,
          ])
        ),
        true
      );
      a = Fp2.frobeniusMap(a, 1);
      eql(
        Fp2.eql(
          a,
          Fp2.fromBigTuple([
            0x00f8d295b2ded9dcccc649c4b9532bf3b966ce3bc2108b138b1a52e0a90f59ed11e59ea221a3b6d22d0078036923ffc7n,
            0x012d1137b8a6a8374e464dea5bcfd41eb3f8afc0ee248cadbe203411c66fb3a5946ae52d684fa7ed977df6efcdaee0dbn,
          ])
        ),
        true
      );
      a = Fp2.frobeniusMap(a, 2);
      eql(
        Fp2.eql(
          a,
          Fp2.fromBigTuple([
            0x00f8d295b2ded9dcccc649c4b9532bf3b966ce3bc2108b138b1a52e0a90f59ed11e59ea221a3b6d22d0078036923ffc7n,
            0x012d1137b8a6a8374e464dea5bcfd41eb3f8afc0ee248cadbe203411c66fb3a5946ae52d684fa7ed977df6efcdaee0dbn,
          ])
        ),
        true
      );
    });
  });
});

// Point
describe('bls12-381 Point', () => {
  const { Fp } = bls.fields;
  const FC_BIGINT = fc.bigInt(1n, Fp.ORDER - 1n);
  const PointG1 = G1Point;
  const PointG2 = G2Point;

  describe('G1', () => {
    should('equals', () => {
      fc.assert(
        fc.property(
          fc.array(FC_BIGINT, { minLength: 3, maxLength: 3 }),
          // @ts-ignore
          fc.array(FC_BIGINT, { minLength: 3, maxLength: 3 }),
          ([x1, y1, z1], [x2, y2, z2]) => {
            const p1 = new PointG1(Fp.create(x1), Fp.create(y1), Fp.create(z1));
            const p2 = new PointG1(Fp.create(x2), Fp.create(y2), Fp.create(z2));
            equal(p1, p1);
            equal(p2, p2);
            eql(p1.equals(p2), false);
            eql(p2.equals(p1), false);
          }
        )
      );
    });

    describe('assertValidity', () => {
      should('passes for x:0, y:0', () => {
        const a = PointG1.fromAffine({ x: Fp.create(0n), y: Fp.create(0n) });
        a.assertValidity();
      });
      should('throws on x:0, y:1', () => {
        const a = PointG1.fromAffine({ x: Fp.create(0n), y: Fp.create(1n) });
        throws(() => a.assertValidity());
      });

      should('passes for x:0x17..., y: 0x08...', () => {
        const a = PointG1.fromAffine({
          x: Fp.create(
            0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bbn
          ),
          y: Fp.create(
            0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1n
          ),
        });
        a.assertValidity();
      });
      should('passes for x:0x19..., y: 0x74...', () => {
        const a = G1Aff(
          Fp.create(
            0x19cdf3807146e68e041314ca93e1fee0991224ec2a74beb2866816fd0826ce7b6263ee31e953a86d1b72cc2215a57793n
          ),
          Fp.create(
            0x7481b1f261aabacf45c6e4fc278055441bfaf99f604d1f835c0752ac9742b4522c9f5c77db40989e7da608505d48616n
          )
        );

        a.assertValidity();
      });
      should('throws on x:0x40..., y: 0x6b...', () => {
        const a = G1Aff(
          Fp.create(
            0x40adc763f94017fc9284572bf75217da57c7e1ab4e9f5b385c995bd090f1da8461ff7e90312817534f08f783229433bn
          ),
          Fp.create(
            0x6b3642db9981bbc805393f7a8b39e1eaaea2c06f91792241d2ef5cc9f08afdd909606b5f654c8d92ee9adc2aa7ddfebn
          )
        );
        throws(() => a.assertValidity());
      });
      should('throws on x:0x17..a, y: 0x08...', () => {
        const a = G1Aff(
          Fp.create(
            0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6ban
          ),
          Fp.create(
            0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1n
          )
        );
        throws(() => a.assertValidity());
      });
      should('not validate incorrect point', () => {
        const x =
          499001545268060011619089734015590154568173930614466321429631711131511181286230338880376679848890024401335766847607n;
        const y =
          3934582309586258715640230772291917282844636728991757779640464479794033391537662970190753981664259511166946374555673n;

        const p = PointG1.fromAffine({ x: Fp.create(x), y: Fp.create(y) });
        throws(() => p.assertValidity());
      });
    });

    describe('double', () => {
      should('correct for x:0x17..., y: 0x08...', () => {
        const a = G1Aff(
          Fp.create(
            0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bbn
          ),
          Fp.create(
            0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1n
          )
        );
        const double = a.double();
        double.assertValidity();
        equal(
          double,
          G1Aff(
            Fp.create(
              0x572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4en
            ),
            Fp.create(
              0x166a9d8cabc673a322fda673779d8e3822ba3ecb8670e461f73bb9021d5fd76a4c56d9d4cd16bd1bba86881979749d28n
            )
          )
        );
        equal(double, a.multiply(2n));
        equal(double, a.add(a));
      });
      should('correct for x:0x19..., y: 0x74...', () => {
        const a = G1Aff(
          Fp.create(
            0x19cdf3807146e68e041314ca93e1fee0991224ec2a74beb2866816fd0826ce7b6263ee31e953a86d1b72cc2215a57793n
          ),
          Fp.create(
            0x7481b1f261aabacf45c6e4fc278055441bfaf99f604d1f835c0752ac9742b4522c9f5c77db40989e7da608505d48616n
          )
        );
        const double = a.double();
        double.assertValidity();
        equal(
          double,
          G1Aff(
            Fp.create(
              0x1252a4ac3529f8b2b6e8189b95a60b8865f07f9a9b73f98d5df708511d3f68632c4c7d1e2b03e6b1d1e2c01839752adan
            ),
            Fp.create(
              0x2a1bc189e36902d1a49b9965eca3cb818ab5c26dffca63ca9af032870f7bbc615ac65f21bed27bd77dd65f2e90f5358n
            )
          )
        );
        equal(double, a.multiply(2n));
        equal(double, a.add(a));
      });
    });
  });

  describe('G2', () => {
    should('equals', () => {
      fc.assert(
        fc.property(
          fc.array(fc.array(FC_BIGINT, { minLength: 2, maxLength: 2 }), {
            minLength: 3,
            maxLength: 3,
          }),
          // @ts-ignore
          fc.array(fc.array(FC_BIGINT, { minLength: 2, maxLength: 2 }), {
            minLength: 3,
            maxLength: 3,
          }),
          ([x1, y1, z1], [x2, y2, z2]) => {
            const p1 = new PointG2(
              Fp2.fromBigTuple(x1),
              Fp2.fromBigTuple(y1),
              Fp2.fromBigTuple(z1)
            );
            const p2 = new PointG2(
              Fp2.fromBigTuple(x2),
              Fp2.fromBigTuple(y2),
              Fp2.fromBigTuple(z2)
            );
            eql(p1.equals(p1), true);
            eql(p2.equals(p2), true);
            eql(p1.equals(p2), false);
            eql(p2.equals(p1), false);
          }
        )
      );
    });
    // should('be placed on curve vector 1', () => {
    //   const a = new PointG2(Fp2.fromBigTuple([0n, 0n]), Fp2.fromBigTuple([0n, 0n]));
    //   a.assertValidity();
    // });
    describe('assertValidity', () => {
      should('passes for 0x02..., 0x0c...', () => {
        const a = new PointG2(
          Fp2.fromBigTuple([
            0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8n,
            0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7en,
          ]),
          Fp2.fromBigTuple([
            0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801n,
            0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79ben,
          ]),
          Fp2.fromBigTuple([1n, 0n])
        );
        a.assertValidity();
      });
      should('passes for 0x18..., 0x7e...', () => {
        const a = PointG2.fromAffine({
          x: Fp2.fromBigTuple([
            0x18405e4b67f957b6465ead9f5afc47832d45643dc3aa03af7314c6cf980fa23dd3bb8db3358693ad06011f6a6b1a5ffn,
            0xc48e0d4f9404ae0a7f10774c55a9e838bb09d3bae85b5eaa6b16b0f4dc2354368117f3799c37f3f7126d8b54d3f8393n,
          ]),
          y: Fp2.fromBigTuple([
            0x7e61f4ec5bc9e2cc8ca471ce4ed40e729b1790cd2c0d9c1cb50e615ec7f346636e77e1cf632c881c07c538589860762n,
            0x11dfaf9281901dd356fc5dfece21898a93d9ad9e4e246dd6e18d3ee46d58ab7e77401a3e8d04057e5638ed74fb956881n,
          ]),
        });
        a.assertValidity();
      });

      should('throws on vector 1', () => {
        const a = new PointG2(
          Fp2.fromBigTuple([0n, 0n]),
          Fp2.fromBigTuple([1n, 0n]),
          Fp2.fromBigTuple([1n, 0n])
        );
        throws(() => a.assertValidity());
      });
      should('throws on vector 2', () => {
        const a = new PointG2(
          Fp2.fromBigTuple([
            0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4410b647ae3d1770bac0326a805bbefd48056c8c121bdb8n,
            0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7en,
          ]),
          Fp2.fromBigTuple([
            0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d229a695160d12c923ac9cc3baca289e193548608b82801n,
            0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79ben,
          ]),
          Fp2.fromBigTuple([1n, 0n])
        );
        throws(() => a.assertValidity());
      });
      should('throws on vector 3', () => {
        const a = new PointG2(
          Fp2.fromBigTuple([
            0x877d52dd65245f8908a03288adcd396f489ef87ae23fe110c5aa48bc208fbd1a0ed403df5b1ac137922b915f1f38ec37n,
            0x0cf8158b9e689553d58194f79863fe02902c5f169f0d4ddf46e23f15bb4f24304a8e26f1e5febc57b750d1c3dc4261d8n,
          ]),
          Fp2.fromBigTuple([
            0x065ae9215806e8a55fd2d9ec4af9d2d448599cdb85d9080b2c9b4766434c33d103730c92c30a69d0602a8804c2a7c65fn,
            0x0e9c342d8a6d4b3a1cbd02c7bdc0e0aa304de41a04569ae33184419e66bbc0271c361c973962955ba6405f0e51beb98bn,
          ]),
          Fp2.fromBigTuple([
            0x19cbaa4ee4fadc2319939b8db45c6a355bfb3755197ba74eda8534d2a2c1a2592475939877594513c326a90c11705002n,
            0x0c0d89405d4e69986559a56057851733967c50fd0b4ec75e4ce92556ae5d33567e6e1a4eb9d83b4355520ebfe0bef37cn,
          ])
        );
        throws(() => a.assertValidity());
      });
    });
  });

  describe('double', () => {
    should('correct for 0x02..., 0x0c...', () => {
      const a = new PointG2(
        Fp2.fromBigTuple([
          0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8n,
          0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7en,
        ]),
        Fp2.fromBigTuple([
          0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801n,
          0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79ben,
        ]),
        Fp2.fromBigTuple([1n, 0n])
      );
      const double = a.double();
      double.assertValidity();
      equal(
        double,
        PointG2.fromAffine({
          x: Fp2.fromBigTuple([
            0x1638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a053n,
            0xa4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c33577n,
          ]),
          y: Fp2.fromBigTuple([
            0x468fb440d82b0630aeb8dca2b5256789a66da69bf91009cbfe6bd221e47aa8ae88dece9764bf3bd999d95d71e4c9899n,
            0xf6d4552fa65dd2638b361543f887136a43253d9c66c411697003f7a13c308f5422e1aa0a59c8967acdefd8b6e36ccf3n,
          ]),
        })
      );
      equal(double, a.multiply(2n));
      equal(double, a.add(a));
    });
    should('correct for 0x18..., 0x7e...', () => {
      const a = PointG2.fromAffine({
        x: Fp2.fromBigTuple([
          0x18405e4b67f957b6465ead9f5afc47832d45643dc3aa03af7314c6cf980fa23dd3bb8db3358693ad06011f6a6b1a5ffn,
          0xc48e0d4f9404ae0a7f10774c55a9e838bb09d3bae85b5eaa6b16b0f4dc2354368117f3799c37f3f7126d8b54d3f8393n,
        ]),
        y: Fp2.fromBigTuple([
          0x7e61f4ec5bc9e2cc8ca471ce4ed40e729b1790cd2c0d9c1cb50e615ec7f346636e77e1cf632c881c07c538589860762n,
          0x11dfaf9281901dd356fc5dfece21898a93d9ad9e4e246dd6e18d3ee46d58ab7e77401a3e8d04057e5638ed74fb956881n,
        ]),
      });
      const double = a.double();
      double.assertValidity();
      equal(
        double,
        PointG2.fromAffine({
          x: Fp2.fromBigTuple([
            0x4b6570b4a6affe97649b0dd7a0ad0df160b37c332a8a7348dd3994cc6b1eb65623b4a9f0a3f320e7278844e26154653n,
            0x5f8fb4cf5e5313f403f15c59c79b9cebaec78291f2053c49d6427f40f2db2aa659d3a8fed7c7b07b7a5680c7b95ab58n,
          ]),
          y: Fp2.fromBigTuple([
            0x45cba5ec3fa9acd1b11e1f28a01ebc028f89f96f814513453c553f58785baca8abd4150f334b405fabb925b71f4f4ddn,
            0x13daf00b8f53af776c2e8c08d55d164aa15027611188e294230477dc1c926102088f0451222fd2eff9802db8b884ab9cn,
          ]),
        })
      );
      equal(double, a.multiply(2n));
      equal(double, a.add(a));
    });
  });

  const wNAF_VECTORS = [
    0x28b90deaf189015d3a325908c5e0e4bf00f84f7e639b056ff82d7e70b6eede4cn,
    0x1_3eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n,
    0x2_3eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n,
    0x3_3eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n,
    0x4_3eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n,
    0x5_3eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n,
    0x6_3eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000n,
  ];
  describe('multiply(k) == multiplyUnsafe(k)', () => {
    should('(G1, W=1)', () => {
      let G = PointG1.BASE.negate().negate(); // create new point
      G.precompute(1);
      for (let k of wNAF_VECTORS) {
        eql(G.multiply(k).equals(G.multiplyUnsafe(k)), true);
      }
    });
    should('(G1, W=4)', () => {
      let G = PointG1.BASE.negate().negate();
      G.precompute(4);
      for (let k of wNAF_VECTORS) {
        eql(G.multiply(k).equals(G.multiplyUnsafe(k)), true);
      }
    });
    should('(G1, W=5)', () => {
      let G = PointG1.BASE.negate().negate();
      G.precompute(5);
      for (let k of wNAF_VECTORS) {
        eql(G.multiply(k).equals(G.multiplyUnsafe(k)), true);
      }
    });
    should('(G2, W=1)', () => {
      let G = PointG2.BASE.negate().negate();
      G.precompute(1);
      for (let k of wNAF_VECTORS) {
        eql(G.multiply(k).equals(G.multiplyUnsafe(k)), true);
      }
    });
    should('(G2, W=4)', () => {
      let G = PointG2.BASE.negate().negate();
      G.precompute(4);
      for (let k of wNAF_VECTORS) {
        eql(G.multiply(k).equals(G.multiplyUnsafe(k)), true);
      }
    });
    should('(G2, W=5)', () => {
      let G = PointG2.BASE.negate().negate();
      G.precompute(5);
      for (let k of wNAF_VECTORS) {
        eql(G.multiply(k).equals(G.multiplyUnsafe(k)), true);
      }
    });
  });
  should('clearCofactor() == multiply(hEff)', () => {
    const points = [
      PointG2.fromAffine({
        x: Fp2.fromBigTuple([
          0x150f8786e06d33c06b1f516cba44a84b66bf8ab3f1df3a36b8197106b578bf503343d1c5e1a5de42e96825fef85b67d0n,
          0xc508c018178f45678061754fc2d82e05b62f7fa6e8cf038bf05079f0f6a8968366f536c7c3d0df0da05fb88ca555487n,
        ]),
        y: Fp2.fromBigTuple([
          0x18ee7785ae2945711bc5b10856e72bc69dc61672452bcc5f0fb63659d0f2e1daf0680a8648d63dc50ccff2eda87c0cf9n,
          0xae6ca56dd5c1d2ddb64757079b7c6908b614eda3bc7c2bce087721837f4f54d1246dfdc099bace0e39c820eac4be302n,
        ]),
      }),
      PointG2.fromAffine({
        x: Fp2.fromBigTuple([
          0x19afe53a6775def367fd60d392707fa66b0fa83ccdde7c6fbd7e08854c65b9505eca028b02d4e63c69b099afb9c346ddn,
          0xf513e2759c4ad8f58c053609065dcc0dcdcaddd8151f383d747ebcf43f7655694a8af9ddfcad0b3ae7a3906733013c0n,
        ]),
        y: Fp2.fromBigTuple([
          0x1036d8e334c53d3d704d08a83201e45cd8a71cc3a5461e7a76633ccde61e5b4966991255db53f11798715ff508f7e9dan,
          0x1120f5d47570eed4daf0e7f65825968cb3c9eb2eea1ddfc44f66b81e28bee2c55da7f62eec752e7bc50aeb63ac551f54n,
        ]),
      }),
      PointG2.fromAffine({
        x: Fp2.fromBigTuple([
          0x14c10efe90d0b9ff68bee9ba9b88cca2c5e3e45ef3fe71d9672eee854c0ba0c0c0bfa6c046270c1a06643b1cc33d36bdn,
          0x17bd40ecdec2d660e45d48a44d1c3baf43a55ca89555c1747e51866d64ae4905e3513e9c34f9e9008d67ebd79314d24en,
        ]),
        y: Fp2.fromBigTuple([
          0x866d937e269d1308f7f66129f727fcec15d1247b30e1aa9ef4daf297fc5f2b7cffa43859a41725134444d150e51f202n,
          0x1fa4634c97827268e3f3f069e19f9d205c67c5750099a708fca5221b0994fab9ce2625b869af069eb67c454363e3fb1n,
        ]),
      }),
      PointG2.fromAffine({
        x: Fp2.fromBigTuple([
          0x196dc4e988ae24defd5211e61f1dc7b69f73db0924828de7a508278e6bb38ef07443a5819c066cf7545a543e342b3a92n,
          0x12ca3952fae858bf82bd63eed7539c669aa4f8d083fec009eee6145b5661cfa663d8513961a8a4214896b92e462998a4n,
        ]),
        y: Fp2.fromBigTuple([
          0x1325608129632ee067bade150bff04ad976571df69b4de950518f70cf4a0d213a7a2ce1a3ec1f2671be96d9676525c61n,
          0xc1394a87486424059fbbbb2bdcf5b78a5be80b07f5b834c867a3785c8a41aefb0faefda2ebcf4f5acda9fbd7153c318n,
        ]),
      }),
      PointG2.fromAffine({
        x: Fp2.fromBigTuple([
          0x150f8786e06d33c06b1f516cba44a84b66bf8ab3f1df3a36b8197106b578bf503343d1c5e1a5de42e96825fef85b67d0n,
          0xc508c018178f45678061754fc2d82e05b62f7fa6e8cf038bf05079f0f6a8968366f536c7c3d0df0da05fb88ca555487n,
        ]),
        y: Fp2.fromBigTuple([
          0x18ee7785ae2945711bc5b10856e72bc69dc61672452bcc5f0fb63659d0f2e1daf0680a8648d63dc50ccff2eda87c0cf9n,
          0xae6ca56dd5c1d2ddb64757079b7c6908b614eda3bc7c2bce087721837f4f54d1246dfdc099bace0e39c820eac4be302n,
        ]),
      }),
    ];
    // Use wNAF allow scalars higher than CURVE.r
    const w = new wNAF(G2Point, 1);
    const hEff = BigInt(
      '0xbc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551'
    );
    for (let p of points) {
      const ours = p.clearCofactor();
      const shouldBe = w._unsafeLadder(p, hEff);
      eql(ours.equals(shouldBe), true, 'clearLast');
    }
  });
});

describe('bls12-381 encoding', () => {
  should('G1.fromBytes', () => {
    // Test Zero
    const g1 = G1Point.fromBytes(hexToBytes(B_192_40));
    eql(g1.x, G1Point.ZERO.x);
    eql(g1.y, G1Point.ZERO.y);
    // Test Non-Zero
    const x = Fp.create(
      BigInt(
        '0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb'
      )
    );
    const y = Fp.create(
      BigInt(
        '0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
      )
    );

    const g1_ = G1Point.fromBytes(
      hexToBytes(
        '17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
      )
    );

    eql(g1_.x, x);
    eql(g1_.y, y);
  });

  should('G1.fromBytes', () => {
    // Test Zero
    const g1 = G1Point.fromBytes(hexToBytes(B_192_40));

    eql(g1.x, G1Point.ZERO.x);
    eql(g1.y, G1Point.ZERO.y);
    // Test Non-Zero
    const x = Fp.create(
      BigInt(
        '0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb'
      )
    );
    const y = Fp.create(
      BigInt(
        '0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
      )
    );

    const g1_ = G1Point.fromBytes(
      hexToBytes(
        '17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
      )
    );

    eql(g1_.x, x);
    eql(g1_.y, y);
  });

  should('G2.fromBytes', () => {
    // Test Zero
    const g2 = G2Point.fromBytes(hexToBytes(B_384_40));
    eql(g2.x, G2Point.ZERO.x, 'zero(x)');
    eql(g2.y, G2Point.ZERO.y, 'zero(y)');
    // Test Non-Zero
    const x = Fp2.fromBigTuple([
      BigInt(
        '0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8'
      ),
      BigInt(
        '0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e'
      ),
    ]);
    const y = Fp2.fromBigTuple([
      BigInt(
        '0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801'
      ),
      BigInt(
        '0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be'
      ),
    ]);

    const g2_ = G2Point.fromBytes(
      hexToBytes(
        '13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801'
      )
    );

    eql(g2_.x, x);
    eql(g2_.y, y);
  });

  should('G2.fromBytes', () => {
    // Test Zero
    const g2 = G2Point.fromBytes(hexToBytes(B_384_40));

    eql(g2.x, G2Point.ZERO.x);
    eql(g2.y, G2Point.ZERO.y);
    // Test Non-Zero
    const x = Fp2.fromBigTuple([
      BigInt(
        '0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8'
      ),
      BigInt(
        '0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e'
      ),
    ]);
    const y = Fp2.fromBigTuple([
      BigInt(
        '0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801'
      ),
      BigInt(
        '0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be'
      ),
    ]);

    const g2_ = G2Point.fromBytes(
      hexToBytes(
        '13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801'
      )
    );

    eql(g2_.x, x);
    eql(g2_.y, y);
  });

  should('G1.toHex', () => {
    // Test Zero
    eql(G1Point.ZERO.toHex(false), B_192_40);
    // Test Non-Zero
    const x = Fp.create(
      BigInt(
        '0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb'
      )
    );
    const y = Fp.create(
      BigInt(
        '0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
      )
    );
    const g1 = G1Point.fromAffine({ x, y });
    eql(
      g1.toHex(false),
      '17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
    );
  });

  should('G1.toHex2', () => {
    // Test Zero
    eql(G1Point.ZERO.toHex(false), B_192_40);
    // Test Non-Zero
    const x = Fp.create(
      BigInt(
        '0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb'
      )
    );
    const y = Fp.create(
      BigInt(
        '0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
      )
    );
    const g1 = G1Point.fromAffine({ x, y });
    eql(
      g1.toHex(false),
      '17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
    );
  });

  should('G2.toHex', () => {
    // Test Zero
    eql(G2Point.ZERO.toHex(false), B_384_40);
    // Test Non-Zero
    const x = Fp2.fromBigTuple([
      BigInt(
        '0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8'
      ),
      BigInt(
        '0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e'
      ),
    ]);
    const y = Fp2.fromBigTuple([
      BigInt(
        '0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801'
      ),
      BigInt(
        '0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be'
      ),
    ]);
    const g2 = G2Point.fromAffine({ x, y });
    eql(
      g2.toHex(false),
      '13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801'
    );
  });

  should('G2.toHex2', () => {
    // Test Zero
    eql(G2Point.ZERO.toHex(false), B_384_40);

    // Test Non-Zero
    const x = Fp2.fromBigTuple([
      BigInt(
        '0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8'
      ),
      BigInt(
        '0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e'
      ),
    ]);
    const y = Fp2.fromBigTuple([
      BigInt(
        '0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801'
      ),
      BigInt(
        '0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be'
      ),
    ]);
    const g2 = G2Point.fromAffine({ x, y });
    eql(
      g2.toHex(false),
      '13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801'
    );
  });

  should('G1 toBytes + fromBytes roundtrip', () => {
    const priv = G1Point.fromPrivateKey(42n);
    const publicKey = priv.toBytes(true);
    const decomp = G1Point.fromBytes(publicKey);
    eql(publicKey, decomp.toBytes(true));
  });

  should('G2 toBytes + fromBytes roundtrip', () => {
    const priv = G2Point.fromPrivateKey(42n);
    const publicKey = priv.toBytes(true);
    const decomp = G2Point.fromBytes(publicKey);
    eql(publicKey, decomp.toBytes(true));
  });

  should('G1 fromPrivateKey throws on 0', () => {
    throws(() => G1Point.fromPrivateKey(0n));
  });
  should('G2 fromPrivateKey throws on 0', () => {
    throws(() => G2Point.fromPrivateKey(0n));
  });

  describe('aggregatePublicKeys', () => {
    const VALID_G1 = new G1Point(
      Fp.create(
        3609742242174788176010452839163620388872641749536604986743596621604118973777515189035770461528205168143692110933639n
      ),
      Fp.create(
        1619277690257184054444116778047375363103842303863153349133480657158810226683757397206929105479676799650932070320089n
      ),
      Fp.create(1n)
    );
    const VALID_G1_2 = new G1Point(
      Fp.create(
        1206972466279728255044019580914616126536509750250979180256809997983196363639429409634110400978470384566664128085207n
      ),
      Fp.create(
        2991142246317096160788653339959532007292638191110818490939476869616372888657136539642598243964263069435065725313423n
      ),
      Fp.create(1n)
    );

    const INVALID_G1 = new G1Point(
      Fp.create(
        499001545268060011619089734015590154568173930614466321429631711131511181286230338880376679848890024401335766847607n
      ),
      Fp.create(
        3934582309586258715640230772291917282844636728991757779640464479794033391537662970190753981664259511166946374555673n
      ),
      Fp.create(1n)
    );
    should('works', () => {
      const agg = blsl.aggregatePublicKeys([VALID_G1, VALID_G1_2]).toAffine();
      eql(
        agg.x,
        2636337749883017793009944726560363863546595464242083394883491066895536780554574413337005575305023872925406746684807n
      );
      eql(
        agg.y,
        2200256264293372104833346444532839112556752874984721583125881868863625579979779052307146195064914375388929781136724n
      );
    });

    should('throws on invalid pubkeys', () => {
      throws(() => blsl.aggregatePublicKeys([VALID_G1, INVALID_G1]));
    });
  });
});

describe('bls12-381 verify', () => {
  describe('longSignatures', () => {
    should(`sign + verify`, () => {
      for (let vector of G2_VECTORS) {
        const [priv, msgs, expected] = vector;
        const msg = blsl.hash(hexToBytes(msgs));
        const sig = blsl.sign(msg, priv);
        const sigb = blsl.Signature.toBytes(sig);
        eql(blsl.Signature.toHex(sig), expected, 'h');
        eql(bytesToHex(sigb), expected, 'b');
        eql(blsl.Signature.toBytes(blsl.Signature.fromBytes(sigb)), sigb, 'b round');
        eql(blsl.Signature.toHex(blsl.Signature.fromBytes(sigb)), bytesToHex(sigb), 'h round');
      }
    });

    should('works', () => {
      for (let i = 0; i < NUM_RUNS; i++) {
        const [priv, msgs] = G2_VECTORS[i];
        const msg = blsl.hash(hexToBytes(msgs));
        const sig = blsl.sign(msg, priv);
        const pub = blsl.getPublicKey(priv);
        const res = blsl.verify(sig, msg, pub);
        eql(res, true, `${priv}-${msg}`);
        const resHex = blsl.verify(sig, msg, pub);
        eql(resHex, true, `${priv}-${msg}-hex`);
      }
    });
    should('false for wrong message', () => {
      for (let i = 0; i < NUM_RUNS; i++) {
        const [priv, msgs] = G2_VECTORS[i];
        const invMsgs = G2_VECTORS[i + 1][1];
        const msg = blsl.hash(hexToBytes(msgs));
        const invMsg = blsl.hash(hexToBytes(invMsgs));
        const sig = blsl.sign(msg, priv);
        const pub = blsl.getPublicKey(priv);
        const res = blsl.verify(sig, invMsg, pub);
        eql(res, false);
      }
    });
    should('false for wrong key', () => {
      for (let i = 0; i < NUM_RUNS; i++) {
        const [priv, msgs] = G2_VECTORS[i];
        const msg = blsl.hash(hexToBytes(msgs));
        const sig = blsl.sign(msg, priv);
        const invPriv = G2_VECTORS[i + 1][1].padStart(64, '0');
        const invPub = blsl.getPublicKey(invPriv);
        const res = blsl.verify(sig, msg, invPub);
        eql(res, false);
        const resHex = blsl.verify(blsl.Signature.toBytes(sig), msg, invPub);
        eql(resHex, false);
      }
    });
  });
  describe('shortSignatures', () => {
    should(`sign + verify`, () => {
      for (let vector of G1_VECTORS) {
        const [priv, msgs, expected] = vector;
        const msg = blss.hash(hexToBytes(msgs.slice()));
        const sig = blss.sign(msg, priv);
        const sigb = blss.Signature.toBytes(sig);
        eql(blss.Signature.toHex(sig), expected);
        eql(blss.Signature.toBytes(blss.Signature.fromBytes(sigb)), sigb);
        eql(blss.Signature.toHex(blss.Signature.fromBytes(sigb)), bytesToHex(sigb));
      }
    });
    should('works', () => {
      for (let i = 0; i < NUM_RUNS; i++) {
        const [priv, msg] = G1_VECTORS[i];
        const hmsg = blss.hash(hexToBytes(msg));
        const sig = blss.sign(hmsg, priv);
        const pub = blss.getPublicKey(priv);
        const res = blss.verify(sig, hmsg, pub);
        eql(res, true, `${priv}-${msg}`);
        const resHex = blss.verify(sig, hmsg, pub);
        eql(resHex, true, `${priv}-${msg}`);
      }
    });
    should('false for wrong msg', () => {
      for (let i = 0; i < NUM_RUNS; i++) {
        const [priv, msgs] = G1_VECTORS[i];
        const invMsgs = G1_VECTORS[i + 1][1];
        const msg = blss.hash(hexToBytes(msgs));
        const invMsg = blss.hash(hexToBytes(invMsgs));
        const sig = blss.sign(msg, priv);
        const pub = blss.getPublicKey(priv);
        const res = blss.verify(sig, invMsg, pub);
        eql(res, false);
        const resHex = blss.verify(sig, invMsg, pub);
        eql(resHex, false);
      }
    });
    should('false for wrong key', () => {
      for (let i = 0; i < NUM_RUNS; i++) {
        const [priv, msgs] = G1_VECTORS[i];
        const msg = blss.hash(hexToBytes(msgs));
        const sig = blss.sign(msg, priv);
        const invPriv = G1_VECTORS[i + 1][1].padStart(64, '0');
        const invPub = blss.getPublicKey(invPriv);
        const res = blss.verify(sig, msg, invPub);
        eql(res, false);
        const resHex = blss.verify(sig, msg, invPub);
        eql(resHex, false);
      }
    });
  });
  should('verify augmented signature', () => {
    // Verify an augmented BLS12-381 signature
    // See https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-message-augmentation for details
    // This sample signature was generated by zkcrypto/bls12_381

    const publicKeyHex =
      '972c4c6cc184b56121a1d27ef1ca3a2334d1a51be93573bd18e168f78f8fe15ce44fb029ffe8e9c3ee6bea2660f4f35e0774a35a80d6236c050fd8f831475b5e145116d3e83d26c533545f64b08464e4bcc755f990a381efa89804212d4eef5f';
    const signatureHex =
      '987db5406ce297e729c8564a106dc896943b00216a095fe9c5d32a16a330c02eb80e6f468ede83cde5462b5145b58f65';
    const message = utf8ToBytes('message');
    const DST = 'BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_';

    const publicKey = G2Point.fromHex(publicKeyHex);
    const signature = G1Point.fromHex(signatureHex);

    const publicKeyBytes = hexToBytes(publicKeyHex);
    const publicKeyAndMessage = concatBytes(publicKeyBytes, message);
    const pubMsg = blss.hash(publicKeyAndMessage, DST);

    const isValid = blss.verify(signature, pubMsg, publicKey);
    eql(isValid, true, 'accepted augmented signature');
  });

  describe('batch', () => {
    should('verify multi-signature', () => {
      fc.assert(
        // @ts-ignore
        fc.property(FC_MSG_5, FC_BIGINT_5, (messagesS, privateKeys) => {
          privateKeys = privateKeys.slice(0, messagesS.length);
          const messages = messagesS
            .slice(0, privateKeys.length)
            .map((m) => blsl.hash(hexToBytes(m)));
          const publicKey = privateKeys.map(getPubKey);
          const signatures = messages.map((message, i) => blsl.sign(message, privateKeys[i]));
          const aggregatedSignature = blsl.aggregateSignatures(signatures);
          eql(bls.verifyBatch(aggregatedSignature, messagesS, publicKey), true);
          eql(
            bls.verifyBatch(blsl.Signature.toHex(aggregatedSignature), messagesS, publicKey),
            true
          );
        })
      );
    });
    should('batch verify multi-signatures', () => {
      fc.assert(
        // @ts-ignore
        fc.property(FC_MSG_5, FC_MSG_5, FC_BIGINT_5, (messagesS, wrongMessagesS, privateKeys) => {
          privateKeys = privateKeys.slice(0, messagesS.length);
          const messages = messagesS
            .slice(0, privateKeys.length)
            .map((m) => blsl.hash(hexToBytes(m)));
          const wrongMessages = messagesS
            .map((a, i) => (typeof wrongMessagesS[i] === 'undefined' ? a : wrongMessagesS[i]))
            .map((m) => blsl.hash(hexToBytes(m)));
          const publicKey = privateKeys.map(getPubKey);
          const signatures = messages.map((message, i) => blsl.sign(message, privateKeys[i]));
          const aggregatedSignature = blsl.aggregateSignatures(signatures);
          eql(
            bls.verifyBatch(aggregatedSignature, wrongMessages, publicKey),
            messages.every((m, i) => m === wrongMessages[i])
          );
          eql(
            bls.verifyBatch(blsl.Signature.toHex(aggregatedSignature), wrongMessages, publicKey),
            messages.every((m, i) => m === wrongMessages[i])
          );
        })
      );
    });
    should('not verify multi-signature with wrong public keys', () => {
      fc.assert(
        // @ts-ignore
        fc.property(
          FC_MSG_5,
          // @ts-ignore
          FC_BIGINT_5,
          FC_BIGINT_5,
          (messagesS, privateKeys, wrongPrivateKeys) => {
            privateKeys = privateKeys.slice(0, messagesS.length);
            wrongPrivateKeys = privateKeys.map((a, i) =>
              wrongPrivateKeys[i] !== undefined ? wrongPrivateKeys[i] : a
            );
            const messages = messagesS
              .slice(0, privateKeys.length)
              .map((m) => blsl.hash(hexToBytes(m)));
            const wrongPublicKeys = wrongPrivateKeys.map(getPubKey);
            const signatures = messages.map((message, i) => blsl.sign(message, privateKeys[i]));
            const aggregatedSignature = blsl.aggregateSignatures(signatures);
            eql(
              bls.verifyBatch(aggregatedSignature, messages, wrongPublicKeys),
              wrongPrivateKeys.every((p, i) => p === privateKeys[i])
            );
            eql(
              bls.verifyBatch(blsl.Signature.toHex(aggregatedSignature), messages, wrongPublicKeys),
              wrongPrivateKeys.every((p, i) => p === privateKeys[i])
            );
          }
        )
      );
    });
    should('verify multi-signature as simple signature', () => {
      fc.assert(
        // @ts-ignore
        fc.property(FC_MSG, FC_BIGINT_5, (messageS, privateKeys) => {
          const message = blsl.hash(hexToBytes(replaceZeroPoint(messageS)));
          const publicKey = privateKeys.map(getPubKey);
          const signatures = privateKeys.map((privateKey) => blsl.sign(message, privateKey));
          const aggregatedSignature = blsl.aggregateSignatures(signatures);
          const aggregatedPublicKey = blsl.aggregatePublicKeys(publicKey);
          // TODO
          // Error: Property failed after 9 tests
          // { seed: 515274642, path: "8:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0", endOnFailure: true }
          // Counterexample: ["0000000000000000000000000000000000000000000000000000000000000000",[4n,52435875175126190479447740508185965837690552500527637822603658699938581184445n,43n,75n,52435875175126190479447740508185965837690552500527637822603658699938581184459n]]
          eql(blsl.verify(aggregatedSignature, message, aggregatedPublicKey), true);
          eql(
            blsl.verify(blsl.Signature.toHex(aggregatedSignature), message, aggregatedPublicKey),
            true
          );
        })
      );
    });
    should('not verify wrong multi-signature as simple signature', () => {
      fc.assert(
        // @ts-ignore
        fc.property(FC_MSG, FC_MSG, FC_BIGINT_5, (messageS, wrongMessageS, privateKeys) => {
          const message = blsl.hash(hexToBytes(replaceZeroPoint(messageS)));
          const wrongMessage = blsl.hash(hexToBytes(wrongMessageS));
          const publicKey = privateKeys.map(getPubKey);
          const signatures = privateKeys.map((privateKey) => blsl.sign(message, privateKey));
          const aggregatedSignature = blsl.aggregateSignatures(signatures);
          const aggregatedPublicKey = blsl.aggregatePublicKeys(publicKey);
          eql(
            blsl.verify(aggregatedSignature, wrongMessage, aggregatedPublicKey),
            message === wrongMessage
          );
          eql(
            blsl.verify(
              blsl.Signature.toHex(aggregatedSignature),
              wrongMessage,
              aggregatedPublicKey
            ),
            message === wrongMessage
          );
        })
      );
    });
  });
});
// Deterministic
describe('bls12-381 deterministic', () => {
  // NOTE: Killic returns all items in reversed order, which looks strange:
  // instead of `Fp2(${this.c0} + ${this.c1}×i)`; it returns `Fp2(${this.c0}×i + ${this.c1})`;
  const killicHex = (lst) =>
    Array.from(lst)
      .reverse()
      .reduce((acc, i) => acc + i);

  const { Fp12 } = bls.fields;

  // hashToCurve
  describe('hash-to-curve killic', () => {
    should('hashToCurve G1', () => {
      for (let i = 0; i < H2C_KILLIC_G1.length; i++) {
        const t = H2C_KILLIC_G1[i];
        const p = bls.G1.hashToCurve(t.msg, {
          DST: 'BLS12381G1_XMD:SHA-256_SSWU_RO_TESTGEN',
        });
        eql(p.toHex(false), t.expected, i.toString());
      }
    });

    should('encodeToCurve G1', () => {
      for (let i = 0; i < BLS_H2C_VEC_ENCODE_G1.length; i++) {
        const t = BLS_H2C_VEC_ENCODE_G1[i];
        const p = bls.G1.encodeToCurve(t.msg, {
          DST: 'BLS12381G1_XMD:SHA-256_SSWU_NU_TESTGEN',
        });
        eql(p.toHex(false), t.expected, i.toString());
      }
    });
    should('hashToCurve G2', () => {
      for (let i = 0; i < BLS_H2C_VEC_HASH_G2.length; i++) {
        const t = BLS_H2C_VEC_HASH_G2[i];
        const p = bls.G2.hashToCurve(t.msg, {
          DST: 'BLS12381G2_XMD:SHA-256_SSWU_RO_TESTGEN',
        });
        eql(p.toHex(false), t.expected, i.toString());
      }
    });

    should('encodeToCurve G2', () => {
      for (let i = 0; i < BLS_H2C_VEC_ENCODE_G2.length; i++) {
        const t = BLS_H2C_VEC_ENCODE_G2[i];
        const p = bls.G2.encodeToCurve(t.msg, {
          DST: 'BLS12381G2_XMD:SHA-256_SSWU_NU_TESTGEN',
        });
        eql(p.toHex(false), t.expected, i.toString());
      }
    });

    should(`hash_to_field for scalars`, () => {
      const options = {
        p: bls.params.r,
        m: 1,
        expand: '_internal_pass',
      };
      for (let vector of SCALAR_VECTORS) {
        const [okmAscii, expectedHex] = vector;
        const expected = BigInt('0x' + expectedHex);
        const okm = utf8ToBytes(okmAscii);
        const scalars = hash_to_field(okm, 1, Object.assign({}, bls.G2.CURVE.htfDefaults, options));
        eql(scalars[0][0], expected);
      }
    });
    should(`hash_to_field for XMD scalars`, () => {
      const options = {
        p: bls.params.r,
        m: 1,
        expand: 'xmd',
        DST: 'QUUX-V01-CS02-with-BLS12381SCALAR_XMD:SHA-256_SSWU_RO_',
      };
      for (let vector of SCALAR_XMD_SHA256_VECTORS) {
        const [okmAscii, expectedHex] = vector;
        const expected = BigInt('0x' + expectedHex);
        const okm = utf8ToBytes(okmAscii);
        const scalars = hash_to_field(okm, 1, Object.assign({}, bls.G2.CURVE.htfDefaults, options));
        eql(scalars[0][0], expected);
      }
    });
  });

  // Pairing
  describe('pairing', () => {
    const { pairing } = bls;
    const { Fp12 } = bls.fields;
    const G1 = G1Point.BASE;
    const G2 = G2Point.BASE;

    should('zkcrypto vectors', () => {
      // github.com/zkcrypto/pairing
      const p1 = pairing(G1, G2);
      eql(
        p1,
        Fp12.fromBigTwelve([
          0x1250ebd871fc0a92a7b2d83168d0d727272d441befa15c503dd8e90ce98db3e7b6d194f60839c508a84305aaca1789b6n,
          0x089a1c5b46e5110b86750ec6a532348868a84045483c92b7af5af689452eafabf1a8943e50439f1d59882a98eaa0170fn,
          0x1368bb445c7c2d209703f239689ce34c0378a68e72a6b3b216da0e22a5031b54ddff57309396b38c881c4c849ec23e87n,
          0x193502b86edb8857c273fa075a50512937e0794e1e65a7617c90d8bd66065b1fffe51d7a579973b1315021ec3c19934fn,
          0x01b2f522473d171391125ba84dc4007cfbf2f8da752f7c74185203fcca589ac719c34dffbbaad8431dad1c1fb597aaa5n,
          0x018107154f25a764bd3c79937a45b84546da634b8f6be14a8061e55cceba478b23f7dacaa35c8ca78beae9624045b4b6n,
          0x19f26337d205fb469cd6bd15c3d5a04dc88784fbb3d0b2dbdea54d43b2b73f2cbb12d58386a8703e0f948226e47ee89dn,
          0x06fba23eb7c5af0d9f80940ca771b6ffd5857baaf222eb95a7d2809d61bfe02e1bfd1b68ff02f0b8102ae1c2d5d5ab1an,
          0x11b8b424cd48bf38fcef68083b0b0ec5c81a93b330ee1a677d0d15ff7b984e8978ef48881e32fac91b93b47333e2ba57n,
          0x03350f55a7aefcd3c31b4fcb6ce5771cc6a0e9786ab5973320c806ad360829107ba810c5a09ffdd9be2291a0c25a99a2n,
          0x04c581234d086a9902249b64728ffd21a189e87935a954051c7cdba7b3872629a4fafc05066245cb9108f0242d0fe3efn,
          0x0f41e58663bf08cf068672cbd01a7ec73baca4d72ca93544deff686bfd6df543d48eaa24afe47e1efde449383b676631n,
        ])
      );
    });
    should('finalExponentiate is correct', () => {
      const p1 = Fp12.fromBigTwelve([
        690392658038414015999440694435086329841032295415825549843130960252222448232974816207293269712691075396080336239827n,
        1673244384695948045466836192250093912021245353707563547917201356526057153141766171738038843400145227470982267854187n,
        2521701268183363687370344286906817113258663667920912959304741393298699171323721428784215127759799558353547063603791n,
        3390741958986800271255412688995304356725465880212612704138250878957654428361390902500149993094444529404319700338173n,
        2937610222696584007500949263676832694169290902527467459057239718838706247113927802450975619528632522479509319939064n,
        1041774303946777132837448067285334026888352159489566377408630813368450973018459091749907377030858960140758778772908n,
        3864799331679524425952286895114884847547051478975342624231897335512502423735668201254948484826445296416036052803892n,
        3824221261758382083252395717303526902028176893529557070611185581959805652254106523709848773658607700988378551642979n,
        3323164764111867304984970151558732202678135525250230081908783488276670159769559857016787572497867551292231024927968n,
        1011304421692205285006791165988839444878224012950060115964565336021949568250312574884591704110914940911299353851697n,
        2263326825947267463771741379953930448565128050766360539694662323032637428903113943692772437175107441778689006777591n,
        2975309739982292949472410540684863862532494446476557866806093059134361887381947558323102825622690771432446161524562n,
      ]);
      eql(
        Fp12.finalExponentiate(p1),
        Fp12.fromBigTwelve([
          0x09d72c189ba2fd4b09b63da857f321b791b45f8ec589858bc6d41c8f4eb05244ad7a22aea1119a958d890a19f6cacedan,
          0x153f579b44547ee81c5d1603571b4776a065e86b4e3da0bba32afedafcca10f0a40005e63c9408785761da689b4b7338n,
          0x00bb1efcca23009c3638ae9ec0ee5153fa94b4edca88c3438029bcd5909e838da44483f0bfb5877609dace3bfa7d4ff3n,
          0x0c0e22bf2d593bc5b7ce484f3ff81a23a0c36725909225c1cf2f277482144951ea3fe425d2a56a91b681e11abc56c7fan,
          0x12c99e5152ab314ca6baec31cddbeff18acdac3a91c0e62de63e029bee76d775e0940408447b0fddad84b8dde9b86deen,
          0x0fe6a726b7d4947bb7bcb22a06dd4a283ce7113e956bcbb0294883046944312a72536fff08166adcfa08dfd65e4c157fn,
          0x176bfe03f017f18f7a2af0f178b5f018434ef3623da77e40d7fc78fca08299f81f6879c69026f4a7ba639463893e0708n,
          0x0282d90ee23efd9a2e0d51af8a2048bbda4517a90a24318a75d0dd6addc29b068d17e7c89a04da84b142996aa29b1516n,
          0x0c2cdf5de0889c4b55752cf839e61a81feaebf97a812c7581c8f66395868b582cbea067c9d435dabb5722913da709bffn,
          0x0741ece37d164288d7a590b3d31d9e6f26ce0797f1b99a77cd0b5eba24eae26afcb8b69f39af06e701ceaabf94c3db5en,
          0x00c9dea49cc3e1c8be938f707bbb0239e8f960fa46617877f90b3212fc3f5890999082b9c2262c8543a278136f34b5dbn,
          0x08f574e635870b8f4ad8c18d162055ab6136db296ad5f25151244e3b1ce0d81389b9d1752a46af018e8fb1ac01b683e1n,
        ])
      );
    });
  });

  describe('killic', () => {
    should('pairing small', () => {
      const t = bls.pairing(G1Point.BASE, G2Point.BASE);
      eql(
        bytesToHex(Fp12.toBytes(t)),
        killicHex([
          '0f41e58663bf08cf068672cbd01a7ec73baca4d72ca93544deff686bfd6df543d48eaa24afe47e1efde449383b676631',
          '04c581234d086a9902249b64728ffd21a189e87935a954051c7cdba7b3872629a4fafc05066245cb9108f0242d0fe3ef',
          '03350f55a7aefcd3c31b4fcb6ce5771cc6a0e9786ab5973320c806ad360829107ba810c5a09ffdd9be2291a0c25a99a2',
          '11b8b424cd48bf38fcef68083b0b0ec5c81a93b330ee1a677d0d15ff7b984e8978ef48881e32fac91b93b47333e2ba57',
          '06fba23eb7c5af0d9f80940ca771b6ffd5857baaf222eb95a7d2809d61bfe02e1bfd1b68ff02f0b8102ae1c2d5d5ab1a',
          '19f26337d205fb469cd6bd15c3d5a04dc88784fbb3d0b2dbdea54d43b2b73f2cbb12d58386a8703e0f948226e47ee89d',
          '018107154f25a764bd3c79937a45b84546da634b8f6be14a8061e55cceba478b23f7dacaa35c8ca78beae9624045b4b6',
          '01b2f522473d171391125ba84dc4007cfbf2f8da752f7c74185203fcca589ac719c34dffbbaad8431dad1c1fb597aaa5',
          '193502b86edb8857c273fa075a50512937e0794e1e65a7617c90d8bd66065b1fffe51d7a579973b1315021ec3c19934f',
          '1368bb445c7c2d209703f239689ce34c0378a68e72a6b3b216da0e22a5031b54ddff57309396b38c881c4c849ec23e87',
          '089a1c5b46e5110b86750ec6a532348868a84045483c92b7af5af689452eafabf1a8943e50439f1d59882a98eaa0170f',
          '1250ebd871fc0a92a7b2d83168d0d727272d441befa15c503dd8e90ce98db3e7b6d194f60839c508a84305aaca1789b6',
        ])
      );
    });
    should('pairing large', () => {
      let p1 = G1Point.BASE;
      let p2 = G2Point.BASE;
      for (let v of pairingVectors) {
        eql(
          bytesToHex(Fp12.toBytes(bls.pairing(p1, p2))),
          // Reverse order
          v
            .match(/[0-9a-fA-F]{96}/g)
            .reverse()
            .join('')
        );
        p1 = p1.add(G1Point.BASE);
        p2 = p2.add(G2Point.BASE);
      }
    });
  });

  describe('zkcrypto', () => {
    should(`G1 compressed`, () => {
      let p1 = G1Point.ZERO;
      for (let i = 0; i < zkVectors.G1_Compressed.length; i++) {
        const t = zkVectors.G1_Compressed[i];
        const P = G1Point.fromBytes(hexToBytes(t));
        eql(P.toHex(true), t);
        eql(P.equals(p1), true);
        eql(p1.toHex(true), t);
        p1 = p1.add(G1Point.BASE);
        if (i) {
          eql(G1Point.BASE.multiply(BigInt(i)).toHex(true), t);
          eql(G1Point.BASE.multiplyUnsafe(BigInt(i)).toHex(true), t);
          eql(G1Point.BASE.multiply(BigInt(i)).toHex(true), t);
        }
      }
    });
    should(`G1 uncompressed`, () => {
      let p1 = G1Point.ZERO;
      for (let i = 0; i < zkVectors.G1_Uncompressed.length; i++) {
        const t = zkVectors.G1_Uncompressed[i];
        const P = G1Point.fromBytes(hexToBytes(t));
        eql(P.toHex(false), t);
        eql(P.equals(p1), true);
        eql(p1.toHex(false), t);
        p1 = p1.add(G1Point.BASE);
        if (i) {
          eql(G1Point.BASE.multiply(BigInt(i)).toHex(false), t);
          eql(G1Point.BASE.multiplyUnsafe(BigInt(i)).toHex(false), t);
          eql(G1Point.BASE.multiply(BigInt(i)).toHex(false), t);
        }
      }
    });
    should(`G2 compressed`, () => {
      let p1 = G2Point.ZERO;
      for (let i = 0; i < zkVectors.G2_Compressed.length; i++) {
        const t = zkVectors.G2_Compressed[i];
        const P = G2Point.fromBytes(hexToBytes(t));
        eql(P.toHex(true), t);
        eql(P.equals(p1), true);
        eql(p1.toHex(true), t);
        p1 = p1.add(G2Point.BASE);
        if (i) {
          let n = BigInt(i);
          eql(G2Point.BASE.multiply(n).toHex(true), t);
          eql(G2Point.BASE.multiplyUnsafe(n).toHex(true), t);
          eql(G2Point.BASE.multiply(n).toHex(true), t);
        }
      }
    });

    should(`G2 uncompressed`, () => {
      let p1 = G2Point.ZERO;
      for (let i = 0; i < zkVectors.G2_Uncompressed.length; i++) {
        const t = zkVectors.G2_Uncompressed[i];
        const P = G2Point.fromBytes(hexToBytes(t));
        eql(P.toHex(false), t);
        eql(P.equals(p1), true);
        eql(p1.toHex(false), t);
        p1 = p1.add(G2Point.BASE);
        if (i) {
          eql(G2Point.BASE.multiply(BigInt(i)).toHex(false), t);
          eql(G2Point.BASE.multiplyUnsafe(BigInt(i)).toHex(false), t);
          eql(G2Point.BASE.multiply(BigInt(i)).toHex(false), t);
        }
      }
    });
    should(`G1 encoding edge cases`, () => {
      const Fp = bls12_381.fields.Fp;
      const S_BIT_POS = Fp.BITS; // C_bit, compression bit for serialization flag
      const I_BIT_POS = Fp.BITS + 1; // I_bit, point-at-infinity bit for serialization flag
      const C_BIT_POS = Fp.BITS + 2; // S_bit, sort bit for serialization flag
      const VECTORS = [
        { pos: C_BIT_POS, shift: 7 }, // compression_flag_set = Choice::from((bytes[0] >> 7) & 1);
        { pos: I_BIT_POS, shift: 6 }, // infinity_flag_set = Choice::from((bytes[0] >> 6) & 1)
        { pos: S_BIT_POS, shift: 5 }, // sort_flag_set = Choice::from((bytes[0] >> 5) & 1)
      ];
      for (const { pos, shift } of VECTORS) {
        const d = utils.numberToBytesBE(utils.bitSet(0n, pos, Boolean(true)), Fp.BYTES);
        eql((d[0] >> shift) & 1, 1, `${pos}`);
      }
      const baseC = G1Point.BASE.toBytes();
      eql(baseC.length, 48);
      const baseU = G1Point.BASE.toBytes(false);
      eql(baseU.length, 96);
      const compressedBit = baseU.slice();
      compressedBit[0] |= 0b1000_0000; // add compression bit
      throws(() => G1Point.fromBytes(compressedBit), 'compressed bit'); // uncompressed point with compressed length
      const uncompressedBit = baseC.slice();
      uncompressedBit[0] &= 0b0111_1111; // remove compression bit
      throws(() => G1Point.fromBytes(uncompressedBit), 'uncompressed bit');
      const infinityUncompressed = baseU.slice();
      infinityUncompressed[0] |= 0b0100_0000;
      throws(() => G1Point.fromBytes(compressedBit), 'infinity uncompressed');
      const infinityCompressed = baseC.slice();
      infinityCompressed[0] |= 0b0100_0000;
      throws(() => G1Point.fromBytes(compressedBit), 'infinity compressed');
    });
    should(`G2 encoding edge cases`, () => {
      const Fp = bls12_381.fields.Fp;
      const S_BIT_POS = Fp.BITS; // C_bit, compression bit for serialization flag
      const I_BIT_POS = Fp.BITS + 1; // I_bit, point-at-infinity bit for serialization flag
      const C_BIT_POS = Fp.BITS + 2; // S_bit, sort bit for serialization flag
      const VECTORS = [
        { pos: C_BIT_POS, shift: 7 }, // compression_flag_set = Choice::from((bytes[0] >> 7) & 1);
        { pos: I_BIT_POS, shift: 6 }, // infinity_flag_set = Choice::from((bytes[0] >> 6) & 1)
        { pos: S_BIT_POS, shift: 5 }, // sort_flag_set = Choice::from((bytes[0] >> 5) & 1)
      ];
      for (const { pos, shift } of VECTORS) {
        const d = utils.numberToBytesBE(utils.bitSet(0n, pos, Boolean(true)), Fp.BYTES);
        eql((d[0] >> shift) & 1, 1, `${pos}`);
      }
      const baseC = G2Point.BASE.toBytes();
      eql(baseC.length, 96);
      const baseU = G2Point.BASE.toBytes(false);
      eql(baseU.length, 192);
      const compressedBit = baseU.slice();
      compressedBit[0] |= 0b1000_0000; // add compression bit
      throws(() => G2Point.fromBytes(compressedBit), 'compressed bit'); // uncompressed point with compressed length
      const uncompressedBit = baseC.slice();
      uncompressedBit[0] &= 0b0111_1111; // remove compression bit
      throws(() => G2Point.fromBytes(uncompressedBit), 'uncompressed bit');
      const infinityUncompressed = baseU.slice();
      infinityUncompressed[0] |= 0b0100_0000;
      throws(() => G2Point.fromBytes(compressedBit), 'infinity uncompressed');
      const infinityCompressed = baseC.slice();
      infinityCompressed[0] |= 0b0100_0000;
      throws(() => G2Point.fromBytes(compressedBit), 'infinity compressed');
      infinityCompressed[0] = 0b00100000;
      throws(() => G2Point.fromBytes(compressedBit), '(!compressed && !infinity && sort)');
      infinityCompressed[0] = 0b01100000;
      throws(() => G2Point.fromBytes(compressedBit), '(!compressed && infinity && sort)');
      infinityCompressed[0] = 0b11100000;
      throws(() => G2Point.fromBytes(compressedBit), '(sort && infinity && compressed)');
    });
  });
  describe('EIP2537', () => {
    const toEthHex = (n) => n.toString(16).padStart(128, '0');
    should('G1', () => {
      for (const v of eip2537.G1) {
        const input = hexToBytes(v.Input);
        const { x, y } = bls12_381.G1.mapToCurve([bytesToNumberBE(input)]).toAffine();
        const val = toEthHex(x) + toEthHex(y);
        eql(val, v.Expected);
      }
    });
    should('G2', () => {
      for (const v of eip2537.G2) {
        const input1 = BigInt(`0x${v.Input.slice(0, 128)}`);
        const input2 = BigInt(`0x${v.Input.slice(128, 256)}`);
        const { x, y } = bls12_381.G2.mapToCurve([input1, input2]).toAffine();
        const res = toEthHex(x.c0) + toEthHex(x.c1) + toEthHex(y.c0) + toEthHex(y.c1);
        eql(res, v.Expected);
      }
    });
    should('zero point', () => {
      // kernel of isogeny
      const t = BigInt(
        '1006044755431560595281793557931171729984964515682961911911398807521437683216171091013202870577238485832047490326971'
      );
      eql(bls12_381.G1.mapToCurve([t]).equals(bls12_381.G1.ProjectivePoint.ZERO), true);
    });
  });
});

should.runWhen(import.meta.url);

// TODO: merge Fp tests with group tests in basic
