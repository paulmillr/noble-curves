import { bls12_381 } from '../lib/esm/bls12-381.js';
import { describe, should } from 'micro-should';
import { deepStrictEqual, notDeepStrictEqual, throws } from 'assert';
import { sha512 } from '@noble/hashes/sha512';
import * as fc from 'fast-check';
import { readFileSync } from 'fs';
import zkVectors from './bls12-381/zkcrypto/converted.json' assert { type: 'json' };
import pairingVectors from './bls12-381/go_pairing_vectors/pairing.json' assert { type: 'json' };
import { wNAF } from '../lib/esm/abstract/group.js';
const bls = bls12_381;
const { Fp2 } = bls;
const G1Point = bls.G1.ProjectivePoint;
const G2Point = bls.G2.ProjectivePoint;
const G1Aff = (x, y) => G1Point.fromAffine({ x, y });

const G2_VECTORS = readFileSync('./test/bls12-381/bls12-381-g2-test-vectors.txt', 'utf-8')
  .trim()
  .split('\n')
  .map((l) => l.split(':'));
// Vectors come from
// https://github.com/zkcrypto/bls12-381/blob/e501265cd36849a4981fe55e10dc87c38ee2213d/src/hash_to_curve/map_scalar.rs#L20
const SCALAR_VECTORS = readFileSync('./test/bls12-381/bls12-381-scalar-test-vectors.txt', 'utf-8')
  .trim()
  .split('\n')
  .map((l) => l.split(':'));

// @ts-ignore
const NUM_RUNS = Number(process.env.RUNS_COUNT || 10); // reduce to 1 to shorten test time
fc.configureGlobal({ numRuns: NUM_RUNS });

// @ts-ignore
const CURVE_ORDER = bls.CURVE.r;

const FC_MSG = fc.hexaString({ minLength: 64, maxLength: 64 });
const FC_MSG_5 = fc.array(FC_MSG, { minLength: 5, maxLength: 5 });
const FC_BIGINT = fc.bigInt(1n, CURVE_ORDER - 1n);
const FC_BIGINT_5 = fc.array(FC_BIGINT, { minLength: 5, maxLength: 5 });
const B_192_40 = '40'.padEnd(192, '0');
const B_384_40 = '40'.padEnd(384, '0'); // [0x40, 0, 0...]

const getPubKey = (priv) => bls.getPublicKey(priv);

function equal(a, b, comment) {
  deepStrictEqual(a.equals(b), true, `eq(${comment})`);
}

// Fp
describe('bls12-381 Fp', () => {
  const Fp = bls.Fp;
  const FC_BIGINT = fc.bigInt(1n, Fp.ORDER - 1n);

  should('multiply/sqrt', () => {
    let sqr1 = Fp.sqrt(Fp.create(300855555557n));
    deepStrictEqual(
      sqr1 && sqr1.toString(),
      '364533921369419647282142659217537440628656909375169620464770009670699095647614890229414882377952296797827799113624'
    );
    throws(() => Fp.sqrt(Fp.create(72057594037927816n)));
  });
});

// Fp2
describe('bls12-381 Fp2', () => {
  const Fp = bls.Fp;
  const Fp2 = bls.Fp2;
  const FC_BIGINT = fc.bigInt(1n, Fp.ORDER - 1n);
  const FC_BIGINT_2 = fc.array(FC_BIGINT, { minLength: 2, maxLength: 2 });

  should('non-equality', () => {
    fc.assert(
      fc.property(FC_BIGINT_2, FC_BIGINT_2, (num1, num2) => {
        const a = Fp2.fromBigTuple([num1[0], num1[1]]);
        const b = Fp2.fromBigTuple([num2[0], num2[1]]);
        deepStrictEqual(Fp2.equals(a, b), num1[0] === num2[0] && num1[1] === num2[1]);
        deepStrictEqual(Fp2.equals(b, a), num1[0] === num2[0] && num1[1] === num2[1]);
      })
    );
  });

  should('div/x/1=x', () => {
    fc.assert(
      fc.property(FC_BIGINT_2, (num) => {
        const a = Fp2.fromBigTuple([num[0], num[1]]);
        deepStrictEqual(Fp2.div(a, Fp2.fromBigTuple([1n, 0n])), a);
        deepStrictEqual(Fp2.div(a, Fp2.ONE), a);
        deepStrictEqual(Fp2.div(a, a), Fp2.ONE);
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
    deepStrictEqual(
      Fp2.equals(
        a,
        Fp2.fromBigTuple([
          0x00f8d295b2ded9dcccc649c4b9532bf3b966ce3bc2108b138b1a52e0a90f59ed11e59ea221a3b6d22d0078036923ffc7n,
          0x012d1137b8a6a8374e464dea5bcfd41eb3f8afc0ee248cadbe203411c66fb3a5946ae52d684fa7ed977df6efcdaee0dbn,
        ])
      ),
      true
    );
    a = Fp2.frobeniusMap(a, 1);
    deepStrictEqual(
      Fp2.equals(
        a,
        Fp2.fromBigTuple([
          0x00f8d295b2ded9dcccc649c4b9532bf3b966ce3bc2108b138b1a52e0a90f59ed11e59ea221a3b6d22d0078036923ffc7n,
          0x18d400b280d93e62fcd559cbe77bd8b8b07e9bc405608611a9109e8f3041427e8a411ad149045812228109103250c9d0n,
        ])
      ),
      true
    );
    a = Fp2.frobeniusMap(a, 1);
    deepStrictEqual(
      Fp2.equals(
        a,
        Fp2.fromBigTuple([
          0x00f8d295b2ded9dcccc649c4b9532bf3b966ce3bc2108b138b1a52e0a90f59ed11e59ea221a3b6d22d0078036923ffc7n,
          0x012d1137b8a6a8374e464dea5bcfd41eb3f8afc0ee248cadbe203411c66fb3a5946ae52d684fa7ed977df6efcdaee0dbn,
        ])
      ),
      true
    );
    a = Fp2.frobeniusMap(a, 2);
    deepStrictEqual(
      Fp2.equals(
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

// Point
describe('bls12-381 Point', () => {
  const Fp = bls.Fp;
  const FC_BIGINT = fc.bigInt(1n, Fp.ORDER - 1n);
  const PointG1 = G1Point;
  const PointG2 = G2Point;

  describe('with Fp coordinates', () => {
    should('Point equality', () => {
      fc.assert(
        fc.property(
          fc.array(FC_BIGINT, { minLength: 3, maxLength: 3 }),
          fc.array(FC_BIGINT, { minLength: 3, maxLength: 3 }),
          ([x1, y1, z1], [x2, y2, z2]) => {
            const p1 = new PointG1(Fp.create(x1), Fp.create(y1), Fp.create(z1));
            const p2 = new PointG1(Fp.create(x2), Fp.create(y2), Fp.create(z2));
            equal(p1, p1);
            equal(p2, p2);
            deepStrictEqual(p1.equals(p2), false);
            deepStrictEqual(p2.equals(p1), false);
          }
        )
      );
    });
    should('be placed on curve vector 1', () => {
      const a = PointG1.fromAffine({ x: Fp.create(0n), y: Fp.create(0n) });
      a.assertValidity();
    });
    should('not be placed on curve vector 1', () => {
      const a = PointG1.fromAffine({ x: Fp.create(0n), y: Fp.create(1n) });
      throws(() => a.assertValidity());
    });

    should('be placed on curve vector 2', () => {
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
    should('be placed on curve vector 3', () => {
      const a = G1Aff(
        Fp.create(
          3971675556538908004130084773503021351583407620890695272226385332452194486153316625183061567093226342405194446632851n
        ),
        Fp.create(
          1120750640227410374130508113691552487207139112596221955734902008063040284119210871734388578113045163251615428544022n
        )
      );

      a.assertValidity();
    });
    should('not be placed on curve vector 3', () => {
      const a = G1Aff(
        Fp.create(
          622186380008502900120948444810967255157373993223369845903602988014033704418470621816206856882891545628885272576827n
        ),
        Fp.create(
          1031339409279989180383920781105371089925712739630078633497696569127911841893478548110664124341123041182605140418539n
        )
      );
      throws(() => a.assertValidity());
    });
    should('not be placed on curve vector 2', () => {
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

    should('be doubled and placed on curve vector 1', () => {
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
            838589206289216005799424730305866328161735431124665289961769162861615689790485775997575391185127590486775437397838n
          ),
          Fp.create(
            3450209970729243429733164009999191867485184320918914219895632678707687208996709678363578245114137957452475385814312n
          )
        )
      );
      equal(double, a.multiply(2n));
      equal(double, a.add(a));
    });
    should('be pdoubled and placed on curve vector 2', () => {
      const a = G1Aff(
        Fp.create(
          3971675556538908004130084773503021351583407620890695272226385332452194486153316625183061567093226342405194446632851n
        ),
        Fp.create(
          1120750640227410374130508113691552487207139112596221955734902008063040284119210871734388578113045163251615428544022n
        )
      );
      const double = a.double();
      double.assertValidity();
      equal(
        double,
        G1Aff(
          Fp.create(
            2820140907397376715097155275119328764341377106900140435029293933353987248389870417008333350832041425944924730501850n
          ),
          Fp.create(
            405067456352079478955518177787903714844851702189644746974501225918909272447622208969148740834643073317421487969112n
          )
        )
      );
      equal(double, a.multiply(2n));
      equal(double, a.add(a));
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

  describe('with Fp2 coordinates', () => {
    should('Point equality', () => {
      fc.assert(
        fc.property(
          fc.array(fc.array(FC_BIGINT, { minLength: 2, maxLength: 2 }), {
            minLength: 3,
            maxLength: 3,
          }),
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
            deepStrictEqual(p1.equals(p1), true);
            deepStrictEqual(p2.equals(p2), true);
            deepStrictEqual(p1.equals(p2), false);
            deepStrictEqual(p2.equals(p1), false);
          }
        )
      );
    });
    // should('be placed on curve vector 1', () => {
    //   const a = new PointG2(Fp2.fromBigTuple([0n, 0n]), Fp2.fromBigTuple([0n, 0n]));
    //   a.assertValidity();
    // });
    should('be placed on curve vector 2', () => {
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
    should('be placed on curve vector 3', () => {
      const a = PointG2.fromAffine({
        x: Fp2.fromBigTuple([
          233289878585407360737561818812172281900488265436962145913969074168503452745466655442125797664134009339799716079103n,
          1890785404699189181161569277356497622423785178845737858235714310995835974899880469355250933575450045792782146044819n,
        ]),
        y: Fp2.fromBigTuple([
          1215754321684097939278683023199690844646077558342794977283698289191570128272085945598449054373022460634252133664610n,
          2751025411942897795042193940345989612527395984463172615380574492034129474560903255212585680112858672276592527763585n,
        ]),
      });
      a.assertValidity();
    });
    should('not be placed on curve vector 1', () => {
      const a = new PointG2(
        Fp2.fromBigTuple([0n, 0n]),
        Fp2.fromBigTuple([1n, 0n]),
        Fp2.fromBigTuple([1n, 0n])
      );
      throws(() => a.assertValidity());
    });
    should('not be placed on curve vector 2', () => {
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
    should('not be placed on curve vector 3', () => {
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

  should('be doubled and placed on curve vector 1', () => {
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
          3419974069068927546093595533691935972093267703063689549934039433172037728172434967174817854768758291501458544631891n,
          1586560233067062236092888871453626466803933380746149805590083683748120990227823365075019078675272292060187343402359n,
        ]),
        y: Fp2.fromBigTuple([
          678774053046495337979740195232911687527971909891867263302465188023833943429943242788645503130663197220262587963545n,
          2374407843478705782611042739236452317510200146460567463070514850492917978226342495167066333366894448569891658583283n,
        ]),
      })
    );
    equal(double, a.multiply(2n));
    equal(double, a.add(a));
  });
  should('be doubled and placed on curve vector 2', () => {
    const a = PointG2.fromAffine({
      x: Fp2.fromBigTuple([
        233289878585407360737561818812172281900488265436962145913969074168503452745466655442125797664134009339799716079103n,
        1890785404699189181161569277356497622423785178845737858235714310995835974899880469355250933575450045792782146044819n,
      ]),
      y: Fp2.fromBigTuple([
        1215754321684097939278683023199690844646077558342794977283698289191570128272085945598449054373022460634252133664610n,
        2751025411942897795042193940345989612527395984463172615380574492034129474560903255212585680112858672276592527763585n,
      ]),
    });
    const double = a.double();
    double.assertValidity();
    equal(
      double,
      PointG2.fromAffine({
        x: Fp2.fromBigTuple([
          725284069620738622060750301926991261102335618423691881774095602348039360646278290301007111649920759181128494302803n,
          919264895242212954093039181597172832206919609583188170141409360396089107784684267919047943917330182442049667967832n,
        ]),
        y: Fp2.fromBigTuple([
          671406920027112857569775418033910829294759327652470956866749681326509356602892160214948716653598897872184523683037n,
          3055998868118150255613397668970777574660658983679486410738349400795670735303668556065367873243198246660959891663772n,
        ]),
      })
    );
    equal(double, a.multiply(2n));
    equal(double, a.add(a));
  });
  const wNAF_VECTORS = [
    0x28b90deaf189015d3a325908c5e0e4bf00f84f7e639b056ff82d7e70b6eede4cn,
    0x13eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n,
    0x23eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n,
    0x33eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n,
    0x43eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n,
    0x53eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n,
    0x63eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000n,
  ];
  describe('wNAF multiplication same as unsafe', () => {
    should('(G1, W=1)', () => {
      let G = PointG1.BASE.negate().negate(); // create new point
      G._setWindowSize(1);
      for (let k of wNAF_VECTORS) {
        deepStrictEqual(G.multiply(k).equals(G.multiplyUnsafe(k)), true);
      }
    });
    should('(G1, W=4)', () => {
      let G = PointG1.BASE.negate().negate();
      G._setWindowSize(4);
      for (let k of wNAF_VECTORS) {
        deepStrictEqual(G.multiply(k).equals(G.multiplyUnsafe(k)), true);
      }
    });
    should('(G1, W=5)', () => {
      let G = PointG1.BASE.negate().negate();
      G._setWindowSize(5);
      for (let k of wNAF_VECTORS) {
        deepStrictEqual(G.multiply(k).equals(G.multiplyUnsafe(k)), true);
      }
    });
    should('(G2, W=1)', () => {
      let G = PointG2.BASE.negate().negate();
      G._setWindowSize(1);
      for (let k of wNAF_VECTORS) {
        deepStrictEqual(G.multiply(k).equals(G.multiplyUnsafe(k)), true);
      }
    });
    should('(G2, W=4)', () => {
      let G = PointG2.BASE.negate().negate();
      G._setWindowSize(4);
      for (let k of wNAF_VECTORS) {
        deepStrictEqual(G.multiply(k).equals(G.multiplyUnsafe(k)), true);
      }
    });
    should('(G2, W=5)', () => {
      let G = PointG2.BASE.negate().negate();
      G._setWindowSize(5);
      for (let k of wNAF_VECTORS) {
        deepStrictEqual(G.multiply(k).equals(G.multiplyUnsafe(k)), true);
      }
    });
  });
  should('PSI cofactor cleaning same as multiplication', () => {
    const points = [
      PointG2.fromAffine({
        x: Fp2.fromBigTuple([
          3241532514922300496112840946857937535679746598786089852337901560508502000671236210655544891931896207857529462155216n,
          1895396002326546958606807865184627576810563909325590769826854838265038910148901969770093629785689196200738594051207n,
        ]),
        y: Fp2.fromBigTuple([
          3837310786345067009730271578787473898123345117675361644389016087559904243233782782806882170766697501716660726009081n,
          1677898256818258755710370015632820289344925154952470675147754839082216730170149764842062980567113751550792217387778n,
        ]),
      }),
      PointG2.fromAffine({
        x: Fp2.fromBigTuple([
          3953605227375649587553282126565793338489478933421008011676219910137022551750442290689597974472294891051907650111197n,
          2357556650209231585002654467241659159063900268360871707630297623496109598089657193704186795702074478622917895656384n,
        ]),
        y: Fp2.fromBigTuple([
          2495601009524620857707705364800595215702994859258454180584354350679476916692161325761009870302795857111988758374874n,
          2636356076845621042340998927146453389877292467744110912831694031602037452225656755036030562878672313329396684758868n,
        ]),
      }),
      PointG2.fromAffine({
        x: Fp2.fromBigTuple([
          3194353741003351193683364524319044762011830478765020903432624057794333426495229091698895944358182869251271971124925n,
          3653808358303084112668893108836368862445971143336505524596401519323087809653188999580874561318367165116767192535630n,
        ]),
        y: Fp2.fromBigTuple([
          1293147983982604948417085455043456439133874729834486879326988078136905862300347946661594156148773025247657033069058n,
          304385694250536139727810974742746004825746444239830780412067821920180289379490776439208435270467062610041367314353n,
        ]),
      }),
      PointG2.fromAffine({
        x: Fp2.fromBigTuple([
          3913848356631365121633829648186849525632038637523196801515536004438620269011326037518995697522336713513734205291154n,
          2892036022910655232784554063257167431129586441456677365843329976181438736451469367386635015809932785607079312857252n,
        ]),
        y: Fp2.fromBigTuple([
          2946839687749075245408468852956330519059225766361204396943480879518352257697157665323514637184706466306723801095265n,
          1858741481287683941330484703798096212920693492850150667744795312336588840954530505769251621475693006537257913664280n,
        ]),
      }),
      PointG2.fromAffine({
        x: Fp2.fromBigTuple([
          3241532514922300496112840946857937535679746598786089852337901560508502000671236210655544891931896207857529462155216n,
          1895396002326546958606807865184627576810563909325590769826854838265038910148901969770093629785689196200738594051207n,
        ]),
        y: Fp2.fromBigTuple([
          3837310786345067009730271578787473898123345117675361644389016087559904243233782782806882170766697501716660726009081n,
          1677898256818258755710370015632820289344925154952470675147754839082216730170149764842062980567113751550792217387778n,
        ]),
      }),
    ];
    // Use wNAF allow scalars higher than CURVE.r
    const w = wNAF(G2Point, 1);
    for (let p of points) {
      const ours = p.clearCofactor();
      const shouldBe = w.unsafeLadder(p, bls.CURVE.G2.hEff);
      deepStrictEqual(ours.equals(shouldBe), true, 'clearLast');
    }
  });
});

// index.ts

// bls.G1.ProjectivePoint.BASE.clearMultiplyPrecomputes();
// bls.G1.ProjectivePoint.BASE.calcMultiplyPrecomputes(4);

describe('bls12-381/basic', () => {
  should('construct point G1 from its uncompressed form (Raw Bytes)', () => {
    // Test Zero
    const g1 = G1Point.fromHex(B_192_40);
    deepStrictEqual(g1.x, G1Point.ZERO.x);
    deepStrictEqual(g1.y, G1Point.ZERO.y);
    // Test Non-Zero
    const x = bls.Fp.create(
      BigInt(
        '0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb'
      )
    );
    const y = bls.Fp.create(
      BigInt(
        '0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
      )
    );

    const g1_ = G1Point.fromHex(
      '17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
    );

    deepStrictEqual(g1_.x, x);
    deepStrictEqual(g1_.y, y);
  });

  should('construct point G1 from its uncompressed form (Hex)', () => {
    // Test Zero
    const g1 = G1Point.fromHex(B_192_40);

    deepStrictEqual(g1.x, G1Point.ZERO.x);
    deepStrictEqual(g1.y, G1Point.ZERO.y);
    // Test Non-Zero
    const x = bls.Fp.create(
      BigInt(
        '0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb'
      )
    );
    const y = bls.Fp.create(
      BigInt(
        '0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
      )
    );

    const g1_ = G1Point.fromHex(
      '17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
    );

    deepStrictEqual(g1_.x, x);
    deepStrictEqual(g1_.y, y);
  });

  should('construct point G2 from its uncompressed form (Raw Bytes)', () => {
    // Test Zero
    const g2 = G2Point.fromHex(B_384_40);
    deepStrictEqual(g2.x, G2Point.ZERO.x, 'zero(x)');
    deepStrictEqual(g2.y, G2Point.ZERO.y, 'zero(y)');
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

    const g2_ = G2Point.fromHex(
      '13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801'
    );

    deepStrictEqual(g2_.x, x);
    deepStrictEqual(g2_.y, y);
  });

  should('construct point G2 from its uncompressed form (Hex)', () => {
    // Test Zero
    const g2 = G2Point.fromHex(B_384_40);

    deepStrictEqual(g2.x, G2Point.ZERO.x);
    deepStrictEqual(g2.y, G2Point.ZERO.y);
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

    const g2_ = G2Point.fromHex(
      '13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801'
    );

    deepStrictEqual(g2_.x, x);
    deepStrictEqual(g2_.y, y);
  });

  should('get uncompressed form of point G1 (Raw Bytes)', () => {
    // Test Zero
    deepStrictEqual(G1Point.ZERO.toHex(false), B_192_40);
    // Test Non-Zero
    const x = bls.Fp.create(
      BigInt(
        '0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb'
      )
    );
    const y = bls.Fp.create(
      BigInt(
        '0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
      )
    );
    const g1 = G1Point.fromAffine({ x, y });
    deepStrictEqual(
      g1.toHex(false),
      '17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
    );
  });

  should('get uncompressed form of point G1 (Hex)', () => {
    // Test Zero
    deepStrictEqual(G1Point.ZERO.toHex(false), B_192_40);
    // Test Non-Zero
    const x = bls.Fp.create(
      BigInt(
        '0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb'
      )
    );
    const y = bls.Fp.create(
      BigInt(
        '0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
      )
    );
    const g1 = G1Point.fromAffine({ x, y });
    deepStrictEqual(
      g1.toHex(false),
      '17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
    );
  });

  should('get uncompressed form of point G2 (Raw Bytes)', () => {
    // Test Zero
    deepStrictEqual(G2Point.ZERO.toHex(false), B_384_40);
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
    deepStrictEqual(
      g2.toHex(false),
      '13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801'
    );
  });

  should('get uncompressed form of point G2 (Hex)', () => {
    // Test Zero
    deepStrictEqual(G2Point.ZERO.toHex(false), B_384_40);

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
    deepStrictEqual(
      g2.toHex(false),
      '13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801'
    );
  });

  should('compress and decompress G1 points', async () => {
    const priv = G1Point.fromPrivateKey(42n);
    const publicKey = priv.toHex(true);
    const decomp = G1Point.fromHex(publicKey);
    deepStrictEqual(publicKey, decomp.toHex(true));
  });
  should('not compress and decompress zero G1 point', () => {
    throws(() => G1Point.fromPrivateKey(0n));
  });
  should('compress and decompress G2 points', () => {
    const priv = G2Point.fromPrivateKey(42n);
    const publicKey = priv.toHex(true);
    const decomp = G2Point.fromHex(publicKey);
    deepStrictEqual(publicKey, decomp.toHex(true));
  });
  should('not compress and decompress zero G2 point', () => {
    throws(() => G2Point.fromPrivateKey(0n));
  });
  const VALID_G1 = new G1Point(
    bls.Fp.create(
      3609742242174788176010452839163620388872641749536604986743596621604118973777515189035770461528205168143692110933639n
    ),
    bls.Fp.create(
      1619277690257184054444116778047375363103842303863153349133480657158810226683757397206929105479676799650932070320089n
    ),
    bls.Fp.create(1n)
  );
  const VALID_G1_2 = new G1Point(
    bls.Fp.create(
      1206972466279728255044019580914616126536509750250979180256809997983196363639429409634110400978470384566664128085207n
    ),
    bls.Fp.create(
      2991142246317096160788653339959532007292638191110818490939476869616372888657136539642598243964263069435065725313423n
    ),
    bls.Fp.create(1n)
  );

  const INVALID_G1 = new G1Point(
    bls.Fp.create(
      499001545268060011619089734015590154568173930614466321429631711131511181286230338880376679848890024401335766847607n
    ),
    bls.Fp.create(
      3934582309586258715640230772291917282844636728991757779640464479794033391537662970190753981664259511166946374555673n
    ),
    bls.Fp.create(1n)
  );

  should('aggregate pubkeys', () => {
    const agg = bls.aggregatePublicKeys([VALID_G1, VALID_G1_2]).toAffine();
    deepStrictEqual(
      agg.x,
      2636337749883017793009944726560363863546595464242083394883491066895536780554574413337005575305023872925406746684807n
    );
    deepStrictEqual(
      agg.y,
      2200256264293372104833346444532839112556752874984721583125881868863625579979779052307146195064914375388929781136724n
    );
  });

  should('not aggregate invalid pubkeys', () => {
    throws(() => bls.aggregatePublicKeys([VALID_G1, INVALID_G1]));
  });
  // should aggregate signatures

  should(`produce correct signatures (${G2_VECTORS.length} vectors)`, async () => {
    for (let vector of G2_VECTORS) {
      const [priv, msg, expected] = vector;
      const sig = bls.sign(msg, priv);
      deepStrictEqual(bls.utils.bytesToHex(sig), expected);
    }
  });
  should(`produce correct scalars (${SCALAR_VECTORS.length} vectors)`, async () => {
    const options = {
      p: bls.CURVE.r,
      m: 1,
      expand: false,
    };
    for (let vector of SCALAR_VECTORS) {
      const [okmAscii, expectedHex] = vector;
      const expected = BigInt('0x' + expectedHex);
      const okm = new Uint8Array(okmAscii.split('').map((c) => c.charCodeAt(0)));
      const scalars = bls.utils.hashToField(okm, 1, options);
      deepStrictEqual(scalars[0][0], expected);
    }
  });
});

// Pairing
describe('pairing', () => {
  const { pairing, Fp12 } = bls;
  const G1 = G1Point.BASE;
  const G2 = G2Point.BASE;

  should('creates negative G1 pairing', () => {
    const p1 = pairing(G1, G2);
    const p2 = pairing(G1.negate(), G2);
    deepStrictEqual(Fp12.mul(p1, p2), Fp12.ONE);
  });
  should('creates negative G2 pairing', () => {
    const p2 = pairing(G1.negate(), G2);
    const p3 = pairing(G1, G2.negate());
    deepStrictEqual(p2, p3);
  });
  should('creates proper pairing output order', () => {
    const p1 = pairing(G1, G2);
    const p2 = Fp12.pow(p1, CURVE_ORDER);
    deepStrictEqual(p2, Fp12.ONE);
  });
  should('G1 billinearity', () => {
    const p1 = pairing(G1, G2);
    const p2 = pairing(G1.multiply(2n), G2);
    deepStrictEqual(Fp12.mul(p1, p1), p2);
  });
  should('should not degenerate', () => {
    const p1 = pairing(G1, G2);
    const p2 = pairing(G1.multiply(2n), G2);
    const p3 = pairing(G1, G2.negate());
    notDeepStrictEqual(p1, p2);
    notDeepStrictEqual(p1, p3);
    notDeepStrictEqual(p2, p3);
  });
  should('G2 billinearity', () => {
    const p1 = pairing(G1, G2);
    const p2 = pairing(G1, G2.multiply(2n));
    deepStrictEqual(Fp12.mul(p1, p1), p2);
  });
  should('proper pairing composite check', () => {
    const p1 = pairing(G1.multiply(37n), G2.multiply(27n));
    const p2 = pairing(G1.multiply(999n), G2);
    deepStrictEqual(p1, p2);
  });
  should('vectors from https://github.com/zkcrypto/pairing', () => {
    const p1 = pairing(G1, G2);
    deepStrictEqual(
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
    deepStrictEqual(
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
// hashToCurve
describe('hash-to-curve', () => {
  const DST = 'QUUX-V01-CS02-with-expander-SHA256-128';
  const VECTORS = [
    {
      msg: '',
      len: 0x20,
      expected: '68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235',
    },
    {
      msg: 'abc',
      len: 0x20,
      expected: 'd8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615',
    },
    {
      msg: 'abcdef0123456789',
      len: 0x20,
      expected: 'eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1',
    },
    {
      msg:
        'q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq' +
        'qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq',
      len: 0x20,
      expected: 'b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9',
    },
    {
      msg:
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      len: 0x20,
      expected: '4623227bcc01293b8c130bf771da8c298dede7383243dc0993d2d94823958c4c',
    },
    {
      msg: '',
      len: 0x80,
      expected:
        'af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac0' +
        '6d5e3e29485dadbee0d121587713a3e0dd4d5e69e93eb7cd4f5df4' +
        'cd103e188cf60cb02edc3edf18eda8576c412b18ffb658e3dd6ec8' +
        '49469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472' +
        'c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced',
    },
    {
      msg: 'abc',
      len: 0x80,
      expected:
        'abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2' +
        'fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b' +
        '664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221' +
        'b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425' +
        'cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40',
    },
    {
      msg: 'abcdef0123456789',
      len: 0x80,
      expected:
        'ef904a29bffc4cf9ee82832451c946ac3c8f8058ae97d8d6' +
        '29831a74c6572bd9ebd0df635cd1f208e2038e760c4994984ce73f' +
        '0d55ea9f22af83ba4734569d4bc95e18350f740c07eef653cbb9f8' +
        '7910d833751825f0ebefa1abe5420bb52be14cf489b37fe1a72f7d' +
        'e2d10be453b2c9d9eb20c7e3f6edc5a60629178d9478df',
    },
    {
      msg:
        'q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq' +
        'qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq',
      len: 0x80,
      expected:
        '80be107d0884f0d881bb460322f0443d38bd222db8bd0b0a' +
        '5312a6fedb49c1bbd88fd75d8b9a09486c60123dfa1d73c1cc3169' +
        '761b17476d3c6b7cbbd727acd0e2c942f4dd96ae3da5de368d26b3' +
        '2286e32de7e5a8cb2949f866a0b80c58116b29fa7fabb3ea7d520e' +
        'e603e0c25bcaf0b9a5e92ec6a1fe4e0391d1cdbce8c68a',
    },
    {
      msg:
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      len: 0x80,
      expected:
        '546aff5444b5b79aa6148bd81728704c32decb73a3ba76e9' +
        'e75885cad9def1d06d6792f8a7d12794e90efed817d96920d72889' +
        '6a4510864370c207f99bd4a608ea121700ef01ed879745ee3e4cee' +
        'f777eda6d9e5e38b90c86ea6fb0b36504ba4a45d22e86f6db5dd43' +
        'd98a294bebb9125d5b794e9d2a81181066eb954966a487',
    },
  ];
  for (let i = 0; i < VECTORS.length; i++) {
    const t = VECTORS[i];
    should(`hash_to_field/expand_message_xmd(SHA-256) (${i})`, async () => {
      const p = bls.utils.expandMessageXMD(
        bls.utils.stringToBytes(t.msg),
        bls.utils.stringToBytes(DST),
        t.len
      );
      deepStrictEqual(bls.utils.bytesToHex(p), t.expected);
    });
  }
  const LONG_DST =
    'QUUX-V01-CS02-with-expander-SHA256-128-long-DST-111111' +
    '111111111111111111111111111111111111111111111111111111' +
    '111111111111111111111111111111111111111111111111111111' +
    '111111111111111111111111111111111111111111111111111111' +
    '1111111111111111111111111111111111111111';
  const VECTORS_BIG = [
    {
      msg: '',
      len: 0x20,
      expected: 'e8dc0c8b686b7ef2074086fbdd2f30e3f8bfbd3bdf177f73f04b97ce618a3ed3',
    },
    {
      msg: 'abc',
      len: 0x20,
      expected: '52dbf4f36cf560fca57dedec2ad924ee9c266341d8f3d6afe5171733b16bbb12',
    },
    {
      msg: 'abcdef0123456789',
      len: 0x20,
      expected: '35387dcf22618f3728e6c686490f8b431f76550b0b2c61cbc1ce7001536f4521',
    },
    {
      msg:
        'q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq' +
        'qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq',
      len: 0x20,
      expected: '01b637612bb18e840028be900a833a74414140dde0c4754c198532c3a0ba42bc',
    },
    {
      msg:
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      len: 0x20,
      expected: '20cce7033cabc5460743180be6fa8aac5a103f56d481cf369a8accc0c374431b',
    },
    {
      msg: '',
      len: 0x80,
      expected:
        '14604d85432c68b757e485c8894db3117992fc57e0e136f7' +
        '1ad987f789a0abc287c47876978e2388a02af86b1e8d1342e5ce4f' +
        '7aaa07a87321e691f6fba7e0072eecc1218aebb89fb14a0662322d' +
        '5edbd873f0eb35260145cd4e64f748c5dfe60567e126604bcab1a3' +
        'ee2dc0778102ae8a5cfd1429ebc0fa6bf1a53c36f55dfc',
    },
    {
      msg: 'abc',
      len: 0x80,
      expected:
        '1a30a5e36fbdb87077552b9d18b9f0aee16e80181d5b951d' +
        '0471d55b66684914aef87dbb3626eaabf5ded8cd0686567e503853' +
        'e5c84c259ba0efc37f71c839da2129fe81afdaec7fbdc0ccd4c794' +
        '727a17c0d20ff0ea55e1389d6982d1241cb8d165762dbc39fb0cee' +
        '4474d2cbbd468a835ae5b2f20e4f959f56ab24cd6fe267',
    },
    {
      msg: 'abcdef0123456789',
      len: 0x80,
      expected:
        'd2ecef3635d2397f34a9f86438d772db19ffe9924e28a1ca' +
        'f6f1c8f15603d4028f40891044e5c7e39ebb9b31339979ff33a424' +
        '9206f67d4a1e7c765410bcd249ad78d407e303675918f20f26ce6d' +
        '7027ed3774512ef5b00d816e51bfcc96c3539601fa48ef1c07e494' +
        'bdc37054ba96ecb9dbd666417e3de289d4f424f502a982',
    },
    {
      msg:
        'q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq' +
        'qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq',
      len: 0x80,
      expected:
        'ed6e8c036df90111410431431a232d41a32c86e296c05d42' +
        '6e5f44e75b9a50d335b2412bc6c91e0a6dc131de09c43110d9180d' +
        '0a70f0d6289cb4e43b05f7ee5e9b3f42a1fad0f31bac6a625b3b5c' +
        '50e3a83316783b649e5ecc9d3b1d9471cb5024b7ccf40d41d1751a' +
        '04ca0356548bc6e703fca02ab521b505e8e45600508d32',
    },
    {
      msg:
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      len: 0x80,
      expected:
        '78b53f2413f3c688f07732c10e5ced29a17c6a16f717179f' +
        'fbe38d92d6c9ec296502eb9889af83a1928cd162e845b0d3c5424e' +
        '83280fed3d10cffb2f8431f14e7a23f4c68819d40617589e4c4116' +
        '9d0b56e0e3535be1fd71fbb08bb70c5b5ffed953d6c14bf7618b35' +
        'fc1f4c4b30538236b4b08c9fbf90462447a8ada60be495',
    },
  ];
  for (let i = 0; i < VECTORS_BIG.length; i++) {
    const t = VECTORS_BIG[i];
    should(`hash_to_field/expand_message_xmd(SHA-256) (long DST) (${i})`, async () => {
      const p = bls.utils.expandMessageXMD(
        bls.utils.stringToBytes(t.msg),
        bls.utils.stringToBytes(LONG_DST),
        t.len
      );
      deepStrictEqual(bls.utils.bytesToHex(p), t.expected);
    });
  }
  const DST_512 = 'QUUX-V01-CS02-with-expander-SHA512-256';
  const VECTORS_SHA512 = [
    {
      msg: '',
      len: 0x20,
      expected: '6b9a7312411d92f921c6f68ca0b6380730a1a4d982c507211a90964c394179ba',
    },
    {
      msg: 'abc',
      len: 0x20,
      expected: '0da749f12fbe5483eb066a5f595055679b976e93abe9be6f0f6318bce7aca8dc',
    },
    {
      msg: 'abcdef0123456789',
      len: 0x20,
      expected: '087e45a86e2939ee8b91100af1583c4938e0f5fc6c9db4b107b83346bc967f58',
    },
    {
      msg:
        'q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq' +
        'qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq',
      len: 0x20,
      expected: '7336234ee9983902440f6bc35b348352013becd88938d2afec44311caf8356b3',
    },
    {
      msg:
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      len: 0x20,
      expected: '57b5f7e766d5be68a6bfe1768e3c2b7f1228b3e4b3134956dd73a59b954c66f4',
    },
    {
      msg: '',
      len: 0x80,
      expected:
        '41b037d1734a5f8df225dd8c7de38f851efdb45c372887be' +
        '655212d07251b921b052b62eaed99b46f72f2ef4cc96bfaf254ebb' +
        'bec091e1a3b9e4fb5e5b619d2e0c5414800a1d882b62bb5cd1778f' +
        '098b8eb6cb399d5d9d18f5d5842cf5d13d7eb00a7cff859b605da6' +
        '78b318bd0e65ebff70bec88c753b159a805d2c89c55961',
    },
    {
      msg: 'abc',
      len: 0x80,
      expected:
        '7f1dddd13c08b543f2e2037b14cefb255b44c83cc397c178' +
        '6d975653e36a6b11bdd7732d8b38adb4a0edc26a0cef4bb4521713' +
        '5456e58fbca1703cd6032cb1347ee720b87972d63fbf232587043e' +
        'd2901bce7f22610c0419751c065922b488431851041310ad659e4b' +
        '23520e1772ab29dcdeb2002222a363f0c2b1c972b3efe1',
    },
    {
      msg: 'abcdef0123456789',
      len: 0x80,
      expected:
        '3f721f208e6199fe903545abc26c837ce59ac6fa45733f1b' +
        'aaf0222f8b7acb0424814fcb5eecf6c1d38f06e9d0a6ccfbf85ae6' +
        '12ab8735dfdf9ce84c372a77c8f9e1c1e952c3a61b7567dd069301' +
        '6af51d2745822663d0c2367e3f4f0bed827feecc2aaf98c949b5ed' +
        '0d35c3f1023d64ad1407924288d366ea159f46287e61ac',
    },
    {
      msg:
        'q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq' +
        'qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq',
      len: 0x80,
      expected:
        'b799b045a58c8d2b4334cf54b78260b45eec544f9f2fb5bd' +
        '12fb603eaee70db7317bf807c406e26373922b7b8920fa29142703' +
        'dd52bdf280084fb7ef69da78afdf80b3586395b433dc66cde048a2' +
        '58e476a561e9deba7060af40adf30c64249ca7ddea79806ee5beb9' +
        'a1422949471d267b21bc88e688e4014087a0b592b695ed',
    },
    {
      msg:
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      len: 0x80,
      expected:
        '05b0bfef265dcee87654372777b7c44177e2ae4c13a27f10' +
        '3340d9cd11c86cb2426ffcad5bd964080c2aee97f03be1ca18e30a' +
        '1f14e27bc11ebbd650f305269cc9fb1db08bf90bfc79b42a952b46' +
        'daf810359e7bc36452684784a64952c343c52e5124cd1f71d474d5' +
        '197fefc571a92929c9084ffe1112cf5eea5192ebff330b',
    },
  ];
  for (let i = 0; i < VECTORS_SHA512.length; i++) {
    const t = VECTORS_SHA512[i];
    should(`hash_to_field/expand_message_xmd(SHA-256) (long DST) (${i})`, async () => {
      const p = bls.utils.expandMessageXMD(
        bls.utils.stringToBytes(t.msg),
        bls.utils.stringToBytes(DST_512),
        t.len,
        sha512
      );
      deepStrictEqual(bls.utils.bytesToHex(p), t.expected);
    });
  }

  // Point G1
  const VECTORS_G1 = [
    {
      msg: bls.utils.stringToBytes(''),
      expected:
        '0576730ab036cbac1d95b38dca905586f28d0a59048db4e8778782d89bff856ddef89277ead5a21e2975c4a6e3d8c79e' +
        '1273e568bebf1864393c517f999b87c1eaa1b8432f95aea8160cd981b5b05d8cd4a7cf00103b6ef87f728e4b547dd7ae',
    },
    {
      msg: bls.utils.stringToBytes('abc'),
      expected:
        '061daf0cc00d8912dac1d4cf5a7c32fca97f8b3bf3f805121888e5eb89f77f9a9f406569027ac6d0e61b1229f42c43d6' +
        '0de1601e5ba02cb637c1d35266f5700acee9850796dc88e860d022d7b9e7e3dce5950952e97861e5bb16d215c87f030d',
    },
    {
      msg: bls.utils.stringToBytes('abcdef0123456789'),
      expected:
        '0fb3455436843e76079c7cf3dfef75e5a104dfe257a29a850c145568d500ad31ccfe79be9ae0ea31a722548070cf98cd' +
        '177989f7e2c751658df1b26943ee829d3ebcf131d8f805571712f3a7527ee5334ecff8a97fc2a50cea86f5e6212e9a57',
    },
    {
      msg: bls.utils.stringToBytes(
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
      ),
      expected:
        '0514af2137c1ae1d78d5cb97ee606ea142824c199f0f25ac463a0c78200de57640d34686521d3e9cf6b3721834f8a038' +
        '047a85d6898416a0899e26219bca7c4f0fa682717199de196b02b95eaf9fb55456ac3b810e78571a1b7f5692b7c58ab6',
    },
  ];
  for (let i = 0; i < VECTORS_G1.length; i++) {
    const t = VECTORS_G1[i];
    should(`hashToCurve/G1 Killic (${i})`, () => {
      const p = bls.hashToCurve.G1.hashToCurve(t.msg, {
        DST: 'BLS12381G1_XMD:SHA-256_SSWU_RO_TESTGEN',
      });
      deepStrictEqual(p.toHex(false), t.expected);
    });
  }
  const VECTORS_G1_RO = [
    {
      msg: bls.utils.stringToBytes(''),
      expected:
        '052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1' +
        '08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265',
    },
    {
      msg: bls.utils.stringToBytes('abc'),
      expected:
        '03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903' +
        '0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885d',
    },
    {
      msg: bls.utils.stringToBytes('abcdef0123456789'),
      expected:
        '11e0b079dea29a68f0383ee94fed1b940995272407e3bb916bbf268c263ddd57a6a27200a784cbc248e84f357ce82d98' +
        '03a87ae2caf14e8ee52e51fa2ed8eefe80f02457004ba4d486d6aa1f517c0889501dc7413753f9599b099ebcbbd2d709',
    },
    {
      msg: bls.utils.stringToBytes(
        'q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq' +
          'qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq'
      ),
      expected:
        '15f68eaa693b95ccb85215dc65fa81038d69629f70aeee0d0f677cf22285e7bf58d7cb86eefe8f2e9bc3f8cb84fac488' +
        '1807a1d50c29f430b8cafc4f8638dfeeadf51211e1602a5f184443076715f91bb90a48ba1e370edce6ae1062f5e6dd38',
    },
    {
      msg: bls.utils.stringToBytes(
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
      ),
      expected:
        '082aabae8b7dedb0e78aeb619ad3bfd9277a2f77ba7fad20ef6aabdc6c31d19ba5a6d12283553294c1825c4b3ca2dcfe' +
        '05b84ae5a942248eea39e1d91030458c40153f3b654ab7872d779ad1e942856a20c438e8d99bc8abfbf74729ce1f7ac8',
    },
  ];
  for (let i = 0; i < VECTORS_G1_RO.length; i++) {
    const t = VECTORS_G1_RO[i];
    should(`hashToCurve/G1 (BLS12381G1_XMD:SHA-256_SSWU_RO_) (${i})`, () => {
      const p = bls.hashToCurve.G1.hashToCurve(t.msg, {
        DST: 'QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_',
      });
      deepStrictEqual(p.toHex(false), t.expected);
    });
  }
  const VECTORS_G1_NU = [
    {
      msg: bls.utils.stringToBytes(''),
      expected:
        '184bb665c37ff561a89ec2122dd343f20e0f4cbcaec84e3c3052ea81d1834e192c426074b02ed3dca4e7676ce4ce48ba' +
        '04407b8d35af4dacc809927071fc0405218f1401a6d15af775810e4e460064bcc9468beeba82fdc751be70476c888bf3',
    },
    {
      msg: bls.utils.stringToBytes('abc'),
      expected:
        '009769f3ab59bfd551d53a5f846b9984c59b97d6842b20a2c565baa167945e3d026a3755b6345df8ec7e6acb6868ae6d' +
        '1532c00cf61aa3d0ce3e5aa20c3b531a2abd2c770a790a2613818303c6b830ffc0ecf6c357af3317b9575c567f11cd2c',
    },
    {
      msg: bls.utils.stringToBytes('abcdef0123456789'),
      expected:
        '1974dbb8e6b5d20b84df7e625e2fbfecb2cdb5f77d5eae5fb2955e5ce7313cae8364bc2fff520a6c25619739c6bdcb6a' +
        '15f9897e11c6441eaa676de141c8d83c37aab8667173cbe1dfd6de74d11861b961dccebcd9d289ac633455dfcc7013a3',
    },
    {
      msg: bls.utils.stringToBytes(
        'q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq' +
          'qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq'
      ),
      expected:
        '0a7a047c4a8397b3446450642c2ac64d7239b61872c9ae7a59707a8f4f950f101e766afe58223b3bff3a19a7f754027c' +
        '1383aebba1e4327ccff7cf9912bda0dbc77de048b71ef8c8a81111d71dc33c5e3aa6edee9cf6f5fe525d50cc50b77cc9',
    },
    {
      msg: bls.utils.stringToBytes(
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
      ),
      expected:
        '0e7a16a975904f131682edbb03d9560d3e48214c9986bd50417a77108d13dc957500edf96462a3d01e62dc6cd468ef11' +
        '0ae89e677711d05c30a48d6d75e76ca9fb70fe06c6dd6ff988683d89ccde29ac7d46c53bb97a59b1901abf1db66052db',
    },
  ];
  for (let i = 0; i < VECTORS_G1_NU.length; i++) {
    const t = VECTORS_G1_NU[i];
    should(`hashToCurve/G1 (BLS12381G1_XMD:SHA-256_SSWU_NU_) (${i})`, () => {
      const p = bls.hashToCurve.G1.encodeToCurve(t.msg, {
        DST: 'QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_NU_',
      });
      deepStrictEqual(p.toHex(false), t.expected);
    });
  }
  const VECTORS_ENCODE_G1 = [
    {
      msg: bls.utils.stringToBytes(''),
      expected:
        '1223effdbb2d38152495a864d78eee14cb0992d89a241707abb03819a91a6d2fd65854ab9a69e9aacb0cbebfd490732c' +
        '0f925d61e0b235ecd945cbf0309291878df0d06e5d80d6b84aa4ff3e00633b26f9a7cb3523ef737d90e6d71e8b98b2d5',
    },
    {
      msg: bls.utils.stringToBytes('abc'),
      expected:
        '179d3fd0b4fb1da43aad06cea1fb3f828806ddb1b1fa9424b1e3944dfdbab6e763c42636404017da03099af0dcca0fd6' +
        '0d037cb1c6d495c0f5f22b061d23f1be3d7fe64d3c6820cfcd99b6b36fa69f7b4c1f4addba2ae7aa46fb25901ab483e4',
    },
    {
      msg: bls.utils.stringToBytes('abcdef0123456789'),
      expected:
        '15aa66c77eded1209db694e8b1ba49daf8b686733afaa7b68c683d0b01788dfb0617a2e2d04c0856db4981921d3004af' +
        '0952bb2f61739dd1d201dd0a79d74cda3285403d47655ee886afe860593a8a4e51c5b77a22d2133e3a4280eaaaa8b788',
    },
    {
      msg: bls.utils.stringToBytes(
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
      ),
      expected:
        '06328ce5106e837935e8da84bd9af473422e62492930aa5f460369baad9545defa468d9399854c23a75495d2a80487ee' +
        '094bfdfe3e552447433b5a00967498a3f1314b86ce7a7164c8a8f4131f99333b30a574607e301d5f774172c627fd0bca',
    },
  ];
  for (let i = 0; i < VECTORS_ENCODE_G1.length; i++) {
    const t = VECTORS_ENCODE_G1[i];
    should(`hashToCurve/G1 (Killic, encodeToCurve) (${i})`, () => {
      const p = bls.hashToCurve.G1.encodeToCurve(t.msg, {
        DST: 'BLS12381G1_XMD:SHA-256_SSWU_NU_TESTGEN',
      });
      deepStrictEqual(p.toHex(false), t.expected);
    });
  }
  // Point G2
  const VECTORS_G2 = [
    {
      msg: bls.utils.stringToBytes(''),
      expected:
        '0fbdae26f9f9586a46d4b0b70390d09064ef2afe5c99348438a3c7d9756471e015cb534204c1b6824617a85024c772dc' +
        '0a650bd36ae7455cb3fe5d8bb1310594551456f5c6593aec9ee0c03d2f6cb693bd2c5e99d4e23cbaec767609314f51d3' +
        '02e5cf8f9b7348428cc9e66b9a9b36fe45ba0b0a146290c3a68d92895b1af0e1f2d9f889fb412670ae8478d8abd4c5aa' +
        '0d8d49e7737d8f9fc5cef7c4b8817633103faf2613016cb86a1f3fc29968fe2413e232d9208d2d74a89bf7a48ac36f83',
    },
    {
      msg: bls.utils.stringToBytes('abc'),
      expected:
        '03578447618463deb106b60e609c6f7cc446dc6035f84a72801ba17c94cd800583b493b948eff0033f09086fdd7f6175' +
        '1953ce6d4267939c7360756d9cca8eb34aac4633ef35369a7dc249445069888e7d1b3f9d2e75fbd468fbcbba7110ea02' +
        '0184d26779ae9d4670aca9b267dbd4d3b30443ad05b8546d36a195686e1ccc3a59194aea05ed5bce7c3144a29ec047c4' +
        '0882ab045b8fe4d7d557ebb59a63a35ac9f3d312581b509af0f8eaa2960cbc5e1e36bb969b6e22980b5cbdd0787fcf4e',
    },
    {
      msg: bls.utils.stringToBytes('abcdef0123456789'),
      expected:
        '195fad48982e186ce3c5c82133aefc9b26d55979b6f530992a8849d4263ec5d57f7a181553c8799bcc83da44847bdc8d' +
        '17b461fc3b96a30c2408958cbfa5f5927b6063a8ad199d5ebf2d7cdeffa9c20c85487204804fab53f950b2f87db365aa' +
        '005cdf3d984e3391e7e969276fb4bc02323c5924a4449af167030d855acc2600cf3d4fab025432c6d868c79571a95bef' +
        '174a3473a3af2d0302b9065e895ca4adba4ece6ce0b41148ba597001abb152f852dd9a96fb45c9de0a43d944746f833e',
    },
    {
      msg: bls.utils.stringToBytes(
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
      ),
      expected:
        '123b6bd9feeba26dd4ad00f8bfda2718c9700dc093ea5287d7711844644eb981848316d3f3f57d5d3a652c6cdc816aca' +
        '0a162306f3b0f2bb326f0c4fb0e1fea020019c3af796dcd1d7264f50ddae94cacf3cade74603834d44b9ab3d5d0a6c98' +
        '05483f3b96d9252dd4fc0868344dfaf3c9d145e3387db23fa8e449304fab6a7b6ec9c15f05c0a1ea66ff0efcc03e001a' +
        '15c1d4f1a685bb63ee67ca1fd96155e3d091e852a684b78d085fd34f6091e5249ddddbdcf2e7ec82ce6c04c63647eeb7',
    },
  ];
  for (let i = 0; i < VECTORS_G2.length; i++) {
    const t = VECTORS_G2[i];
    should(`hashToCurve/G2 Killic (${i})`, () => {
      const p = bls.hashToCurve.G2.hashToCurve(t.msg, {
        DST: 'BLS12381G2_XMD:SHA-256_SSWU_RO_TESTGEN',
      });
      deepStrictEqual(p.toHex(false), t.expected);
    });
  }
  const VECTORS_G2_RO = [
    {
      msg: bls.utils.stringToBytes(''),
      expected:
        '05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d' +
        '0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a' +
        '12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d6' +
        '0503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd92',
    },
    {
      msg: bls.utils.stringToBytes('abc'),
      expected:
        '139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd8' +
        '02c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6' +
        '00aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1e1ce70dd94a733534f106d4cec0eddd16' +
        '1787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244aeb197642555a0645fb87bf7466b2ba48',
    },
    {
      msg: bls.utils.stringToBytes('abcdef0123456789'),
      expected:
        '190d119345b94fbd15497bcba94ecf7db2cbfd1e1fe7da034d26cbba169fb3968288b3fafb265f9ebd380512a71c3f2c' +
        '121982811d2491fde9ba7ed31ef9ca474f0e1501297f68c298e9f4c0028add35aea8bb83d53c08cfc007c1e005723cd0' +
        '0bb5e7572275c567462d91807de765611490205a941a5a6af3b1691bfe596c31225d3aabdf15faff860cb4ef17c7c3be' +
        '05571a0f8d3c08d094576981f4a3b8eda0a8e771fcdcc8ecceaf1356a6acf17574518acb506e435b639353c2e14827c8',
    },
    {
      msg: bls.utils.stringToBytes(
        'q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq' +
          'qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq'
      ),
      expected:
        '0934aba516a52d8ae479939a91998299c76d39cc0c035cd18813bec433f587e2d7a4fef038260eef0cef4d02aae3eb91' +
        '19a84dd7248a1066f737cc34502ee5555bd3c19f2ecdb3c7d9e24dc65d4e25e50d83f0f77105e955d78f4762d33c17da' +
        '09bcccfa036b4847c9950780733633f13619994394c23ff0b32fa6b795844f4a0673e20282d07bc69641cee04f5e5662' +
        '14f81cd421617428bc3b9fe25afbb751d934a00493524bc4e065635b0555084dd54679df1536101b2c979c0152d09192',
    },
    {
      msg: bls.utils.stringToBytes(
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
      ),
      expected:
        '11fca2ff525572795a801eed17eb12785887c7b63fb77a42be46ce4a34131d71f7a73e95fee3f812aea3de78b4d01569' +
        '01a6ba2f9a11fa5598b2d8ace0fbe0a0eacb65deceb476fbbcb64fd24557c2f4b18ecfc5663e54ae16a84f5ab7f62534' +
        '03a47f8e6d1763ba0cad63d6114c0accbef65707825a511b251a660a9b3994249ae4e63fac38b23da0c398689ee2ab52' +
        '0b6798718c8aed24bc19cb27f866f1c9effcdbf92397ad6448b5c9db90d2b9da6cbabf48adc1adf59a1a28344e79d57e',
    },
  ];
  for (let i = 0; i < VECTORS_G2_RO.length; i++) {
    const t = VECTORS_G2_RO[i];
    should(`hashToCurve/G2 (BLS12381G2_XMD:SHA-256_SSWU_RO_) (${i})`, () => {
      const p = bls.hashToCurve.G2.hashToCurve(t.msg, {
        DST: 'QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_',
      });
      deepStrictEqual(p.toHex(false), t.expected);
    });
  }
  const VECTORS_G2_NU = [
    {
      msg: bls.utils.stringToBytes(''),
      expected:
        '126b855e9e69b1f691f816e48ac6977664d24d99f8724868a184186469ddfd4617367e94527d4b74fc86413483afb35b' +
        '00e7f4568a82b4b7dc1f14c6aaa055edf51502319c723c4dc2688c7fe5944c213f510328082396515734b6612c4e7bb7' +
        '1498aadcf7ae2b345243e281ae076df6de84455d766ab6fcdaad71fab60abb2e8b980a440043cd305db09d283c895e3d' +
        '0caead0fd7b6176c01436833c79d305c78be307da5f6af6c133c47311def6ff1e0babf57a0fb5539fce7ee12407b0a42',
    },
    {
      msg: bls.utils.stringToBytes('abc'),
      expected:
        '0296238ea82c6d4adb3c838ee3cb2346049c90b96d602d7bb1b469b905c9228be25c627bffee872def773d5b2a2eb57d' +
        '108ed59fd9fae381abfd1d6bce2fd2fa220990f0f837fa30e0f27914ed6e1454db0d1ee957b219f61da6ff8be0d6441f' +
        '153606c417e59fb331b7ae6bce4fbf7c5190c33ce9402b5ebe2b70e44fca614f3f1382a3625ed5493843d0b0a652fc3f' +
        '033f90f6057aadacae7963b0a0b379dd46750c1c94a6357c99b65f63b79e321ff50fe3053330911c56b6ceea08fee656',
    },
    {
      msg: bls.utils.stringToBytes('abcdef0123456789'),
      expected:
        '0da75be60fb6aa0e9e3143e40c42796edf15685cafe0279afd2a67c3dff1c82341f17effd402e4f1af240ea90f4b659b' +
        '038af300ef34c7759a6caaa4e69363cafeed218a1f207e93b2c70d91a1263d375d6730bd6b6509dcac3ba5b567e85bf3' +
        '0492f4fed741b073e5a82580f7c663f9b79e036b70ab3e51162359cec4e77c78086fe879b65ca7a47d34374c8315ac5e' +
        '19b148cbdf163cf0894f29660d2e7bfb2b68e37d54cc83fd4e6e62c020eaa48709302ef8e746736c0e19342cc1ce3df4',
    },
    {
      msg: bls.utils.stringToBytes(
        'q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq' +
          'qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq'
      ),
      expected:
        '12c8c05c1d5fc7bfa847f4d7d81e294e66b9a78bc9953990c358945e1f042eedafce608b67fdd3ab0cb2e6e263b9b1ad' +
        '0c5ae723be00e6c3f0efe184fdc0702b64588fe77dda152ab13099a3bacd3876767fa7bbad6d6fd90b3642e902b208f9' +
        '11c624c56dbe154d759d021eec60fab3d8b852395a89de497e48504366feedd4662d023af447d66926a28076813dd646' +
        '04e77ddb3ede41b5ec4396b7421dd916efc68a358a0d7425bddd253547f2fb4830522358491827265dfc5bcc1928a569',
    },
    {
      msg: bls.utils.stringToBytes(
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
      ),
      expected:
        '1565c2f625032d232f13121d3cfb476f45275c303a037faa255f9da62000c2c864ea881e2bcddd111edc4a3c0da3e88d' +
        '0ea4e7c33d43e17cc516a72f76437c4bf81d8f4eac69ac355d3bf9b71b8138d55dc10fd458be115afa798b55dac34be1' +
        '0f8991d2a1ad662e7b6f58ab787947f1fa607fce12dde171bc17903b012091b657e15333e11701edcf5b63ba2a561247' +
        '043b6f5fe4e52c839148dc66f2b3751e69a0f6ebb3d056d6465d50d4108543ecd956e10fa1640dfd9bc0030cc2558d28',
    },
  ];
  for (let i = 0; i < VECTORS_G2_NU.length; i++) {
    const t = VECTORS_G2_NU[i];
    should(`hashToCurve/G2 (BLS12381G2_XMD:SHA-256_SSWU_NU_) (${i})`, () => {
      const p = bls.hashToCurve.G2.encodeToCurve(t.msg, {
        DST: 'QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_NU_',
      });
      deepStrictEqual(p.toHex(false), t.expected);
    });
  }
  const VECTORS_ENCODE_G2 = [
    {
      msg: bls.utils.stringToBytes(''),
      expected:
        '0d4333b77becbf9f9dfa3ca928002233d1ecc854b1447e5a71f751c9042d000f42db91c1d6649a5e0ad22bd7bf7398b8' +
        '027e4bfada0b47f9f07e04aec463c7371e68f2fd0c738cd517932ea3801a35acf09db018deda57387b0f270f7a219e4d' +
        '0cc76dc777ea0d447e02a41004f37a0a7b1fafb6746884e8d9fc276716ccf47e4e0899548a2ec71c2bdf1a2a50e876db' +
        '053674cba9ef516ddc218fedb37324e6c47de27f88ab7ef123b006127d738293c0277187f7e2f80a299a24d84ed03da7',
    },
    {
      msg: bls.utils.stringToBytes('abc'),
      expected:
        '18f0f87b40af67c056915dbaf48534c592524e82c1c2b50c3734d02c0172c80df780a60b5683759298a3303c5d942778' +
        '09349f1cb5b2e55489dcd45a38545343451cc30a1681c57acd4fb0a6db125f8352c09f4a67eb7d1d8242cb7d3405f97b' +
        '10a2ba341bc689ab947b7941ce6ef39be17acaab067bd32bd652b471ab0792c53a2bd03bdac47f96aaafe96e441f63c0' +
        '02f2d9deb2c7742512f5b8230bf0fd83ea42279d7d39779543c1a43b61c885982b611f6a7a24b514995e8a098496b811',
    },
    {
      msg: bls.utils.stringToBytes('abcdef0123456789'),
      expected:
        '19808ec5930a53c7cf5912ccce1cc33f1b3dcff24a53ce1cc4cba41fd6996dbed4843ccdd2eaf6a0cd801e562718d163' +
        '149fe43777d34f0d25430dea463889bd9393bdfb4932946db23671727081c629ebb98a89604f3433fba1c67d356a4af7' +
        '04783e391c30c83f805ca271e353582fdf19d159f6a4c39b73acbb637a9b8ac820cfbe2738d683368a7c07ad020e3e33' +
        '04c0d6793a766233b2982087b5f4a254f261003ccb3262ea7c50903eecef3e871d1502c293f9e063d7d293f6384f4551',
    },
    {
      msg: bls.utils.stringToBytes(
        'a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
      ),
      expected:
        '0b8e0094c886487870372eb6264613a6a087c7eb9804fab789be4e47a57b29eb19b1983a51165a1b5eb025865e9fc63a' +
        '0804152cbf8474669ad7d1796ab92d7ca21f32d8bed70898a748ed4e4e0ec557069003732fc86866d938538a2ae95552' +
        '14c80f068ece15a3936bb00c3c883966f75b4e8d9ddde809c11f781ab92d23a2d1d103ad48f6f3bb158bf3e3a4063449' +
        '09e5c8242dd7281ad32c03fe4af3f19167770016255fb25ad9b67ec51d62fade31a1af101e8f6172ec2ee8857662be3a',
    },
  ];
  for (let i = 0; i < VECTORS_ENCODE_G2.length; i++) {
    const t = VECTORS_ENCODE_G2[i];
    should(`hashToCurve/G2 (Killic, encodeToCurve) (${i})`, () => {
      const p = bls.hashToCurve.G2.encodeToCurve(t.msg, {
        DST: 'BLS12381G2_XMD:SHA-256_SSWU_NU_TESTGEN',
      });
      deepStrictEqual(p.toHex(false), t.expected);
    });
  }
});

describe('verify()', () => {
  should('verify signed message', async () => {
    for (let i = 0; i < NUM_RUNS; i++) {
      const [priv, msg] = G2_VECTORS[i];
      const sig = bls.sign(msg, priv);
      const pub = bls.getPublicKey(priv);
      const res = bls.verify(sig, msg, pub);
      deepStrictEqual(res, true, `${priv}-${msg}`);
    }
  });
  should('not verify signature with wrong message', async () => {
    for (let i = 0; i < NUM_RUNS; i++) {
      const [priv, msg] = G2_VECTORS[i];
      const invMsg = G2_VECTORS[i + 1][1];
      const sig = bls.sign(msg, priv);
      const pub = bls.getPublicKey(priv);
      const res = bls.verify(sig, invMsg, pub);
      deepStrictEqual(res, false);
    }
  });
  should('not verify signature with wrong key', async () => {
    for (let i = 0; i < NUM_RUNS; i++) {
      const [priv, msg] = G2_VECTORS[i];
      const sig = bls.sign(msg, priv);
      const invPriv = G2_VECTORS[i + 1][1].padStart(64, '0');
      const invPub = bls.getPublicKey(invPriv);
      const res = bls.verify(sig, msg, invPub);
      deepStrictEqual(res, false);
    }
  });
  describe('batch', () => {
    should('verify multi-signature', async () => {
      await fc.assert(
        fc.asyncProperty(FC_MSG_5, FC_BIGINT_5, async (messages, privateKeys) => {
          privateKeys = privateKeys.slice(0, messages.length);
          messages = messages.slice(0, privateKeys.length);
          const publicKey = privateKeys.map(getPubKey);
          const signatures = messages.map((message, i) => bls.sign(message, privateKeys[i]));
          const aggregatedSignature = bls.aggregateSignatures(signatures);
          deepStrictEqual(bls.verifyBatch(aggregatedSignature, messages, publicKey), true);
        })
      );
    });
    should('batch verify multi-signatures', async () => {
      await fc.assert(
        fc.asyncProperty(
          FC_MSG_5,
          FC_MSG_5,
          FC_BIGINT_5,
          async (messages, wrongMessages, privateKeys) => {
            privateKeys = privateKeys.slice(0, messages.length);
            messages = messages.slice(0, privateKeys.length);
            wrongMessages = messages.map((a, i) =>
              typeof wrongMessages[i] === 'undefined' ? a : wrongMessages[i]
            );
            const publicKey = privateKeys.map(getPubKey);
            const signatures = messages.map((message, i) => bls.sign(message, privateKeys[i]));
            const aggregatedSignature = bls.aggregateSignatures(signatures);
            deepStrictEqual(
              bls.verifyBatch(aggregatedSignature, wrongMessages, publicKey),
              messages.every((m, i) => m === wrongMessages[i])
            );
          }
        )
      );
    });
    should('not verify multi-signature with wrong public keys', async () => {
      await fc.assert(
        fc.asyncProperty(
          FC_MSG_5,
          FC_BIGINT_5,
          FC_BIGINT_5,
          async (messages, privateKeys, wrongPrivateKeys) => {
            privateKeys = privateKeys.slice(0, messages.length);
            wrongPrivateKeys = privateKeys.map((a, i) =>
              wrongPrivateKeys[i] !== undefined ? wrongPrivateKeys[i] : a
            );
            messages = messages.slice(0, privateKeys.length);
            const wrongPublicKeys = wrongPrivateKeys.map(getPubKey);
            const signatures = messages.map((message, i) => bls.sign(message, privateKeys[i]));
            const aggregatedSignature = bls.aggregateSignatures(signatures);
            deepStrictEqual(
              bls.verifyBatch(aggregatedSignature, messages, wrongPublicKeys),
              wrongPrivateKeys.every((p, i) => p === privateKeys[i])
            );
          }
        )
      );
    });
    should('verify multi-signature as simple signature', async () => {
      await fc.assert(
        fc.asyncProperty(FC_MSG, FC_BIGINT_5, async (message, privateKeys) => {
          const publicKey = privateKeys.map(getPubKey);
          const signatures = privateKeys.map((privateKey) => bls.sign(message, privateKey));
          const aggregatedSignature = bls.aggregateSignatures(signatures);
          const aggregatedPublicKey = bls.aggregatePublicKeys(publicKey);
          deepStrictEqual(bls.verify(aggregatedSignature, message, aggregatedPublicKey), true);
        })
      );
    });
    should('not verify wrong multi-signature as simple signature', async () => {
      await fc.assert(
        fc.asyncProperty(
          FC_MSG,
          FC_MSG,
          FC_BIGINT_5,
          async (message, wrongMessage, privateKeys) => {
            const publicKey = privateKeys.map(getPubKey);
            const signatures = privateKeys.map((privateKey) => bls.sign(message, privateKey));
            const aggregatedSignature = bls.aggregateSignatures(signatures);
            const aggregatedPublicKey = bls.aggregatePublicKeys(publicKey);
            deepStrictEqual(
              bls.verify(aggregatedSignature, wrongMessage, aggregatedPublicKey),
              message === wrongMessage
            );
          }
        )
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

  const Fp12 = bls.Fp12;

  should('Killic based/Pairing', () => {
    const t = bls.pairing(G1Point.BASE, G2Point.BASE);
    deepStrictEqual(
      bls.utils.bytesToHex(Fp12.toBytes(t)),
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
  should('Killic based/Pairing (big)', () => {
    let p1 = G1Point.BASE;
    let p2 = G2Point.BASE;
    for (let v of pairingVectors) {
      deepStrictEqual(
        bls.utils.bytesToHex(Fp12.toBytes(bls.pairing(p1, p2))),
        // Reverse order
        v.match(/.{96}/g).reverse().join('')
      );
      p1 = p1.add(G1Point.BASE);
      p2 = p2.add(G2Point.BASE);
    }
  });

  should(`zkcrypto/G1/compressed`, () => {
    let p1 = G1Point.ZERO;
    for (let i = 0; i < zkVectors.G1_Compressed.length; i++) {
      const t = zkVectors.G1_Compressed[i];
      const P = G1Point.fromHex(t);
      deepStrictEqual(P.toHex(true), t);
      deepStrictEqual(P.equals(p1), true);
      deepStrictEqual(p1.toHex(true), t);
      p1 = p1.add(G1Point.BASE);
      if (i) {
        deepStrictEqual(G1Point.BASE.multiply(BigInt(i)).toHex(true), t);
        deepStrictEqual(G1Point.BASE.multiplyUnsafe(BigInt(i)).toHex(true), t);
        deepStrictEqual(G1Point.BASE.multiply(BigInt(i)).toHex(true), t);
      }
    }
  });
  should(`zkcrypto/G1/uncompressed`, () => {
    let p1 = G1Point.ZERO;
    for (let i = 0; i < zkVectors.G1_Uncompressed.length; i++) {
      const t = zkVectors.G1_Uncompressed[i];
      const P = G1Point.fromHex(t);
      deepStrictEqual(P.toHex(false), t);
      deepStrictEqual(P.equals(p1), true);
      deepStrictEqual(p1.toHex(false), t);
      p1 = p1.add(G1Point.BASE);
      if (i) {
        deepStrictEqual(G1Point.BASE.multiply(BigInt(i)).toHex(false), t);
        deepStrictEqual(G1Point.BASE.multiplyUnsafe(BigInt(i)).toHex(false), t);
        deepStrictEqual(G1Point.BASE.multiply(BigInt(i)).toHex(false), t);
      }
    }
  });
  should(`zkcrypto/G2/compressed`, () => {
    let p1 = G2Point.ZERO;
    for (let i = 0; i < zkVectors.G2_Compressed.length; i++) {
      const t = zkVectors.G2_Compressed[i];
      const P = G2Point.fromHex(t);
      deepStrictEqual(P.toHex(true), t);
      deepStrictEqual(P.equals(p1), true);
      deepStrictEqual(p1.toHex(true), t);
      p1 = p1.add(G2Point.BASE);
      if (i) {
        let n = BigInt(i);
        deepStrictEqual(G2Point.BASE.multiply(n).toHex(true), t);
        deepStrictEqual(G2Point.BASE.multiplyUnsafe(n).toHex(true), t);
        deepStrictEqual(G2Point.BASE.multiply(n).toHex(true), t);
      }
    }
  });
  should(`zkcrypto/G2/uncompressed`, () => {
    let p1 = G2Point.ZERO;
    for (let i = 0; i < zkVectors.G2_Uncompressed.length; i++) {
      const t = zkVectors.G2_Uncompressed[i];
      const P = G2Point.fromHex(t);
      deepStrictEqual(P.toHex(false), t);
      deepStrictEqual(P.equals(p1), true);
      deepStrictEqual(p1.toHex(false), t);
      p1 = p1.add(G2Point.BASE);
      if (i) {
        deepStrictEqual(G2Point.BASE.multiply(BigInt(i)).toHex(false), t);
        deepStrictEqual(G2Point.BASE.multiplyUnsafe(BigInt(i)).toHex(false), t);
        deepStrictEqual(G2Point.BASE.multiply(BigInt(i)).toHex(false), t);
      }
    }
  });
});

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}

// TODO: merge Fp tests with group tests in basic
