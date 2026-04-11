import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { eddsa, edwards } from '../src/abstract/edwards.ts';
import { babyjubjub, jubjub, jubjub_findGroupHash } from '../src/misc.ts';
const Point = jubjub.Point;

const G_SPEND = new Point(
  0x055f1f24f0f0512287e51c3c5a0a6903fc0baf8711de9eafd7c0e66f69d8d2dbn,
  0x566178b2505fdd52132a5007d80a04652842e78ffb376897588f406278214ed7n,
  0x0141fafa1f11088a3b2007c14d652375888f3b37838ba6bdffae096741ceddfen,
  0x12eada93c0b7d595f5f04f5ebfb4b7d033ef2884136475cab5e41ce17db5be9cn
);
const G_PROOF = new Point(
  0x0174d54ce9fad258a2f8a86a1deabf15c7a2b51106b0fbcd9d29020f78936f71n,
  0x16871d6d877dcd222e4ec3bccb3f37cb1865a2d37dd3a5dcbc032a69b62b4445n,
  0x57a3cd31e496d82bd4aa78bd5ecd751cfb76d54a5d3f4560866379f9fc11c9b3n,
  0x42cc53f6b519d1f4f52c47ff1256463a616c2c2f49ffe77765481eca04c72081n
);

const getXY = (p) => ({ x: p.x, y: p.y });

describe('jubjub', () => {
  should('toBytes/fromBytes', () => {
    // More than field
    throws(() =>
      Point.fromBytes(
        new Uint8Array([
          255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
          255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        ])
      )
    );
    // Multiplicative generator (sqrt == null), not on curve.
    throws(() =>
      Point.fromBytes(
        new Uint8Array([
          7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0,
        ])
      )
    );
    const tmp = Point.fromBytes(
      new Uint8Array([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,
      ])
    );
    eql(tmp.x, 0x8d51ccce760304d0ec030002760300000001000000000000n);
    eql(tmp.y, 0n);

    const S = G_SPEND.toBytes();
    const S2 = G_SPEND.double().toBytes();
    const P = G_PROOF.toBytes();
    const P2 = G_PROOF.double().toBytes();
    const S_exp = Point.fromBytes(S);
    const S2_exp = Point.fromBytes(S2);
    const P_exp = Point.fromBytes(P);
    const P2_exp = Point.fromBytes(P2);
    eql(getXY(G_SPEND.toAffine()), getXY(S_exp));
    eql(getXY(G_SPEND.double().toAffine()), getXY(S2_exp));
    eql(getXY(G_PROOF.toAffine()), getXY(P_exp));
    eql(getXY(G_PROOF.double().toAffine()), getXY(P2_exp));
  });

  should('Find generators', () => {
    const spend = jubjub_findGroupHash(
      Uint8Array.of(),
      Uint8Array.from([90, 99, 97, 115, 104, 95, 71, 95])
    );
    const proof = jubjub_findGroupHash(
      Uint8Array.of(),
      Uint8Array.from([90, 99, 97, 115, 104, 95, 72, 95])
    );
    eql(getXY(spend.toAffine()), getXY(G_SPEND.toAffine()));
    eql(getXY(proof.toAffine()), getXY(G_PROOF.toAffine()));
  });

  should('find-group-hash validates personalization length', () => {
    let err = '';
    try {
      jubjub_findGroupHash(new Uint8Array([]), Uint8Array.of(1));
    } catch (e) {
      err = String(e);
    }
    eql(err, 'RangeError: "personalization" expected Uint8Array of length 8, got length=1');
  });
});

describe('babyjubjub', () => {
  should('sign and verify', () => {
    const seed = new Uint8Array(32).fill(9);
    const msg = new Uint8Array([1, 2, 3]);
    const keys = babyjubjub.keygen(seed);
    const sig = babyjubjub.sign(msg, keys.secretKey);
    eql(babyjubjub.verify(sig, msg, keys.publicKey), true);
  });

  should('reject hashes whose declared outputLen cannot expand the secret key', () => {
    const bad = Object.assign((msg: Uint8Array) => msg.subarray(0, 32), { outputLen: 32 });
    throws(() => eddsa(edwards(babyjubjub.Point.CURVE()), bad), new Error('hash.outputLen must be 64, got 32'));
  });

  should('Point.BASE matches the EIP-2494 subgroup base point B of order l', () => {
    const l = babyjubjub.Point.Fn.ORDER;
    eql(babyjubjub.Point.BASE.toAffine(), {
      x: 5299619240641551281634865583518297030282874472190772894086521144482721001553n,
      y: 16950150798460657717958625567821834550301663161624707787222815936182638968203n,
    });
    eql(
      babyjubjub.Point.BASE.multiplyUnsafe(l - 1n).add(babyjubjub.Point.BASE).equals(babyjubjub.Point.ZERO),
      true
    );
  });
});

should.runWhen(import.meta.url);
