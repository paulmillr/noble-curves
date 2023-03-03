import { jubjub, findGroupHash } from '../jubjub.js';
import { describe, should } from 'micro-should';
import { deepStrictEqual, throws } from 'assert';
const Point = jubjub.ExtendedPoint;

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
  should('toHex/fromHex', () => {
    // More than field
    throws(() =>
      Point.fromHex(
        new Uint8Array([
          255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
          255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        ])
      )
    );
    // Multiplicative generator (sqrt == null), not on curve.
    throws(() =>
      Point.fromHex(
        new Uint8Array([
          7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0,
        ])
      )
    );
    const tmp = Point.fromHex(
      new Uint8Array([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,
      ])
    );
    deepStrictEqual(tmp.x, 0x8d51ccce760304d0ec030002760300000001000000000000n);
    deepStrictEqual(tmp.y, 0n);

    const S = G_SPEND.toRawBytes();
    const S2 = G_SPEND.double().toRawBytes();
    const P = G_PROOF.toRawBytes();
    const P2 = G_PROOF.double().toRawBytes();
    const S_exp = Point.fromHex(S);
    const S2_exp = Point.fromHex(S2);
    const P_exp = Point.fromHex(P);
    const P2_exp = Point.fromHex(P2);
    deepStrictEqual(getXY(G_SPEND.toAffine()), getXY(S_exp));
    deepStrictEqual(getXY(G_SPEND.double().toAffine()), getXY(S2_exp));
    deepStrictEqual(getXY(G_PROOF.toAffine()), getXY(P_exp));
    deepStrictEqual(getXY(G_PROOF.double().toAffine()), getXY(P2_exp));
  });

  should('Find generators', () => {
    const spend = findGroupHash(
      new Uint8Array(),
      new Uint8Array([90, 99, 97, 115, 104, 95, 71, 95])
    );
    const proof = findGroupHash(
      new Uint8Array(),
      new Uint8Array([90, 99, 97, 115, 104, 95, 72, 95])
    );
    deepStrictEqual(getXY(spend.toAffine()), getXY(G_SPEND.toAffine()));
    deepStrictEqual(getXY(proof.toAffine()), getXY(G_PROOF.toAffine()));
  });
});

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
