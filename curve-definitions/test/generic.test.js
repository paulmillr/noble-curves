import { deepStrictEqual, throws } from 'assert';
import { should } from 'micro-should';
import * as fc from 'fast-check';
// Generic tests for all curves in package
import { secp192r1, secp224r1, secp256k1, secp256r1, secp384r1, secp521r1 } from '../lib/nist.js';
import { ed25519, ed25519ctx, ed25519ph, ed448, ed448ph } from '../lib/ed.js';
import { starkCurve } from '../lib/starknet.js';
import { pallas, vesta } from '../lib/pasta.js';
import { bn254 } from '../lib/bn.js';

// prettier-ignore
const CURVES = {
  secp192r1, secp224r1, secp256k1, secp256r1, secp384r1, secp521r1,
  ed25519, ed25519ctx, ed25519ph, ed448, ed448ph,
  starkCurve,
  pallas, vesta,
  bn254,
};

for (const name in CURVES) {
  const C = CURVES[name];
  // Generic sanity tests:
  // - group laws:
  //   G*(CURVE.n-1) + 1 = Point.ZERO
  //   G*(CURVE.n-2) + 2 = Point.ZERO
  //   G*(CURVE.n/2).double() = Point.ZERO or Point.BASE?
  //   rand*G + rand2*G = G*(rand+rand mod N)
  // - double works
  //   ZERO.double() == zero
  // - adding zero point works
  // - add(samePoint) works
  // - add(-samePoint) works
  // - 2+2 = 2.double() = 7-5 (should have different Z coordinates, but it is same point)
  // ToAffine: Point.BASE = Extended/Jacobian.toAffine()
  // Property tests:
  // signatures, getSharedKey/etc
  //const FC_BIGINT = fc.bigInt(1n + 1n, C.n - 1n);

  should(`${name}/Basic`, () => {});
  const POINTS = { Point: C.Point, JacobianPoint: C.JacobianPoint, ExtendedPoint: C.ExtendedPoint };
  for (const pointName in POINTS) {
    const p = POINTS[pointName];
    if (!p) continue;

    const G = [p.ZERO, p.BASE];
    for (let i = 2; i < 10; i++) G.push(G[1].multiply(i));
    should(`${name}/${pointName}/Basic`, () => {
      // ... And we dont have it
      //deepStrictEqual(G[2].double().equals(G[4]), true);
      //console.log('Z', G);
    });
  }
}
// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
