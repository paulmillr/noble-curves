import { randomBytes } from '@noble/hashes/utils.js';
import compare from '@paulmillr/jsbt/benchmark-compare.js';
import { bls12_381 } from '../src/bls12-381.ts';
import { ed25519, ed25519_hasher } from '../src/ed25519.ts';
import { ed448, ed448_hasher } from '../src/ed448.ts';
import { p256, p256_hasher, p384, p384_hasher, p521, p521_hasher } from '../src/nist.ts';
import { secp256k1, secp256k1_hasher } from '../src/secp256k1.ts';
import { bytesToHex } from '../src/utils.ts';
import { generateData } from './_shared.ts';

(async () => {
  const baseCurves = { ed25519, ed448, secp256k1, p256, p384, p521 };
  const hashToCurves = {
    ed25519: ed25519_hasher,
    ed448: ed448_hasher,
    p256: p256_hasher,
    p384: p384_hasher,
    p521: p521_hasher,
    secp256k1: secp256k1_hasher,
  };
  const curves = {};
  const scalar = 2n ** 180n - 15820n;

  for (const [name, curve] of Object.entries(baseCurves)) {
    curve.Point.BASE.precompute(6, false);
    const d = generateData(curve);
    const pubHex = bytesToHex(d.pub);

    curves[name] = {
      fromHex: () => d.Point.fromHex(pubHex),
      hashToCurve: () => hashToCurves[name].hashToCurve(d.msg),
      Point_add: () => d.point.add(d.point),
      Point_mul: () => d.point.multiply(scalar),
      Point_mulUns: () => d.point.multiplyUnsafe(scalar),
    };
  }

  for (const [name, group] of [
    ['bls12_381 G1', bls12_381.G1],
    ['bls12_381 G2', bls12_381.G2],
  ] as const) {
    const Point = group.Point;
    Point.BASE.precompute(6, false);
    const point = Point.BASE.multiply(scalar);
    const pubHex = point.toHex(true);
    const msg = randomBytes(32);

    curves[name] = {
      fromHex: () => Point.fromHex(pubHex),
      hashToCurve: () => group.hashToCurve(msg),
      Point_add: () => point.add(point),
      Point_mul: () => point.multiply(scalar),
      Point_mulUns: () => point.multiplyUnsafe(scalar),
    };
  }

  await compare('curve point operations', curves, {
    levels: ['curve', 'algorithm'],
    order: ['algorithm'],
  });
})();
