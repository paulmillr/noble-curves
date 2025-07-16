import { ed25519, ed25519_hasher, x25519 } from '@noble/curves/ed25519';
import { ed448, ed448_hasher, x448 } from '@noble/curves/ed448';
import { p256, p256_hasher, p384, p384_hasher, p521, p521_hasher } from '@noble/curves/nist.js';
import { secp256k1, secp256k1_hasher } from '@noble/curves/secp256k1.js';
import { randomBytes } from '@noble/hashes/utils.js';
import compare from 'micro-bmark/compare.js';
import { generateData } from './_shared.js';

(async () => {
  const curves_ = { ed25519, ed448, secp256k1, p256, p384, p521 };
  const hashToCurves = {
    ed25519: ed25519_hasher,
    ed448: ed448_hasher,
    p256: p256_hasher,
    p384: p384_hasher,
    p521: p521_hasher,
    secp256k1: secp256k1_hasher
  }
  const curves = {};
  const scalar = 2n ** 180n - 15820n;
  for (let kv of Object.entries(curves_)) {
    const [name, curve] = kv;
    // console.log();
    // title(name);
    curve.utils.precompute(8);
    const d = generateData(curve);
    const d2 = generateData(curve);
    const rand32 = [randomBytes(32), randomBytes(32)];
    const rand56 = [randomBytes(56), randomBytes(56)];
    const getSharedSecret = name === 'ed25519' ?
      (() => x25519.getSharedSecret(rand32[0], rand32[1])) :
      name === 'ed448' ?
      (() => x448.getSharedSecret(rand56[0], rand56[1])) :
      (() => curve.getSharedSecret(d.priv, d2.pub));
    curves[name] = {
      getPublicKey: () => curve.getPublicKey(d.priv),
      sign: () => curve.sign(d.msg, d.priv),
      verify: () => curve.verify(d.sig, d.msg, d.pub),
      getSharedSecret: getSharedSecret,
      fromHex: () => d.Point.fromHex(d.pub),
      hashToCurve: () => hashToCurves[name].hashToCurve(d.msg),
      Point_add: () => d.point.add(d.point),
      Point_mul: () => d.point.multiply(scalar),
      Point_mulUns: () => d.point.multiplyUnsafe(scalar)
    }
  }
  compare('curve operations', {}, curves, { libDims: ['curve', 'algorithm'], dims: ['algorithm'], samples: () => 1000 })
})();
