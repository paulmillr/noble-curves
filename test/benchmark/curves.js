import { ed25519, hashToCurve as ed25519_hash, x25519 } from '@noble/curves/ed25519';
import { ed448, hashToCurve as ed448_hash, x448 } from '@noble/curves/ed448';
import { p256, hashToCurve as p256_hash } from '@noble/curves/p256';
import { p384, hashToCurve as p384_hash } from '@noble/curves/p384';
import { p521, hashToCurve as p521_hash } from '@noble/curves/p521';
import { secp256k1, hashToCurve as secp256k1_hash } from '@noble/curves/secp256k1';
import { randomBytes } from '@noble/hashes/utils';
import compare from 'micro-bmark/compare.js';
import { generateData } from './_shared.js';

(async () => {
  const curves_ = { ed25519, ed448, secp256k1, p256, p384, p521 };
  const hashToCurves = {
    ed25519: ed25519_hash,
    ed448: ed448_hash,
    p256: p256_hash,
    p384: p384_hash,
    p521: p521_hash,
    secp256k1: secp256k1_hash
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
      hashToCurve: () => hashToCurves[name](d.msg),
      Point_add: () => d.point.add(d.point),
      Point_mul: () => d.point.multiply(scalar),
      Point_mulUns: () => d.point.multiplyUnsafe(scalar)
    }
  }
  compare('curve operations', {}, curves, { libDims: ['curve', 'algorithm'], dims: ['algorithm'], samples: () => 1000 })
})();
