import { randomBytes } from '@noble/hashes/utils.js';
import compare from '@paulmillr/jsbt/benchmark-compare.js';
import { bls12_381 } from '../src/bls12-381.ts';
import { ed25519, x25519 } from '../src/ed25519.ts';
import { ed448, x448 } from '../src/ed448.ts';
import { p256, p384, p521 } from '../src/nist.ts';
import { secp256k1 } from '../src/secp256k1.ts';
import { generateData } from './_shared.ts';

(async () => {
  const baseCurves = { ed25519, ed448, secp256k1, p256, p384, p521 };
  const curves = {};

  for (const [name, curve] of Object.entries(baseCurves)) {
    curve.Point.BASE.precompute(6, false);
    const d = generateData(curve);
    const d2 = generateData(curve);
    const rand32 = [randomBytes(32), randomBytes(32)];
    const rand56 = [randomBytes(56), randomBytes(56)];
    const getSharedSecret =
      name === 'ed25519'
        ? () => x25519.getSharedSecret(rand32[0], rand32[1])
        : name === 'ed448'
          ? () => x448.getSharedSecret(rand56[0], rand56[1])
          : () => curve.getSharedSecret(d.priv, d2.pub);

    curves[name] = {
      getPublicKey: () => curve.getPublicKey(d.priv),
      sign: () => curve.sign(d.msg, d.priv),
      verify: () => curve.verify(d.sig, d.msg, d.pub),
      getSharedSecret,
    };
  }

  // long = pubkeys on G1, sigs on G2; short = pubkeys on G2, sigs on G1
  bls12_381.G1.Point.BASE.precompute(6, false);
  bls12_381.G2.Point.BASE.precompute(6, false);
  const blsPriv = bls12_381.utils.randomSecretKey();
  const blsMsg = randomBytes(32);
  for (const [name, sigs] of [
    ['bls12_381 (long, G2 sig)', bls12_381.longSignatures],
    ['bls12_381 (short, G1 sig)', bls12_381.shortSignatures],
  ] as const) {
    const pub = sigs.getPublicKey(blsPriv);
    const sig = sigs.sign(sigs.hash(blsMsg), blsPriv);
    curves[name] = {
      getPublicKey: () => sigs.getPublicKey(blsPriv),
      sign: () => sigs.sign(sigs.hash(blsMsg), blsPriv),
      verify: () => sigs.verify(sig, sigs.hash(blsMsg), pub),
    };
  }

  await compare('curve signature operations', curves, {
    levels: ['curve', 'algorithm'],
    order: ['algorithm'],
  });
})();
