import { randomBytes } from '@noble/hashes/utils.js';
import compare from '@paulmillr/jsbt/bench-compare.js';
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

  await compare('curve signature operations', {}, curves, {
    libraryDimensions: ['curve', 'algorithm'],
    dimensions: ['algorithm'],
    iterations: 1000,
  });
})();
