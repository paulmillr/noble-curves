import mark from '@paulmillr/jsbt/bench.js';
import * as fft from '../../src/abstract/fft.ts';
import { bls12_381 } from '../../src/bls12-381.ts';
import { title } from './_shared.ts';

(async () => {
  title('fft');
  const curve = bls12_381;

  const Fr = curve.fields.Fr;
  const G1 = curve.G1.Point;
  const pFR = [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n];
  const pG1 = pFR.map((i) => G1.BASE.multiplyUnsafe(i));

  const roots = fft.rootsOfUnity(Fr, 7n);
  const fftFr = fft.FFT(roots, Fr);
  const fftG1 = fft.FFT(roots, {
    add: (a, b) => a.add(b),
    sub: (a, b) => a.subtract(b),
    mul: (a, scalar) => a.multiplyUnsafe(scalar),
    inv: Fr.inv,
  });

  await mark('fftFt', () => fftFr.direct(pFR));
  await mark('fftG1', () => fftG1.direct(pG1));
})();
