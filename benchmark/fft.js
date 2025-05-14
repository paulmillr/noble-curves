import * as fft from '@noble/curves/abstract/fft';
import { bls12_381 } from '@noble/curves/bls12-381';

import mark from 'micro-bmark';
import { generateData, title } from './_shared.js';

(async () => {
  title('fft');
  const curve = bls12_381;

  const Fr = curve.fields.Fr;
  const G1 = curve.G1.ProjectivePoint;
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

  await mark('fftFt', 1_000_000, () => fftFr.direct(pFR));
  await mark('fftG1', 1000, () => fftG1.direct(pG1));
})();
