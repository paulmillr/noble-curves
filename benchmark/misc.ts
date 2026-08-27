import { hexToBytes } from '@noble/hashes/utils.js';
import bench, { section } from '@paulmillr/jsbt/benchmark.js';
import { readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { pippenger } from '../src/abstract/curve.ts';
import * as fft from '../src/abstract/fft.ts';
import { bls12_381 as bls } from '../src/bls12-381.ts';

const __dirname = dirname(fileURLToPath(import.meta.url));
const G2_VECTORS = readFileSync(
  `${__dirname}/../test/vectors/bls12-381/bls12-381-g2-test-vectors.txt`,
  'utf-8'
)
  .trim()
  .split('\n')
  .map((l) => l.split(':'));

(async () => {
  section('bls12-381');
  let p1, p2;
  const blsl = bls.longSignatures;
  await bench('init', 'once', () => {
    p1 =
      bls.G1.Point.BASE.multiply(
        0x28b90deaf189015d3a325908c5e0e4bf00f84f7e639b056ff82d7e70b6eede4cn
      );
    p2 =
      bls.G2.Point.BASE.multiply(
        0x28b90deaf189015d3a325908c5e0e4bf00f84f7e639b056ff82d7e70b6eede4dn
      );
    bls.pairing(p1, p2);
  });
  const pubs = G2_VECTORS.map((v) => blsl.getPublicKey(hexToBytes(v[0])));
  const sigs = G2_VECTORS.map((v) => hexToBytes(v[2]));
  const pub512 = pubs.slice(0, 512);
  const pub32 = pub512.slice(0, 32);
  const pub128 = pub512.slice(0, 128);
  const sig512 = sigs.slice(0, 512);
  const sig32 = sig512.slice(0, 32);
  const sig128 = sig512.slice(0, 128);
  const sig2048 = sig512.concat(sig512, sig512, sig512);
  await bench('pairing', () => bls.pairing(p1, p2));

  const _pow1 = 2n ** 235n;
  const _pow2 = 2n ** 241n;

  const amount = 32768;
  const scalars1 = Array(amount)
    .fill(0)
    .map((i) => _pow1 - BigInt(i));
  const scalars2 = Array(amount)
    .fill(0)
    .map((i) => _pow2 + BigInt(i));
  let pointsG1;
  let pointsG2;

  section('misc');
  await bench(`initializing ${amount} G1 points`, () => {
    pointsG1 = scalars1.map((s) => bls.G1.Point.BASE.multiply(s));
  });
  await bench(`MSM pippenger x${amount}`, () => {
    pippenger(bls.G1.Point, pointsG1, scalars2);
  });

  section('aggregate G1 publicKeys / signatures');
  await bench('agg G1 x8', () => blsl.aggregatePublicKeys(pubs.slice(0, 8)));
  await bench('agg G1 x32', () => blsl.aggregatePublicKeys(pub32));
  await bench('agg G1 x128', () => blsl.aggregatePublicKeys(pub128));
  await bench('agg G1 x512', () => blsl.aggregatePublicKeys(pub512));
  await bench('agg G1 x2048', () => blsl.aggregatePublicKeys(pointsG1.slice(0, 2048)));
  await bench('agg G1 x8192', () => blsl.aggregatePublicKeys(pointsG1.slice(0, 8192)));
  await bench('agg G1 x32768', () => blsl.aggregatePublicKeys(pointsG1));

  section('aggregate G2 publicKeys / signatures');
  await bench('agg G2 x8', () => blsl.aggregateSignatures(sigs.slice(0, 8)));
  await bench('agg G2 x32', () => blsl.aggregateSignatures(sig32));
  await bench('agg G2 x128', () => blsl.aggregateSignatures(sig128));
  await bench('agg G2 x512', () => blsl.aggregateSignatures(sig512));
  await bench('agg G2 x2048', () => blsl.aggregateSignatures(sig2048));

  await bench('initializing 4096 G2 points', () => {
    pointsG2 = scalars1.slice(0, 4096).map((s) => bls.G2.Point.BASE.multiply(s));
  });
  const pairingBatch = 10;
  await bench(`pairing${pairingBatch}`, () => {
    const res = [];
    for (let i = 0; i < pairingBatch; i++) res.push({ g1: pointsG1[i], g2: pointsG2[i] });
    bls.pairingBatch(res);
  });

  section('fft');
  const Fr = bls.fields.Fr;
  const G1 = bls.G1.Point;
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

  await bench('fftFr', () => fftFr.direct(pFR));
  await bench('fftG1', () => fftG1.direct(pG1));
})();
