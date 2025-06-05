import { bls12_381 as bls } from '@noble/curves/bls12-381';
import bench from 'micro-bmark';
import { readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { title } from './_shared.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const G2_VECTORS = readFileSync(
  `${__dirname}/../test/bls12-381/bls12-381-g2-test-vectors.txt`,
  'utf-8'
)
  .trim()
  .split('\n')
  .map((l) => l.split(':'));

(async () => {
  title('bls12-381');
  let p1, p2, sig;
  await bench('init', 1, () => {
    p1 =
      bls.G1.ProjectivePoint.BASE.multiply(
        0x28b90deaf189015d3a325908c5e0e4bf00f84f7e639b056ff82d7e70b6eede4cn
      );
    p2 =
      bls.G2.ProjectivePoint.BASE.multiply(
        0x28b90deaf189015d3a325908c5e0e4bf00f84f7e639b056ff82d7e70b6eede4dn
      );
    bls.pairing(p1, p2);
  });
  const priv = '28b90deaf189015d3a325908c5e0e4bf00f84f7e639b056ff82d7e70b6eede4c';
  sig = bls.sign('09', priv);
  const pubs = G2_VECTORS.map((v) => bls.getPublicKey(v[0]));
  const sigs = G2_VECTORS.map((v) => v[2]);
  const pub = bls.getPublicKey(priv);
  const pub512 = pubs.slice(0, 512); // .map(bls.PointG1.fromHex)
  const pub32 = pub512.slice(0, 32);
  const pub128 = pub512.slice(0, 128);
  const pub2048 = pub512.concat(pub512, pub512, pub512);
  const sig512 = sigs.slice(0, 512); // .map(bls.PointG2.fromSignature);
  const sig32 = sig512.slice(0, 32);
  const sig128 = sig512.slice(0, 128);
  const sig2048 = sig512.concat(sig512, sig512, sig512);
  await bench('getPublicKey 1-bit', () => bls.getPublicKey('2'.padStart(64, '0')));
  await bench('getPublicKey', () => bls.getPublicKey(priv));
  await bench('sign', () => bls.sign('09', priv));
  await bench('verify', () => bls.verify(sig, '09', pub));
  await bench('pairing', () => bls.pairing(p1, p2));

  const scalars1 = Array(4096)
    .fill(0)
    .map((i) => 2n ** 235n - BigInt(i));
  const scalars2 = Array(4096)
    .fill(0)
    .map((i) => 2n ** 241n + BigInt(i));
  const points = scalars1.map((s) => bls.G1.ProjectivePoint.BASE.multiply(s));
  const pointsG2 = scalars1.map((s) => bls.G2.ProjectivePoint.BASE.multiply(s));

  const pairingBatch = 10;
  await bench(`pairing${pairingBatch}`, 10, () => {
    const res = [];
    for (let i = 0; i < pairingBatch; i++) res.push({ g1: points[i], g2: pointsG2[i] });
    bls.pairingBatch(res);
  });

  await bench('MSM 4096 scalars x points', 1, () => {
    // naive approach, not using multi-scalar-multiplication
    let sum = bls.G1.ProjectivePoint.ZERO;
    for (let i = 0; i < 4096; i++) {
      const scalar = scalars2[i];
      const G1 = points[i];
      const mutliplied = G1.multiplyUnsafe(scalar);
      sum = sum.add(mutliplied);
    }
  });

  await bench('aggregatePublicKeys/8', () => bls.aggregatePublicKeys(pubs.slice(0, 8)));
  await bench('aggregatePublicKeys/32', () => bls.aggregatePublicKeys(pub32));
  await bench('aggregatePublicKeys/128', () => bls.aggregatePublicKeys(pub128));
  await bench('aggregatePublicKeys/512', () => bls.aggregatePublicKeys(pub512));
  await bench('aggregatePublicKeys/2048', () => bls.aggregatePublicKeys(pub2048));
  await bench('aggregateSignatures/8', () => bls.aggregateSignatures(sigs.slice(0, 8)));
  await bench('aggregateSignatures/32', () => bls.aggregateSignatures(sig32));
  await bench('aggregateSignatures/128', () => bls.aggregateSignatures(sig128));
  await bench('aggregateSignatures/512', () => bls.aggregateSignatures(sig512));
  await bench('aggregateSignatures/2048', () => bls.aggregateSignatures(sig2048));
})();
