import { pippenger } from '@noble/curves/abstract/curve.js';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { hexToBytes } from '@noble/hashes/utils.js';
import bench from 'micro-bmark';
import { readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { title } from './_shared.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const G2_VECTORS = readFileSync(
  `${__dirname}/../vectors/bls12-381/bls12-381-g2-test-vectors.txt`,
  'utf-8'
)
  .trim()
  .split('\n')
  .map((l) => l.split(':'));

(async () => {
  title('bls12-381');
  let p1, p2, sig, sig_s;
  const blsl = bls.longSignatures;
  const blss = bls.shortSignatures;
  await bench('init', 1, () => {
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
  const priv = hexToBytes('28b90deaf189015d3a325908c5e0e4bf00f84f7e639b056ff82d7e70b6eede4c');
  sig = blsl.sign(blsl.hash(Uint8Array.of(0x09)), priv);
  sig_s = blss.sign(blss.hash(Uint8Array.of(0x09)), priv);
  const pubs = G2_VECTORS.map((v) => blsl.getPublicKey(hexToBytes(v[0])));
  const sigs = G2_VECTORS.map((v) => hexToBytes(v[2]));
  const pub = blsl.getPublicKey(priv);
  const pub_s = blss.getPublicKey(priv);
  const pub512 = pubs.slice(0, 512); // .map(bls.PointG1.fromHex)
  const pub32 = pub512.slice(0, 32);
  const pub128 = pub512.slice(0, 128);
  const pub2048 = pub512.concat(pub512, pub512, pub512);
  const sig512 = sigs.slice(0, 512); // .map(bls.PointG2.fromSignature);
  const sig32 = sig512.slice(0, 32);
  const sig128 = sig512.slice(0, 128);
  const sig2048 = sig512.concat(sig512, sig512, sig512);
  // await bench('getPublicKey 1-bit', () => blsl.getPublicKey(hexToBytes('2'.padStart(64, '0'))));
  await bench('pairing', () => bls.pairing(p1, p2));

  console.log('# longSignatures')
  await bench('getPublicKey', () => blsl.getPublicKey(priv));
  await bench('sign', () => blsl.sign(blsl.hash(Uint8Array.of(0x09)), priv));
  await bench('verify', () => blsl.verify(sig, blsl.hash(Uint8Array.of(0x09)), pub));

  console.log('# shortSignatures')
  await bench('getPublicKey', () => blss.getPublicKey(priv));
  await bench('sign', () => blss.sign(blss.hash(Uint8Array.of(0x09)), priv));
  await bench('verify', () => blss.verify(sig_s, blss.hash(Uint8Array.of(0x09)), pub_s));

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

  console.log('# misc');
  await bench(`initializing ${amount} G1 points`, 1, () => {
    pointsG1 = scalars1.map((s) => bls.G1.Point.BASE.multiply(s));
  });
  await bench(`MSM pippenger x${amount}`, () => {
    pippenger(bls.G1.Point, pointsG1, scalars2);
  });

  console.log('# aggregate G1 publicKeys / signatures')
  await bench('agg G1 x8', () => blsl.aggregatePublicKeys(pubs.slice(0, 8)));
  await bench('agg G1 x32', () => blsl.aggregatePublicKeys(pub32));
  await bench('agg G1 x128', () => blsl.aggregatePublicKeys(pub128));
  await bench('agg G1 x512', () => blsl.aggregatePublicKeys(pub512));
  await bench('agg G1 x2048', () => blsl.aggregatePublicKeys(pointsG1.slice(0, 2048)));
  await bench('agg G1 x8192', () => blsl.aggregatePublicKeys(pointsG1.slice(0, 8192)));
  await bench('agg G1 x32768', () => blsl.aggregatePublicKeys(pointsG1));

  console.log('# aggregate G2 publicKeys / signatures')
  await bench('agg G2 x8', () => blsl.aggregateSignatures(sigs.slice(0, 8)));
  await bench('agg G2 x32', () => blsl.aggregateSignatures(sig32));
  await bench('agg G2 x128', () => blsl.aggregateSignatures(sig128));
  await bench('agg G2 x512', () => blsl.aggregateSignatures(sig512));
  await bench('agg G2 x2048', () => blsl.aggregateSignatures(sig2048));

  await bench('initializing 4096 G2 points', 1, () => {
    pointsG2 = scalars1.slice(0, 4096).map((s) => bls.G2.Point.BASE.multiply(s));
  });
  const pairingBatch = 10;
  await bench(`pairing${pairingBatch}`, () => {
    const res = [];
    for (let i = 0; i < pairingBatch; i++) res.push({ g1: pointsG1[i], g2: pointsG2[i] });
    bls.pairingBatch(res);
  });
})();