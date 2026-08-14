import { sha256 } from '@noble/hashes/sha2.js';
import { hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import bench, { section } from '@paulmillr/jsbt/benchmark.js';
import { readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { pippenger } from '../src/abstract/curve.ts';
import { hash_to_field } from '../src/abstract/hash-to-curve.ts';
import { Field } from '../src/abstract/modular.ts';
import { bls12_381 as bls } from '../src/bls12-381.ts';
import {
  ed25519,
  ed25519_hasher,
  ristretto255,
  ristretto255_hasher,
  x25519,
} from '../src/ed25519.ts';
import { decaf448, decaf448_hasher, ed448, ed448_hasher, x448 } from '../src/ed448.ts';
import { p256, p256_hasher, p384, p384_hasher, p521, p521_hasher } from '../src/nist.ts';
import { schnorr, secp256k1, secp256k1_hasher } from '../src/secp256k1.ts';
import { generateData } from './_shared.ts';

// Emits all benchmarks in the format of README.md "Speed" section.
// Run it, then paste output into README.md.

const __dirname = dirname(fileURLToPath(import.meta.url));

(async () => {
  section('secp256k1');
  await bench('init', 'once', () => secp256k1.Point.BASE.precompute(6, false));
  const d = generateData(secp256k1);
  await bench('getPublicKey', () => secp256k1.getPublicKey(d.priv));
  await bench('sign', () => secp256k1.sign(d.msg, d.priv));
  await bench('verify', () => secp256k1.verify(d.sig, d.msg, d.pub));
  await bench('recoverPublicKey', () =>
    secp256k1.Signature.fromBytes(d.sig).addRecoveryBit(1).recoverPublicKey(d.msg)
  );
  const pub2 = secp256k1.getPublicKey(secp256k1.utils.randomSecretKey());
  await bench('getSharedSecret', () => secp256k1.getSharedSecret(d.priv, pub2));
  const spub = schnorr.getPublicKey(d.priv);
  const ssig = schnorr.sign(d.msg, d.priv);
  await bench('schnorr.sign', () => schnorr.sign(d.msg, d.priv));
  await bench('schnorr.verify', () => schnorr.verify(ssig, d.msg, spub));

  for (const [name, curve] of Object.entries({ ed25519, ed448, p256, p384, p521 })) {
    section(name);
    await bench('init', 'once', () => curve.Point.BASE.precompute(6, false));
    const dc = generateData(curve);
    await bench('getPublicKey', () => curve.getPublicKey(dc.priv));
    await bench('sign', () => curve.sign(dc.msg, dc.priv));
    await bench('verify', () => curve.verify(dc.sig, dc.msg, dc.pub));
  }

  section('ristretto255');
  const RistrettoPoint = ristretto255.Point;
  const rpriv = ristretto255_hasher.hashToScalar(randomBytes(64));
  const rpub = RistrettoPoint.BASE.multiply(rpriv);
  const rbytes = rpub.toBytes();
  await bench('add', () => rpub.add(RistrettoPoint.BASE));
  await bench('multiply', () => RistrettoPoint.BASE.multiply(rpriv));
  await bench('encode', () => rpub.toBytes());
  await bench('decode', () => RistrettoPoint.fromBytes(rbytes));

  section('decaf448');
  const DecafPoint = decaf448.Point;
  const dpriv = decaf448_hasher.hashToScalar(randomBytes(112));
  const dpub = DecafPoint.BASE.multiply(dpriv);
  const dbytes = dpub.toBytes();
  await bench('add', () => dpub.add(DecafPoint.BASE));
  await bench('multiply', () => DecafPoint.BASE.multiply(dpriv));
  await bench('encode', () => dpub.toBytes());
  await bench('decode', () => DecafPoint.fromBytes(dbytes));

  section('ECDH');
  for (const [name, curve] of Object.entries({ x25519, x448, secp256k1, p256, p384, p521 })) {
    const priv = curve.utils.randomSecretKey();
    const pub = curve.getPublicKey(curve.utils.randomSecretKey());
    await bench(name, () => curve.getSharedSecret(priv, pub));
  }

  section('hash-to-curve');
  const rand40 = randomBytes(40);
  const msg = randomBytes(32);
  const hashers = {
    secp256k1: secp256k1_hasher,
    p256: p256_hasher,
    p384: p384_hasher,
    p521: p521_hasher,
    ed25519: ed25519_hasher,
    ed448: ed448_hasher,
  };
  await bench('hashToScalar', () => secp256k1_hasher.hashToScalar(rand40));
  await bench('hash_to_field', () =>
    hash_to_field(rand40, 1, {
      DST: 'secp256k1',
      hash: sha256,
      expand: 'xmd',
      p: secp256k1.Point.Fn.ORDER,
      m: 1,
      k: 128,
    })
  );
  for (const [name, hasher] of Object.entries(hashers)) {
    await bench(`hashToCurve ${name}`, () => hasher.hashToCurve(msg));
  }
  await bench('hash_to_ristretto255', () =>
    ristretto255_hasher.hashToCurve(msg, { DST: 'ristretto255_XMD:SHA-512_R255MAP_RO_' })
  );
  await bench('hash_to_decaf448', () =>
    decaf448_hasher.hashToCurve(msg, { DST: 'decaf448_XOF:SHAKE256_D448MAP_RO_' })
  );

  section('modular over secp256k1 P field');
  const secpFp = secp256k1.Point.Fp;
  const FpStark = Field(
    BigInt('0x800000000000011000000000000000000000000000000000000000000000001')
  );
  const NUM0 = 2n ** 232n - 5910n;
  const NUM1 = 2n ** 231n - 5910n;
  const NUM2 = 2n ** 231n - 5909n;
  await bench('invert a', () => secpFp.inv(NUM0));
  await bench('invert b', () => secpFp.inv(NUM1));
  await bench('sqrt p = 3 mod 4', () => secpFp.sqrt(NUM1));
  await bench('sqrt tonneli-shanks', () => FpStark.sqrt(NUM2));

  section('bls12-381');
  const blsl = bls.longSignatures;
  let p1, p2;
  await bench('init', 'once', () => {
    p1 = bls.G1.Point.BASE.multiply(
      0x28b90deaf189015d3a325908c5e0e4bf00f84f7e639b056ff82d7e70b6eede4cn
    );
    p2 = bls.G2.Point.BASE.multiply(
      0x28b90deaf189015d3a325908c5e0e4bf00f84f7e639b056ff82d7e70b6eede4dn
    );
    bls.pairing(p1, p2);
  });
  const bpriv = hexToBytes('28b90deaf189015d3a325908c5e0e4bf00f84f7e639b056ff82d7e70b6eede4c');
  const bmsg = blsl.hash(Uint8Array.of(0x09));
  const bpub = blsl.getPublicKey(bpriv);
  const bsig = blsl.sign(bmsg, bpriv);
  await bench('getPublicKey', () => blsl.getPublicKey(bpriv));
  await bench('sign', () => blsl.sign(bmsg, bpriv));
  await bench('verify', () => blsl.verify(bsig, bmsg, bpub));
  await bench('pairing', () => bls.pairing(p1, p2));

  const msmAmount = 4096;
  const msmScalars = Array.from({ length: msmAmount }, (_, i) => 2n ** 235n - 1n - BigInt(i));
  const msmPoints = msmScalars.map((s) => bls.G1.Point.BASE.multiply(s));
  const pointsG2 = msmScalars.slice(0, 10).map((s) => bls.G2.Point.BASE.multiply(s));
  const pairs10 = msmPoints.slice(0, 10).map((g1, i) => ({ g1, g2: pointsG2[i] }));
  await bench('pairing10', () => bls.pairingBatch(pairs10));
  await bench(`MSM ${msmAmount} scalars x points`, 'once', () =>
    pippenger(bls.G1.Point, msmPoints, msmScalars)
  );

  const G2_VECTORS = readFileSync(
    `${__dirname}/../test/vectors/bls12-381/bls12-381-g2-test-vectors.txt`,
    'utf-8'
  )
    .trim()
    .split('\n')
    .map((l) => l.split(':'));
  const pub512 = G2_VECTORS.slice(0, 512).map((v) => blsl.getPublicKey(hexToBytes(v[0])));
  const sig512 = G2_VECTORS.slice(0, 512).map((v) => hexToBytes(v[2]));
  const pub2048 = pub512.concat(pub512, pub512, pub512);
  const sig2048 = sig512.concat(sig512, sig512, sig512);
  for (const n of [8, 32, 128, 512, 2048]) {
    const pubs = pub2048.slice(0, n);
    await bench(`aggregatePublicKeys/${n}`, () => blsl.aggregatePublicKeys(pubs));
  }
  for (const n of [8, 32, 128, 512, 2048]) {
    const sigs = sig2048.slice(0, n);
    await bench(`aggregateSignatures/${n}`, () => blsl.aggregateSignatures(sigs));
  }
})();
