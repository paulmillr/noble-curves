import * as bench from 'micro-bmark';
const { run, mark } = bench; // or bench.mark
import { readFileSync } from 'fs';

// Curves
import { secp256k1 } from '../lib/secp256k1.js';
import { P256 } from '../lib/p256.js';
import { P384 } from '../lib/p384.js';
import { P521 } from '../lib/p521.js';
import { ed25519 } from '../lib/ed25519.js';
import { ed448 } from '../lib/ed448.js';
import { bls12_381 as bls } from '../lib/bls12-381.js';

// Others
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';

import * as old_secp from '@noble/secp256k1';
import * as old_bls from '@noble/bls12-381';
import { concatBytes, hexToBytes } from '@noble/hashes/utils';

import * as starkwareCrypto from '@starkware-industries/starkware-crypto-utils';
import * as stark from '../lib/stark.js';

old_secp.utils.sha256Sync = (...msgs) =>
  sha256
    .create()
    .update(concatBytes(...msgs))
    .digest();
old_secp.utils.hmacSha256Sync = (key, ...msgs) =>
  hmac
    .create(sha256, key)
    .update(concatBytes(...msgs))
    .digest();
import * as noble_ed25519 from '@noble/ed25519';
noble_ed25519.utils.sha512Sync = (...m) => sha512(concatBytes(...m));

// BLS
const G2_VECTORS = readFileSync('../test/bls12-381/bls12-381-g2-test-vectors.txt', 'utf-8')
  .trim()
  .split('\n')
  .map((l) => l.split(':'));
let p1, p2, oldp1, oldp2;
// /BLS

for (let item of [secp256k1, ed25519, ed448, P256, P384, P521, old_secp, noble_ed25519]) {
  item.utils.precompute(8);
}

const ONLY_NOBLE = process.argv[2] === 'noble';

function generateData(namespace) {
  const priv = namespace.utils.randomPrivateKey();
  const pub = namespace.getPublicKey(priv);
  const msg = namespace.utils.randomPrivateKey();
  const sig = namespace.sign(msg, priv);
  return { priv, pub, msg, sig };
}

export const CURVES = {
  secp256k1: {
    data: () => {
      return generateData(secp256k1);
    },
    getPublicKey1: {
      samples: 10000,
      secp256k1_old: () => old_secp.getPublicKey(3n),
      secp256k1: () => secp256k1.getPublicKey(3n),
    },
    getPublicKey255: {
      samples: 10000,
      secp256k1_old: () => old_secp.getPublicKey(2n ** 255n - 1n),
      secp256k1: () => secp256k1.getPublicKey(2n ** 255n - 1n),
    },
    sign: {
      samples: 5000,
      secp256k1_old: ({ msg, priv }) => old_secp.signSync(msg, priv),
      secp256k1: ({ msg, priv }) => secp256k1.sign(msg, priv),
    },
    verify: {
      samples: 1000,
      secp256k1_old: ({ sig, msg, pub }) => {
        return old_secp.verify(new old_secp.Signature(sig.r, sig.s), msg, pub);
      },
      secp256k1: ({ sig, msg, pub }) => secp256k1.verify(sig, msg, pub),
    },
    getSharedSecret: {
      samples: 1000,
      secp256k1_old: ({ pub, priv }) => old_secp.getSharedSecret(priv, pub),
      secp256k1: ({ pub, priv }) => secp256k1.getSharedSecret(priv, pub),
    },
    recoverPublicKey: {
      samples: 1000,
      secp256k1_old: ({ sig, msg }) =>
        old_secp.recoverPublicKey(msg, new old_secp.Signature(sig.r, sig.s), sig.recovery),
      secp256k1: ({ sig, msg }) => sig.recoverPublicKey(msg),
    },
    // hashToCurve: {
    //   samples: 500,
    //   noble: () => secp256k1.Point.hashToCurve('abcd'),
    // },
  },
  ed25519: {
    data: () => {
      function to32Bytes(numOrStr) {
        const hex = typeof numOrStr === 'string' ? numOrStr : numOrStr.toString(16);
        return hexToBytes(hex.padStart(64, '0'));
      }
      const priv = to32Bytes(0x9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60n);
      const pub = noble_ed25519.sync.getPublicKey(priv);
      const msg = to32Bytes('deadbeefdeadbeefdeadbeefdeadbeefdeadbeef');
      const sig = noble_ed25519.sync.sign(msg, priv);
      return { pub, priv, msg, sig };
    },
    getPublicKey: {
      samples: 10000,
      old: () => noble_ed25519.sync.getPublicKey(noble_ed25519.utils.randomPrivateKey()),
      noble: () => ed25519.getPublicKey(ed25519.utils.randomPrivateKey()),
    },
    sign: {
      samples: 5000,
      old: ({ msg, priv }) => noble_ed25519.sync.sign(msg, priv),
      noble: ({ msg, priv }) => ed25519.sign(msg, priv),
    },
    verify: {
      samples: 1000,
      old: ({ sig, msg, pub }) => noble_ed25519.sync.verify(sig, msg, pub),
      noble: ({ sig, msg, pub }) => ed25519.verify(sig, msg, pub),
    },
    // hashToCurve: {
    //   samples: 500,
    //   noble: () => ed25519.Point.hashToCurve('abcd'),
    // },
  },
  ed448: {
    data: () => {
      const priv = ed448.utils.randomPrivateKey();
      const pub = ed448.getPublicKey(priv);
      const msg = ed448.utils.randomPrivateKey();
      const sig = ed448.sign(msg, priv);
      return { priv, pub, msg, sig };
    },
    getPublicKey: {
      samples: 5000,
      noble: () => ed448.getPublicKey(ed448.utils.randomPrivateKey()),
    },
    sign: {
      samples: 2500,
      noble: ({ msg, priv }) => ed448.sign(msg, priv),
    },
    verify: {
      samples: 500,
      noble: ({ sig, msg, pub }) => ed448.verify(sig, msg, pub),
    },
    hashToCurve: {
      samples: 500,
      noble: () => ed448.Point.hashToCurve('abcd'),
    },
  },
  nist: {
    data: () => {
      return { p256: generateData(P256), p384: generateData(P384), p521: generateData(P521) };
    },
    getPublicKey: {
      samples: 2500,
      P256: () => P256.getPublicKey(P256.utils.randomPrivateKey()),
      P384: () => P384.getPublicKey(P384.utils.randomPrivateKey()),
      P521: () => P521.getPublicKey(P521.utils.randomPrivateKey()),
    },
    sign: {
      samples: 1000,
      P256: ({ p256: { msg, priv } }) => P256.sign(msg, priv),
      P384: ({ p384: { msg, priv } }) => P384.sign(msg, priv),
      P521: ({ p521: { msg, priv } }) => P521.sign(msg, priv),
    },
    verify: {
      samples: 250,
      P256: ({ p256: { sig, msg, pub } }) => P256.verify(sig, msg, pub),
      P384: ({ p384: { sig, msg, pub } }) => P384.verify(sig, msg, pub),
      P521: ({ p521: { sig, msg, pub } }) => P521.verify(sig, msg, pub),
    },
    hashToCurve: {
      samples: 500,
      P256: () => P256.Point.hashToCurve('abcd'),
      P384: () => P384.Point.hashToCurve('abcd'),
      P521: () => P521.Point.hashToCurve('abcd'),
    },
  },
  stark: {
    data: () => {
      const priv = '2dccce1da22003777062ee0870e9881b460a8b7eca276870f57c601f182136c';
      const msg = 'c465dd6b1bbffdb05442eb17f5ca38ad1aa78a6f56bf4415bdee219114a47';
      const pub = stark.getPublicKey(priv);
      const sig = stark.sign(msg, priv);

      const privateKey = '2dccce1da22003777062ee0870e9881b460a8b7eca276870f57c601f182136c';
      const msgHash = 'c465dd6b1bbffdb05442eb17f5ca38ad1aa78a6f56bf4415bdee219114a47';
      const keyPair = starkwareCrypto.default.ec.keyFromPrivate(privateKey, 'hex');
      const publicKeyStark = starkwareCrypto.default.ec.keyFromPublic(
        keyPair.getPublic(true, 'hex'),
        'hex'
      );

      return { priv, sig, msg, pub, publicKeyStark, msgHash, keyPair };
    },
    pedersen: {
      samples: 500,
      old: () => {
        return starkwareCrypto.default.pedersen([
          '3d937c035c878245caf64531a5756109c53068da139362728feb561405371cb',
          '208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31a',
        ]);
      },
      noble: () => {
        return stark.pedersen(
          '3d937c035c878245caf64531a5756109c53068da139362728feb561405371cb',
          '208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31a'
        );
      },
    },
    poseidon: {
      samples: 2000,
      noble: () => {
        return stark.poseidonHash(
          0x3d937c035c878245caf64531a5756109c53068da139362728feb561405371cbn,
          0x208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31an
        );
      },
    },
    verify: {
      samples: 500,
      old: ({ publicKeyStark, msgHash, keyPair }) => {
        return starkwareCrypto.default.verify(
          publicKeyStark,
          msgHash,
          starkwareCrypto.default.sign(keyPair, msgHash)
        );
      },
      noble: ({ priv, msg, pub }) => {
        return stark.verify(stark.sign(msg, priv), msg, pub);
      },
    },
  },
  'bls12-381': {
    data: async () => {
      const priv = '28b90deaf189015d3a325908c5e0e4bf00f84f7e639b056ff82d7e70b6eede4c';
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
      return {
        priv,
        pubs,
        sigs,
        pub,
        pub512,
        pub32,
        pub128,
        pub2048,
        sig32,
        sig128,
        sig512,
        sig2048,
      };
    },
    init: {
      samples: 1,
      old: () => {
        oldp1 =
          old_bls.PointG1.BASE.multiply(
            0x28b90deaf189015d3a325908c5e0e4bf00f84f7e639b056ff82d7e70b6eede4cn
          );
        oldp2 =
          old_bls.PointG2.BASE.multiply(
            0x28b90deaf189015d3a325908c5e0e4bf00f84f7e639b056ff82d7e70b6eede4dn
          );
        old_bls.pairing(oldp1, oldp2);
      },
      noble: () => {
        p1 =
          bls.G1.ProjectivePoint.BASE.multiply(
            0x28b90deaf189015d3a325908c5e0e4bf00f84f7e639b056ff82d7e70b6eede4cn
          );
        p2 =
          bls.G2.ProjectivePoint.BASE.multiply(
            0x28b90deaf189015d3a325908c5e0e4bf00f84f7e639b056ff82d7e70b6eede4dn
          );
        bls.pairing(p1, p2);
      },
    },
    'getPublicKey (1-bit)': {
      samples: 1000,
      old: () => old_bls.getPublicKey('2'.padStart(64, '0')),
      noble: () => bls.getPublicKey('2'.padStart(64, '0')),
    },
    getPublicKey: {
      samples: 1000,
      old: ({ priv }) => old_bls.getPublicKey(priv),
      noble: ({ priv }) => bls.getPublicKey(priv),
    },
    sign: {
      samples: 50,
      old: ({ priv }) => old_bls.sign('09', priv),
      noble: ({ priv }) => bls.sign('09', priv),
    },
    verify: {
      samples: 50,
      old: ({ pub }) =>
        old_bls.verify(
          '8647aa9680cd0cdf065b94e818ff2bb948cc97838bcee987b9bc1b76d0a0a6e0d85db4e9d75aaedfc79d4ea2733a21ae0579014de7636dd2943d45b87c82b1c66a289006b0b9767921bb8edd3f6c5c5dec0d54cd65f61513113c50cc977849e5',
          '09',
          pub
        ),
      noble: ({ pub }) =>
        bls.verify(
          '8647aa9680cd0cdf065b94e818ff2bb948cc97838bcee987b9bc1b76d0a0a6e0d85db4e9d75aaedfc79d4ea2733a21ae0579014de7636dd2943d45b87c82b1c66a289006b0b9767921bb8edd3f6c5c5dec0d54cd65f61513113c50cc977849e5',
          '09',
          pub
        ),
    },
    pairing: {
      samples: 100,
      old: () => old_bls.pairing(oldp1, oldp2),
      noble: () => bls.pairing(p1, p2),
    },
    'hashToCurve/G1': {
      samples: 500,
      old: () => old_bls.PointG1.hashToCurve('abcd'),
      noble: () => bls.hashToCurve.G1.hashToCurve('abcd'),
    },
    'hashToCurve/G2': {
      samples: 200,
      old: () => old_bls.PointG2.hashToCurve('abcd'),
      noble: () => bls.hashToCurve.G2.hashToCurve('abcd'),
    },
    // SLOW PART
    // Requires points which we cannot init before (data fn same for all)
    // await mark('sign/nc', 30, () => bls.sign(msgp, priv));
    // await mark('verify/nc', 30, () => bls.verify(sigp, msgp, pubp));
    'aggregatePublicKeys/8': {
      samples: 100,
      old: ({ pubs }) => old_bls.aggregatePublicKeys(pubs.slice(0, 8)),
      noble: ({ pubs }) => bls.aggregatePublicKeys(pubs.slice(0, 8)),
    },
    'aggregatePublicKeys/32': {
      samples: 50,
      old: ({ pub32 }) => old_bls.aggregatePublicKeys(pub32.map(old_bls.PointG1.fromHex)),
      noble: ({ pub32 }) => bls.aggregatePublicKeys(pub32.map(bls.G1.ProjectivePoint.fromHex)),
    },
    'aggregatePublicKeys/128': {
      samples: 20,
      old: ({ pub128 }) => old_bls.aggregatePublicKeys(pub128.map(old_bls.PointG1.fromHex)),
      noble: ({ pub128 }) => bls.aggregatePublicKeys(pub128.map(bls.G1.ProjectivePoint.fromHex)),
    },
    'aggregatePublicKeys/512': {
      samples: 10,
      old: ({ pub512 }) => old_bls.aggregatePublicKeys(pub512.map(old_bls.PointG1.fromHex)),
      noble: ({ pub512 }) => bls.aggregatePublicKeys(pub512.map(bls.G1.ProjectivePoint.fromHex)),
    },
    'aggregatePublicKeys/2048': {
      samples: 5,
      old: ({ pub2048 }) => old_bls.aggregatePublicKeys(pub2048.map(old_bls.PointG1.fromHex)),
      noble: ({ pub2048 }) => bls.aggregatePublicKeys(pub2048.map(bls.G1.ProjectivePoint.fromHex)),
    },
    'aggregateSignatures/8': {
      samples: 50,
      old: ({ sigs }) => old_bls.aggregateSignatures(sigs.slice(0, 8)),
      noble: ({ sigs }) => bls.aggregateSignatures(sigs.slice(0, 8)),
    },
    'aggregateSignatures/32': {
      samples: 10,
      old: ({ sig32 }) => old_bls.aggregateSignatures(sig32.map(old_bls.PointG2.fromSignature)),
      noble: ({ sig32 }) => bls.aggregateSignatures(sig32.map(bls.Signature.decode)),
    },
    'aggregateSignatures/128': {
      samples: 5,
      old: ({ sig128 }) => old_bls.aggregateSignatures(sig128.map(old_bls.PointG2.fromSignature)),
      noble: ({ sig128 }) => bls.aggregateSignatures(sig128.map(bls.Signature.decode)),
    },
    'aggregateSignatures/512': {
      samples: 3,
      old: ({ sig512 }) => old_bls.aggregateSignatures(sig512.map(old_bls.PointG2.fromSignature)),
      noble: ({ sig512 }) => bls.aggregateSignatures(sig512.map(bls.Signature.decode)),
    },
    'aggregateSignatures/2048': {
      samples: 2,
      old: ({ sig2048 }) => old_bls.aggregateSignatures(sig2048.map(old_bls.PointG2.fromSignature)),
      noble: ({ sig2048 }) => bls.aggregateSignatures(sig2048.map(bls.Signature.decode)),
    },
  },
};

const main = () =>
  run(async () => {
    for (const [name, curve] of Object.entries(CURVES)) {
      console.log(`==== ${name} ====`);
      const data = await curve.data();
      for (const [fnName, libs] of Object.entries(curve)) {
        if (fnName === 'data') continue;
        const samples = libs.samples;
        console.log(`  - ${fnName} (samples: ${samples})`);
        for (const [lib, fn] of Object.entries(libs)) {
          if (lib === 'samples') continue;
          if (ONLY_NOBLE && lib !== 'noble') continue;
          await mark(`    ${lib}`, samples, () => fn(data));
        }
      }
    }
    // Log current RAM
    bench.logMem();
  });

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  main();
}
