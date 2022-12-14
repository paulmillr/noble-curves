import * as bench from 'micro-bmark';
const { run, mark } = bench; // or bench.mark
// Curves
import { secp256k1 } from '../lib/secp256k1.js';
import { P256 } from '../lib/p256.js';
import { P384 } from '../lib/p384.js';
import { P521 } from '../lib/p521.js';
import { ed25519 } from '../lib/ed25519.js';
import { ed448 } from '../lib/ed448.js';

// Others
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';

import * as old_secp from '@noble/secp256k1';
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

secp256k1.utils.precompute(8); // Not enabled by default?
ed25519.utils.precompute(8);
ed448.utils.precompute(8);
P256.utils.precompute(8);
P384.utils.precompute(8);
P521.utils.precompute(8);

noble_ed25519.utils.sha512Sync = (...m) => sha512(concatBytes(...m));
old_secp.utils.precompute(8);
noble_ed25519.utils.precompute(8);

const wrapBuf = (arrayBuffer) => new Uint8Array(arrayBuffer);
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
      secp256k1_old: () => old_secp.getPublicKey(2n**255n-1n),
      secp256k1: () => secp256k1.getPublicKey(2n**255n-1n),
    },
    sign: {
      samples: 5000,
      secp256k1_old: ({ msg, priv }) => old_secp.signSync(msg, priv),
      secp256k1: ({ msg, priv }) => secp256k1.sign(msg, priv),
    },
    getSharedSecret: {
      samples: 1000,
      secp256k1_old: ({ pub, priv }) => old_secp.getSharedSecret(priv, pub),
      secp256k1: ({ pub, priv }) => secp256k1.getSharedSecret(priv, pub),
    },
    verify: {
      samples: 1000,
      secp256k1_old: ({ sig, msg, pub }) => {
        return old_secp.verify((new old_secp.Signature(sig.r, sig.s)), msg, pub);
      },
      secp256k1: ({ sig, msg, pub }) => secp256k1.verify(sig, msg, pub)
    }
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
      noble: ({ sig, msg, pub }) => ed448.verify(sig, msg, pub)
    }
  },
  nist: {
    data: () => {
      return { p256: generateData(P256), p384: generateData(P384), p521: generateData(P521) }
    },
    getPublicKey: {
      samples: 2500,
      P256: () => P256.getPublicKey(P256.utils.randomPrivateKey()),
      P384: () => P384.getPublicKey(P384.utils.randomPrivateKey()),
      P521: () => P521.getPublicKey(P521.utils.randomPrivateKey()),
    },
    sign: {
      samples: 1000,
      P256: ({ p256: {msg, priv} }) => P256.sign(msg, priv),
      P384: ({ p384: {msg, priv} }) => P384.sign(msg, priv),
      P521: ({ p521: {msg, priv} }) => P521.sign(msg, priv),
    },
    verify: {
      samples: 250,
      P256: ({ p256: {sig, msg, pub} }) => P256.verify(sig, msg, pub),
      P384: ({ p384: {sig, msg, pub} }) => P384.verify(sig, msg, pub),
      P521: ({ p521: {sig, msg, pub} }) => P521.verify(sig, msg, pub),
    }
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
        keyPair.getPublic(true, 'hex'), 'hex'
      );

      return { priv, sig, msg, pub, publicKeyStark, msgHash, keyPair }
    },
    pedersen: {
      samples: 500,
      old: () => {
        return starkwareCrypto.default.pedersen([
          '3d937c035c878245caf64531a5756109c53068da139362728feb561405371cb',
          '208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31a',
        ])
      },
      noble: () => {
        return stark.pedersen(
          '3d937c035c878245caf64531a5756109c53068da139362728feb561405371cb',
          '208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31a'
        )
      }
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
        return stark.verify(stark.sign(msg, priv), msg, pub)
      }
    }
  }
};

const main = () =>
  run(async () => {
    for (const [name, curve] of Object.entries(CURVES)) {
      console.log(`==== ${name} ====`);
      const data = curve.data();
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
