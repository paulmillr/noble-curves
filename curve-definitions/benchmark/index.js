import * as bench from 'micro-bmark';
const { run, mark } = bench; // or bench.mark
// Curves
import { secp256k1 } from '../lib/secp256k1.js';
import { ed25519 } from '../lib/ed25519.js';
import { ed448 } from '../lib/ed448.js';

// Others
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';

import * as noble_secp256k1 from '@noble/secp256k1';
import { concatBytes, hexToBytes } from '@noble/hashes/utils';

noble_secp256k1.utils.sha256Sync = (...msgs) =>
  sha256
    .create()
    .update(concatBytes(...msgs))
    .digest();
noble_secp256k1.utils.hmacSha256Sync = (key, ...msgs) =>
  hmac
    .create(sha256, key)
    .update(concatBytes(...msgs))
    .digest();
import * as noble_ed25519 from '@noble/ed25519';

secp256k1.utils.precompute(8); // Not enabled by default?
ed25519.utils.precompute(8);
ed448.utils.precompute(8);

noble_ed25519.utils.sha512Sync = (...m) => sha512(concatBytes(...m));
noble_secp256k1.utils.precompute(8);
noble_ed25519.utils.precompute(8);

const wrapBuf = (arrayBuffer) => new Uint8Array(arrayBuffer);

const ONLY_NOBLE = process.argv[2] === 'noble';
// TODO: add more?
export const CURVES = {
  secp256k1: {
    data: () => {
      const priv = 'f6fc7fd5acaf8603709160d203253d5cd17daa307483877ad811ec8411df56d2';
      const pub = noble_secp256k1.getPublicKey(priv, false);
      const msg = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
      const sig = noble_secp256k1.signSync(msg, priv);
      return { priv, pub, msg, sig };
    },
    getPublicKey: {
      samples: 10000,
      old: () => noble_secp256k1.getPublicKey(noble_secp256k1.utils.randomPrivateKey()),
      noble: () => secp256k1.getPublicKey(secp256k1.utils.randomPrivateKey()),
    },
    sign: {
      samples: 5000,
      old: ({ msg, priv }) => noble_secp256k1.signSync(msg, priv),
      noble: ({ msg, priv }) => secp256k1.sign(msg, priv),
    },
    getSharedSecret: {
      samples: 1000,
      old: ({ pub, priv }) => noble_secp256k1.getSharedSecret(priv, pub),
      noble: ({ pub, priv }) => secp256k1.getSharedSecret(priv, pub),
    },
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
      ed448: () => ed448.getPublicKey(ed448.utils.randomPrivateKey()),
    },
    sign: {
      samples: 5000,
      old: ({ msg, priv }) => noble_ed25519.sync.sign(msg, priv),
      noble: ({ msg, priv }) => ed25519.sign(msg, priv),
      ed448: () => ed448.sign(ed448.utils.randomPrivateKey(), ed448.utils.randomPrivateKey()),
    },
    verify: {
      samples: 1000,
      old: ({ msg, pub, sig }) => noble_ed25519.sync.verify(sig, msg, pub),
      noble: ({ msg, pub, sig }) => ed25519.verify(sig, msg, pub),
    },
  },
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
