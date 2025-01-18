import { ed25519 } from '@noble/curves/ed25519';
import { ed448 } from '@noble/curves/ed448';
import { p256 } from '@noble/curves/p256';
import { p384 } from '@noble/curves/p384';
import { p521 } from '@noble/curves/p521';
import mark from 'micro-bmark';
import { generateData } from './_shared.js';

(async () => {
  for (let kv of Object.entries({ ed25519, ed448, p256, p384, p521 })) {
    const [name, curve] = kv;
    console.log();
    console.log(`\x1b[36m${name}\x1b[0m`);

    await mark('init', 1, () => curve.utils.precompute(8));
    const d = generateData(curve);
    await mark('getPublicKey', 5000, () => curve.getPublicKey(d.priv));
    await mark('sign', 5000, () => curve.sign(d.msg, d.priv));
    await mark('verify', 500, () => curve.verify(d.sig, d.msg, d.pub));
  }
})();
