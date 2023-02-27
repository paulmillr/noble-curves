import { run, mark } from 'micro-bmark';
import { secp256k1 } from '../secp256k1.js';

run(async () => {
  console.log(`\x1b[36mmodular, secp256k1 field\x1b[0m`);
  const { Fp } = secp256k1.CURVE;
  await mark('invert a', 30000, () => Fp.inv(2n ** 232n - 5910n));
  await mark('invert b', 30000, () => Fp.inv(2n ** 231n - 5910n));
  await mark('sqrt', 15000, () => Fp.sqrt(2n ** 231n - 5910n));
});
