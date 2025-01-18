import { Field as Fp } from '@noble/curves/abstract/modular';
import { secp256k1 } from '@noble/curves/secp256k1';
import mark from 'micro-bmark';

(async () => {
  console.log(`\x1b[36mmodular, secp256k1 field\x1b[0m`);
  const { Fp: secpFp } = secp256k1.CURVE;
  await mark('invert a', 300000, () => secpFp.inv(2n ** 232n - 5910n));
  await mark('invert b', 300000, () => secpFp.inv(2n ** 231n - 5910n));
  await mark('sqrt p = 3 mod 4', 15000, () => secpFp.sqrt(2n ** 231n - 5910n));
  const FpStark = Fp(BigInt('0x800000000000011000000000000000000000000000000000000000000000001'));
  await mark('sqrt tonneli-shanks', 500, () => FpStark.sqrt(2n ** 231n - 5909n));
})();
