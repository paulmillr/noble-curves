import { hexToBytes } from '@noble/curves/abstract/utils';
import mark from 'micro-bmark';

(async () => {
  const hex32 = '0123456789abcdef'.repeat(4);
  const hex256 = hex32.repeat(8);
  await mark('hexToBytes 32b', 5000000, () => hexToBytes(hex32));
  await mark('hexToBytes 256b', 500000, () => hexToBytes(hex256));
})();
