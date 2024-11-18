import { throws } from 'node:assert';
import { describe, should } from 'micro-should';
import { bytesToHex, hexToBytes } from '../esm/abstract/utils.js';
import { TYPE_TEST } from './utils.js';

// Here goes test for tests...
describe('Tests', () => {
  should('hexToBytes', () => {
    for (let v of TYPE_TEST.hex) {
      throws(() => {
        hexToBytes(v);
      });
    }
  });
  should('bytesToHex', () => {
    for (let v of TYPE_TEST.bytes) {
      throws(() => {
        bytesToHex(v);
      });
    }
  });
});

// ESM is broken.
import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
