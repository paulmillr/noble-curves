import { deepStrictEqual } from 'assert';
import { should, describe } from 'micro-should';
import * as fs from 'fs';
import {
  hexToBytes,
  hexToNumber,
  concatBytes,
  bytesToHex as toHex,
} from '../esm/abstract/utils.js';
// Generic tests for all curves in package
import { secp256k1, elligatorSwift } from '../esm/secp256k1.js';
// ESM is broken.
import { dirname } from 'path';
import { fileURLToPath } from 'url';
export const __dirname = dirname(fileURLToPath(import.meta.url));

// https://eprint.iacr.org/2022/759

const parseCSV = (path) => {
  const data = fs.readFileSync(`${__dirname}/vectors/secp256k1/${path}`, 'utf8');
  const lines = data.split('\n').filter((i) => !!i);
  const rows = lines.map((i) => i.trim().split(','));
  const lengths = new Set(rows.map((i) => i.length));
  if (lengths.size !== 1) throw new Error('wrong dimensions');
  if (rows.length < 2) throw new Error('wrong rows length');
  const [head, ...rest] = rows;
  return rest.map((row) => Object.fromEntries(row.map((cell, j) => [head[j], cell])));
};

describe('ElligatorSwift', () => {
  should('packet_encoding_test_vectors', () => {
    for (const t of parseCSV('bip-0324/packet_encoding_test_vectors.csv')) {
      const inPriv = hexToNumber(t['in_priv_ours']);
      const pubX = secp256k1.ProjectivePoint.BASE.multiply(inPriv)
        .x.toString(16)
        .padStart(2 * 32, '0');
      deepStrictEqual(pubX, t['mid_x_ours']);

      const bytesOurs = hexToBytes(t['in_ellswift_ours']);
      const decoded = elligatorSwift.decode(bytesOurs);
      deepStrictEqual(toHex(decoded), t['mid_x_ours']);

      const bytesTheirs = hexToBytes(t['in_ellswift_theirs']);
      deepStrictEqual(toHex(elligatorSwift.decode(bytesTheirs)), t['mid_x_theirs']);

      const xShared = elligatorSwift.getSharedSecret(t['in_priv_ours'], bytesTheirs);
      deepStrictEqual(toHex(xShared), t['mid_x_shared']);

      const sharedSecret = elligatorSwift.getSharedSecretBip324(
        t['in_priv_ours'],
        t['in_ellswift_theirs'],
        t['in_ellswift_ours'],
        t['in_initiating'] === '1'
      );
      deepStrictEqual(toHex(sharedSecret), t['mid_shared_secret']);
    }
  });

  should('xswiftec_inv_test_vectors', () => {
    for (const t of parseCSV('bip-0324/xswiftec_inv_test_vectors.csv')) {
      const Fp = secp256k1.CURVE.Fp;
      const u = Fp.create(Fp.fromBytes(hexToBytes(t['u'])));
      const x = Fp.create(Fp.fromBytes(hexToBytes(t['x'])));
      for (let c = 0; c < 8; c++) {
        const name = `case${c}_t`;
        const ret = elligatorSwift._inv(x, u, c);
        if (!ret) deepStrictEqual(t[name], '', 'empty case');
        else {
          deepStrictEqual(toHex(Fp.toBytes(ret)), t[name], 'real case');
          deepStrictEqual(
            elligatorSwift.decode(concatBytes(Fp.toBytes(u), Fp.toBytes(ret))),
            Fp.toBytes(x)
          );
        }
      }
    }
  });

  should('ellswift_decode_test_vectors', () => {
    for (const t of parseCSV('bip-0324/ellswift_decode_test_vectors.csv')) {
      deepStrictEqual(toHex(elligatorSwift.decode(t['ellswift'])), t['x']);
    }
  });
  should('Example', () => {
    // random, so test more.
    for (let i = 0; i < 100; i++) {
      const alice = elligatorSwift.keygen();
      const bob = elligatorSwift.keygen();
      // ECDH
      const sharedAlice = elligatorSwift.getSharedSecret(alice.privateKey, bob.publicKey);
      const sharedBob = elligatorSwift.getSharedSecret(bob.privateKey, alice.publicKey);
      deepStrictEqual(sharedAlice, sharedBob);
      // ECDH BIP324
      const sharedAlice2 = elligatorSwift.getSharedSecretBip324(
        alice.privateKey,
        bob.publicKey,
        alice.publicKey,
        true
      );
      const sharedBob2 = elligatorSwift.getSharedSecretBip324(
        bob.privateKey,
        alice.publicKey,
        bob.publicKey,
        false
      );
      deepStrictEqual(sharedAlice2, sharedBob2);
      // pubKey decoding
      for (const k of [alice, bob]) {
        deepStrictEqual(
          toHex(elligatorSwift.decode(k.publicKey)),
          toHex(secp256k1.getPublicKey(k.privateKey, true).subarray(1))
        );
      }
    }
  });
});

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
