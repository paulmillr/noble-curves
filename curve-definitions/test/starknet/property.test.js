import { deepStrictEqual, throws } from 'assert';
import { should } from 'micro-should';
import * as starknet from '../../lib/starknet.js';
import * as fc from 'fast-check';

const FC_BIGINT = fc.bigInt(1n + 1n, starknet.CURVE.n - 1n);

should('Point#toHex() roundtrip', () => {
  fc.assert(
    fc.property(FC_BIGINT, (x) => {
      const point1 = starknet.Point.fromPrivateKey(x);
      const hex = point1.toHex(true);
      deepStrictEqual(starknet.Point.fromHex(hex).toHex(true), hex);
    })
  );
});

should('Signature.fromCompactHex() roundtrip', () => {
  fc.assert(
    fc.property(FC_BIGINT, FC_BIGINT, (r, s) => {
      const sig = new starknet.Signature(r, s);
      deepStrictEqual(starknet.Signature.fromCompact(sig.toCompactHex()), sig);
    })
  );
});

should('Signature.fromDERHex() roundtrip', () => {
  fc.assert(
    fc.property(FC_BIGINT, FC_BIGINT, (r, s) => {
      const sig = new starknet.Signature(r, s);
      deepStrictEqual(starknet.Signature.fromDER(sig.toDERHex()), sig);
    })
  );
});

should('verify()/should verify random signatures', () =>
  fc.assert(
    fc.asyncProperty(FC_BIGINT, fc.hexaString({ minLength: 64, maxLength: 64 }), (privNum, msg) => {
      const privKey = privNum.toString(16).padStart(64, '0');
      const pub = starknet.getPublicKey(privKey);
      const sig = starknet.sign(msg, privKey);
      deepStrictEqual(starknet.verify(sig, msg, pub), true);
    })
  )
);

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
