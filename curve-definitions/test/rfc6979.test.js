import { deepStrictEqual } from 'assert';
import { should } from 'micro-should';
import * as nist from '../lib/nist.js';
import { default as rfc6979 } from './fixtures/rfc6979.json' assert { type: 'json' };
function hexToBigint(hex) {
  return BigInt('0x' + hex)
}

should('RFC6979', () => {
  for (const v of rfc6979) {
    const curve = nist[v.curve];
    deepStrictEqual(curve.CURVE.n, hexToBigint(v.q));
    const pubKey = curve.getPublicKey(v.private);
    const pubPoint = curve.Point.fromHex(pubKey);
    deepStrictEqual(pubPoint.x, hexToBigint(v.Ux));
    deepStrictEqual(pubPoint.y, hexToBigint(v.Uy));
    for (const c of v.cases) {
      const h = curve.CURVE.hash(c.message);
      const sigObj = curve.sign(h, v.private);
      // const sigObj = curve.Signature.fromDER(sig);
      deepStrictEqual(sigObj.r, hexToBigint(c.r), 'R');
      deepStrictEqual(sigObj.s, hexToBigint(c.s), 'S');
      deepStrictEqual(curve.verify(sigObj.toDERRawBytes(), h, pubKey), true, 'verify(1)');
      deepStrictEqual(curve.verify(sigObj, h, pubKey), true, 'verify(2)');
    }
  }
});

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
