import { sha1 } from '@noble/hashes/legacy.js';
import { sha224, sha256, sha384, sha512, sha512_224, sha512_256 } from '@noble/hashes/sha2.js';
import { sha3_224, sha3_256, sha3_384, sha3_512 } from '@noble/hashes/sha3.js';
import { hexToBytes } from '@noble/hashes/utils.js';
import { describe, should } from 'micro-should';
import { deepStrictEqual as eql } from 'node:assert';
import { ed25519, ed25519ctx, ed25519ph } from '../esm/ed25519.js';
import { ed448, ed448ph } from '../esm/ed448.js';
import { p256, p384, p521 } from '../esm/nist.js';
import { hexToNumber } from '../esm/utils.js';
import { jsonGZ } from './utils.js';

const loadACVP = (name, gzip = true) => {
  const json = (fname) =>
    jsonGZ(`vectors/acvp-vectors/gen-val/json-files/${name}/${fname}.json${gzip ? '.gz' : ''}`);
  const prompt = json('prompt');
  const expectedResult = json('expectedResults');
  const internalProjection = json('internalProjection');
  eql(prompt.testGroups.length, expectedResult.testGroups.length);
  eql(prompt.testGroups.length, internalProjection.testGroups.length);
  const groups = [];
  for (let gid = 0; gid < prompt.testGroups.length; gid++) {
    const { tests: pTests, ...pInfo } = prompt.testGroups[gid];
    const { tests: erTests, ...erInfo } = expectedResult.testGroups[gid];
    const { tests: ipTests, ...ipInfo } = internalProjection.testGroups[gid];
    const group = { info: { p: pInfo, er: erInfo, ip: ipInfo }, tests: [] };
    eql(pTests.length, erTests.length);
    eql(pTests.length, ipTests.length);
    for (let tid = 0; tid < pTests.length; tid++) {
      group.tests.push({
        p: pTests[tid],
        er: erTests[tid],
        ip: ipTests[tid],
      });
    }
    groups.push(group);
  }
  return groups;
};

const CURVES = {
  //'P-224': p224,
  'P-256': p256,
  'P-384': p384,
  'P-521': p521,
  'ED-25519': ed25519,
  'ED-448': ed448,
};

const ED_CURVES = {
  'ED-25519': { basic: ed25519, ctx: ed25519ctx, prehash: ed25519ph },
  'ED-448': { basic: ed448, ctx: ed448, prehash: ed448ph },
};

const HASHES = {
  'SHA-1': sha1,
  'SHA2-224': sha224,
  'SHA2-256': sha256,
  'SHA2-384': sha384,
  'SHA2-512': sha512,
  'SHA2-512/224': sha512_224,
  'SHA2-512/256': sha512_256,
  'SHA3-224': sha3_224,
  'SHA3-256': sha3_256,
  'SHA3-384': sha3_384,
  'SHA3-512': sha3_512,
  // 'SHAKE-128': shake128_32,
  // 'SHAKE-256': shake256_64,
};

describe('ACVP', () => {
  should('ECDSA-KeyGen', () => {
    const groups = [...loadACVP('ECDSA-KeyGen-1.0'), ...loadACVP('ECDSA-KeyGen-FIPS186-5')];
    for (const { info, tests } of groups) {
      const curve = CURVES[info.ip.curve];
      if (!curve) continue;
      for (const t of tests) {
        const pub = curve.getPublicKey(hexToBytes(t.ip.d));
        const { x, y } = curve.Point.fromHex(pub).toAffine();
        eql(curve.Point.Fp.toBytes(x), hexToBytes(t.ip.qx));
        eql(curve.Point.Fp.toBytes(y), hexToBytes(t.ip.qy));
      }
    }
  });

  should('ECDSA-KeyVer', () => {
    const groups = [...loadACVP('ECDSA-KeyVer-1.0'), ...loadACVP('ECDSA-KeyVer-FIPS186-5')];
    for (const { info, tests } of groups) {
      const curve = CURVES[info.ip.curve];
      if (!curve) continue;
      for (const t of tests) {
        const x = hexToNumber(t.ip.qx);
        const y = hexToNumber(t.ip.qy);
        let ok;
        try {
          const p = curve.Point.fromAffine({ x, y });
          p.assertValidity();
          ok = true;
        } catch (e) {
          ok = false;
        }
        if (ok !== t.ip.testPassed) throw new Error('fail');
      }
    }
  });
  should('ECDSA-SigGen', () => {
    const groups = [
      // These require injecting 'k'
      //  ...loadACVP('ECDSA-SigGen-1.0'),
      //  ...loadACVP('ECDSA-SigGen-FIPS186-5'),
      ...loadACVP('DetECDSA-SigGen-FIPS186-5'),
    ];
    /*
      sign: (msgHash: Hex, privKey: PrivKey, opts?: SignOpts) => RecoveredSignatureType;
  verify: (signature: Hex | SignatureLike, msgHash: Hex, publicKey: Hex, opts?: VerOpts) => boolean;
    */
    for (const { info, tests } of groups) {
      const curve = CURVES[info.ip.curve];
      if (!curve) continue;
      const hash = HASHES[info.ip.hashAlg];
      const curveWithHash = curve.create(hash);
      for (const t of tests) {
        if (t.ip.randomValue) continue; // mesage randomization
        const sk = hexToBytes(info.ip.d);
        const x = hexToNumber(info.ip.qx);
        const y = hexToNumber(info.ip.qy);
        const pk = curve.Point.fromAffine({ x, y }).toBytes();
        eql(pk, curve.getPublicKey(sk));
        const opts = { lowS: false, prehash: true };
        const msg = hexToBytes(t.ip.message);
        const sig = curveWithHash.sign(hexToBytes(t.ip.message), sk, opts);
        const r = curve.Point.Fn.toBytes(sig.r);
        const s = curve.Point.Fn.toBytes(sig.s);
        eql(r, hexToBytes(t.ip.r));
        eql(s, hexToBytes(t.ip.s));
        eql(curveWithHash.verify(sig, msg, curve.getPublicKey(sk), opts), true);
      }
    }
  });
  should('ECDSA-SigVer', () => {
    const groups = [...loadACVP('ECDSA-SigVer-1.0'), ...loadACVP('ECDSA-SigVer-FIPS186-5')];
    for (const { info, tests } of groups) {
      const curve = CURVES[info.ip.curve];
      if (!curve) continue;
      // TODO: remove
      if (info.ip.hashAlg.startsWith('SHAKE-')) continue;
      // console.log(info.ip.hashAlg);
      const hash = HASHES[info.ip.hashAlg];
      const curveWithHash = curve.create(hash);
      for (const t of tests) {
        if (t.ip.randomValue) continue; // mesage randomization
        const opts = { lowS: false, prehash: true };
        const msg = hexToBytes(t.ip.message);
        const x = hexToNumber(t.ip.qx);
        const y = hexToNumber(t.ip.qy);
        const pk = curve.Point.fromAffine({ x, y }).toBytes();
        if (info.ip.d) {
          const sk = hexToBytes(info.ip.d);
          eql(pk, curve.getPublicKey(sk));
        }
        const r = hexToNumber(t.ip.r);
        const s = hexToNumber(t.ip.s);
        let passed;
        try {
          const sig = new curve.Signature(r, s);
          passed = curveWithHash.verify(sig, msg, pk, opts);
        } catch (e) {
          passed = false;
        }
        eql(passed, t.ip.testPassed);
      }
    }
  });
  should('EDDSA-KeyGen', () => {
    const groups = loadACVP('EDDSA-KeyGen-1.0');
    for (const { info, tests } of groups) {
      const curve = ED_CURVES[info.ip.curve].basic;
      if (!curve) continue;
      for (const t of tests) {
        eql(curve.getPublicKey(hexToBytes(t.ip.d)), hexToBytes(t.ip.q));
      }
    }
  });
  should('EDDSA-KeyVer', () => {
    const groups = loadACVP('EDDSA-KeyVer-1.0');
    for (const { info, tests } of groups) {
      const curve = ED_CURVES[info.ip.curve].basic;
      if (!curve) continue;
      for (const t of tests) {
        let passed;
        try {
          curve.Point.fromHex(hexToBytes(t.ip.q)).assertValidity();
          passed = true;
        } catch {
          passed = false;
        }
        eql(passed, t.ip.testPassed);
      }
    }
  });
  should('EDDSA-SigGen', () => {
    const groups = loadACVP('EDDSA-SigGen-1.0');
    for (const { info, tests } of groups) {
      let curve = ED_CURVES[info.ip.curve];
      if (!curve) continue;
      curve = info.ip.preHash ? curve.prehash : curve.basic;
      for (const t of tests) {
        const msg = hexToBytes(t.ip.message);
        const sk = hexToBytes(info.ip.d);
        const ctx = t.ip.context ? hexToBytes(t.ip.context) : undefined;
        const sig = curve.sign(msg, sk, { prehash: info.ip.preHash, context: ctx });
        eql(sig, hexToBytes(t.ip.signature));
      }
    }
  });
  should('EDDSA-SigVer', () => {
    const groups = loadACVP('EDDSA-SigVer-1.0');
    for (const { info, tests } of groups) {
      let curve = ED_CURVES[info.ip.curve];
      if (!curve) continue;
      curve = info.ip.preHash ? curve.prehash : curve.basic;
      for (const t of tests) {
        const msg = hexToBytes(t.ip.message);
        const pk = hexToBytes(t.ip.q);
        const ctx = t.ip.context ? hexToBytes(t.ip.context) : undefined;
        const sig = hexToBytes(t.ip.signature);
        let passed;
        try {
          passed = curve.verify(sig, msg, pk, { prehash: info.ip.preHash, context: ctx });
        } catch {
          passed = false;
        }
        eql(passed, t.ip.testPassed);
      }
    }
  });
});

should.runWhen(import.meta.url);
