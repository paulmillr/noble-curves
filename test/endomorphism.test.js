import * as fc from 'fast-check';
import { describe, should } from 'micro-should';
import { deepStrictEqual } from 'node:assert';
import {
  _splitEndoScalar as splitScalar,
  weierstrass as weierstrassN,
} from '../abstract/weierstrass.js';
import { bitLen } from '../utils.js';
import { calcEndo, calculateScalarBound, config } from './misc/endomorphism.js';

// TODO: calculate endomorphism
const SECP160K1 = {
  p: '0xfffffffffffffffffffffffffffffffeffffac73',
  n: '0x100000000000000000001b8fa16dfab9aca16b6b3',
  h: '0x1',
  a: '0x0',
  b: '0x7',
  Gx: '0x3b4c382ce37aa192a4019e763036f4f5dd4d7ebb',
  Gy: '0x938cf935318fdced6bc28286531733c3f03c4fee',
};
const SECP192K1 = {
  p: '0xfffffffffffffffffffffffffffffffffffffffeffffee37',
  n: '0xfffffffffffffffffffffffe26f2fc170f69466a74defd8d',
  h: '0x1',
  a: '0x0',
  b: '0x3',
  Gx: '0xdb4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d',
  Gy: '0x9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d',
};

const SECP224K1 = {
  p: '0xfffffffffffffffffffffffffffffffffffffffffffffffeffffe56d',
  n: '0x010000000000000000000000000001dce8d2ec6184caf0a971769fb1f7',
  h: '0x1',
  a: '0x0',
  b: '0x5',
  Gx: '0xa1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c',
  Gy: '0x7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5',
};

const SECP256K1 = {
  p: BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f'),
  n: BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'),
  h: BigInt(1),
  a: BigInt(0),
  b: BigInt(7),
  Gx: BigInt('0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
  Gy: BigInt('0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'),
};

const BLS12381_G1 = {
  p: BigInt(
    '0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab'
  ),
  n: BigInt('0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001'),
  h: BigInt('0x396c8c005555e1568c00aaab0000aaab'),
  a: BigInt(0),
  b: BigInt(4),
  Gx: BigInt(
    '0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb'
  ),
  Gy: BigInt(
    '0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
  ),
};

const curvesEndo = {
  SECP160K1,
  SECP192K1,
  SECP224K1,
  SECP256K1,
  BLS12381_G1,
};

// We test 10k+ different scalars using fast-check below; those are just statics
const testScalars = [
  3n,
  33333n,
  2n ** 33n,
  2n ** 150n - 12930n,
  2n ** 255n - 19n,
  2n ** 207n - 11n,
  2n ** 520n + 41290903n,
];

function testScalar(Fn, num, basis, lambda) {
  const sN = Fn.create(num);
  const { k1, k2, k1neg, k2neg } = splitScalar(sN, basis, Fn.ORDER);
  const composed = Fn.add(Fn.mul(lambda, k2neg ? Fn.neg(k2) : k2), k1neg ? Fn.neg(k1) : k1);
  if (!Fn.eql(sN, composed)) throw new Error('splitScalar failed');
  const bound = calculateScalarBound(basis);
  if (k1 > bound || k2 > bound) throw new Error('scalar overflow');
}

export const endoCurves = {};
config.log = false;

function hex(n) {
  const _16 = n.toString(16);
  const abs = n < 0 ? _16.slice(1) : _16;
  return `${n < 0 ? '-' : ''}BigInt(0x${abs})`;
}

describe('Endomorphism', () => {
  for (let [name, e] of Object.entries(curvesEndo)) {
    should(name, () => {
      const p = BigInt(e.p);
      const n = BigInt(e.n);
      const params = {
        p: BigInt(p),
        a: BigInt(e.a),
        b: BigInt(e.b),
        Gx: BigInt(e.Gx),
        Gy: BigInt(e.Gy),
        n: n,
        h: BigInt(e.h),
      };
      const curve = weierstrassN(params);
      const { Fp, Fn } = curve;
      for (const { lambda, beta, basis } of calcEndo(p, n)) {
        // Basic EC aritchmetic
        const p = curve.BASE.multiply(lambda); // p * lambda
        const p2 = curve.fromAffine({ x: Fp.mul(curve.BASE.x, beta), y: curve.BASE.y }); // p(x*beta, y)
        if (!p.equals(p2)) throw new Error('incorrect lambda-beta pair');
        // splitScalar: k2*lambda + k1== s
        // console.log('ENDO', {
        //   beta: hex(beta),
        //   basis: basis.map((i) => i.map(hex)),
        // });
        const curveEndo = weierstrassN(params, { endo: { beta, basises: basis } });
        const FC_BIGINT = fc.bigInt(1n, Fn.ORDER - 1n);
        // Test exhaustively, since this is very important!
        fc.assert(
          fc.property(FC_BIGINT, (num) => {
            testScalar(Fn, num, basis, lambda);
          }),
          { numRuns: 10000 }
        );
        // EC stuff is slow, so only 100 tests
        fc.assert(
          fc.property(FC_BIGINT, (num) => {
            const sN = Fn.create(num);
            deepStrictEqual(
              curveEndo.BASE.multiply(sN).toAffine(),
              curve.BASE.multiply(sN).toAffine()
            );
          }),
          { numRuns: 100 }
        );
        for (const s of testScalars) {
          testScalar(Fn, s, basis, lambda);
          // Now same over EC
          const sN = Fn.create(s);
          const { k1, k2, k1neg, k2neg } = splitScalar(sN, basis, Fn.ORDER);
          const p = curve.BASE.multiplyUnsafe(sN); // G*s
          const p1 = curve.BASE.multiplyUnsafe(k1);
          const p2 = curve.BASE.multiplyUnsafe(k2);
          const p2beta = curve.fromAffine({ x: Fp.mul(p2.x, beta), y: p2.y });
          const p1real = k1neg ? p1.negate() : p1;
          const p2real = k2neg ? p2beta.negate() : p2beta;
          const pComposed = p1real.add(p2real);
          if (!pComposed.equals(p)) throw new Error('split scalar over points failed');
          const maxLen = Math.ceil(bitLen(n) / 2);
          if (bitLen(k1) > maxLen || bitLen(k2) > maxLen) throw new Error('scalar overflow');
          // Now curves
          deepStrictEqual(
            curveEndo.BASE.multiply(sN).toAffine(),
            curve.BASE.multiply(sN).toAffine()
          );
        }
      }
      //endoCurves[name] = createCurve(params, sha256);
    });
  }
});

should.runWhen(import.meta.url);
