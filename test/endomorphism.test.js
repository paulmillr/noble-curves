import { sha256 } from '@noble/hashes/sha2.js';
import { createCurve } from '../esm/_shortw_utils.js';
import { Field } from '../esm/abstract/modular.js';
import { calcEndo, config } from './misc/endomorphism.js';

// TODO: calculate endomorphism
const SECP160K1 = {
  p: '0xfffffffffffffffffffffffffffffffeffffac73',
  a: '0x0',
  b: '0x7',
  Gx: '0x3b4c382ce37aa192a4019e763036f4f5dd4d7ebb',
  Gy: '0x938cf935318fdced6bc28286531733c3f03c4fee',
  n: '0x100000000000000000001b8fa16dfab9aca16b6b3',
  h: '0x1',
  oid: '1.3.132.0.9',
};
const SECP192K1 = {
  p: '0xfffffffffffffffffffffffffffffffffffffffeffffee37',
  a: '0x0',
  b: '0x3',
  Gx: '0xdb4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d',
  Gy: '0x9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d',
  n: '0xfffffffffffffffffffffffe26f2fc170f69466a74defd8d',
  h: '0x1',
};

const SECP224K1 = {
  p: '0xfffffffffffffffffffffffffffffffffffffffffffffffeffffe56d',
  a: '0x0',
  b: '0x5',
  Gx: '0xa1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c',
  Gy: '0x7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5',
  n: '0x010000000000000000000000000001dce8d2ec6184caf0a971769fb1f7',
  h: '0x1',
};

const curvesEndo = {
  SECP192K1,
  SECP224K1,
  SECP160K1,
};
export const endoCurves = {};
config.log = false;
for (let [name, e] of Object.entries(curvesEndo)) {
  const p = BigInt(e.p);
  const n = BigInt(e.n);
  const params = {
    Fp: Field(p),
    a: BigInt(e.a),
    b: BigInt(e.b),
    Gx: BigInt(e.Gx),
    Gy: BigInt(e.Gy),
    n: n,
    h: BigInt(e.h),
  };
  console.log();
  console.log();
  const endo = calcEndo(p, n);
  console.log('calculating endo for', name);
  // const hex = (n) => {
  //   const _16 = n.toString(16);
  //   // const abs = n < 0 ? _16.slice(1) : _16;
  //   // const pref = n < 0 ? '-0x' : '0x';
  //   // const res = pref + abs
  //   return `BigInt("${_16}")`;
  // };
  console.log('betas', endo.betas);
  console.log('lambdas', endo.lambdas);
  console.log('basises', endo.basises);
  const index = 0;
  params.betas = endo.betas[index];
  params.lambdas = endo.lambdas[index];
  params.basises = endo.basises[index];
  endoCurves[name] = createCurve(params, sha256);
}
