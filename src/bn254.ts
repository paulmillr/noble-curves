/**
 * bn254, previously known as alt_bn_128, when it had 128-bit security.

Barbulescu-Duquesne 2017 shown it's weaker: just about 100 bits,
so the naming has been adjusted to its prime bit count:
https://hal.science/hal-01534101/file/main.pdf.
Compatible with EIP-196 and EIP-197.

There are huge compatibility issues in the ecosystem:

1. Different libraries call it in different ways: "bn254", "bn256", "alt_bn128", "bn128".
2. libff has bn128, but it's a different curve with different G2:
   https://github.com/scipr-lab/libff/blob/a44f482e18b8ac04d034c193bd9d7df7817ad73f/libff/algebra/curves/bn128/bn128_init.cpp#L166-L169
3. halo2curves bn256 is also incompatible and returns different outputs

We don't implement Point methods toHex / toBytes.
To work around this limitation, has to initialize points on their own from BigInts.
Reason it's not implemented is because [there is no standard](https://github.com/privacy-scaling-explorations/halo2curves/issues/109).
Points of divergence:

- Endianness: LE vs BE (byte-swapped)
- Flags as first hex bits (similar to BLS) vs no-flags
- Imaginary part last in G2 vs first (c0, c1 vs c1, c0)

The goal of our implementation is to support "Ethereum" variant of the curve,
because it at least has specs:

- EIP196 (https://eips.ethereum.org/EIPS/eip-196) describes bn254 ECADD and ECMUL opcodes for EVM
- EIP197 (https://eips.ethereum.org/EIPS/eip-197) describes bn254 pairings
- It's hard: EIPs don't have proper tests. EIP-197 returns boolean output instead of Fp12
- The existing implementations are bad. Some are deprecated:
    - https://github.com/paritytech/bn (old version)
    - https://github.com/ewasm/ethereum-bn128.rs (uses paritytech/bn)
    - https://github.com/zcash-hackworks/bn
    - https://github.com/arkworks-rs/curves/blob/master/bn254/src/lib.rs
- Python implementations use different towers and produce different Fp12 outputs:
    - https://github.com/ethereum/py_pairing
    - https://github.com/ethereum/py_ecc/tree/main/py_ecc/bn128
- Points are encoded differently in different implementations

### Params
Seed (X): 4965661367192848881
Fr: (36x⁴+36x³+18x²+6x+1)
Fp: (36x⁴+36x³+24x²+6x+1)
(E  / Fp ): Y² = X³+3
(Et / Fp²): Y² = X³+3/(u+9) (D-type twist)
Ate loop size: 6x+2

### Towers
- Fp²[u] = Fp/u²+1
- Fp⁶[v] = Fp²/v³-9-u
- Fp¹²[w] = Fp⁶/w²-v

 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import {
  blsBasic,
  type BlsCurvePair,
  type BlsPostPrecomputeFn,
  type BlsPostPrecomputePointAddFn,
} from './abstract/bls.ts';
import { Field, type IField } from './abstract/modular.ts';
import type { Fp, Fp12, Fp2 } from './abstract/tower.ts';
import { psiFrobenius, tower12 } from './abstract/tower.ts';
import { weierstrass, type WeierstrassOpts } from './abstract/weierstrass.ts';
import { bitLen, type TRet } from './utils.ts';
// prettier-ignore
const _0n = /* @__PURE__ */ BigInt(0), _1n = /* @__PURE__ */ BigInt(1), _2n = /* @__PURE__ */ BigInt(2), _3n = /* @__PURE__ */ BigInt(3);
const _6n = /* @__PURE__ */ BigInt(6);

// Locally documented BN pairing seed. EIP-197 does not name this scalar
// directly; noble stores the positive value and derives any `-x` uses later.
const BN_X = /* @__PURE__ */ BigInt('4965661367192848881');
// Bit width of the stored seed itself, not the derived Miller-loop scalar `6x+2`.
const BN_X_LEN = /* @__PURE__ */ (() => bitLen(BN_X))();
// Derived scalar used by the optimized G2 subgroup test required by EIP-197.
const SIX_X_SQUARED = /* @__PURE__ */ (() => _6n * BN_X ** _2n)();

const bn254_G1_CURVE: WeierstrassOpts<bigint> = {
  p: BigInt('0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47'),
  n: BigInt('0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001'),
  // The Ethereum specs define G1 as prime-order but do not spell out the
  // cofactor separately; `h = 1` is the implementation-derived value.
  h: _1n,
  a: _0n,
  b: _3n,
  Gx: _1n,
  Gy: BigInt(2),
};

// r == n
// Finite field over r. It's for convenience and is not used in the code below,
// and its canonical `fromBytes()` decoder is stricter than the EIP-196 MUL
// scalar rule that accepts any 256-bit integer.
// These factories are side-effect free; mark them pure so single-export bundles can drop the rest.
/** bn254 scalar field. */
export const bn254_Fr: TRet<IField<bigint>> = /* @__PURE__ */ (() =>
  Field(bn254_G1_CURVE.n) as TRet<IField<bigint>>)();

// `3 / (i + 9)` from EIP-197, stored in noble's internal `(c0, c1) = (b, a)`
// order rather than the spec's `a * i + b` notation.
const Fp2B = /* @__PURE__ */ (() => ({
  c0: BigInt('19485874751759354771024239261021720505790618469301721065564631296452457478373'),
  c1: BigInt('266929791119991161246907387137283842545076965332900288569378510910307636690'),
}))();

// Bootstrap binding: `Fp12finalExponentiate` needs to reference the finished
// field object while `tower12(...)` is still constructing it.
let Fp12: ReturnType<typeof tower12>['Fp12'];
const tower = /* @__PURE__ */ (() => {
  const res = tower12({
    ORDER: bn254_G1_CURVE.p,
    X_LEN: BN_X_LEN,
    // Public `Fp2.NONRESIDUE` below is the sextic-tower seed `(9, 1)`, not the
    // quadratic relation `i^2 + 1 = 0` from the EIP text.
    FP2_NONRESIDUE: [BigInt(9), _1n],
    Fp2mulByB: (num: Fp2) => Fp2.mul(num, Fp2B),
    Fp12finalExponentiate: (num: Fp12) => {
      const powMinusX = (num: Fp12) => Fp12.conjugate(Fp12._cyclotomicExp(num, BN_X));
      const r0 = Fp12.mul(Fp12.conjugate(num), Fp12.inv(num));
      const r = Fp12.mul(Fp12.frobeniusMap(r0, 2), r0);
      const y1 = Fp12._cyclotomicSquare(powMinusX(r));
      const y2 = Fp12.mul(Fp12._cyclotomicSquare(y1), y1);
      const y4 = powMinusX(y2);
      const y6 = powMinusX(Fp12._cyclotomicSquare(y4));
      const y8 = Fp12.mul(Fp12.mul(Fp12.conjugate(y6), y4), Fp12.conjugate(y2));
      const y9 = Fp12.mul(y8, y1);
      return Fp12.mul(
        Fp12.frobeniusMap(Fp12.mul(Fp12.conjugate(r), y9), 3),
        Fp12.mul(
          Fp12.frobeniusMap(y8, 2),
          Fp12.mul(Fp12.frobeniusMap(y9, 1), Fp12.mul(Fp12.mul(y8, y4), r))
        )
      );
    },
  });
  Fp12 = res.Fp12;
  return res;
})();
const Fp = /* @__PURE__ */ (() => tower.Fp)();
const Fp2 = /* @__PURE__ */ (() => tower.Fp2)();

// END OF CURVE FIELDS
// BN254 uses the same tower seed `(9, 1)` for the Frobenius helper that powers
// the divisive-twist G2 endomorphism.
let frob: ReturnType<typeof psiFrobenius> | undefined;
const getFrob = () => frob || (frob = psiFrobenius(Fp, Fp2, Fp2.NONRESIDUE));
// Eager psiFrobenius setup now dominates `bn254.js` import, so defer it to
// first use. After that these locals are rewritten to the direct helper refs.
let psi: ReturnType<typeof psiFrobenius>['psi'] = (x, y) => {
  const fn = getFrob().psi;
  psi = fn;
  return fn(x, y);
};
let G2psi: ReturnType<typeof psiFrobenius>['G2psi'] = (c, P) => {
  const fn = getFrob().G2psi;
  G2psi = fn;
  return fn(c, P);
};

export const _postPrecompute: BlsPostPrecomputeFn = (
  Rx: Fp2,
  Ry: Fp2,
  Rz: Fp2,
  Qx: Fp2,
  Qy: Fp2,
  pointAdd: BlsPostPrecomputePointAddFn
) => {
  const q = psi(Qx, Qy);
  ({ Rx, Ry, Rz } = pointAdd(Rx, Ry, Rz, q[0], q[1]));
  const q2 = psi(q[0], q[1]);
  pointAdd(Rx, Ry, Rz, q2[0], Fp2.neg(q2[1]));
};

// cofactor: (36 * X^4) + (36 * X^3) + (30 * X^2) + 6*X + 1
const bn254_G2_CURVE: WeierstrassOpts<Fp2> = /* @__PURE__ */ (() => ({
  p: Fp2.ORDER,
  n: bn254_G1_CURVE.n,
  // As with G1, the Ethereum specs do not spell out the G2 cofactor
  // separately; this literal is the implementation-derived value.
  h: BigInt('0x30644e72e131a029b85045b68181585e06ceecda572a2489345f2299c0f9fa8d'),
  a: Fp2.ZERO,
  b: Fp2B,
  Gx: Fp2.fromBigTuple([
    BigInt('10857046999023057135944570762232829481370756359578518086990519993285655852781'),
    BigInt('11559732032986387107991004021392285783925812861821192530917403151452391805634'),
  ]),
  Gy: Fp2.fromBigTuple([
    BigInt('8495653923123431417604973247489272438418190587263600148770280649306958101930'),
    BigInt('4082367875863433681332203403145435568316851327593401208105741076214120093531'),
  ]),
}))();

const fields = /* @__PURE__ */ (() => ({ Fp, Fp2, Fp6: tower.Fp6, Fp12, Fr: bn254_Fr }))();
const bn254_G1 = /* @__PURE__ */ weierstrass(bn254_G1_CURVE, {
  Fp,
  Fn: bn254_Fr,
  // Ethereum encodes infinity as `(0, 0)`, so the public point API accepts it
  // even though it is not an affine curve point, and `fromAffine()` stays lazy:
  // adversarial inputs still need `assertValidity()`.
  allowInfinityPoint: true,
});
const bn254_G2 = /* @__PURE__ */ weierstrass(bn254_G2_CURVE, {
  Fp: Fp2,
  Fn: bn254_Fr,
  // Ethereum encodes infinity as `((0, 0), (0, 0))`, so the public point API
  // accepts it even though it is not an affine curve point.
  allowInfinityPoint: true,
  // Optimized BN254 G2 subgroup test used to satisfy the EIP-197 order check.
  isTorsionFree: (c, P) => P.multiplyUnsafe(SIX_X_SQUARED).equals(G2psi(c, P)), // [p]P = [6X^2]P
});
/*
No hashToCurve for now (and signatures):

- RFC 9380 doesn't mention bn254 and doesn't provide test vectors
- Overall seems like nobody is using BLS signatures on top of bn254
- Seems like it can utilize SVDW, which is not implemented yet
*/
// const htfDefaults = Object.freeze({
//   // DST: a domain separation tag defined in section 2.2.5
//   DST: 'BN254G2_XMD:SHA-256_SVDW_RO_',
//   encodeDST: 'BN254G2_XMD:SHA-256_SVDW_RO_',
//   p: Fp.ORDER,
//   m: 2,
//   k: 128,
//   expand: 'xmd',
//   hash: sha256,
// });
// const hasherOpts = {
//   { ...htfDefaults, m: 1, DST: 'BN254G2_XMD:SHA-256_SVDW_RO_' }
// };
const bn254_params = /* @__PURE__ */ (() => ({
  // Optimal-ate Miller loop parameter derived from the positive BN seed.
  ateLoopSize: BN_X * _6n + _2n,
  r: bn254_Fr.ORDER,
  xNegative: false,
  // EIP-197 writes G2 as `y^2 = x^3 + 3 / (i + 9)`, so the pairing
  // configuration uses the divisive twist convention.
  twistType: 'divisive' as const,
  postPrecompute: _postPrecompute,
}))();
// const bn254_hasher = {
//   hasherOpts: htfDefaults,
//   hasherOptsG1: { m: 1, DST: 'BN254G2_XMD:SHA-256_SVDW_RO_' },
//   hasherOptsG2: htfDefaults
// };
// G2_heff     hEff: BigInt('21888242871839275222246405745257275088844257914179612981679871602714643921549'),
// fromBytes: notImplemented,
// toBytes: notImplemented,

// mapToCurve: notImplemented,
// fromBytes: notImplemented,
// toBytes: notImplemented,
// ShortSignature: {
//   fromBytes: notImplemented,
//   fromHex: notImplemented,
//   toBytes: notImplemented,
//   toRawBytes: notImplemented,
//   toHex: notImplemented,
// },

/**
 * bn254 (a.k.a. alt_bn128) pairing-friendly curve.
 * Contains G1 / G2 operations and pairings only; the commented-out
 * hash-to-curve and signature surface is intentionally not exposed here.
 * @example
 * Compute a pairing from the two generator points.
 *
 * ```ts
 * const gt = bn254.pairing(bn254.G1.Point.BASE, bn254.G2.Point.BASE);
 * ```
 */
// bn254_hasher
export const bn254: BlsCurvePair = /* @__PURE__ */ blsBasic(
  fields,
  bn254_G1,
  bn254_G2,
  bn254_params
);
