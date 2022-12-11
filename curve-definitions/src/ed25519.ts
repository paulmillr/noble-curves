import { sha512 } from '@noble/hashes/sha512';
import { concatBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils';
import { twistedEdwards } from '@noble/curves/edwards';
import { montgomery } from '@noble/curves/montgomery';
import { mod, pow2, isNegativeLE } from '@noble/curves/modular';

const ed25519P = BigInt(
  '57896044618658097711785492504343953926634992332820282019728792003956564819949'
);
// √(-1) aka √(a) aka 2^((p-1)/4)
const ED25519_SQRT_M1 = BigInt(
  '19681161376707505956807079304988542015446066515923890162744021073123829784752'
);

function ed25519_pow_2_252_3(x: bigint) {
  const P = ed25519P;
  const _1n = BigInt(1);
  const _2n = BigInt(2);
  const _5n = BigInt(5);
  const _10n = BigInt(10);
  const _20n = BigInt(20);
  const _40n = BigInt(40);
  const _80n = BigInt(80);
  const x2 = (x * x) % P;
  const b2 = (x2 * x) % P; // x^3, 11
  const b4 = (pow2(b2, _2n, P) * b2) % P; // x^15, 1111
  const b5 = (pow2(b4, _1n, P) * x) % P; // x^31
  const b10 = (pow2(b5, _5n, P) * b5) % P;
  const b20 = (pow2(b10, _10n, P) * b10) % P;
  const b40 = (pow2(b20, _20n, P) * b20) % P;
  const b80 = (pow2(b40, _40n, P) * b40) % P;
  const b160 = (pow2(b80, _80n, P) * b80) % P;
  const b240 = (pow2(b160, _80n, P) * b80) % P;
  const b250 = (pow2(b240, _10n, P) * b10) % P;
  const pow_p_5_8 = (pow2(b250, _2n, P) * x) % P;
  // ^ To pow to (p+3)/8, multiply it by x.
  return { pow_p_5_8, b2 };
}
function adjustScalarBytes(bytes: Uint8Array): Uint8Array {
  // Section 5: For X25519, in order to decode 32 random bytes as an integer scalar,
  // set the three least significant bits of the first byte
  bytes[0] &= 248; // 0b1111_1000
  // and the most significant bit of the last to zero,
  bytes[31] &= 127; // 0b0111_1111
  // set the second most significant bit of the last byte to 1
  bytes[31] |= 64; // 0b0100_0000
  return bytes;
}

// Just in case
export const ED25519_TORSION_SUBGROUP = [
  '0100000000000000000000000000000000000000000000000000000000000000',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  '0000000000000000000000000000000000000000000000000000000000000080',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
  '0000000000000000000000000000000000000000000000000000000000000000',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
];

const ED25519_DEF = {
  // Param: a
  a: BigInt(-1),
  // Equal to -121665/121666 over finite field.
  // Negative number is P - number, and division is invert(number, P)
  d: BigInt('37095705934669439343138083508754565189542113879843219016388785533085940283555'),
  // Finite field 𝔽p over which we'll do calculations; 2n ** 255n - 19n
  P: ed25519P,
  // Subgroup order: how many points ed25519 has
  // 2n ** 252n + 27742317777372353535851937790883648493n;
  n: BigInt('7237005577332262213973186563042994240857116359379907606001950938285454250989'),
  // Cofactor
  h: BigInt(8),
  // Base point (x, y) aka generator point
  Gx: BigInt('15112221349535400772501151409588531511454012693041857206046113283949847762202'),
  Gy: BigInt('46316835694926478169428394003475163141307993866256225615783033603165251855960'),
  hash: sha512,
  randomBytes,
  adjustScalarBytes,
  // dom2
  // Ratio of u to v. Allows us to combine inversion and square root. Uses algo from RFC8032 5.1.3.
  // Constant-time, u/√v
  uvRatio: (u: bigint, v: bigint): { isValid: boolean; value: bigint } => {
    const P = ed25519P;
    const v3 = mod(v * v * v, P); // v³
    const v7 = mod(v3 * v3 * v, P); // v⁷
    // (p+3)/8 and (p-5)/8
    const pow = ed25519_pow_2_252_3(u * v7).pow_p_5_8;
    let x = mod(u * v3 * pow, P); // (uv³)(uv⁷)^(p-5)/8
    const vx2 = mod(v * x * x, P); // vx²
    const root1 = x; // First root candidate
    const root2 = mod(x * ED25519_SQRT_M1, P); // Second root candidate
    const useRoot1 = vx2 === u; // If vx² = u (mod p), x is a square root
    const useRoot2 = vx2 === mod(-u, P); // If vx² = -u, set x <-- x * 2^((p-1)/4)
    const noRoot = vx2 === mod(-u * ED25519_SQRT_M1, P); // There is no valid root, vx² = -u√(-1)
    if (useRoot1) x = root1;
    if (useRoot2 || noRoot) x = root2; // We return root2 anyway, for const-time
    if (isNegativeLE(x, P)) x = mod(-x, P);
    return { isValid: useRoot1 || useRoot2, value: x };
  },
} as const;

export const ed25519 = twistedEdwards(ED25519_DEF);
function ed25519_domain(data: Uint8Array, ctx: Uint8Array, phflag: boolean) {
  if (ctx.length > 255) throw new Error('Context is too big');
  return concatBytes(
    utf8ToBytes('SigEd25519 no Ed25519 collisions'),
    new Uint8Array([phflag ? 1 : 0, ctx.length]),
    ctx,
    data
  );
}
export const ed25519ctx = twistedEdwards({ ...ED25519_DEF, domain: ed25519_domain });
export const ed25519ph = twistedEdwards({
  ...ED25519_DEF,
  domain: ed25519_domain,
  preHash: sha512,
});

export const x25519 = montgomery({
  P: ed25519P,
  a24: BigInt('121665'),
  montgomeryBits: 255, // n is 253 bits
  nByteLength: 32,
  Gu: '0900000000000000000000000000000000000000000000000000000000000000',
  powPminus2: (x: bigint): bigint => {
    const P = ed25519P;
    // x^(p-2) aka x^(2^255-21)
    const { pow_p_5_8, b2 } = ed25519_pow_2_252_3(x);
    return mod(pow2(pow_p_5_8, BigInt(3), P) * b2, P);
  },
  adjustScalarBytes,
});
