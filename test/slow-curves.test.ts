import { bytesToHex } from '@noble/hashes/utils.js';
import { describe, it } from '@paulmillr/jsbt/test.js';
import { strictEqual as eql } from 'node:assert';
import { bls12_381 as bls } from '../src/bls12-381.ts';
import { x25519 } from '../src/ed25519.ts';
import { x448 } from '../src/ed448.ts';
import { numberToBytesBE } from '../src/utils.ts';
import { CURVES, ScalarMultiplier, interleavedMSMUnsafe, pippenger } from './point.helpers.ts';

const SCALAR_RUNS = 1_000;
const CODEC_RUNS = 10_000;
const BLS_BATCH_SIZE = 2_048;
const PUBLIC_CURVES = Object.entries(CURVES).filter(([name]) => !name.startsWith('misc_'));

// Deterministic xorshift64: failures reproduce without recording external randomness.
function makeRng(initialSeed: bigint) {
  let seed = initialSeed;
  const mask64 = (1n << 64n) - 1n;
  const rnd64 = () => {
    seed = (seed ^ (seed << 13n)) & mask64;
    seed ^= seed >> 7n;
    seed = (seed ^ (seed << 17n)) & mask64;
    return seed;
  };
  const rndBig = (bits: number) => {
    let res = 0n;
    for (let i = 0; i < bits; i += 64) res = (res << 64n) | rnd64();
    return res & ((1n << BigInt(bits)) - 1n);
  };
  const rndBelow = (n: bigint) => {
    const bits = n.toString(2).length;
    while (true) {
      const res = rndBig(bits);
      if (res < n) return res;
    }
  };
  const randomBytes = (length: number) => {
    const out = new Uint8Array(length);
    for (let i = 0; i < length; ) {
      let word = rnd64();
      for (let j = 0; j < 8 && i < length; j++, i++) {
        out[i] = Number(word & 0xffn);
        word >>= 8n;
      }
    }
    return out;
  };
  return { rndBelow, randomBytes };
}

// Independent reference which only uses the group add/double operations.
function naiveMul(zero, point, scalar: bigint) {
  let acc = zero;
  let base = point;
  while (scalar > 0n) {
    if (scalar & 1n) acc = acc.add(base);
    if (scalar > 1n) base = base.double();
    scalar >>= 1n;
  }
  return acc;
}

function scalarCases(order: bigint, count: number, rndBelow: (n: bigint) => bigint) {
  const cases = new Set<bigint>();
  const add = (scalar: bigint) => {
    if (scalar > 0n && scalar < order) cases.add(scalar);
  };
  [1n, 2n, 3n, 7n, order - 1n, order - 2n, (order - 1n) / 2n, (order + 1n) / 2n].forEach(add);
  const bits = order.toString(2).length;
  for (const bit of [8, 16, 31, 32, 33, 63, 64, 65, 127, 128, 129, bits - 2, bits - 1]) {
    if (bit < 1) continue;
    const power = 1n << BigInt(bit);
    add(power - 1n);
    add(power);
    add(power + 1n);
  }
  while (cases.size < count) add(rndBelow(order - 1n) + 1n);
  return [...cases].slice(0, count);
}

function acceptedEncodingRoundtrip(Point, encoded: Uint8Array, label: string) {
  let point;
  try {
    point = Point.fromBytes(encoded);
  } catch {
    return;
  }
  point.assertValidity();
  const canonical = point.toBytes();
  eql(Point.fromBytes(canonical).equals(point), true, label);
}

function pointEncodings(point) {
  const encodings = [point.toBytes()];
  try {
    encodings.push(point.toBytes(false));
  } catch {
    // Some prime-order wrappers expose one canonical encoding only.
  }
  const unique = new Map(encodings.map((encoding) => [bytesToHex(encoding), encoding]));
  return [...unique.values()];
}

const VECTORS = [
  {
    name: 'X25519',
    curve: x25519,
    expected: '7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424',
  },
  {
    name: 'X448',
    curve: x448,
    expected:
      '077f453681caca3693198420bbe515cae0002472519b3e67661a7e89cab94695c8f4bcd66e61b9b9c946da8d524de3d69bd9d9d66b997e37',
  },
];

describe('RFC 7748 million-iteration vectors', () => {
  for (const { name, curve, expected } of VECTORS) {
    it(name, () => {
      let k = curve.GuBytes;
      for (let i = 0, u = k; i < 1_000_000; i++) [k, u] = [curve.scalarMult(k, u), k];
      eql(bytesToHex(k), expected);
    });
  }
});

describe('scalar multiplication differential soak', () => {
  it(`${SCALAR_RUNS} deterministic scalars across every configured curve`, () => {
    let curveIndex = 0;
    for (const [name, curve] of Object.entries(CURVES)) {
      const Point = curve.Point;
      const order = Point.Fn.ORDER;
      const rng = makeRng(0x7363616c61720000n + BigInt(curveIndex++));
      const scalars = scalarCases(order, SCALAR_RUNS, rng.rndBelow);
      const qScalar = rng.rndBelow(order - 1n) + 1n;
      const Q = Point.BASE.multiplyUnsafe(qScalar);
      eql(Q.equals(naiveMul(Point.ZERO, Point.BASE, qScalar)), true, `${name}: Q`);
      const multiplier = new ScalarMultiplier(Point);

      for (let i = 0; i < scalars.length; i++) {
        const scalar = scalars[i];
        const point = i % 2 === 0 ? Point.BASE : Q;
        const expected = naiveMul(Point.ZERO, point, scalar);
        const label = `${name}: scalar ${i}`;
        eql(point.multiply(scalar).equals(expected), true, `${label}: multiply`);
        eql(point.multiplyUnsafe(scalar).equals(expected), true, `${label}: multiplyUnsafe`);
        eql(multiplier.mulCT(point, scalar).p.equals(expected), true, `${label}: mulCT`);
      }
    }
  });
});

describe('point decoder mutation soak', () => {
  it(`${CODEC_RUNS} deterministic encodings per public curve`, () => {
    let curveIndex = 0;
    for (const [name, curve] of PUBLIC_CURVES) {
      const Point = curve.Point;
      const rng = makeRng(0x636f646563000000n + BigInt(curveIndex++));
      const baseEncodings = pointEncodings(Point.BASE);
      const derivedEncodings = pointEncodings(Point.BASE.multiplyUnsafe(0x12345n));
      const mutationSeeds = [...baseEncodings, ...derivedEncodings];

      for (let i = 0; i < mutationSeeds.length; i++) {
        const seed = mutationSeeds[i];
        for (let bit = 0; bit < seed.length * 8; bit++) {
          const mutated = seed.slice();
          mutated[bit >> 3] ^= 1 << (bit & 7);
          acceptedEncodingRoundtrip(Point, mutated, `${name}: seed ${i}, bit ${bit}`);
        }
      }

      for (let i = 0; i < CODEC_RUNS; i++) {
        const encoding = baseEncodings[i % baseEncodings.length];
        acceptedEncodingRoundtrip(
          Point,
          rng.randomBytes(encoding.length),
          `${name}: random encoding ${i}`
        );
      }
    }
  });
});

describe('large MSM boundary soak', () => {
  const curveNames = [
    'secp256k1',
    'secp256r1',
    'ed25519',
    'bls12_381_G1',
    'bls12_381_G2',
    'bn254_G1',
    'bn254_G2',
  ];
  const sizes = [31, 32, 33, 127, 128, 129, 511, 512, 513, 2047, 2048, 2049];

  it('Pippenger and interleaved MSM around size/window boundaries', () => {
    for (let curveIndex = 0; curveIndex < curveNames.length; curveIndex++) {
      const name = curveNames[curveIndex];
      const Point = CURVES[name].Point;
      const order = Point.Fn.ORDER;
      const rng = makeRng(0x6d736d0000000000n + BigInt(curveIndex));
      const max = sizes[sizes.length - 1];
      const startScalar = rng.rndBelow(order - 1n) + 1n;
      const stepScalar = rng.rndBelow(order - 1n) + 1n;
      const stepPoint = Point.BASE.multiplyUnsafe(stepScalar);
      const points = [];
      const scalars = [];
      const totals = [];
      let point = Point.BASE.multiplyUnsafe(startScalar);
      let pointScalar = startScalar;
      let total = 0n;

      for (let i = 0; i < max; i++) {
        const scalar = i % 17 === 0 ? 0n : rng.rndBelow(order);
        points.push(point);
        scalars.push(scalar);
        total = (total + pointScalar * scalar) % order;
        totals.push(total);
        point = point.add(stepPoint);
        pointScalar = (pointScalar + stepScalar) % order;
      }

      for (const size of sizes) {
        const selectedPoints = points.slice(0, size);
        const selectedScalars = scalars.slice(0, size);
        const expected = totals[size - 1]
          ? Point.BASE.multiplyUnsafe(totals[size - 1])
          : Point.ZERO;
        eql(
          pippenger(Point, selectedPoints, selectedScalars).equals(expected),
          true,
          `${name}: pippenger L=${size}`
        );
        eql(
          interleavedMSMUnsafe(Point, selectedPoints, 5)(selectedScalars).equals(expected),
          true,
          `${name}: interleaved L=${size}, W=5`
        );
        if (size === 129) {
          for (const window of [2, 8]) {
            eql(
              interleavedMSMUnsafe(Point, selectedPoints, window)(selectedScalars).equals(expected),
              true,
              `${name}: interleaved L=${size}, W=${window}`
            );
          }
        }
      }
    }
  });
});

function largeBlsBatch(api, PubPoint, SigPoint, name: string) {
  const secretKeys = Array.from({ length: BLS_BATCH_SIZE }, (_, i) =>
    numberToBytesBE(BigInt(i + 1), 32)
  );
  const publicKeys = secretKeys.map((secretKey) => api.getPublicKey(secretKey));

  {
    const messages = secretKeys.map((_, i) => api.hash(numberToBytesBE(BigInt(i), 8)));
    const signatures = messages.map((message, i) => api.sign(message, secretKeys[i]));
    const signature = api.aggregateSignatures(signatures);
    const items = messages.map((message, i) => ({ message, publicKey: publicKeys[i] }));
    eql(api.verifyBatch(signature, items), true, `${name}: unique messages`);

    const wrongItems = items.slice();
    const wrongIndex = Math.floor(BLS_BATCH_SIZE / 2);
    wrongItems[wrongIndex] = {
      ...wrongItems[wrongIndex],
      message: api.hash(numberToBytesBE(BigInt(BLS_BATCH_SIZE + 1), 8)),
    };
    eql(api.verifyBatch(signature, wrongItems), false, `${name}: wrong unique message`);
    eql(
      api.verifyBatch(signature.add(SigPoint.BASE), items),
      false,
      `${name}: wrong aggregate signature`
    );
  }

  {
    const message = api.hash(numberToBytesBE(0x73616d652d6d7367n, 8));
    const signatures = secretKeys.map((secretKey) => api.sign(message, secretKey));
    const signature = api.aggregateSignatures(signatures);
    const items = publicKeys.map((publicKey) => ({ message, publicKey }));
    eql(api.verifyBatch(signature, items), true, `${name}: shared message`);

    const wrongItems = items.slice();
    wrongItems[0] = { message, publicKey: publicKeys[0].add(PubPoint.BASE) };
    eql(api.verifyBatch(signature, wrongItems), false, `${name}: wrong shared-message key`);
  }
}

describe('large BLS batch verification soak', () => {
  it(`${BLS_BATCH_SIZE} long-signature items`, () => {
    largeBlsBatch(bls.longSignatures, bls.G1.Point, bls.G2.Point, 'long signatures');
  });
  it(`${BLS_BATCH_SIZE} short-signature items`, () => {
    largeBlsBatch(bls.shortSignatures, bls.G2.Point, bls.G1.Point, 'short signatures');
  });
});

it.runWhen(import.meta.url);
