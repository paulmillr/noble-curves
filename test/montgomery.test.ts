import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql } from 'node:assert';
import { __TEST as montTest } from '../src/abstract/montgomery.ts';
import { x25519 } from '../src/ed25519.ts';
import { x448 } from '../src/ed448.ts';
import { numberToBytesLE } from '../src/utils.ts';

describe('Montgomery low-order keys', () => {
  it('reject low-order public keys', () => {
    // Every u whose order divides the cofactor, on the curve or on its quadratic twist.
    // Same set libsodium and post-CVE-2017-0379 Libgcrypt blocklist. Rejection must happen
    // before the ladder runs, so an unauthenticated peer cannot use these as a free timing
    // oracle on the long-term secret key.
    const P25519 = 2n ** 255n - 19n;
    const P448 = 2n ** 448n - 2n ** 224n - 1n;
    const CASES: [typeof x25519, number, bigint[]][] = [
      [
        x25519,
        32,
        [
          0n,
          1n,
          325606250916557431795983626356110631294008115727848805560023387167927233504n,
          39382357235489614581723060781553021112529911719440698176882885853963445705823n,
          P25519 - 1n,
          P25519, // non-canonical encodings of 0 and 1, reduced by decodeU
          P25519 + 1n,
        ],
      ],
      [x448, 56, [0n, 1n, P448 - 1n, P448, P448 + 1n]],
    ];
    for (const [curve, len, lowOrder] of CASES) {
      const secretKey = curve.utils.randomSecretKey();
      // sanity: an honest peer key still works
      curve.getSharedSecret(secretKey, curve.getPublicKey(curve.utils.randomSecretKey()));
      for (const u of lowOrder) {
        let failed = false;
        try {
          curve.getSharedSecret(secretKey, numberToBytesLE(u, len));
        } catch (error) {
          failed = true;
        }
        eql(failed, true, `low-order u=${u}`);
      }
    }
    // Pin the ordering, not just the rejection: the peer key is refused before the secret key
    // is touched at all, so a malformed secret never even reaches its length check here.
    let message = '';
    try {
      x25519.getSharedSecret(new Uint8Array(31), numberToBytesLE(1n, 32));
    } catch (error) {
      message = error.message;
    }
    eql(message.includes('invalid private or public key received'), true, message);
  });
});

describe('Montgomery cswap', () => {
  const { cmask, cswap } = montTest;
  const P25519 = 2n ** 255n - 19n;
  const P448 = 2n ** 448n - 2n ** 224n - 1n;
  // 13 is prime and tiny, so the edge cases below (0, 1, P-1, equal inputs) are dense rather
  // than astronomically unlikely, and every intermediate stays readable when one fails.
  const PRIMES = [P25519, P448, 13n];
  const mod = (a: bigint, P: bigint) => ((a % P) + P) % P;
  // Deterministic, so a failure reproduces exactly. Values are unstructured enough to catch a
  // formula that only works for small or sparse inputs.
  let seed = 0x2545f491n;
  const rnd = (P: bigint) => {
    let acc = 0n;
    for (let i = 0; i < 8; i++) {
      seed = (seed * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n);
      acc = (acc << 64n) | seed;
    }
    return mod(acc, P);
  };

  it('cmask selects P / P + 1 from the low bit alone', () => {
    for (const P of PRIMES) {
      // Every value the ladder actually feeds cmask: `kx >> t` at every t, plus k itself.
      // A formula that mishandled wide or sparse inputs would show up here, not on small ints.
      for (let trial = 0; trial < 32; trial++) {
        const k = rnd(1n << 512n);
        for (let t = 0n; t <= 512n; t++) eql(cmask(P, k >> t), P + ((k >> t) & 1n));
        eql(cmask(P, k), P + (k & 1n));
      }
      for (let v = 0n; v < 128n; v++) eql(cmask(P, v), P + (v & 1n));
      // The invariant the timing hardening rests on: cswap's multiplier is never 0n or 1n, avoiding
      // those two special operand values there. Coordinates may still be 0n/1n, and none of this
      // implies that BigInt arithmetic is constant-time.
      for (const v of [0n, 1n, 2n, 255n, 1n << 400n, (1n << 400n) + 1n])
        eql(cmask(P, v) >= P, true);
    }
  });

  it('cswap keeps on P and swaps on P + 1', () => {
    for (const P of PRIMES) {
      const keep = cmask(P, 0n);
      const swapMask = cmask(P, 1n);
      const swap = cswap(P);
      eql([keep, swapMask], [P, P + 1n]);
      const vals = [0n, 1n, 2n, P - 1n, P - 2n, (P - 1n) / 2n];
      for (let i = 0; i < 24; i++) vals.push(rnd(P));
      for (const x of vals) {
        for (const y of vals) {
          eql(swap(keep, x, y), { x_2: x, x_3: y });
          eql(swap(swapMask, x, y), { x_2: y, x_3: x });
          // Higher bits of the cmask input must not leak into the selection.
          eql(swap(cmask(P, 0xf0n), x, y), { x_2: x, x_3: y });
          eql(swap(cmask(P, 0xffn), x, y), { x_2: y, x_3: x });
          // Outputs feed straight back into the ladder, which assumes canonical inputs.
          for (const r of [swap(keep, x, y), swap(swapMask, x, y)]) {
            eql(r.x_2 >= 0n && r.x_2 < P, true);
            eql(r.x_3 >= 0n && r.x_3 < P, true);
          }
          // Swapping twice is the identity; the ladder relies on it round to round.
          const once = swap(swapMask, x, y);
          eql(swap(swapMask, once.x_2, once.x_3), { x_2: x, x_3: y });
        }
      }
    }
  });

  it('cswap requires canonical inputs', () => {
    // Documented precondition, not a bug: cswap skips validation because it runs twice per
    // ladder round. Pin the failure mode so nobody "optimizes" a caller into feeding it
    // unreduced values - the kept side silently returns a wrong representative.
    const P = 13n;
    const swap = cswap(P);
    eql(swap(cmask(P, 0n), 14n, 3n), { x_2: 1n, x_3: 16n }); // 14 === 1 mod 13
    eql(swap(cmask(P, 0n), 1n, 3n), { x_2: 1n, x_3: 3n }); // reduced: correct
  });

  it('cswap drives the ladder exactly like the RFC 7748 reference', () => {
    // RFC 7748 tracks `swap` across rounds and swaps conditionally; this implementation
    // recomputes the bit per round and uses the same branchless helper for both selectors. Check
    // the two agree on the full sequence of states, for both curves' bit widths.
    for (const [P, bits] of [
      [P25519, 255],
      [P448, 448],
    ] as const) {
      const swap = cswap(P);
      for (let trial = 0; trial < 8; trial++) {
        const k = rnd(1n << BigInt(bits));
        // Reference: RFC 7748 section 5, carrying `swap` between rounds.
        let rx2 = rnd(P);
        let rx3 = rnd(P);
        const [ix2, ix3] = [rx2, rx3];
        let refSwap = 0n;
        for (let t = BigInt(bits - 1); t >= 0n; t--) {
          const kt = (k >> t) & 1n;
          refSwap ^= kt;
          if (refSwap === 1n) [rx2, rx3] = [rx3, rx2];
          refSwap = kt;
        }
        if (refSwap === 1n) [rx2, rx3] = [rx3, rx2];

        // Implementation: bit t of (k XOR k>>1), no carried state or selector branch.
        let x2 = ix2;
        let x3 = ix3;
        const kx = k ^ (k >> 1n);
        for (let t = BigInt(bits - 1); t >= 0n; t--)
          ({ x_2: x2, x_3: x3 } = swap(cmask(P, kx >> t), x2, x3));
        ({ x_2: x2, x_3: x3 } = swap(cmask(P, k), x2, x3));

        eql([x2, x3], [rx2, rx3]);
      }
    }
  });
});

it.runWhen(import.meta.url);
