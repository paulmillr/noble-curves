import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { toWasm } from '@awasm/compiler/codegen.js';
import { Module, array } from '@awasm/compiler/module.js';

const LIMBS = 8;
const TMP_LIMBS = 18;
const POINT_WORDS = LIMBS * 3;
const W = 8;
const WINDOWS = 33;
const WINDOW_SIZE = 1 << (W - 1);
const TABLE_POINTS = WINDOWS * WINDOW_SIZE;
const EC_SLOTS = 48;
const K1_C = 0x3d1; // 977; for secp256k1, 2^256 = 2^32 + 977.

const PX = 0;
const PY = 1;
const PZ = 2;
const QX = 3;
const QY = 4;
const QZ = 5;
const RX = 6;
const RY = 7;
const RZ = 8;
const ACCX = 9;
const ACCY = 10;
const ACCZ = 11;
const DBLX = 12;
const DBLY = 13;
const DBLZ = 14;
const SELX = 15;
const SELY = 16;
const SELZ = 17;
const T0 = 18;
const T1 = 19;
const T2 = 20;
const T3 = 21;
const T4 = 22;
const T5 = 23;
const T6 = 24;
const T7 = 25;
const T8 = 26;
const T9 = 27;
const T10 = 28;
const T11 = 29;

function c(s: any, n: number) {
  return s.types.u32.const(n);
}

function asVal(s: any, v: any) {
  return typeof v === 'number' ? c(s, v) : v;
}

function slotPos(s: any, slot: any, limb: any) {
  const { u32 } = s.types;
  return u32.add(u32.mul(asVal(s, slot), c(s, LIMBS)), limb);
}

function pointPos(s: any, pointSlot: any, coord: number, limb: any) {
  const { u32 } = s.types;
  return slotPos(s, u32.add(asVal(s, pointSlot), c(s, coord)), limb);
}

function tablePos(s: any, idx: any, coord: number, limb: any) {
  const { u32 } = s.types;
  return u32.add(u32.mul(idx, c(s, POINT_WORDS)), u32.add(c(s, coord * LIMBS), limb));
}

function k1PrimeLimb(s: any, i: any) {
  const { u32 } = s.types;
  const is0 = u32.sub(c(s, 0), u32.eq(i, c(s, 0)));
  const is1 = u32.sub(c(s, 0), u32.eq(i, c(s, 1)));
  const rest = u32.not(u32.or(is0, is1));
  return u32.or(
    u32.or(u32.and(c(s, 0xfffffc2f), is0), u32.and(c(s, 0xfffffffe), is1)),
    u32.and(c(s, 0xffffffff), rest)
  );
}

function buildModule() {
  const mod = new Module('secp256k1Wasm')
    .mem('a', array('u32', {}, LIMBS))
    .mem('b', array('u32', {}, LIMBS))
    .mem('out', array('u32', {}, LIMBS + 1))
    .mem('tmp', array('u32', {}, TMP_LIMBS))
    .mem('acc', array('u32', {}, LIMBS))
    .mem('base', array('u32', {}, LIMBS))
    .mem('exp', array('u32', {}, LIMBS))
    .mem('scalar', array('u32', {}, LIMBS))
    .mem('point', array('u32', {}, POINT_WORDS))
    .mem('result', array('u32', {}, POINT_WORDS))
    .mem('ec', array('u32', {}, EC_SLOTS * LIMBS))
    .mem('table', array('u32', {}, TABLE_POINTS * POINT_WORDS))
    .mem('baseReady', array('u32', {}, 1))
    .fn('addCarry', ['u32', 'u32'], 'void', (s, pos, carry) => {
      const { u32, u64 } = s.types;
      s.doWhile(
        [pos, carry],
        (_pos, value) => u32.ne(value, c(s, 0)),
        (p, value) => {
          const sum = u64.add(u64.fromN('u32', s.memory.tmp[p].get()), u64.fromN('u32', value));
          const [lo, hi] = u64.to('u32', sum);
          s.memory.tmp[p].set(lo);
          return [u32.add(p, c(s, 1)), hi];
        }
      );
    })
    .fn('k1AddTmp', ['u32', 'u32'], 'void', (s, pos, value) => {
      const { u32, u64 } = s.types;
      const sum = u64.add(
        u64.fromN('u32', s.memory.tmp[pos].get()),
        u64.fromN('u32', value)
      );
      const [lo, hi] = u64.to('u32', sum);
      s.memory.tmp[pos].set(lo);
      s.functions.addCarry.call(u32.add(pos, c(s, 1)), hi);
    })
    .fn('k1AddMulTmp977', ['u32', 'u32'], 'void', (s, pos, value) => {
      const { u32, u64 } = s.types;
      const sum = u64.add(
        u64.fromN('u32', s.memory.tmp[pos].get()),
        u64.mul(u64.fromN('u32', value), u64.fromN('u32', c(s, K1_C)))
      );
      const [lo, hi] = u64.to('u32', sum);
      s.memory.tmp[pos].set(lo);
      s.functions.addCarry.call(u32.add(pos, c(s, 1)), hi);
    })
    .fn('k1AddOut', ['u32', 'u32'], 'void', (s, pos, value) => {
      const { u32, u64 } = s.types;
      s.doWhile(
        [pos, value],
        (p, value) => u32.and(u32.ne(value, c(s, 0)), u32.lt(p, c(s, LIMBS + 1))),
        (p, value) => {
          const sum = u64.add(
            u64.fromN('u32', s.memory.out[p].get()),
            u64.fromN('u32', value)
          );
          const [lo, hi] = u64.to('u32', sum);
          s.memory.out[p].set(lo);
          return [u32.add(p, c(s, 1)), hi];
        }
      );
    })
    .fn('k1AddMulOut977', ['u32', 'u32'], 'void', (s, pos, value) => {
      const { u32, u64 } = s.types;
      const sum = u64.add(
        u64.fromN('u32', s.memory.out[pos].get()),
        u64.mul(u64.fromN('u32', value), u64.fromN('u32', c(s, K1_C)))
      );
      const [lo, hi] = u64.to('u32', sum);
      s.memory.out[pos].set(lo);
      s.functions.k1AddOut.call(u32.add(pos, c(s, 1)), hi);
    })
    .fn('k1FoldOut', [], 'void', (s) => {
      const { u32 } = s.types;
      s.doN([], c(s, 2), () => {
        const high = s.memory.out[c(s, LIMBS)].get();
        s.memory.out[c(s, LIMBS)].set(c(s, 0));
        s.functions.k1AddMulOut977.call(c(s, 0), high);
        s.functions.k1AddOut.call(c(s, 1), high);
      });
    })
    .fn('k1CondSubOut', [], 'void', (s) => {
      const { u32 } = s.types;
      const [borrow] = s.doN([c(s, 0)], c(s, LIMBS), (i, borrow) => {
        const ai = s.memory.out[i].get();
        const bi = k1PrimeLimb(s, i);
        const diff = u32.sub(u32.sub(ai, bi), borrow);
        const lt = u32.lt(ai, bi);
        const eq = u32.eq(ai, bi);
        s.memory.tmp[i].set(diff);
        return [u32.or(lt, u32.and(borrow, eq))];
      });
      const mask = u32.sub(c(s, 0), u32.eq(borrow, c(s, 0)));
      const notMask = u32.not(mask);
      s.doN([], c(s, LIMBS), (i) => {
        const keep = u32.and(s.memory.out[i].get(), notMask);
        const sub = u32.and(s.memory.tmp[i].get(), mask);
        s.memory.out[i].set(u32.or(keep, sub));
      });
    })
    .fn('k1NormalizeOut', [], 'void', (s) => {
      s.functions.k1FoldOut.call();
      s.functions.k1CondSubOut.call();
      s.functions.k1CondSubOut.call();
      s.functions.k1CondSubOut.call();
    })
    .fn('k1ReduceTmp', [], 'void', (s) => {
      const { u32 } = s.types;
      s.doN([], c(s, 3), () => {
        s.doN([], c(s, TMP_LIMBS - LIMBS), (i) => {
          const pos = u32.sub(c(s, TMP_LIMBS - 1), i);
          const high = s.memory.tmp[pos].get();
          s.memory.tmp[pos].set(c(s, 0));
          const low = u32.sub(pos, c(s, LIMBS));
          s.functions.k1AddMulTmp977.call(low, high);
          s.functions.k1AddTmp.call(u32.add(low, c(s, 1)), high);
        });
      });
      s.doN([], c(s, LIMBS), (i) => {
        s.memory.out[i].set(s.memory.tmp[i].get());
      });
      s.functions.k1NormalizeOut.call();
    })
    .fn('k1Add', [], 'void', (s) => {
      const { u32, u64 } = s.types;
      s.memory.out[c(s, LIMBS)].set(c(s, 0));
      const [carry] = s.doN([c(s, 0)], c(s, LIMBS), (i, carry) => {
        const sum = u64.add(
          u64.add(u64.fromN('u32', s.memory.a[i].get()), u64.fromN('u32', s.memory.b[i].get())),
          u64.fromN('u32', carry)
        );
        const [lo, hi] = u64.to('u32', sum);
        s.memory.out[i].set(lo);
        return [hi];
      });
      s.memory.out[c(s, LIMBS)].set(carry);
      s.functions.k1NormalizeOut.call();
    })
    .fn('k1Sub', [], 'void', (s) => {
      const { u32, u64 } = s.types;
      s.memory.out[c(s, LIMBS)].set(c(s, 0));
      const [borrow] = s.doN([c(s, 0)], c(s, LIMBS), (i, borrow) => {
        const ai = s.memory.a[i].get();
        const bi = s.memory.b[i].get();
        const diff = u32.sub(u32.sub(ai, bi), borrow);
        const lt = u32.lt(ai, bi);
        const eq = u32.eq(ai, bi);
        s.memory.out[i].set(diff);
        return [u32.or(lt, u32.and(borrow, eq))];
      });
      const mask = u32.sub(c(s, 0), borrow);
      s.doN([c(s, 0)], c(s, LIMBS), (i, carry) => {
        const addend = u32.and(k1PrimeLimb(s, i), mask);
        const sum = u64.add(
          u64.add(u64.fromN('u32', s.memory.out[i].get()), u64.fromN('u32', addend)),
          u64.fromN('u32', carry)
        );
        const [lo, hi] = u64.to('u32', sum);
        s.memory.out[i].set(lo);
        return [hi];
      });
    })
    .fn('k1Mul', [], 'void', (s) => {
      const { u32, u64 } = s.types;
      s.doN([], c(s, TMP_LIMBS), (i) => {
        s.memory.tmp[i].set(c(s, 0));
      });
      s.doN([], c(s, LIMBS), (i) => {
        const [carry] = s.doN([c(s, 0)], c(s, LIMBS), (j, carry) => {
          const pos = u32.add(i, j);
          const prod = u64.add(
            u64.add(
              u64.fromN('u32', s.memory.tmp[pos].get()),
              u64.mul(u64.fromN('u32', s.memory.a[i].get()), u64.fromN('u32', s.memory.b[j].get()))
            ),
            u64.fromN('u32', carry)
          );
          const [lo, hi] = u64.to('u32', prod);
          s.memory.tmp[pos].set(lo);
          return [hi];
        });
        s.functions.addCarry.call(u32.add(i, c(s, LIMBS)), carry);
      });
      s.functions.k1ReduceTmp.call();
    })
    .fn('k1Sqr', [], 'void', (s) => {
      const { u32 } = s.types;
      s.doN([], c(s, LIMBS), (i) => {
        s.memory.b[i].set(s.memory.a[i].get());
      });
      s.functions.k1Mul.call();
    })
    .fn('k1Pow', ['u32'], 'void', (s, bits) => {
      const { u32 } = s.types;
      s.doN([], c(s, LIMBS), (i) => {
        s.memory.acc[i].set(u32.eq(i, c(s, 0)));
        s.memory.base[i].set(s.memory.a[i].get());
      });
      s.doN([], bits, (bitPos) => {
        const word = s.memory.exp[u32.shr(bitPos, c(s, 5))].get();
        const bit = u32.and(u32.shr(word, u32.and(bitPos, c(s, 31))), c(s, 1));
        const mask = u32.sub(c(s, 0), bit);
        const notMask = u32.not(mask);
        s.doN([], c(s, LIMBS), (i) => {
          s.memory.a[i].set(s.memory.acc[i].get());
          s.memory.b[i].set(s.memory.base[i].get());
        });
        s.functions.k1Mul.call();
        s.doN([], c(s, LIMBS), (i) => {
          const keep = u32.and(s.memory.acc[i].get(), notMask);
          const select = u32.and(s.memory.out[i].get(), mask);
          s.memory.acc[i].set(u32.or(keep, select));
        });
        s.doN([], c(s, LIMBS), (i) => {
          const word = s.memory.base[i].get();
          s.memory.a[i].set(word);
          s.memory.b[i].set(word);
        });
        s.functions.k1Mul.call();
        s.doN([], c(s, LIMBS), (i) => {
          s.memory.base[i].set(s.memory.out[i].get());
        });
      });
      s.doN([], c(s, LIMBS), (i) => {
        s.memory.out[i].set(s.memory.acc[i].get());
      });
    })
    .fn('slotCopy', ['u32', 'u32'], 'void', (s, dst, src) => {
      s.doN([], c(s, LIMBS), (i) => {
        s.memory.ec[slotPos(s, dst, i)].set(s.memory.ec[slotPos(s, src, i)].get());
      });
    })
    .fn('slotZero', ['u32'], 'void', (s, dst) => {
      s.doN([], c(s, LIMBS), (i) => {
        s.memory.ec[slotPos(s, dst, i)].set(c(s, 0));
      });
    })
    .fn('slotOne', ['u32'], 'void', (s, dst) => {
      s.memory.ec[slotPos(s, dst, c(s, 0))].set(c(s, 1));
      s.doN([], c(s, LIMBS - 1), (i) => {
        s.memory.ec[slotPos(s, dst, s.types.u32.add(i, c(s, 1)))].set(c(s, 0));
      });
    })
    .fn('slotIsZero', ['u32'], 'u32', (s, src) => {
      const { u32 } = s.types;
      const [acc] = s.doN([c(s, 0)], c(s, LIMBS), (i, acc) => [
        u32.or(acc, s.memory.ec[slotPos(s, src, i)].get()),
      ]);
      return u32.eq(acc, c(s, 0));
    })
    .fn('slotEq', ['u32', 'u32'], 'u32', (s, lhs, rhs) => {
      const { u32 } = s.types;
      const [acc] = s.doN([c(s, 0)], c(s, LIMBS), (i, acc) => {
        const diff = u32.xor(
          s.memory.ec[slotPos(s, lhs, i)].get(),
          s.memory.ec[slotPos(s, rhs, i)].get()
        );
        return [u32.or(acc, diff)];
      });
      return u32.eq(acc, c(s, 0));
    })
    .fn('slotCmov', ['u32', 'u32', 'u32', 'u32'], 'void', (s, dst, lhs, rhs, cond) => {
      const { u32 } = s.types;
      const mask = u32.sub(c(s, 0), cond);
      const notMask = u32.not(mask);
      s.doN([], c(s, LIMBS), (i) => {
        const a = s.memory.ec[slotPos(s, lhs, i)].get();
        const b = s.memory.ec[slotPos(s, rhs, i)].get();
        s.memory.ec[slotPos(s, dst, i)].set(u32.or(u32.and(a, notMask), u32.and(b, mask)));
      });
    })
    .fn('slotFromOut', ['u32'], 'void', (s, dst) => {
      s.doN([], c(s, LIMBS), (i) => {
        s.memory.ec[slotPos(s, dst, i)].set(s.memory.out[i].get());
      });
    })
    .fn('slotSetA', ['u32'], 'void', (s, src) => {
      s.doN([], c(s, LIMBS), (i) => {
        s.memory.a[i].set(s.memory.ec[slotPos(s, src, i)].get());
      });
    })
    .fn('slotSetB', ['u32'], 'void', (s, src) => {
      s.doN([], c(s, LIMBS), (i) => {
        s.memory.b[i].set(s.memory.ec[slotPos(s, src, i)].get());
      });
    })
    .fn('slotAdd', ['u32', 'u32', 'u32'], 'void', (s, dst, lhs, rhs) => {
      s.functions.slotSetA.call(lhs);
      s.functions.slotSetB.call(rhs);
      s.functions.k1Add.call();
      s.functions.slotFromOut.call(dst);
    })
    .fn('slotSub', ['u32', 'u32', 'u32'], 'void', (s, dst, lhs, rhs) => {
      s.functions.slotSetA.call(lhs);
      s.functions.slotSetB.call(rhs);
      s.functions.k1Sub.call();
      s.functions.slotFromOut.call(dst);
    })
    .fn('slotMul', ['u32', 'u32', 'u32'], 'void', (s, dst, lhs, rhs) => {
      s.functions.slotSetA.call(lhs);
      s.functions.slotSetB.call(rhs);
      s.functions.k1Mul.call();
      s.functions.slotFromOut.call(dst);
    })
    .fn('slotSqr', ['u32', 'u32'], 'void', (s, dst, src) => {
      s.functions.slotSetA.call(src);
      s.functions.k1Sqr.call();
      s.functions.slotFromOut.call(dst);
    })
    .fn('slotNeg', ['u32', 'u32'], 'void', (s, dst, src) => {
      s.doN([], c(s, LIMBS), (i) => {
        s.memory.a[i].set(c(s, 0));
        s.memory.b[i].set(s.memory.ec[slotPos(s, src, i)].get());
      });
      s.functions.k1Sub.call();
      s.functions.slotFromOut.call(dst);
    })
    .fn('slotInv', ['u32', 'u32'], 'void', (s, dst, src) => {
      const { u32 } = s.types;
      s.functions.slotSetA.call(src);
      s.doN([], c(s, LIMBS), (i) => {
        const is0 = u32.sub(c(s, 0), u32.eq(i, c(s, 0)));
        const is1 = u32.sub(c(s, 0), u32.eq(i, c(s, 1)));
        const rest = u32.not(u32.or(is0, is1));
        const limb = u32.or(
          u32.or(u32.and(c(s, 0xfffffc2d), is0), u32.and(c(s, 0xfffffffe), is1)),
          u32.and(c(s, 0xffffffff), rest)
        );
        s.memory.exp[i].set(limb);
      });
      s.functions.k1Pow.call(c(s, 256));
      s.functions.slotFromOut.call(dst);
    })
    .fn('pointZero', ['u32'], 'void', (s, dst) => {
      const { u32 } = s.types;
      s.functions.slotZero.call(dst);
      s.functions.slotOne.call(u32.add(dst, c(s, 1)));
      s.functions.slotZero.call(u32.add(dst, c(s, 2)));
    })
    .fn('pointCopy', ['u32', 'u32'], 'void', (s, dst, src) => {
      const { u32 } = s.types;
      s.functions.slotCopy.call(dst, src);
      s.functions.slotCopy.call(u32.add(dst, c(s, 1)), u32.add(src, c(s, 1)));
      s.functions.slotCopy.call(u32.add(dst, c(s, 2)), u32.add(src, c(s, 2)));
    })
    .fn('pointFromInput', ['u32'], 'void', (s, dst) => {
      const { u32 } = s.types;
      s.doN([], c(s, POINT_WORDS), (i) => {
        s.memory.ec[slotPos(s, u32.add(dst, u32.div(i, c(s, LIMBS))), u32.rem(i, c(s, LIMBS)))].set(
          s.memory.point[i].get()
        );
      });
    })
    .fn('pointToResult', ['u32'], 'void', (s, src) => {
      const { u32 } = s.types;
      s.doN([], c(s, POINT_WORDS), (i) => {
        s.memory.result[i].set(
          s.memory.ec[slotPos(s, u32.add(src, u32.div(i, c(s, LIMBS))), u32.rem(i, c(s, LIMBS)))].get()
        );
      });
    })
    .fn('pointStoreTable', ['u32', 'u32'], 'void', (s, idx, src) => {
      const { u32 } = s.types;
      s.doN([], c(s, POINT_WORDS), (i) => {
        const coord = u32.div(i, c(s, LIMBS));
        const limb = u32.rem(i, c(s, LIMBS));
        s.memory.table[u32.add(u32.mul(idx, c(s, POINT_WORDS)), i)].set(
          s.memory.ec[slotPos(s, u32.add(src, coord), limb)].get()
        );
      });
    })
    .fn('pointSelectTable', ['u32', 'u32', 'u32', 'u32'], 'void', (s, dst, window, absMinus1, nonZero) => {
      const { u32 } = s.types;
      s.functions.pointZero.call(dst);
      s.doN([], c(s, WINDOW_SIZE), (j) => {
        const tableIdx = u32.add(u32.mul(window, c(s, WINDOW_SIZE)), j);
        const mask = u32.sub(c(s, 0), u32.and(nonZero, u32.eq(j, absMinus1)));
        const notMask = u32.not(mask);
        s.doN([], c(s, POINT_WORDS), (i) => {
          const coord = u32.div(i, c(s, LIMBS));
          const limb = u32.rem(i, c(s, LIMBS));
          const pos = slotPos(s, u32.add(dst, coord), limb);
          const keep = u32.and(s.memory.ec[pos].get(), notMask);
          const selected = u32.and(s.memory.table[tablePos(s, tableIdx, 0, i)].get(), mask);
          s.memory.ec[pos].set(u32.or(keep, selected));
        });
      });
    })
    .fn('pointNegIf', ['u32', 'u32'], 'void', (s, point, cond) => {
      const { u32 } = s.types;
      s.functions.slotNeg.call(c(s, T0), u32.add(point, c(s, 1)));
      s.functions.slotCmov.call(u32.add(point, c(s, 1)), u32.add(point, c(s, 1)), c(s, T0), cond);
    })
    .fn('pointNormalize', ['u32'], 'void', (s, point) => {
      const { u32 } = s.types;
      const X = point;
      const Y = u32.add(point, c(s, 1));
      const Z = u32.add(point, c(s, 2));
      const [z0] = s.functions.slotIsZero.call(Z);
      s.ifElse(
        z0,
        [],
        () => {
          s.functions.pointZero.call(point);
          return [];
        },
        () => {
          s.functions.slotInv.call(c(s, T0), Z);
          s.functions.slotSqr.call(c(s, T1), c(s, T0));
          s.functions.slotMul.call(X, X, c(s, T1));
          s.functions.slotMul.call(c(s, T2), c(s, T1), c(s, T0));
          s.functions.slotMul.call(Y, Y, c(s, T2));
          s.functions.slotOne.call(Z);
          return [];
        }
      );
    })
    .fn('pointDouble', ['u32', 'u32'], 'void', (s, dst, src) => {
      const { u32 } = s.types;
      const [z0] = s.functions.slotIsZero.call(u32.add(src, c(s, 2)));
      const [y0] = s.functions.slotIsZero.call(u32.add(src, c(s, 1)));
      const inf = u32.or(z0, y0);
      s.ifElse(
        inf,
        [],
        () => {
          s.functions.pointZero.call(dst);
          return [];
        },
        () => {
          const X1 = src;
          const Y1 = u32.add(src, c(s, 1));
          const Z1 = u32.add(src, c(s, 2));
          const A = c(s, T0);
          const B = c(s, T1);
          const C = c(s, T2);
          const D = c(s, T3);
          const E = c(s, T4);
          const F = c(s, T5);
          const X3 = dst;
          const Y3 = u32.add(dst, c(s, 1));
          const Z3 = u32.add(dst, c(s, 2));
          s.functions.slotSqr.call(A, X1);
          s.functions.slotSqr.call(B, Y1);
          s.functions.slotSqr.call(C, B);
          s.functions.slotAdd.call(D, X1, B);
          s.functions.slotSqr.call(D, D);
          s.functions.slotSub.call(D, D, A);
          s.functions.slotSub.call(D, D, C);
          s.functions.slotAdd.call(D, D, D);
          s.functions.slotAdd.call(E, A, A);
          s.functions.slotAdd.call(E, E, A);
          s.functions.slotSqr.call(F, E);
          s.functions.slotSub.call(X3, F, D);
          s.functions.slotSub.call(X3, X3, D);
          s.functions.slotSub.call(Y3, D, X3);
          s.functions.slotMul.call(Y3, E, Y3);
          s.functions.slotAdd.call(c(s, T6), C, C);
          s.functions.slotAdd.call(c(s, T6), c(s, T6), c(s, T6));
          s.functions.slotAdd.call(c(s, T6), c(s, T6), c(s, T6));
          s.functions.slotSub.call(Y3, Y3, c(s, T6));
          s.functions.slotAdd.call(Z3, Y1, Y1);
          s.functions.slotMul.call(Z3, Z3, Z1);
          return [];
        }
      );
    })
    .fn('pointAdd', ['u32', 'u32', 'u32'], 'void', (s, dst, p, q) => {
      const { u32 } = s.types;
      const [pz0] = s.functions.slotIsZero.call(u32.add(p, c(s, 2)));
      const [qz0] = s.functions.slotIsZero.call(u32.add(q, c(s, 2)));
      s.ifElse(
        pz0,
        [],
        () => {
          s.functions.pointCopy.call(dst, q);
          return [];
        },
        () => {
          s.ifElse(
            qz0,
            [],
            () => {
              s.functions.pointCopy.call(dst, p);
              return [];
            },
            () => {
              const X1 = p;
              const Y1 = u32.add(p, c(s, 1));
              const Z1 = u32.add(p, c(s, 2));
              const X2 = q;
              const Y2 = u32.add(q, c(s, 1));
              const Z2 = u32.add(q, c(s, 2));
              const Z1Z1 = c(s, T0);
              const Z2Z2 = c(s, T1);
              const U1 = c(s, T2);
              const U2 = c(s, T3);
              const S1 = c(s, T4);
              const S2 = c(s, T5);
              const H = c(s, T6);
              const R = c(s, T7);
              s.functions.slotSqr.call(Z1Z1, Z1);
              s.functions.slotSqr.call(Z2Z2, Z2);
              s.functions.slotMul.call(U1, X1, Z2Z2);
              s.functions.slotMul.call(U2, X2, Z1Z1);
              s.functions.slotMul.call(S1, Y1, Z2);
              s.functions.slotMul.call(S1, S1, Z2Z2);
              s.functions.slotMul.call(S2, Y2, Z1);
              s.functions.slotMul.call(S2, S2, Z1Z1);
              s.functions.slotSub.call(H, U2, U1);
              s.functions.slotSub.call(R, S2, S1);
              const [h0] = s.functions.slotIsZero.call(H);
              const [r0] = s.functions.slotIsZero.call(R);
              s.ifElse(
                h0,
                [],
                () => {
                  s.ifElse(
                    r0,
                    [],
                    () => {
                      s.functions.pointDouble.call(dst, p);
                      return [];
                    },
                    () => {
                      s.functions.pointZero.call(dst);
                      return [];
                    }
                  );
                  return [];
                },
                () => {
                  const HH = c(s, T8);
                  const HHH = c(s, T9);
                  const V = c(s, T10);
                  const X3 = dst;
                  const Y3 = u32.add(dst, c(s, 1));
                  const Z3 = u32.add(dst, c(s, 2));
                  s.functions.slotSqr.call(HH, H);
                  s.functions.slotMul.call(HHH, H, HH);
                  s.functions.slotMul.call(V, U1, HH);
                  s.functions.slotSqr.call(X3, R);
                  s.functions.slotSub.call(X3, X3, HHH);
                  s.functions.slotAdd.call(c(s, T11), V, V);
                  s.functions.slotSub.call(X3, X3, c(s, T11));
                  s.functions.slotSub.call(Y3, V, X3);
                  s.functions.slotMul.call(Y3, R, Y3);
                  s.functions.slotMul.call(c(s, T11), S1, HHH);
                  s.functions.slotSub.call(Y3, Y3, c(s, T11));
                  s.functions.slotMul.call(Z3, Z1, Z2);
                  s.functions.slotMul.call(Z3, Z3, H);
                  return [];
                }
              );
              return [];
            }
          );
          return [];
        }
      );
    })
    .fn('buildBaseTable', [], 'void', (s) => {
      const { u32 } = s.types;
      s.functions.pointFromInput.call(c(s, PX));
      s.functions.pointCopy.call(c(s, QX), c(s, PX));
      s.doN([], c(s, WINDOWS), (window) => {
        const start = u32.mul(window, c(s, WINDOW_SIZE));
        s.functions.pointCopy.call(c(s, RX), c(s, QX));
        s.functions.pointStoreTable.call(start, c(s, RX));
        s.doN([], c(s, WINDOW_SIZE - 1), (i) => {
          s.functions.pointAdd.call(c(s, DBLX), c(s, RX), c(s, QX));
          s.functions.pointCopy.call(c(s, RX), c(s, DBLX));
          s.functions.pointStoreTable.call(u32.add(start, u32.add(i, c(s, 1))), c(s, RX));
        });
        s.functions.pointDouble.call(c(s, DBLX), c(s, RX));
        s.functions.pointCopy.call(c(s, QX), c(s, DBLX));
      });
      s.memory.baseReady[c(s, 0)].set(c(s, 1));
    })
    .fn('mulBaseWnaf', [], 'void', (s) => {
      const { u32 } = s.types;
      s.functions.buildBaseTable.callIf(u32.eq(s.memory.baseReady[c(s, 0)].get(), c(s, 0)));
      s.functions.pointZero.call(c(s, ACCX));
      const [carry] = s.doN([c(s, 0)], c(s, WINDOWS), (window, carry) => {
        const [byte] = s.ifElse(
          u32.lt(window, c(s, 32)),
          [c(s, 0)],
          () => {
            const word = s.memory.scalar[u32.shr(window, c(s, 2))].get();
            const shift = u32.shl(u32.and(window, c(s, 3)), c(s, 3));
            return [u32.and(u32.shr(word, shift), c(s, 0xff))];
          },
          (cur) => [cur]
        );
        const wbits = u32.add(byte, carry);
        const neg = u32.gt(wbits, c(s, WINDOW_SIZE));
        const abs = u32.select(neg, u32.sub(c(s, 1 << W), wbits), wbits);
        const nonZero = u32.ne(abs, c(s, 0));
        const absMinus1 = u32.sub(abs, c(s, 1));
        s.functions.pointSelectTable.call(c(s, SELX), window, absMinus1, nonZero);
        s.functions.pointNegIf.call(c(s, SELX), neg);
        s.functions.pointAdd.call(c(s, RX), c(s, ACCX), c(s, SELX));
        s.functions.pointCopy.call(c(s, ACCX), c(s, RX));
        return [neg];
      });
      s.functions.pointNormalize.call(c(s, ACCX));
      s.functions.pointToResult.call(c(s, ACCX));
      // Malformed scalars would leave carry set here. JS validates subgroup scalars first.
      s.memory.baseReady[c(s, 0)].set(u32.or(s.memory.baseReady[c(s, 0)].get(), carry));
    })
    .fn('mulLadder', [], 'void', (s) => {
      const { u32 } = s.types;
      s.functions.pointFromInput.call(c(s, PX));
      s.functions.pointZero.call(c(s, ACCX));
      s.functions.pointCopy.call(c(s, DBLX), c(s, PX));
      s.doN([], c(s, 256), (bitPos) => {
        const word = s.memory.scalar[u32.shr(bitPos, c(s, 5))].get();
        const bit = u32.and(u32.shr(word, u32.and(bitPos, c(s, 31))), c(s, 1));
        s.ifElse(
          bit,
          [],
          () => {
            s.functions.pointAdd.call(c(s, RX), c(s, ACCX), c(s, DBLX));
            s.functions.pointCopy.call(c(s, ACCX), c(s, RX));
            return [];
          },
          () => []
        );
        s.functions.pointDouble.call(c(s, RX), c(s, DBLX));
        s.functions.pointCopy.call(c(s, DBLX), c(s, RX));
      });
      s.functions.pointNormalize.call(c(s, ACCX));
      s.functions.pointToResult.call(c(s, ACCX));
    });
  return mod;
}

const generated = toWasm(buildModule(), { native64bit: true, optimize: true }).modFn.replace(
  'export default function secp256k1Wasm(_imports = {}, pool)',
  'export default function createSecp256k1Wasm(_imports: any = {}, pool?: any): any'
);
const source = `// @ts-nocheck\n// Generated by scripts/build-secp256k1-wasm.ts. Do not edit by hand.\n${generated}\n`;
const out = fileURLToPath(new URL('../src/abstract/secp256k1-wasm.ts', import.meta.url));
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, source);
