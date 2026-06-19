import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { toWasm } from '@awasm/compiler/codegen.js';
import { Module, array } from '@awasm/compiler/module.js';

const MAX_LIMBS = 17; // ceil(521 / 32)
const TMP_LIMBS = MAX_LIMBS * 2 + 4;
const K1_LIMBS = 8;
const K1_TMP_LIMBS = 18;
const K1_C = 0x3d1; // 977; for secp256k1, 2^256 = 2^32 + 977.
const P25519_LIMBS = 8;
const P25519_TMP_LIMBS = 16;
const P25519_C = 19; // 2^255 = 19.

function k1PrimeLimb(s: any, i: any) {
  const { u32 } = s.types;
  const is0 = u32.sub(u32.const(0), u32.eq(i, u32.const(0)));
  const is1 = u32.sub(u32.const(0), u32.eq(i, u32.const(1)));
  const rest = u32.not(u32.or(is0, is1));
  return u32.or(
    u32.or(u32.and(u32.const(0xfffffc2f), is0), u32.and(u32.const(0xfffffffe), is1)),
    u32.and(u32.const(0xffffffff), rest)
  );
}

function p25519PrimeLimb(s: any, i: any) {
  const { u32 } = s.types;
  const is0 = u32.sub(u32.const(0), u32.eq(i, u32.const(0)));
  const isTop = u32.sub(u32.const(0), u32.eq(i, u32.const(P25519_LIMBS - 1)));
  const middle = u32.not(u32.or(is0, isTop));
  return u32.or(
    u32.or(
      u32.and(u32.const(0xffffffed), is0),
      u32.and(u32.const(0x7fffffff), isTop)
    ),
    u32.and(u32.const(0xffffffff), middle)
  );
}

function buildModule() {
  const mod = new Module('fieldWasm')
    .mem('a', array('u32', {}, MAX_LIMBS))
    .mem('b', array('u32', {}, MAX_LIMBS))
    .mem('out', array('u32', {}, MAX_LIMBS))
    .mem('acc', array('u32', {}, MAX_LIMBS))
    .mem('base', array('u32', {}, MAX_LIMBS))
    .mem('exp', array('u32', {}, MAX_LIMBS))
    .mem('one', array('u32', {}, MAX_LIMBS))
    .mem('mod', array('u32', {}, MAX_LIMBS))
    .mem('tmp', array('u32', {}, TMP_LIMBS))
    .fn('addCarry', ['u32', 'u32'], 'void', (s, pos, carry) => {
      const { u32, u64 } = s.types;
      s.doWhile(
        [pos, carry],
        (_pos, c) => u32.ne(c, u32.const(0)),
        (p, c) => {
          const sum = u64.add(u64.fromN('u32', s.memory.tmp[p].get()), u64.fromN('u32', c));
          const [lo, hi] = u64.to('u32', sum);
          s.memory.tmp[p].set(lo);
          return [u32.add(p, u32.const(1)), hi];
        }
      );
    })
    .fn('condSubOut', ['u32', 'u32'], 'void', (s, limbs, high) => {
      const { u32 } = s.types;
      const [borrow] = s.doN([u32.const(0)], limbs, (i, borrow) => {
        const ai = s.memory.out[i].get();
        const bi = s.memory.mod[i].get();
        const diff = u32.sub(u32.sub(ai, bi), borrow);
        const lt = u32.lt(ai, bi);
        const eq = u32.eq(ai, bi);
        s.memory.tmp[i].set(diff);
        return [u32.or(lt, u32.and(borrow, eq))];
      });
      const select = u32.or(u32.ne(high, u32.const(0)), u32.eq(borrow, u32.const(0)));
      const mask = u32.sub(u32.const(0), select);
      const notMask = u32.not(mask);
      s.doN([], limbs, (i) => {
        const keep = u32.and(s.memory.out[i].get(), notMask);
        const sub = u32.and(s.memory.tmp[i].get(), mask);
        s.memory.out[i].set(u32.or(keep, sub));
      });
    })
    .fn('add', ['u32'], 'void', (s, limbs) => {
      const { u32, u64 } = s.types;
      const [carry] = s.doN([u32.const(0)], limbs, (i, carry) => {
        const sum = u64.add(
          u64.add(u64.fromN('u32', s.memory.a[i].get()), u64.fromN('u32', s.memory.b[i].get())),
          u64.fromN('u32', carry)
        );
        const [lo, hi] = u64.to('u32', sum);
        s.memory.out[i].set(lo);
        return [hi];
      });
      s.functions.condSubOut.call(limbs, carry);
    })
    .fn('sub', ['u32'], 'void', (s, limbs) => {
      const { u32, u64 } = s.types;
      const [borrow] = s.doN([u32.const(0)], limbs, (i, borrow) => {
        const ai = s.memory.a[i].get();
        const bi = s.memory.b[i].get();
        const diff = u32.sub(u32.sub(ai, bi), borrow);
        const lt = u32.lt(ai, bi);
        const eq = u32.eq(ai, bi);
        s.memory.out[i].set(diff);
        return [u32.or(lt, u32.and(borrow, eq))];
      });
      const mask = u32.sub(u32.const(0), borrow);
      s.doN([u32.const(0)], limbs, (i, carry) => {
        const addend = u32.and(s.memory.mod[i].get(), mask);
        const sum = u64.add(
          u64.add(u64.fromN('u32', s.memory.out[i].get()), u64.fromN('u32', addend)),
          u64.fromN('u32', carry)
        );
        const [lo, hi] = u64.to('u32', sum);
        s.memory.out[i].set(lo);
        return [hi];
      });
    })
    .fn('mul', ['u32', 'u32'], 'void', (s, limbs, nInv) => {
      const { u32, u64 } = s.types;
      const dbl = u32.add(u32.mul(limbs, u32.const(2)), u32.const(2));
      s.doN([], dbl, (i) => {
        s.memory.tmp[i].set(u32.const(0));
      });
      s.doN([], limbs, (i) => {
        const [carry] = s.doN([u32.const(0)], limbs, (j, carry) => {
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
        s.functions.addCarry.call(u32.add(i, limbs), carry);
      });
      s.doN([], limbs, (i) => {
        const m = u32.mul(s.memory.tmp[i].get(), nInv);
        const [carry] = s.doN([u32.const(0)], limbs, (j, carry) => {
          const pos = u32.add(i, j);
          const prod = u64.add(
            u64.add(
              u64.fromN('u32', s.memory.tmp[pos].get()),
              u64.mul(u64.fromN('u32', m), u64.fromN('u32', s.memory.mod[j].get()))
            ),
            u64.fromN('u32', carry)
          );
          const [lo, hi] = u64.to('u32', prod);
          s.memory.tmp[pos].set(lo);
          return [hi];
        });
        s.functions.addCarry.call(u32.add(i, limbs), carry);
      });
      s.doN([], limbs, (i) => {
        s.memory.out[i].set(s.memory.tmp[u32.add(i, limbs)].get());
      });
      const high = u32.or(
        s.memory.tmp[u32.mul(limbs, u32.const(2))].get(),
        s.memory.tmp[u32.add(u32.mul(limbs, u32.const(2)), u32.const(1))].get()
      );
      s.functions.condSubOut.call(limbs, high);
    })
    .fn('pow', ['u32', 'u32', 'u32'], 'void', (s, limbs, nInv, bits) => {
      const { u32 } = s.types;
      s.doN([], limbs, (i) => {
        s.memory.acc[i].set(s.memory.one[i].get());
        s.memory.base[i].set(s.memory.a[i].get());
      });
      s.doN([], bits, (bitPos) => {
        const word = s.memory.exp[u32.shr(bitPos, u32.const(5))].get();
        const bit = u32.and(u32.shr(word, u32.and(bitPos, u32.const(31))), u32.const(1));
        const mask = u32.sub(u32.const(0), bit);
        const notMask = u32.not(mask);
        s.doN([], limbs, (i) => {
          s.memory.a[i].set(s.memory.acc[i].get());
          s.memory.b[i].set(s.memory.base[i].get());
        });
        s.functions.mul.call(limbs, nInv);
        s.doN([], limbs, (i) => {
          const keep = u32.and(s.memory.acc[i].get(), notMask);
          const select = u32.and(s.memory.out[i].get(), mask);
          s.memory.acc[i].set(u32.or(keep, select));
        });
        s.doN([], limbs, (i) => {
          const word = s.memory.base[i].get();
          s.memory.a[i].set(word);
          s.memory.b[i].set(word);
        });
        s.functions.mul.call(limbs, nInv);
        s.doN([], limbs, (i) => {
          s.memory.base[i].set(s.memory.out[i].get());
        });
      });
      s.doN([], limbs, (i) => {
        s.memory.out[i].set(s.memory.acc[i].get());
      });
    })
    .fn('p25519AddOut', ['u32', 'u32'], 'void', (s, pos, value) => {
      const { u32, u64 } = s.types;
      s.doWhile(
        [pos, value],
        (p, c) => u32.and(u32.ne(c, u32.const(0)), u32.lt(p, u32.const(MAX_LIMBS))),
        (p, c) => {
          const sum = u64.add(
            u64.fromN('u32', s.memory.out[p].get()),
            u64.fromN('u32', c)
          );
          const [lo, hi] = u64.to('u32', sum);
          s.memory.out[p].set(lo);
          return [u32.add(p, u32.const(1)), hi];
        }
      );
    })
    .fn('p25519AddMulOut19', ['u32', 'u32'], 'void', (s, pos, value) => {
      const { u32, u64 } = s.types;
      const sum = u64.add(
        u64.fromN('u32', s.memory.out[pos].get()),
        u64.mul(u64.fromN('u32', value), u64.fromN('u32', u32.const(P25519_C)))
      );
      const [lo, hi] = u64.to('u32', sum);
      s.memory.out[pos].set(lo);
      s.functions.p25519AddOut.call(u32.add(pos, u32.const(1)), hi);
    })
    .fn('p25519AddMulOut38', ['u32', 'u32'], 'void', (s, pos, value) => {
      const { u32, u64 } = s.types;
      const sum = u64.add(
        u64.fromN('u32', s.memory.out[pos].get()),
        u64.mul(u64.fromN('u32', value), u64.fromN('u32', u32.const(P25519_C * 2)))
      );
      const [lo, hi] = u64.to('u32', sum);
      s.memory.out[pos].set(lo);
      s.functions.p25519AddOut.call(u32.add(pos, u32.const(1)), hi);
    })
    .fn('p25519CondSubOut', [], 'void', (s) => {
      const { u32 } = s.types;
      const [borrow] = s.doN([u32.const(0)], u32.const(P25519_LIMBS), (i, borrow) => {
        const ai = s.memory.out[i].get();
        const bi = p25519PrimeLimb(s, i);
        const diff = u32.sub(u32.sub(ai, bi), borrow);
        const lt = u32.lt(ai, bi);
        const eq = u32.eq(ai, bi);
        s.memory.tmp[i].set(diff);
        return [u32.or(lt, u32.and(borrow, eq))];
      });
      const mask = u32.sub(u32.const(0), u32.eq(borrow, u32.const(0)));
      const notMask = u32.not(mask);
      s.doN([], u32.const(P25519_LIMBS), (i) => {
        const keep = u32.and(s.memory.out[i].get(), notMask);
        const sub = u32.and(s.memory.tmp[i].get(), mask);
        s.memory.out[i].set(u32.or(keep, sub));
      });
    })
    .fn('p25519FoldOut', [], 'void', (s) => {
      const { u32 } = s.types;
      s.doN([], u32.const(4), () => {
        const highBit = u32.shr(
          s.memory.out[u32.const(P25519_LIMBS - 1)].get(),
          u32.const(31)
        );
        s.memory.out[u32.const(P25519_LIMBS - 1)].set(
          u32.and(s.memory.out[u32.const(P25519_LIMBS - 1)].get(), u32.const(0x7fffffff))
        );
        s.functions.p25519AddMulOut19.call(u32.const(0), highBit);
        const highWord = s.memory.out[u32.const(P25519_LIMBS)].get();
        s.memory.out[u32.const(P25519_LIMBS)].set(u32.const(0));
        s.functions.p25519AddMulOut38.call(u32.const(0), highWord);
      });
    })
    .fn('p25519NormalizeOut', [], 'void', (s) => {
      s.functions.p25519FoldOut.call();
      s.functions.p25519CondSubOut.call();
      s.functions.p25519CondSubOut.call();
      s.functions.p25519CondSubOut.call();
    })
    .fn('p25519ReduceTmp', [], 'void', (s) => {
      const { u32 } = s.types;
      s.doN([], u32.const(MAX_LIMBS), (i) => {
        s.memory.out[i].set(u32.const(0));
      });
      s.doN([], u32.const(P25519_LIMBS - 1), (i) => {
        s.memory.out[i].set(s.memory.tmp[i].get());
      });
      s.memory.out[u32.const(P25519_LIMBS - 1)].set(
        u32.and(s.memory.tmp[u32.const(P25519_LIMBS - 1)].get(), u32.const(0x7fffffff))
      );
      s.doN([], u32.const(P25519_LIMBS), (i) => {
        const lo = u32.shr(
          s.memory.tmp[u32.add(i, u32.const(P25519_LIMBS - 1))].get(),
          u32.const(31)
        );
        const hi = u32.shl(
          s.memory.tmp[u32.add(i, u32.const(P25519_LIMBS))].get(),
          u32.const(1)
        );
        s.functions.p25519AddMulOut19.call(i, u32.or(lo, hi));
      });
      s.functions.p25519AddMulOut19.call(
        u32.const(P25519_LIMBS),
        u32.shr(s.memory.tmp[u32.const(P25519_TMP_LIMBS - 1)].get(), u32.const(31))
      );
      s.functions.p25519NormalizeOut.call();
    })
    .fn('p25519Add', [], 'void', (s) => {
      const { u32, u64 } = s.types;
      s.memory.out[u32.const(P25519_LIMBS)].set(u32.const(0));
      const [carry] = s.doN([u32.const(0)], u32.const(P25519_LIMBS), (i, carry) => {
        const sum = u64.add(
          u64.add(u64.fromN('u32', s.memory.a[i].get()), u64.fromN('u32', s.memory.b[i].get())),
          u64.fromN('u32', carry)
        );
        const [lo, hi] = u64.to('u32', sum);
        s.memory.out[i].set(lo);
        return [hi];
      });
      s.memory.out[u32.const(P25519_LIMBS)].set(carry);
      s.functions.p25519NormalizeOut.call();
    })
    .fn('p25519Sub', [], 'void', (s) => {
      const { u32, u64 } = s.types;
      s.memory.out[u32.const(P25519_LIMBS)].set(u32.const(0));
      const [borrow] = s.doN([u32.const(0)], u32.const(P25519_LIMBS), (i, borrow) => {
        const ai = s.memory.a[i].get();
        const bi = s.memory.b[i].get();
        const diff = u32.sub(u32.sub(ai, bi), borrow);
        const lt = u32.lt(ai, bi);
        const eq = u32.eq(ai, bi);
        s.memory.out[i].set(diff);
        return [u32.or(lt, u32.and(borrow, eq))];
      });
      const mask = u32.sub(u32.const(0), borrow);
      s.doN([u32.const(0)], u32.const(P25519_LIMBS), (i, carry) => {
        const addend = u32.and(p25519PrimeLimb(s, i), mask);
        const sum = u64.add(
          u64.add(u64.fromN('u32', s.memory.out[i].get()), u64.fromN('u32', addend)),
          u64.fromN('u32', carry)
        );
        const [lo, hi] = u64.to('u32', sum);
        s.memory.out[i].set(lo);
        return [hi];
      });
    })
    .fn('p25519Mul', [], 'void', (s) => {
      const { u32, u64 } = s.types;
      s.doN([], u32.const(P25519_TMP_LIMBS), (i) => {
        s.memory.tmp[i].set(u32.const(0));
      });
      s.doN([], u32.const(P25519_LIMBS), (i) => {
        const [carry] = s.doN([u32.const(0)], u32.const(P25519_LIMBS), (j, carry) => {
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
        s.functions.addCarry.call(u32.add(i, u32.const(P25519_LIMBS)), carry);
      });
      s.functions.p25519ReduceTmp.call();
    })
    .fn('p25519Sqr', [], 'void', (s) => {
      const { u32 } = s.types;
      s.doN([], u32.const(P25519_LIMBS), (i) => {
        s.memory.b[i].set(s.memory.a[i].get());
      });
      s.functions.p25519Mul.call();
    })
    .fn('p25519Pow', ['u32'], 'void', (s, bits) => {
      const { u32 } = s.types;
      s.doN([], u32.const(P25519_LIMBS), (i) => {
        s.memory.acc[i].set(s.memory.one[i].get());
        s.memory.base[i].set(s.memory.a[i].get());
      });
      s.doN([], bits, (bitPos) => {
        const word = s.memory.exp[u32.shr(bitPos, u32.const(5))].get();
        const bit = u32.and(u32.shr(word, u32.and(bitPos, u32.const(31))), u32.const(1));
        const mask = u32.sub(u32.const(0), bit);
        const notMask = u32.not(mask);
        s.doN([], u32.const(P25519_LIMBS), (i) => {
          s.memory.a[i].set(s.memory.acc[i].get());
          s.memory.b[i].set(s.memory.base[i].get());
        });
        s.functions.p25519Mul.call();
        s.doN([], u32.const(P25519_LIMBS), (i) => {
          const keep = u32.and(s.memory.acc[i].get(), notMask);
          const select = u32.and(s.memory.out[i].get(), mask);
          s.memory.acc[i].set(u32.or(keep, select));
        });
        s.doN([], u32.const(P25519_LIMBS), (i) => {
          const word = s.memory.base[i].get();
          s.memory.a[i].set(word);
          s.memory.b[i].set(word);
        });
        s.functions.p25519Mul.call();
        s.doN([], u32.const(P25519_LIMBS), (i) => {
          s.memory.base[i].set(s.memory.out[i].get());
        });
      });
      s.doN([], u32.const(P25519_LIMBS), (i) => {
        s.memory.out[i].set(s.memory.acc[i].get());
      });
    })
    .fn('k1AddTmp', ['u32', 'u32'], 'void', (s, pos, value) => {
      const { u32, u64 } = s.types;
      const sum = u64.add(
        u64.fromN('u32', s.memory.tmp[pos].get()),
        u64.fromN('u32', value)
      );
      const [lo, hi] = u64.to('u32', sum);
      s.memory.tmp[pos].set(lo);
      s.functions.addCarry.call(u32.add(pos, u32.const(1)), hi);
    })
    .fn('k1AddMulTmp977', ['u32', 'u32'], 'void', (s, pos, value) => {
      const { u32, u64 } = s.types;
      const sum = u64.add(
        u64.fromN('u32', s.memory.tmp[pos].get()),
        u64.mul(u64.fromN('u32', value), u64.fromN('u32', u32.const(K1_C)))
      );
      const [lo, hi] = u64.to('u32', sum);
      s.memory.tmp[pos].set(lo);
      s.functions.addCarry.call(u32.add(pos, u32.const(1)), hi);
    })
    .fn('k1AddOut', ['u32', 'u32'], 'void', (s, pos, value) => {
      const { u32, u64 } = s.types;
      s.doWhile(
        [pos, value],
        (p, c) => u32.and(u32.ne(c, u32.const(0)), u32.lt(p, u32.const(MAX_LIMBS))),
        (p, c) => {
          const sum = u64.add(
            u64.fromN('u32', s.memory.out[p].get()),
            u64.fromN('u32', c)
          );
          const [lo, hi] = u64.to('u32', sum);
          s.memory.out[p].set(lo);
          return [u32.add(p, u32.const(1)), hi];
        }
      );
    })
    .fn('k1AddMulOut977', ['u32', 'u32'], 'void', (s, pos, value) => {
      const { u32, u64 } = s.types;
      const sum = u64.add(
        u64.fromN('u32', s.memory.out[pos].get()),
        u64.mul(u64.fromN('u32', value), u64.fromN('u32', u32.const(K1_C)))
      );
      const [lo, hi] = u64.to('u32', sum);
      s.memory.out[pos].set(lo);
      s.functions.k1AddOut.call(u32.add(pos, u32.const(1)), hi);
    })
    .fn('k1FoldOut', [], 'void', (s) => {
      const { u32 } = s.types;
      s.doN([], u32.const(2), () => {
        const high = s.memory.out[u32.const(K1_LIMBS)].get();
        s.memory.out[u32.const(K1_LIMBS)].set(u32.const(0));
        s.functions.k1AddMulOut977.call(u32.const(0), high);
        s.functions.k1AddOut.call(u32.const(1), high);
      });
    })
    .fn('k1CondSubOut', [], 'void', (s) => {
      const { u32 } = s.types;
      const [borrow] = s.doN([u32.const(0)], u32.const(K1_LIMBS), (i, borrow) => {
        const ai = s.memory.out[i].get();
        const bi = k1PrimeLimb(s, i);
        const diff = u32.sub(u32.sub(ai, bi), borrow);
        const lt = u32.lt(ai, bi);
        const eq = u32.eq(ai, bi);
        s.memory.tmp[i].set(diff);
        return [u32.or(lt, u32.and(borrow, eq))];
      });
      const mask = u32.sub(u32.const(0), u32.eq(borrow, u32.const(0)));
      const notMask = u32.not(mask);
      s.doN([], u32.const(K1_LIMBS), (i) => {
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
      s.doN([], u32.const(3), () => {
        s.doN([], u32.const(K1_TMP_LIMBS - K1_LIMBS), (i) => {
          const pos = u32.sub(u32.const(K1_TMP_LIMBS - 1), i);
          const high = s.memory.tmp[pos].get();
          s.memory.tmp[pos].set(u32.const(0));
          const low = u32.sub(pos, u32.const(K1_LIMBS));
          s.functions.k1AddMulTmp977.call(low, high);
          s.functions.k1AddTmp.call(u32.add(low, u32.const(1)), high);
        });
      });
      s.doN([], u32.const(K1_LIMBS), (i) => {
        s.memory.out[i].set(s.memory.tmp[i].get());
      });
      s.functions.k1NormalizeOut.call();
    })
    .fn('k1Add', [], 'void', (s) => {
      const { u32, u64 } = s.types;
      s.memory.out[u32.const(K1_LIMBS)].set(u32.const(0));
      const [carry] = s.doN([u32.const(0)], u32.const(K1_LIMBS), (i, carry) => {
        const sum = u64.add(
          u64.add(u64.fromN('u32', s.memory.a[i].get()), u64.fromN('u32', s.memory.b[i].get())),
          u64.fromN('u32', carry)
        );
        const [lo, hi] = u64.to('u32', sum);
        s.memory.out[i].set(lo);
        return [hi];
      });
      s.memory.out[u32.const(K1_LIMBS)].set(carry);
      s.functions.k1NormalizeOut.call();
    })
    .fn('k1Sub', [], 'void', (s) => {
      const { u32, u64 } = s.types;
      s.memory.out[u32.const(K1_LIMBS)].set(u32.const(0));
      const [borrow] = s.doN([u32.const(0)], u32.const(K1_LIMBS), (i, borrow) => {
        const ai = s.memory.a[i].get();
        const bi = s.memory.b[i].get();
        const diff = u32.sub(u32.sub(ai, bi), borrow);
        const lt = u32.lt(ai, bi);
        const eq = u32.eq(ai, bi);
        s.memory.out[i].set(diff);
        return [u32.or(lt, u32.and(borrow, eq))];
      });
      const mask = u32.sub(u32.const(0), borrow);
      s.doN([u32.const(0)], u32.const(K1_LIMBS), (i, carry) => {
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
      s.doN([], u32.const(K1_TMP_LIMBS), (i) => {
        s.memory.tmp[i].set(u32.const(0));
      });
      s.doN([], u32.const(K1_LIMBS), (i) => {
        const [carry] = s.doN([u32.const(0)], u32.const(K1_LIMBS), (j, carry) => {
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
        s.functions.addCarry.call(u32.add(i, u32.const(K1_LIMBS)), carry);
      });
      s.functions.k1ReduceTmp.call();
    })
    .fn('k1Sqr', [], 'void', (s) => {
      const { u32 } = s.types;
      s.doN([], u32.const(K1_LIMBS), (i) => {
        s.memory.b[i].set(s.memory.a[i].get());
      });
      s.functions.k1Mul.call();
    })
    .fn('k1Pow', ['u32'], 'void', (s, bits) => {
      const { u32 } = s.types;
      s.doN([], u32.const(K1_LIMBS), (i) => {
        s.memory.acc[i].set(s.memory.one[i].get());
        s.memory.base[i].set(s.memory.a[i].get());
      });
      s.doN([], bits, (bitPos) => {
        const word = s.memory.exp[u32.shr(bitPos, u32.const(5))].get();
        const bit = u32.and(u32.shr(word, u32.and(bitPos, u32.const(31))), u32.const(1));
        const mask = u32.sub(u32.const(0), bit);
        const notMask = u32.not(mask);
        s.doN([], u32.const(K1_LIMBS), (i) => {
          s.memory.a[i].set(s.memory.acc[i].get());
          s.memory.b[i].set(s.memory.base[i].get());
        });
        s.functions.k1Mul.call();
        s.doN([], u32.const(K1_LIMBS), (i) => {
          const keep = u32.and(s.memory.acc[i].get(), notMask);
          const select = u32.and(s.memory.out[i].get(), mask);
          s.memory.acc[i].set(u32.or(keep, select));
        });
        s.doN([], u32.const(K1_LIMBS), (i) => {
          const word = s.memory.base[i].get();
          s.memory.a[i].set(word);
          s.memory.b[i].set(word);
        });
        s.functions.k1Mul.call();
        s.doN([], u32.const(K1_LIMBS), (i) => {
          s.memory.base[i].set(s.memory.out[i].get());
        });
      });
      s.doN([], u32.const(K1_LIMBS), (i) => {
        s.memory.out[i].set(s.memory.acc[i].get());
      });
    });
  return mod;
}

const generated = toWasm(buildModule(), { native64bit: true, optimize: true }).modFn.replace(
  'export default function fieldWasm(_imports = {}, pool)',
  'export default function createFieldWasm(_imports: any = {}, pool?: any): any'
);
const source = `// @ts-nocheck\n// Generated by scripts/build-field-wasm.ts. Do not edit by hand.\n${generated}\n`;
const out = fileURLToPath(new URL('../src/abstract/field-wasm-core.ts', import.meta.url));
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, source);
