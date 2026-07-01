# Design note: GLV endomorphism in the CT-hardened multiply (lattice-randomized split + entrywise-ψ comb)

Status: **future work, not implemented.** Written on the `0701-timing` branch after the wNAF→comb
refactor, as the answer to "can endo still be utilized in the current constant-time-hardened
setting?" Short version: yes, but only with the design below, and the trade-offs argue against
building it until secp256k1 sign latency is an actual bottleneck.

## Context: current state and why endo was dropped from the secret path

The hardened secret-scalar path (`Comb.cachedSecret` → `cachedBlinded` in `src/abstract/curve.ts`)
computes `n = k + r·ORDER` with a 128-bit blind `r` (top bits forced to `10`), then runs one
constant-time comb walk over `Fn.BITS + 128` bits. GLV endomorphism survives only in the
variable-time public path (`mulEndoUnsafe`, un-precomputed `multiplyUnsafe`).

Endo was dropped from the secret path because **GLV splitting and additive blinding cancel each
other**:

- *Split the blinded scalar:* the GLV decomposition is Babai rounding — it maps any integer
  representative of `k mod n` to the same short lattice-coset vector. Splitting `k + r·n` yields
  (essentially) the same ~128-bit halves as splitting `k`. The identity that makes blinding correct
  (`n·P = O`) is exactly what makes it evaporate under decomposition: fixed control flow, zero
  randomization.
- *Blind the halves at full width:* `k₁' = k₁ + r₁·n` is valid, but each half becomes 384 bits. Two
  384-bit streams with shared doublings (38 dbl + ~78 adds) is strictly worse than the current
  single stream (38 dbl + 39 adds). Full-width blinding erases the entire endo win.

The workable middle ground randomizes the *decomposition* instead of the scalar.

## Background: the split is Babai rounding on a 2-D lattice

`_splitEndoScalar` (`src/abstract/weierstrass.ts`) works over

```
L = { (u, v) ∈ ℤ² : u + v·λ ≡ 0 (mod n) }
```

Every lattice point is "a way of writing 0". The curve config supplies a reduced basis
`b⃗₁ = (a1, b1)`, `b⃗₂ = (a2, b2)` with entries ≈ √n ≈ 2^128 (`endo.basises` in
`src/secp256k1.ts`). Given `k`, the code computes `c1 = divNearest(b2·k, n)`,
`c2 = divNearest(−b1·k, n)` and subtracts `c1·b⃗₁ + c2·b⃗₂` from `(k, 0)`: it maps `(k, 0)` to the
*nearest* coset representative. That is why the halves are short — and why the output is
**deterministic in `k mod n`**, which is the incompatibility with blinding described above.

## Idea 1: lattice-randomized split

Pick a random *nearby* representative instead of the nearest one:

```
(k₁', k₂') = (k₁, k₂) + e₁·b⃗₁ + e₂·b⃗₂,   e₁, e₂ random in [2^(t−1), 2^t)
```

Correctness is one line: `b⃗₁, b⃗₂ ∈ L`, so `k₁' + k₂'·λ ≡ k₁ + k₂·λ ≡ k (mod n)`, hence
`k₁'·P + k₂'·ψ(P) = k·P` for any `P` in the order-`n` subgroup. No side condition beyond what GLV
itself needs (endo curves here — secp256k1, bn254 — are cofactor-1 anyway).

Properties, mirroring the current blind's construction:

- **Width**: `|kᵢ'| ≤ |kᵢ| + (e₁ + e₂)·2^128 ≈ 2^(129+t)`. At t=32, halves are ~161 bits.
- **Entropy**: 2t bits of per-call representation randomness — each `(e₁, e₂)` produces a different
  comb digit sequence, which is what a DPA/template adversary would need to average over.
- **Forced low end** `e ≥ 2^(t−1)`: same trick as `blind[0] |= 0x80` today — even under a
  degenerate RNG the representative is never the deterministic Babai one, and the halves'
  bit-length is pinned to ~129+t so the walk shape does not vary.
- **Signs**: `k₁', k₂'` can still be negative. Each stream carries one secret sign bit for the whole
  multiply; fold it in by selecting `P` vs `−P` once per stream with a data-oblivious select (a
  2-element scan, same pattern as the table lookup). The half-width assertion in `_splitEndoScalar`
  changes from `2^⌈bits/2⌉` to the public constant `2^(129+t)`.
- **Hardening the split**: the two `divNearest` calls and four products touch raw `k` with
  variable-*value* bigint arithmetic. Once the `k1neg`/`k2neg` if-negations become selects there are
  no secret-dependent *branches* left, matching the library's "algorithmic best-effort" model — but
  this is arithmetic on the **unblinded** secret, a surface the current design does not have (today
  `k` is consumed once, into `scalar + blind·ORDER`).

## Idea 2: the ψ-table is free (entrywise-ψ comb)

Naively, two scalar streams need two comb tables: one for `P`, one for `ψ(P)`. But **ψ is a group
homomorphism and comb entries are sums of doublings of `P`**. A comb entry is
`T[m] = Σ_{i ∈ m} 2^(i·d)·P`, so

```
ψ(T[m]) = Σ 2^(i·d)·ψ(P)
```

— exactly entry `m` of the comb table for `ψ(P)`, same `(W, d)` layout. And ψ on coordinates is a
single field multiplication: `(x, y) ↦ (β·x, y)`. Two ways to exploit this:

- **Materialized**: after building (and `normalizeZ`-ing) the `P` table, derive the ψ-table by
  mapping `x → β·x` over the 1024 entries. That is 1024 field muls, versus ~1000 point *additions*
  (≈12 field muls each) to build a table from scratch — table #2 costs under 1% of table #1.
- **On-the-fly**: keep only the `P` table; each row selects `T[digit₂]` with the second stream's
  digit and applies `β` to the selected point's x before adding. Costs `d` extra field muls per
  multiply (~17 for t=32) and zero extra memory. Normalized entries stay normalized (Z=1), so
  mixed-add speed is preserved.

## The interleaved walk

Strauss–Shamir over the comb structure — the doublings are shared between streams, which is the
entire point:

```
d = ceil((129+t) / W)                     // 17 rows for W=10, t=32
for row = d−1 … 0:
    p = p.double()                        // once per row (skip first), SHARED
    digit₁, digit₂ = comb digits of k₁', k₂' at this row
    S₁ = oblivious-scan(T_P, digit₁);  S₁ = signSelect₁(S₁)
    S₂ = oblivious-scan(T_P, digit₂);  S₂ = ψ(signSelect₂(S₂))
    p/f += S₁;  p/f += S₂                 // zero digits feed the fake accumulator, as combCT does
```

Cost model (secp256k1, W=10, complete formulas ≈ 12M per add, ≈ 9M per double):

| variant                          | rows `d` | doubles | adds | ≈ field muls |
| -------------------------------- | -------- | ------- | ---- | ------------ |
| current blinded comb (384-bit)   | 39       | 38      | 39   | ~810M        |
| endo, t=32 (161-bit halves)      | 17       | 16      | 34   | ~560M        |
| endo, t=64 (193-bit halves)      | 20       | 19      | 40   | ~650M        |

So **~1.45x faster sign** at t=32, decaying toward ~1.25x if entropy is pushed to 128 bits (t=64).
That monotone trade — every bit of blinding costs speed — is the design's honest summary. The
current non-endo scheme sits at the far end: full 127-bit entropy, zero endo speedup.

## Risks and open items

1. **The entropy argument gets weaker and vaguer.** 64 bits of representation randomness (t=32) is
   probably enough to defeat trace averaging in practice, but "probably enough" is a worse position
   than the current 2^127, and the proof burden shifts from a one-line bound to a
   lattice-distribution argument (randomized representatives form a box in lattice coordinates, not
   a uniform interval).
2. **Raw-secret arithmetic in the split**: `b2·k`, `divNearest` — value-dependent bigint ops on
   unblinded `k` before any masking exists. Minerva taught us aggregate-trend leaks live exactly in
   places like this.
3. **Digit regularity**: the sketch inherits `combCT`'s "zero digit → fake add" pattern. The
   literature's polished answer is **GLV-SAC** (Faz-Hernández–Longa–Sánchez): recode the two halves
   into signed odd digits aligned column-wise so *every* row does a real add and no fake accumulator
   is needed — stronger regularity, at the cost of a recoding step and signed-digit tables. If this
   graduates from sketch to implementation, GLV-SAC recoding on top of the comb bases is the version
   to build; FourQ's implementation is the reference art.
4. **Integration**: a `cachedSecretEndo` branch in `Comb.cachedSecret`, gated on the curve passing
   `(beta, basises)` down (today `Comb` is endo-blind — weierstrass keeps endo entirely outside the
   class). Table cache gains a `(W, bits = 129+t)` entry; `getCombPrecomputes` needs a ψ-derivation
   hook or the on-the-fly β variant. Roughly +150 lines on the most security-critical path, for
   secp256k1/bn254 only.

## Bottom line

The math closes — correctness is a one-line homomorphism argument at each step — but the design
spends audit surface and blinding margin to buy ~1.45x on one curve family. Keep as a documented
design note; do not build until secp256k1 sign throughput is an actual bottleneck for a real
consumer.
