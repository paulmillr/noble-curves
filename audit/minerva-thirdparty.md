# Minerva timing side-channel: noble vs `elliptic` vs `sjcl`

Comparative study of the Minerva class of attack (leak the ECDSA nonce's bit-length via `sign()`
timing → Howgrave-Graham–Smart / Hidden-Number-Problem lattice → recover the private key; see
`audit/lattice.md` and the reference PoC in `audit/minerva/`) across three JavaScript ECC libraries,
all on **P-256 (secp256r1)**.

**Headline result:** the *same* attack that gets **zero traction on noble** recovers a **full P-256
private key from `sjcl`** (and finds a moderate leak in `elliptic`) using nothing but real
JS wall-clock `sign()` timing. noble's constant-time scalar multiplication is the load-bearing
defense the other two lack.

| library | version | fastest-90 mean leading-zeros | Pearson r(bitlen, time) | outcome |
|---|---|---|---|---|
| **@noble/curves** | main | **0.99** (= random) | ~0.02 (noise floor) | no usable leak — lattice never gets traction |
| **elliptic** | 6.6.1 | **1.5** | 0.10 | moderate leak; oracle-recoverable, real-timing borderline |
| **sjcl** | 1.0.9 | **8.2** | 0.20 | strong leak — **FULL KEY RECOVERED from real timing** |

("fastest-90 mean leading-zeros" = the average number of leading zero bits of the *recovered nonces*
of the 90 fastest-timed signatures; random nonces average ~1.0. Higher = the timing reliably
identifies short nonces = a usable Minerva oracle.)

## Threat model & method

- **Victim:** each library signing P-256 ECDSA with a fixed key.
- **Attacker:** co-located, can trigger signing and time each `sign()` (`process.hrtime`), single
  measurement per signature. No simulated oracle — the timing is the real side channel.
- **Measurement** (`benchmark/thirdparty/minerva_3p.mjs`): sign, recover each nonce
  `k = s⁻¹(z + r·d) mod n` (we hold the key; recovery sanity-checked via `(k·G).x == r`), bin the
  timing by `bit_length(k)`, report the correlation and the leading-zero enrichment of the
  fastest-timed signatures.
- **Lattice** (`audit/minerva/poc/attack/attack.py`, `fpylll` LLL/BKZ): standard Minerva HNP
  `k = t·d + u (mod n)` with `t = s⁻¹r`, `u = -s⁻¹h`, sorted by timing, `geom_bound` per-rank
  known-leading-zero weights.

## Root cause of the difference

The classic Minerva leak is a **bit-length-proportional loop** in scalar multiplication: `k·G` runs
≈`bit_length(k)` iterations, so shorter nonces sign measurably faster and the timing is a clean
per-signature bit-length oracle.

- **sjcl** and **elliptic** use variable-time scalar multiplication → this leak is present (strong in
  sjcl, moderate in elliptic; elliptic's base-point mul is partly windowed so it's weaker/noisier).
- **noble** uses **fixed-window constant-time** scalar multiplication (`wNAF_CT` processes a fixed
  number of windows regardless of the scalar) → no bit-length leak. Its only variable-time part,
  the extended-Euclidean inversion, leaks the *GCD iteration count*, which is value-scattered rather
  than bit-length-proportional and therefore **not rankable per-signature** (see the branch note in
  `CLAUDE.md` / the noble Minerva analysis). Enrichment stays at 0.99 ≈ random.

Perfect-oracle sanity check (sort by *true* bit-length instead of timing) recovers all three
instantly (noble 628, elliptic 538, sjcl 814 bits of lattice info) — i.e. every library's signatures
are cryptographically attackable *given a clean oracle*; the only thing that differs is whether the
timing provides one.

## Full `sjcl` key recovery from real timing (finalized)

sjcl uses **random** nonces, so signing one fixed message many times yields many distinct nonces
sharing one message representative — the exact input shape of the reference `attack.py`.

Pipeline:

1. `benchmark/thirdparty/collect_sjcl_attackpy.mjs` — collect **120,000** signatures of one fixed
   message, timing each `sign()` (single-shot, real JS wall clock). A larger N makes the fastest-timed
   tail genuinely short (fastest-90 average ≈ 8.2 leading zeros, only ~3 full-length contaminants).
2. Run the validated `attack.py` Solver with two standard robustness tweaks (both needed for noisy
   real timing):
   - **skip the fastest ~20 measured signatures** — single-shot measurement outliers whose
     `geom_bound` would be wildly over-assigned and fatal;
   - **subtract a margin (~4) from `geom_bound`** — keep per-row bounds ≤ the true (noisy)
     leading-zeros; any over-estimate makes the target vector nonexistent.
   - dimension 110, LLL → BKZ.

Result: **private key recovered in ~69 s**, verified `d·G == pubkey`:

```
Building lattice with 694 bits of information (overhead 2.71).
*** FOUND PRIVATE KEY *** : 0x4fb774788070df987db2757028d654c320fda15df6f279dbad4dd5d9741b5807
recovered * G == pubkey  : True
```

Why the naive attack fails and this succeeds: single-shot timing produces **random per-row
over-estimates** of leading-zeros; the hard-bound lattice cannot tolerate a single over-estimate.
`skip` removes the worst offenders (measurement outliers at the head), `margin` keeps the rest
conservative, and the large N supplies a short-enough tail — the same engineering the Minerva paper
used (`audit/minerva/experiments/{bounds,recenter,random_subsets}`).

`elliptic`'s leak (enrichment 1.5) is real and oracle-recoverable but sits near the edge for the
standard lattice from real single-shot timing; with its **deterministic** nonces an attacker can
average repeated same-message signatures to sharpen the oracle.

## Conclusion

- **noble is Minerva-resistant** because of its constant-time fixed-window scalar multiplication; the
  attack gets no usable per-signature bit-length signal (0.99 enrichment).
- **sjcl is fully Minerva-exploitable** — end-to-end private-key recovery from real timing
  demonstrated here.
- **elliptic** leaks moderately.
- This is a concrete, end-to-end confirmation that constant-time scalar multiplication is the
  property that matters, and that unmaintained libraries (sjcl) remain exploitable.

## Reproduction

Prerequisites — the lattice drivers reuse the reference Minerva PoC (`ec.py`, `attack.py`), which is
**not** a submodule; clone it into `audit/minerva/` and install `fpylll`:

```sh
git clone https://github.com/crocs-muni/minerva audit/minerva
pip install fpylll
cd benchmark/thirdparty && npm i                          # installs elliptic, sjcl
```

Then (all commands from `benchmark/thirdparty/`):

```sh
# 1) leak measurement — sign, recover nonces, report bit-length enrichment (+ per-sig CSV)
node minerva_3p.mjs elliptic 3000 150 /tmp/ct_elliptic.csv
node minerva_3p.mjs sjcl    100000 1  /tmp/ct_sjcl.csv

# 2) attackability check (perfect oracle) on the per-signature CSVs
python3 minerva_lattice.py /tmp/ct_sjcl.csv 70 oracle     # -> FOUND PRIVATE KEY (LLL, instant)

# 3) full sjcl key recovery from REAL timing
node collect_sjcl_attackpy.mjs 120000 /tmp/sjcl_big.csv   # attack.py-format input (fixed msg)
python3 minerva_attack.py /tmp/sjcl_big.csv 4 110 20      # margin=4 dim=110 skip=20 -> key in ~70s
```

Tooling, all committed under `benchmark/thirdparty/`:
- `minerva_3p.mjs` — leak measurement + per-signature CSV, for all three libraries.
- `collect_sjcl_attackpy.mjs` — `attack.py`-format collector (sjcl, fixed message, random nonces).
- `minerva_lattice.py` — per-signature-hash HNP lattice (`oracle`/`timing` modes); verifies
  recovered keys via `g·G == pubkey`.
- `minerva_attack.py` — same-message recovery with the `skip`+`margin` robustness tweaks.

The two Python drivers are thin wrappers over the reference `Solver` in
`audit/minerva/poc/attack/attack.py` and resolve it via a path relative to their own location, so
they run from a clean checkout once `audit/minerva/` is cloned.
